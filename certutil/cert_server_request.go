package certutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

/*
var attributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}
*/

func subjectToPkixName(subject string) (*pkix.Name, error) {
	ret := &pkix.Name{}
	dns, err := ldap.ParseDN(subject)
	if err != nil {
		return nil, err
	}
	for _, dn := range dns.RDNs {
		for _, attr := range dn.Attributes {
			k, v := attr.Type, attr.Value
			switch k {
			case "C":
				ret.Country = append(ret.Country, v)
			case "O":
				ret.Organization = append(ret.Organization, v)
			case "OU":
				ret.OrganizationalUnit = append(ret.OrganizationalUnit, v)
			case "CN":
				ret.CommonName = v
			case "L":
				ret.Locality = append(ret.Locality, v)
			case "ST":
				ret.Province = append(ret.Province, v)
			case "STREET":
				ret.StreetAddress = append(ret.StreetAddress, v)
			case "SERIALNUMBER":
				ret.SerialNumber = v
			case "POSTALCODE":
				ret.PostalCode = append(ret.PostalCode, v)
			default:
				return nil, fmt.Errorf("unsupported %s", k)
			}
		}
	}
	return ret, nil
}

// no password
func newRSAPriv() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func dumpRSAPriv(priv *rsa.PrivateKey) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	buff := new(bytes.Buffer)
	err := pem.Encode(buff, block)
	if err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}

// yes, it's return as sm2.xxxx, because sm2 supports both
func newRSAServerCR(name *pkix.Name) (*x509.CertificateRequest, error) {
	cr := &x509.CertificateRequest{}
	cr.Subject = *name
	cr.SignatureAlgorithm = x509.SHA256WithRSA
	return cr, nil
}

func newSM2ServerCR(name *pkix.Name) (*x509.CertificateRequest, error) {
	cr := &x509.CertificateRequest{}
	cr.Subject = *name
	cr.SignatureAlgorithm = x509.SM2WithSM3
	return cr, nil
}

func newServerCSR(cr *x509.CertificateRequest, priv interface{}) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, cr, priv.(crypto.Signer))
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	buff := new(bytes.Buffer)
	err = pem.Encode(buff, block)
	if err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}

func newSM2Priv() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

func dumpSM2Priv(priv *sm2.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalSm2PrivateKey(priv, nil)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	buff := new(bytes.Buffer)
	err = pem.Encode(buff, block)
	if err != nil {
		return nil, err
	}
	return buff.Bytes(), err
}

func NewCSR(subject, algo string) (privBytes []byte, csrBytes []byte, err error) {
	name, er := subjectToPkixName(subject)
	if er != nil {
		err = er
		return
	}

	switch algo {
	case "sm2":
		cr, er := newSM2ServerCR(name)
		if er != nil {
			err = er
			return
		}

		priv, er := newSM2Priv()
		if er != nil {
			err = er
			return
		}
		pbs, er := dumpSM2Priv(priv)
		if er != nil {
			err = er
			return
		}
		privBytes = pbs

		cbs, er := newServerCSR(cr, priv)
		if er != nil {
			err = er
			return
		}
		csrBytes = cbs
		return
	case "rsa":
		cr, er := newRSAServerCR(name)
		if er != nil {
			err = er
			return
		}
		priv, er := newRSAPriv()
		if er != nil {
			err = er
			return
		}
		pbs, er := dumpRSAPriv(priv)
		if er != nil {
			err = er
			return
		}
		privBytes = pbs

		cbs, er := newServerCSR(cr, priv)
		if er != nil {
			err = er
			return
		}
		csrBytes = cbs
		return
	default:
		return nil, nil, fmt.Errorf("only supports ras and sm2")
	}
}
