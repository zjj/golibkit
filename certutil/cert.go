package certutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"time"

	gox509 "crypto/x509"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

type Certificate = x509.Certificate

var (
	ParsePKCS7        = x509.ParsePKCS7
	ParseCertificate  = x509.ParseCertificate
	ParseCertificates = x509.ParseCertificates
)

var (
	OIDSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureSM2WithSM3      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
)

func GetPublicKeySizeFromCert(cert *Certificate) int {
	signAlgo := cert.SignatureAlgorithm.String()
	if strings.HasPrefix(signAlgo, "SM2-") {
		return 256
	}

	pub := cert.PublicKey
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub.Size() * 8 // bits
	case *ecdsa.PublicKey:
		return 0 //FIXME: 0 ?
	case *sm2.PublicKey:
		return 256
	default:
		return 0
	}
}

// ReadCertificateFromFile reads cert from file
// only one
func ReadCertificateFromFile(path string) (*Certificate, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ReadCertificateFromBytes(f)
}

func ReadCertificateFromBytes(f []byte) (*Certificate, error) {
	if !bytes.Contains(f, []byte("CERTIFICATE")) {
		cert, err := ParseCertificate(f)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}

	block, rest := pem.Decode(f)
	if block == nil || len(rest) > 0 {
		return nil, errors.New("seems wrong cert file")
	}

	switch typ := block.Type; typ {
	case "PKCS7":
		p7, err := ParsePKCS7(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pkcs7 cert:%s", err.Error())
		}
		if len(p7.Certificates) == 0 {
			return nil, fmt.Errorf("there's no certs")
		}
		return p7.Certificates[0], nil
	default:
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, fmt.Errorf("there's no certs")
		}
		return cert, nil
	}
}

func DumpCertificateAsPem(cert *Certificate) ([]byte, error) {
	if len(cert.Raw) == 0 {
		return nil, errors.New("cert Raw empty")
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	var buf bytes.Buffer
	err := pem.Encode(&buf, block)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadPrivateKeyFromFile .
func ReadPrivateKeyFromFile(path string) (crypto.PrivateKey, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKeyFromBytes(f)
}

// ReadPrivateKeyFromBytes .
func ReadPrivateKeyFromBytes(f []byte) (crypto.PrivateKey, error) {
	var der []byte
	if bytes.Contains(f, []byte("PRIVATE KEY")) {
		block, rest := pem.Decode(f)
		if block == nil || len(rest) > 0 {
			return nil, errors.New("seems wrong private file")
		}
		der = block.Bytes
	} else {
		der = f
	}
	priv, err := parsePrivateKey(der)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der, nil); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseSm2PrivateKey(der); err == nil {
		fmt.Println(key.PublicKey)
		return key, nil
	}
	if key, err := gox509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := gox509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("tls: failed to parse private key")
}

func GetRawPublicKeyInfoFromCSR(f []byte) ([]byte, error) {
	var der []byte
	var err error
	func() {
		if bytes.Contains(f, []byte("REQUEST")) {
			block, rest := pem.Decode(f)
			if block == nil || len(rest) > 0 {
				err = errors.New("seems wrong CSR file")
				return
			}
			der = block.Bytes
			return
		}
		block, rest := pem.Decode(f)
		if block != nil && len(rest) == 0 {
			der = block.Bytes
			return
		}
		der, err = base64.StdEncoding.DecodeString(string(f))
		if err == nil {
			return
		}
		der = f
	}()
	if err != nil {
		return nil, err
	}

	cr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	return cr.RawSubjectPublicKeyInfo, nil
}

func ParseSignatureAlgo(s string) (x509.SignatureAlgorithm, error) {
	switch s {
	case OIDSignatureSHA256WithRSA.String():
		return x509.SHA256WithRSA, nil
	case OIDSignatureSM2WithSM3.String():
		return x509.SM2WithSM3, nil
	default:
		return 0, fmt.Errorf("non supported algo for RA:%s", s)
	}
}

func FmtSerialNumberString(s *big.Int) string {
	return fmt.Sprintf("%x", s)
}

func CheckSignatureByCert(
	algo x509.SignatureAlgorithm,
	msg []byte,
	sig []byte,
	cert *x509.Certificate,
) error {
	return cert.CheckSignature(algo, msg, sig)
}

func SignMsgByPrivateKey(
	algo x509.SignatureAlgorithm,
	msg []byte,
	priv crypto.PrivateKey,
) (sig []byte, err error) {
	hashFunc := NewHashFunc(algo, nil)
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		hash := GetHashOfAlgo(algo)
		sig, err = priv.Sign(rand.Reader, hashFunc(msg), hash)
		return
	case *sm2.PrivateKey:
		sig, err = priv.Sign(rand.Reader, msg, nil)
		return
	default:
		err = errors.New("non support privakey algo")
		return
	}
}

// SignAndVerify check if priv and cert's pub match
func SignAndVerify(priv crypto.PrivateKey, cert *x509.Certificate) error {
	msg := []byte("123456")
	algo := x509.SHA256WithRSA // since the algo is not used by sm2sm3
	sig, err := SignMsgByPrivateKey(algo, msg, priv)
	if err != nil {
		return err
	}
	return CheckSignatureByCert(algo, msg, sig, cert)
}

func CertDateValidCheck(cert *x509.Certificate) bool {
	now := time.Now().UTC()
	return cert.NotAfter.UTC().After(now) && cert.NotBefore.UTC().Before(now)
}
