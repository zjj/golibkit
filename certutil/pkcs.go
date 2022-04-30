package certutil

import (
	"github.com/tjfoc/gmsm/pkcs12"
	"github.com/tjfoc/gmsm/x509"
)

// MakePfx .
func MakePfx(priv interface{}, certificate *x509.Certificate, pwd string) ([]byte, error) {
	pfxDataNew, err := pkcs12.Encode(priv, certificate, nil, pwd)
	if err != nil {
		return nil, err
	}
	return pfxDataNew, nil
}
