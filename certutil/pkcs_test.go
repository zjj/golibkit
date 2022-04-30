package certutil

import (
	"encoding/base64"
	"fmt"
	"log"
	"testing"
)

func TestMakePfx(x *testing.T) {
	priv, _ := ReadPrivateKeyFromFile("/tmp/certs/private.key")
	cert, _ := ReadCertificateFromFile("/tmp/certs/server.cert")
	pfxData, err := MakePfx(priv, cert, "123456")
	if err != nil {
		log.Fatal(err)
	}
	_ = pfxData
	fmt.Println(base64.StdEncoding.EncodeToString(pfxData))
}
