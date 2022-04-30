package certutil

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
)

/*
func TestReadCertificateFromFile(t *testing.T) {
	f := "/home/pi/example.org.cer.pem.p7b"
	f = "/tmp/a.p7b"
	f = "/home/pi/Downloads/yanzheng.cer"
	c, err := ReadCertificateFromFile(f)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c.Subject.String())
	fmt.Printf("%x", c.SerialNumber)
}

func TestReadPrivateKeyFromFile(t *testing.T) {
	p, err := ReadPrivateKeyFromFile("/home/pi/ra/certs/private.key")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(p)
	priv := p.(*rsa.PrivateKey)
	fmt.Println(priv.E)
}

type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func TestReadCsr(t *testing.T) {
	pemx := `-----BEGIN CERTIFICATE REQUEST-----
MIICxjCCAa4CAQAwcDESMBAGA1UEAwwJ54ix5Y+R5ZGGMQswCQYDVQQKDAIzNDEL
MAkGA1UECwwCNDMxCzAJBgNVBAYTAkNOMQowCAYDVQQIDAE0MQswCQYDVQQHDAI0
NDEaMBgGCSqGSIb3DQEJARYLNDQzQGZkYS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCmbtSuDRNt1zzlspGV/uIXAM6nOoNy9NV277hg8cDxbLU5
3HJdSTkQAQrRPuygJFvNQH3YXectY+pnVOS+7Z/xs5f01DiszXmq1/nLfAhaYgTb
BGzO0XNt3DWXbJ/kafLH05oRlSiuSuungMsc+xe6JqU8DIKGEb6uJqCrNJUYY7+u
dDmqUyH/an4Ylircl/dEzsxgCGyXQ8MxwTVn48WtHMRZp+9CdoCfazmxCmqfRvG2
KaOIT6bq3TQJnERh/77Tc2LB190DuLqIEoAY4A833xfwPOjquLkY29wstXEx1I4r
Ls8qR0MZIYuMvTPHTsqVm0QlqR/xiDUxCb3sLBeBAgMBAAGgETAPBgkqhkiG9w0B
CQ4xAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCJUSuD80EupymyqFb2RUyB6SVPojLm
MoTu7q9RBKqc0f34LeXJ5Fp6a9siD2oKCGQM4nYXKOfFnp+v0JZ9XJJGolJTQklj
QT03dNpAvEh1GyCiJmHY+x0kUvMegT9FFhFPNYFsCtJBivQefA2Wom6NelMgLt8f
kOTBrqwvGRgQlK02vJhz2X8zipJpQqE9nfwT+f/VDQgR02weEFurcabj4vzVwYDg
arjyiSQKpRT8o4aEzNTlsFB7Ji4q3D2txQT0CyBljSvfCDUTrIYZLxflZhN3HaQv
/w0s1MSXoIUSEaqTuF/spY3RMG0Vmu9tOzFM6RRqael/T4qYItH1bvFX
-----END CERTIFICATE REQUEST-----`

	block, _ := pem.Decode([]byte(pemx))
	der := block.Bytes

	cr, err := sm2.ParseCertificateRequest(der)
	if err != nil {
		log.Fatal(err)
	}
	var pki SubjectPublicKeyInfo
	asn1.Unmarshal(cr.RawSubjectPublicKeyInfo, &pki)

	b, err := asn1.Marshal(pki)
	if err != nil {
		log.Fatal(err)
	}
	x := base64.StdEncoding.EncodeToString(b)
	fmt.Println(x)
}

*/
/*
func TestDecryptByPrivateKey(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := sm2.Encrypt(pub, msg, rand.Reader)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := DecryptByPrivateKey(priv, d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)
}
*/
func TestDecryptbyPrivateKeySM2(t *testing.T) {
	privPem := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgx4WP68odpACn0kN0
UToNNvTul/Jr6aO/wDBh4n6tXBSgCgYIKoEcz1UBgi2hRANCAATW8RPe1azrvu4k
xW8IqljWUkGp0Z3qUKzcodHzjY5m0G1NeconKYKMTJ5rXvT2M5hP+sWcocKzuo/g
e5yfiLuu
-----END PRIVATE KEY-----`

	certPem := `-----BEGIN CERTIFICATE-----
MIICVDCCAfqgAwIBAgIQGAotuUUrRY1B/4N1L0LHgDAKBggqgRzPVQGDdTA+MQsw
CQYDVQQGEwJDTjEPMA0GA1UECgwG5rKD6YCaMR4wHAYDVQQDDBVzdWJfc20yXzAz
MjTpgJrnlKjlkI0wHhcNMjEwMzI1MDY1OTE3WhcNMjIwMzI1MDY1OTE3WjA+MQsw
CQYDVQQGEwJDTjEPMA0GA1UECgwG5rKD6YCaMR4wHAYDVQQDDBVSQeacjeWKoeWZ
qOivgeS5pjAzMjUwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATW8RPe1azrvu4k
xW8IqljWUkGp0Z3qUKzcodHzjY5m0G1NeconKYKMTJ5rXvT2M5hP+sWcocKzuo/g
e5yfiLuuo4HZMIHWMB0GA1UdDgQWBBQK8ws1tU1TvGQ5xgtz5epVXcrbkjAfBgNV
HSMEGDAWgBSDjf2kISJL4xIPkTpvY2z57OQYdDASBgNVHREECzAJggdSQQ2haMFm
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DAYDVR0TAQH/BAIwADBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY2F0ZXN0LmNv
cnAud29zaWduLmNvbS9jcmwvc3ViX3NtMl8wMzI0LmNybDAKBggqgRzPVQGDdQNI
ADBFAiBD8BbFs2Lh22mknt3ujRmoHhCdlyf3f6AyUyawzB31bgIhAKuaLdet3/dj
FccRhzqkOAZ/4i998MIqAR4hxQg7ueTX
-----END CERTIFICATE-----`

	privi, _ := ReadPrivateKeyFromBytes([]byte(privPem))
	cert, _ := ReadCertificateFromBytes([]byte(certPem))
	_ = cert

	priv := privi.(crypto.Signer)
	raw := []byte("180a2db9452b458d41ff83752f42c78012")
	signature, err := SignMsgByPrivateKey(16, raw, priv)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("sig")
	fmt.Println(base64.StdEncoding.EncodeToString(signature))
	fmt.Println(hex.EncodeToString(signature))

	err = CheckSignatureByCert(16, []byte(raw), signature, cert)
	if err != nil {
		log.Fatal(err)
	}
	err = SignAndVerify(priv, cert)
	if err != nil {
		log.Fatal(err)
	}
}

func TestDecryptbyPrivateKeyRSA(t *testing.T) {
	privPem := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsyn+b/caFzDV4nM+BB/0zqG2Q
tND4yj8RmBzV6aulnHZASDt0+WwysTBAikBhC5wspUxwV4Pm8UzwKXFRPhyAIK6E6GzfaXG5UKit
1kXaVURrnVYfLDr2sUrWC9yoDBljgxS7tCBevHcfVkQ7CYDcwNA7qg9i0MjZrN3+XA1pO9Ex7AGW
OfNazxUNa2SMSBy3tFDIsqgGnzw3deCFU8eNToC9oCzAjNERcRQWzqOu1m9DxT5WdzGwAQFseW/i
Dg1b7DwXGdEEPNExGgmqyXHlK6B0c1k3Ho5W80v6yPOzSoUL9DF01WotL4MzEpM897xWy3uS64xh
fSTrmtyB7IFtAgMBAAECggEABsj+4NPCz2847E8QEOuM5FHpV4TaLeLXPiwgeb/uxxaRSC3t88Z1
mrn9gJNNOuJXVCN7kG/HVLLGCCpAcmXDfb6Ky9pKqC0+U34Y2Zav8IZnpOgtQRUeDaDhpO0bUZgE
CTXVAxfsK3wwG1FqZX0Wi9SgeK9RYlp7gJy6rOnVdvvbUvWS6apOzbVdxE1sCYEb+Uy1JLXoz3Hp
nuFpB47mhmFVaKWaN7Tmpq9O2SG3ENoKvXBG54YJUkR5l+4wiFum9MJ3ZBse+CHj7izzbi+sjXP/
Ve1FAet7AJJas0hUsd1JhTlUTDR0fA8EJZjwGUEEM9quZfj3slUFs42AR4jYqwKBgQDTpgawpNSI
17wdB/BBI0OaQeast7Djxn9m53D9UfPhtdp2Bu3iwBAvv/dtjMduvixqoNIo28+i895Odx4UnrrH
bf15UEe4sDoorjozVwUgX5+FjKRwmt4pe4LdR+ISMG4AqKfITOqn0tOC465L+OCIbQrhSxgTL+9u
bc1e8Srb1wKBgQDQ//Gp8x1y3cdetodKT/wn5Zh6GI/Qv8dkoKQOn/WAJlnzVsBUHh5kLpz2Bqog
vWxvBwUngQbe1QZQCh57MJsDcFpHXsSoitXWnI0DbPk3MqEqSDCAJG9BMKd3ColgUqrXMzeRih+2
BENpC+OjHMlRXuVu5NyCRAjCuCy0hacEWwKBgAKoaBcZys15IBShP+QhhDzQrQvoNqF1oa3yJBoa
SFzCQt8OkTgyv0FKQNowVWTPoJEqOdlngUEDnPwRROBvadsNR4yZdH0eQWy3W2W/pwHUEZXEwV/k
ofuVYHxU5cLits7tT0YVqTC4Vg2jvFGZ63/rFqLjpYbAKFqTqGuTzbz7AoGAY+s5OisE1Tm6a0mQ
fLKottpJf3Xmq8JELZOvW16WHGI5duDuqkiL9xFh8S1WgLiO8rXEfRJumnH1xqZP1E10jrxULPLd
ykY13ZiSwiSDMSR/cJt6tIi2t8/vADaFXwumqaPO2UHTz01SfRI2DnFgvgpEXjQESDMGjTFIDjYn
lykCgYEAuS+NBXn98MMR86d60yQZZm+q2+neOLca1HM1Wogs1icFteiZd74R1Dz295+UADDJpmCV
+GNZhSDYvSZdwolfQxvAnTav8q4hQAwn9ofUzqpI0nR8JRJnfOYQKb50b5l5XYoMyk7vdXebLgZq
IdVZJVXQzqI5pJ0HY702Q44esm0=
-----END PRIVATE KEY-----`
	certPem := `-----BEGIN CERTIFICATE-----
MIIDZzCCAk+gAwIBAgIQPRVryWwG8u5XDkOghWjt5DANBgkqhkiG9w0BAQsFADAx
MQswCQYDVQQGEwJDTjELMAkGA1UECgwCV1QxFTATBgNVBAMMDHN1Yl9SU0FfdGVz
dDAeFw0yMDEyMTUxMjMyNTZaFw0yMTEyMDYxMjMyNTZaMB4xCzAJBgNVBAoMAkNO
MQ8wDQYDVQQDDAZzaGVuamkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCsyn+b/caFzDV4nM+BB/0zqG2QtND4yj8RmBzV6aulnHZASDt0+WwysTBAikBh
C5wspUxwV4Pm8UzwKXFRPhyAIK6E6GzfaXG5UKit1kXaVURrnVYfLDr2sUrWC9yo
DBljgxS7tCBevHcfVkQ7CYDcwNA7qg9i0MjZrN3+XA1pO9Ex7AGWOfNazxUNa2SM
SBy3tFDIsqgGnzw3deCFU8eNToC9oCzAjNERcRQWzqOu1m9DxT5WdzGwAQFseW/i
Dg1b7DwXGdEEPNExGgmqyXHlK6B0c1k3Ho5W80v6yPOzSoUL9DF01WotL4MzEpM8
97xWy3uS64xhfSTrmtyB7IFtAgMBAAGjgY0wgYowHQYDVR0OBBYEFOYRqRRgAl+h
iV+UGy3HTBX+ulbSMB8GA1UdIwQYMBaAFKOHvSAjWiBr//DSWt5MrikDZZG4MAsG
A1UdEQQEMAKCADAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG
CCsGAQUFBwMEMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHsAXBOh
OjJ0TAvryJGXXhaKFgli4C3V3LLySMzXQOT2dUBi5Gi6ySIVZ/X+8IcbRFDXXt55
mK3IEbp5c4HGFvrXk7bUFAhbZNvvr9lAxV7YQy3F4qnNipjZNz6T54O0V0G9GD6N
j4k31dGgaQKwXZRPX39u6BhEI8IH00QP4RlXnQRKzg3nebVGieBqhV8RngPmhhmM
FNej7A77hl4aoGoAZL/5C+B8f/v9z4Hv2TUuLXGLIX0qUFtce1eUlYqnxKE3ecd7
5eLxeI4ukJxGYmZ+xIGNt0b7YH1Sq3NukHJTNjpd9lKmIFFu6QEHxKmLjvZ46evy
ueUMooWn2yChuZI=
-----END CERTIFICATE-----`

	privi, _ := ReadPrivateKeyFromBytes([]byte(privPem))
	cert, _ := ReadCertificateFromBytes([]byte(certPem))
	_ = cert

	priv := privi.(crypto.Signer)
	raw := "/business/certmanage/certinfo/id/87/downloadsuccess"
	signature, err := SignMsgByPrivateKey(4, []byte(raw), priv)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("sig")
	fmt.Println(base64.StdEncoding.EncodeToString(signature))

	//err = cert.CheckSignature(4, []byte(raw), signature)
	err = CheckSignatureByCert(4, []byte(raw), signature, cert)
	if err != nil {
		log.Fatal(err)
	}
	err = SignAndVerify(priv, cert)
	if err != nil {
		log.Fatal(err)
	}
}
