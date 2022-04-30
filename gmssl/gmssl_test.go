/* +build cgo */
package gmssl

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"ra/libs/httpx"
	"strings"
	"testing"
)

func foo() {
	dial := func(network, addr string) (net.Conn, error) {
		sslctx, err := NewSSLContext("", true)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(addr, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("addr error:%s", addr)
		}
		host, port := parts[0], parts[1]
		return sslctx.Connect(host, port, "SM2-WITH-SMS4-SM3")
	}

	tr := &http.Transport{
		DialTLS: dial,
	}

	client := &http.Client{
		Transport: tr,
	}

	resp, err := client.Get("https://sm2test.ovssl.cn/style.css")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println(string(body))
	_ = body

	client.CloseIdleConnections()
	return
}

func TestSSLConnect(t *testing.T) {
	foo()
	return
}

