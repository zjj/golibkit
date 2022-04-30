package certutil

import (
	"fmt"
	"log"
	"testing"
)

func TestNewCSR(t *testing.T) {

	p, c, err := NewCSR("C=US, ST=California, L=San Francisco, O=Wikimedia Foundation Inc., CN=*.wikipedia.org",
		"rsa",
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(p))
	fmt.Println(string(c))
}
