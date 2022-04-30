package httpx

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestRetry(t *testing.T) {
	/*
		client := http.Client{
		}
	*/

	retryClient := RetryHttpClient{
		//Client:   client,
		Client: http.Client{
			Timeout: 5 * time.Second,
		},
		maxRetry: 3,
		interval: time.Second,
	}

	resp, _ := retryClient.Get("http://baidu.com")
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}
