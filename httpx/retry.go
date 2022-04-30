/*
simple http client wrapping with retry
*/
package httpx

import (
	"io"
	"net/http"
	"time"
)

type Client = http.Client

var (
	defaultMaxRetry_ = 3
	defaultInterval_ = time.Microsecond * 300
	defaultTimeout_  = time.Second * 30
)

type RetryHttpClient struct {
	Client
	maxRetry int
	interval time.Duration
}

func NewRetryHttpClient() *RetryHttpClient {
	client := http.Client{
		Timeout: defaultTimeout_,
	}
	return &RetryHttpClient{
		Client:   client,
		maxRetry: defaultMaxRetry_,
		interval: defaultInterval_,
	}
}

func (c *RetryHttpClient) WithTransport(tr http.RoundTripper) *RetryHttpClient {
	c.Client.Transport = tr
	return c
}

func (c *RetryHttpClient) WithTimeout(t time.Duration) *RetryHttpClient {
	c.Client.Timeout = t
	return c
}

func (c *RetryHttpClient) WithMaxRetry(n int) *RetryHttpClient {
	c.maxRetry = n
	return c
}

func (c *RetryHttpClient) WithInterval(d time.Duration) *RetryHttpClient {
	c.interval = d
	return c
}

func (c *RetryHttpClient) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var doErr error
	maxRetry := c.maxRetry
	for maxRetry > 0 {
		resp, doErr = c.Client.Do(req)
		if doErr == nil {
			return resp, nil
		}

		maxRetry--
		time.Sleep(c.interval)
		if req.GetBody != nil {
			var err error
			req.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		}
	}
	return nil, doErr
}

func (c *RetryHttpClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *RetryHttpClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}
