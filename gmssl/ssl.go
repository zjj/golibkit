/*
 * Copyright (c) 2017 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* +build cgo */

package gmssl

/*
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

static int _BIO_do_connect(BIO *b) {
	return BIO_do_connect(b);
}

static int _BIO_get_fd(BIO *b) {
	int x;
	BIO_get_fd(b, &x);
	return x;
}

static int _BIO_Close(BIO *b) {
	return BIO_set_close(b, BIO_CLOSE);
}

static long _BIO_get_ssl(BIO *b, SSL **sslp) {
	return BIO_get_ssl(b, sslp);
}

static long _BIO_set_conn_hostname(BIO *b, char *name) {
	return BIO_set_conn_hostname(b, name);
}

static int _SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version) {
	return SSL_CTX_set_min_proto_version(ctx, version);
}

static int _SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version) {
	return SSL_CTX_set_max_proto_version(ctx, version);
}

static int _SSL_set_tlsext_host_name(SSL *ssl, char *name) {
	return SSL_set_tlsext_host_name(ssl, name);
}
*/
import "C"

import (
	"errors"
	"net"
	"runtime"
	"time"
	"unsafe"
)

type SSLContext struct {
	ctx *C.SSL_CTX
}

func NewSSLContext(caCerts string, skipVerify bool) (*SSLContext, error) {
	ctx := C.SSL_CTX_new(C.TLS_client_method())
	if ctx == nil {
		return nil, GetErrors()
	}

	ret := &SSLContext{ctx}
	runtime.SetFinalizer(ret, func(ret *SSLContext) {
		C.SSL_CTX_free(ret.ctx)
		ret.ctx = nil
	})

	if skipVerify {
		C.SSL_CTX_set_verify(ctx, C.SSL_VERIFY_NONE, nil)
	} else {
		C.SSL_CTX_set_verify(ctx, C.SSL_VERIFY_PEER, nil)
	}

	C.SSL_CTX_set_options(ctx, C.SSL_OP_NO_SSLv2|C.SSL_OP_NO_SSLv3|C.SSL_OP_NO_COMPRESSION)

	if len(caCerts) > 0 {
		cca_certs := C.CString(caCerts)
		defer C.free(unsafe.Pointer(cca_certs))
		if 1 != C.SSL_CTX_load_verify_locations(ctx, cca_certs, nil) {
			return nil, GetErrors()
		}
	}

	if 1 != C._SSL_CTX_set_min_proto_version(ctx, C.GMTLS1_1_VERSION) {
		return nil, GetErrors()
	}

	if 1 != C._SSL_CTX_set_max_proto_version(ctx, C.GMTLS1_1_VERSION) {
		return nil, GetErrors()
	}

	return ret, nil
}

type SSLConnection struct {
	bio *C.BIO
}

func (ctx *SSLContext) Connect(hostname, port, ciphers string) (*SSLConnection, error) {
	bio := C.BIO_new_ssl_connect(ctx.ctx)
	if bio == nil {
		return nil, GetErrors()
	}
	ret := &SSLConnection{bio}
	runtime.SetFinalizer(ret, func(ret *SSLConnection) {
		C.BIO_free_all(ret.bio)
	})
	hostname_and_port := hostname + ":" + port
	chostname_and_port := C.CString(hostname_and_port)
	defer C.free(unsafe.Pointer(chostname_and_port))
	if 1 != C._BIO_set_conn_hostname(bio, chostname_and_port) {
		return nil, GetErrors()
	}
	var ssl *C.SSL
	C._BIO_get_ssl(bio, &ssl)
	if ssl == nil {
		return nil, GetErrors()
	}
	cciphers := C.CString(ciphers)
	defer C.free(unsafe.Pointer(cciphers))
	if 1 != C.SSL_set_cipher_list(ssl, cciphers) {
		return nil, GetErrors()
	}
	chostname := C.CString(hostname)
	defer C.free(unsafe.Pointer(chostname))
	if 1 != C._SSL_set_tlsext_host_name(ssl, chostname) {
		return nil, GetErrors()
	}
	if 1 != C._BIO_do_connect(bio) {
		return nil, GetErrors()
	}
	return ret, nil
}

func (conn *SSLConnection) GetVerifyResult() (int64, error) {
	var ssl *C.SSL
	C._BIO_get_ssl(conn.bio, &ssl)
	if ssl == nil {
		return -1, GetErrors()
	}
	result := C.SSL_get_verify_result(ssl)
	if result != C.X509_V_OK {
		return int64(result), GetErrors()
	}
	return int64(result), nil
}

func (conn *SSLConnection) GetPeerCertificate() (*Certificate, error) {
	var ssl *C.SSL
	C._BIO_get_ssl(conn.bio, &ssl)
	if ssl == nil {
		return nil, GetErrors()
	}
	x509 := C.SSL_get_peer_certificate(ssl)
	if x509 == nil {
		return nil, GetErrors()
	}
	ret := &Certificate{x509}
	runtime.SetFinalizer(ret, func(ret *Certificate) {
		C.X509_free(ret.x509)
	})
	return ret, nil
}

func (conn *SSLConnection) read(nbytes int) ([]byte, error) {
	outbuf := make([]byte, nbytes)
	n := C.BIO_read(conn.bio, unsafe.Pointer(&outbuf[0]), C.int(nbytes))
	if n < 0 {
		return nil, GetErrors()
	}
	return outbuf[:n], nil
}

func (conn *SSLConnection) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	out, err := conn.read(len(b))
	if err != nil {
		return 0, err
	}
	n := copy(b, out)

	return n, nil
}

func (conn *SSLConnection) ReadAll() ([]byte, error) {
	b := make([]byte, 0, 512)
	for {
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}
		n, err := conn.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			return b, err
		}
	}
}

func (conn *SSLConnection) Write(data []byte) (int, error) {
	n := C.BIO_write(conn.bio, unsafe.Pointer(&data[0]), C.int(len(data)))
	if n < 0 {
		return int(n), GetErrors()
	}
	return int(n), nil
}

func (conn *SSLConnection) Close() error {
	ret := C._BIO_Close(conn.bio)
	if ret < 0 {
		return GetErrors()
	}
	return nil
}

func (conn *SSLConnection) LocalAddr() net.Addr {
	panic("ssl connection LocalAddr not impl")
	return nil
}

func (conn *SSLConnection) RemoteAddr() net.Addr {
	panic("ssl connection RemoteAddr not impl")
	return nil
}

func (conn *SSLConnection) SetDeadline(t time.Time) (err error) {
	err = errors.New("ssl connection SetDeadline not impl")
	panic(err)
}

func (conn *SSLConnection) SetReadDeadline(t time.Time) (err error) {
	err = errors.New("ssl connection SetReadDeadline not impl")
	panic(err)
}

func (conn *SSLConnection) SetWriteDeadline(t time.Time) (err error) {
	err = errors.New("ssl connection SetWriteDeadline not impl")
	panic(err)
}
