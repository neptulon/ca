Go CA
=====

[![Build Status](https://travis-ci.org/nbusy/ca.svg?branch=master)](https://travis-ci.org/nbusy/ca) [![GoDoc](https://godoc.org/github.com/nbusy/ca?status.svg)](https://godoc.org/github.com/nbusy/ca)

Go certificate authority library for creating:

-	CA certificates
-	Intermediate signing certificates
-	Server/hosting certificates (i.e. to be used with TLS)
-	Client certificates (i.e. to be used for TLS client authentication)

This library is a lightweight wrapper around Go "crypto/x509" package with no external dependencies. This is done so to make it easy to copy-paste relevant functions into your project if you don't want to take a dependency on this package.

Example
-------

```go
// create CA and server certificates
caCert, caKey, err = ca.CreateCACert(pkix.Name{
	CommonName: "FooBar Root CA",
}, time.Hour, 2048)

svrCert, svrKey, err := CreateServerCert(pkix.Name{
	Country:      []string{"SE"},
	Organization: []string{"FooBar"},
	CommonName:   "127.0.0.1",
}, "127.0.0.1", time.Hour, 2048, caCert, caKey)

// create a new TLS listener with created server certificate
tlsCert, err := tls.X509KeyPair(svrCert, svrKey)

conf := tls.Config{
	Certificates: []tls.Certificate{tlsCert},
}

l, err := tls.Listen("tcp", "localhost", &conf)

// todo: add 'err != nil' checks and start accepting connections on listener
```
