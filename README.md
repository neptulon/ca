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
// generate a new CA cert as PEM encoded X.509 cert and private key pair
cert, key, _ = ca.GenCert("localhost", 0, 2048, "localhost", "myorganizqtion")

// create a new TLS listener with created cert
tlsCert, err := tls.X509KeyPair(cert, key)
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(cert)

conf := tls.Config{
	Certificates: []tls.Certificate{tlsCert},
	ClientCAs:    pool,
	ClientAuth:   tls.VerifyClientCertIfGiven,
}

l, err := tls.Listen("tcp", "localhost", &conf)

// todo: add 'err != nil' checks and start accepting connections on listener
```
