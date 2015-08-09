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
import (
	"crypto/tls"
	"log"
	"time"

	"github.com/nbusy/ca"
)

func main() {
	// create CA and server certificates along with ready-to-use tls.Conf object that uses generated certs
	certChain, err := ca.GenCertChain("FooBar", "127.0.0.1", "127.0.0.1", time.Hour, 512)
	if err != nil {
		log.Fatal(err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:4444", certChain.ServerTLSConf)
	if err != nil {
		log.Fatal(err)
	}

	// todo: use l.Accept() to start accepting connections
}
```

To see a more comprehensive example, check the godocs and the tests file (`TestCreateCertChain`).
