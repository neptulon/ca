package ca_test

import (
	"crypto/tls"
	"log"
	"time"

	"github.com/nbusy/ca"
)

// Example demonstrating the use of nbusy/ca with a tls.Listener.
func Example() {
	// create CA and server certificates along with ready-to-use tls.Conf object that uses generated certs
	certChain, certErr := ca.GenCertChain("FooBar", "127.0.0.1", "127.0.0.1", time.Hour, 512)
	if certErr != nil {
		log.Fatal(certErr)
	}

	/*listener*/ _, tlsErr := tls.Listen("tcp", "127.0.0.1:4444", certChain.ServerTLSConf)
	if tlsErr != nil {
		log.Fatal(tlsErr)
	}

	// todo: uncomment /*listener*/ and use listener.Accept() to start accepting connections
}
