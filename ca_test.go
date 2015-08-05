package ca

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestCreateCertChain(t *testing.T) {
	certChain, err := GenCertChain("FooBar", "127.0.0.1", "127.0.0.1", time.Hour, 512)
	if err != nil {
		t.Fatal(err)
	}

	// create a TLS listener
	laddr := "127.0.0.1:3000"
	l, err := tls.Listen("tcp", laddr, certChain.ServerTLSConf)
	if err != nil {
		t.Fatalf("Failed to create TLS listener on network address %v with error: %v", laddr, err)
	}

	go func() {
		_, err := l.Accept()
		if err != nil {
			t.Fatal("Errored while accepting new connection on listener:", err)
		}
	}()

	time.Sleep(time.Second)

	// connect to previously created TLS listener
	conn, err := tls.Dial("tcp", laddr, certChain.ClientTLSConf)
	if err != nil {
		t.Fatal("Failed to open connection to listener with error:", err)
	}

	conn.Close()
	l.Close()
}

// func TestGenCert(t *testing.T) {
// 	// keyLength := 0 // used for internal test cert generation
// 	keyLength := 512
//
// 	caCert, caKey, clientCert, clientKey, err := genTestCertPair(keyLength)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	if keyLength == 0 {
// 		fmt.Println("CA cert:")
// 		fmt.Println(string(caCert))
// 		fmt.Println(string(caKey))
// 		fmt.Println("Client cert:")
// 		fmt.Println(string(clientCert))
// 		fmt.Println(string(clientKey))
// 	}
// }
//
// func genTestCertPair(keyLength int) (caCert, caKey, clientCert, clientKey []byte, err error) {
// 	// CA certificate
// 	caCert, caKey, err = genCert("127.0.0.1", 0, nil, nil, keyLength, "127.0.0.1", "devastator")
//
// 	if err != nil {
// 		err = fmt.Errorf("Failed to generate CA certificate or key: %v", err)
// 		return
// 	}
// 	if caCert == nil || caKey == nil {
// 		err = fmt.Errorf("Generated empty CA certificate or key")
// 		return
// 	}
//
// 	tlsCert, err := tls.X509KeyPair(caCert, caKey)
//
// 	if err != nil {
// 		err = fmt.Errorf("Generated invalid CA certificate or key: %v", err)
// 		return
// 	}
// 	if &tlsCert == nil {
// 		err = fmt.Errorf("Generated invalid CA certificate or key")
// 		return
// 	}
//
// 	// client certificate
// 	pub, err := x509.ParseCertificate(tlsCert.Certificate[0])
// 	if err != nil {
// 		err = fmt.Errorf("Failed to parse x509 certificate of CA cert to sign client-cert: %v", err)
// 		return
// 	}
//
// 	clientCert, clientKey, err = genCert("client.127.0.0.1", 0, pub, tlsCert.PrivateKey.(*rsa.PrivateKey), keyLength, "client.127.0.0.1", "devastator")
// 	if err != nil {
// 		err = fmt.Errorf("Failed to generate client-certificate or key: %v", err)
// 		return
// 	}
//
// 	tlsCert2, err := tls.X509KeyPair(clientCert, clientKey)
//
// 	if err != nil {
// 		err = fmt.Errorf("Generated invalid client-certificate or key: %v", err)
// 		return
// 	}
// 	if &tlsCert2 == nil {
// 		err = fmt.Errorf("Generated invalid client-certificate or key")
// 		return
// 	}
//
// 	return
// }
