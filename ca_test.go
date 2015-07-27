package ca

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestCreateCertChain(t *testing.T) {
	// create an entire certificate chain
	caCert, caKey, err := CreateCACert(pkix.Name{
		Country:            []string{"SE"},
		Organization:       []string{"FooBar"},
		OrganizationalUnit: []string{"FooBar Certificate Authority"},
		CommonName:         "FooBar Root CA",
	}, time.Hour, 512)

	if caCert == nil || caKey == nil || err != nil {
		t.Fatal("Failed to created CA cert", err)
	}

	signingCert, signingKey, err := CreateSigningCert(pkix.Name{
		Country:            []string{"SE"},
		Organization:       []string{"FooBar"},
		OrganizationalUnit: []string{"FooBar Intermediate Certificate Authority"},
		CommonName:         "FooBar Intermadiate CA",
	}, time.Hour, 512, caCert, caKey)

	if signingCert == nil || signingKey == nil || err != nil {
		t.Fatal("Failed to created signing cert", err)
	}

	svrCert, svrKey, err := CreateServerCert(pkix.Name{
		Country:      []string{"SE"},
		Organization: []string{"FooBar"},
		CommonName:   "127.0.0.1",
	}, "127.0.0.1", time.Hour, 512, signingCert, signingKey)

	if svrCert == nil || svrKey == nil || err != nil {
		t.Fatal("Failed to created server cert", err)
	}

	clientCert, clientKey, err := CreateClientCert(pkix.Name{
		Country:      []string{"SE"},
		Organization: []string{"FooBar"},
		CommonName:   "chuck.norris",
	}, time.Hour, 512, signingCert, signingKey)

	if clientCert == nil || clientKey == nil || err != nil {
		t.Fatal("Failed to created client cert", err)
	}

	// add server and all leaf certs and create tls listener and connect with client cert
	tlsCert, err := tls.X509KeyPair(svrCert, svrKey)
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(signingCert)
	if err != nil || !ok {
		t.Fatalf("failed to parse the certificate or the private key: %v", err)
	}

	conf := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}

	l, err := tls.Listen("tcp", "127.0.0.1:3000", &conf)
	if err != nil {
		t.Fatalf("failed to create TLS listener on network address %v with error: %v", "127.0.0.1:3000", err)
	}

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
