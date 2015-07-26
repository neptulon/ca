package ca

import (
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestCreateCertChain(t *testing.T) {
	caCert, caKey, err := CreateCACert(pkix.Name{
		Country:            []string{"SE"},
		Organization:       []string{"FooBar"},
		OrganizationalUnit: []string{"FooBar Certificate Authority"},
		CommonName:         "FooBar Root CA",
	}, time.Hour, 512)

	if caCert == nil || caKey == nil || err != nil {
		t.Fatal(err)
	}

	signingCert, signingKey, err := CreateSigningCert(pkix.Name{
		Country:            []string{"SE"},
		Organization:       []string{"FooBar"},
		OrganizationalUnit: []string{"FooBar Intermediate Certificate Authority"},
		CommonName:         "FooBar Intermadiate CA",
	}, time.Hour, 512, caCert, caKey)

	if signingCert == nil || signingKey == nil || err != nil {
		t.Fatal(err)
	}

	svrCert, svrKey, err := CreateServerCert(pkix.Name{
		Country:      []string{"SE"},
		Organization: []string{"FooBar"},
		CommonName:   "127.0.0.1",
	}, "127.0.0.1", time.Hour, 512, signingCert, signingKey)

	if svrCert == nil || svrKey == nil || err != nil {
		t.Fatal(err)
	}

	// todo: add hosting and all leaf certs and create tls listener and connect with client cert
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
