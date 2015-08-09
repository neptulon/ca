// Package ca provides easy to use certificate authority related functions.
// This is a lightweight wrapper around "crypto/x509" package for
// creating CA certs, client certs, signing requests, and more.
//
// Any "cert, key []byte" type of function parameters and return types are
// always PEM encoded X.509 certificate and private key pairs.
// You can store the certificate/key pair with standard naming as
// "cert.pem" and "key.pem" in the file system.
//
// This package is mostly based on the example code provided at:
// http://golang.org/src/crypto/tls/generate_cert.go
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// CertChain is a ready to use certificate chain object, created by GenCertChain function.
// Byte slices are the PEM encoded X.509 certificate and private key pairs.
// ServerTLSConf/ClientTLSConf are tead to use tls.Config objects for a TLS server and client.
type CertChain struct {
	RootCACert,
	RootCAKey,
	IntCACert,
	IntCAKey,
	ServerCert,
	ServerKey,
	ClientCert,
	ClientKey []byte
	ServerTLSConf,
	ClientTLSConf *tls.Config
}

// GenCertChain generates an entire certificate chain with the following hierarchy:
// Root CA -> Intermediate CA -> Server Certificate & Client Certificate
//
// name = Certificate name. i.e. FooBar
// host = Comma-separated hostnames and IPs to generate the server certificate for. i.e. "localhost,127.0.0.1"
// hostName = Server host address. i.e. foobar.com
func GenCertChain(name, host, hostName string, validFor time.Duration, keyLength int) (c CertChain, err error) {

	// create certificate chain
	if c.RootCACert, c.RootCAKey, err = GenCACert(pkix.Name{
		Organization:       []string{name},
		OrganizationalUnit: []string{name + " Certificate Authority"},
		CommonName:         name + " Root CA",
	}, time.Hour, keyLength, nil, nil); err != nil {
		err = fmt.Errorf("Failed to create root CA certificate: %v", err)
		return
	}

	if c.IntCACert, c.IntCAKey, err = GenCACert(pkix.Name{
		Organization:       []string{name},
		OrganizationalUnit: []string{name + " Intermediate Certificate Authority"},
		CommonName:         name + " Intermadiate CA",
	}, time.Hour, keyLength, c.RootCACert, c.RootCAKey); err != nil {
		err = fmt.Errorf("Failed to create intermediate CA certificate: %v", err)
		return
	}

	if c.ServerCert, c.ServerKey, err = GenServerCert(pkix.Name{
		Organization: []string{name},
		CommonName:   hostName,
	}, host, time.Hour, keyLength, c.IntCACert, c.IntCAKey); err != nil {
		err = fmt.Errorf("Failed to create server certificate: %v", err)
		return
	}

	if c.ClientCert, c.ClientKey, err = GenClientCert(pkix.Name{
		Organization: []string{name},
		CommonName:   name,
	}, time.Hour, keyLength, c.IntCACert, c.IntCAKey); err != nil {
		err = fmt.Errorf("Failed to create client certificate: %v", err)
		return
	}

	// crate server tls.Config object
	serverTLSCert, e := tls.X509KeyPair(c.ServerCert, c.ServerKey)
	if e != nil {
		err = fmt.Errorf("Failed to parse the newly created server certificate or the key: %v", e)
		return
	}

	// todo #1: I'm not use if current Go TLS implementation verifies the entire cert chain (doesn't seem like so) so below line might not be needed atm (also see todo #3 down below)
	// serverTLSCert.Certificate = append(serverTLSCert.Certificate, c.IntCACert, c.RootCACert)

	sc, _ := pem.Decode(c.ServerCert)
	if serverTLSCert.Leaf, err = x509.ParseCertificate(sc.Bytes); err != nil {
		err = fmt.Errorf("Failed to parse the newly created server certificate: %v", err)
		return
	}

	clientCACertPool := x509.NewCertPool()
	if !clientCACertPool.AppendCertsFromPEM(c.IntCACert) {
		err = errors.New("Failed to parse the newly created intermediate CA certificate.")
		return
	}

	c.ServerTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    clientCACertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// create client tls.Config object
	clientTLSCert, e := tls.X509KeyPair(c.ClientCert, c.ClientKey)
	if e != nil {
		err = fmt.Errorf("Failed to parse the newly created client certificate or the key: %v", e)
		return
	}

	// todo #1: (same as above)
	// clientTLSCert.Certificate = append(clientTLSCert.Certificate, c.IntCACert, c.RootCACert)

	cc, _ := pem.Decode(c.ClientCert)
	if clientTLSCert.Leaf, err = x509.ParseCertificate(cc.Bytes); err != nil {
		err = fmt.Errorf("Failed to parse the newly created client certificate: %v", err)
		return
	}

	rootCACertPool := x509.NewCertPool()
	if !rootCACertPool.AppendCertsFromPEM(c.IntCACert) {
		err = errors.New("Failed to parse the newly created intermediate CA certificate.")
		return
	}

	c.ClientTLSConf = &tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      clientCACertPool,
	}

	return
}

// GenCACert generates a CA certificate.
// If signingCert and signingKey are not provided, the certificate is created as a self-signed root CA.
// If signingCert and signingKey are provided, the certificate is created as an intermediate CA, signed with provided certificate.
// The generated certificate can only be used for signing other certificates and CRLs.
// The returned slices are the PEM encoded X.509 certificate and private key pair.
func GenCACert(subject pkix.Name, validFor time.Duration, keyLength int, signingCert, signingKey []byte) (cert, key []byte, err error) {
	var (
		sc, c *x509.Certificate
		sk, k *rsa.PrivateKey
	)

	if c, k, err = createBaseCert(subject, validFor, keyLength); err != nil {
		return
	}

	if signingCert == nil || signingKey == nil {
		sc = c
		sk = k
	} else if sc, sk, err = parseCertAndKey(signingCert, signingKey); err != nil {
		return
	}

	c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	c.IsCA = true

	cert, key, err = signAndEncodeCert(sc, sk, c, k)
	return
}

// GenServerCert generates a hosting certificate for TLS servers.
// host = Comma-separated hostnames and IPs to generate a certificate for. i.e. "localhost,127.0.0.1"
// The returned slices are the PEM encoded X.509 certificate and private key pair.
func GenServerCert(subject pkix.Name, host string, validFor time.Duration, keyLength int, signingCert, signingKey []byte) (cert, key []byte, err error) {
	var (
		sc, c *x509.Certificate
		sk, k *rsa.PrivateKey
	)

	if sc, sk, err = parseCertAndKey(signingCert, signingKey); err != nil {
		return
	}

	if c, k, err = createBaseCert(subject, validFor, keyLength); err != nil {
		return
	}

	c.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	c.IsCA = false
	setHosts(host, c)

	cert, key, err = signAndEncodeCert(sc, sk, c, k)
	return
}

// GenClientCert generates a client certificate.
// The generated certificate will have its extended key usage set to 'client authentication' and will be ready for use in TLS client authentication.
// The returned slices are the PEM encoded X.509 certificate and private key pair.
func GenClientCert(subject pkix.Name, validFor time.Duration, keyLength int, signingCert, signingKey []byte) (cert, key []byte, err error) {
	var (
		sc, c *x509.Certificate
		sk, k *rsa.PrivateKey
	)

	if sc, sk, err = parseCertAndKey(signingCert, signingKey); err != nil {
		return
	}

	if c, k, err = createBaseCert(subject, validFor, keyLength); err != nil {
		return
	}

	c.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	c.IsCA = false

	cert, key, err = signAndEncodeCert(sc, sk, c, k)
	return
}

// todo #3: this might be only useful if todo #1 is necessary
// // ExportCertChain takes individual PEM encoded X.509 certificates in a trust chain and produces a single certificate chain file.
// // Input certificates should start with leaf certificate and end with the root CA certificate. i.e. [0] Leaf, [1] Intermediate CA, [2] Root CA
// func ExportCertChain(certs []byte) ([]byte, error) {
// 	return nil, nil
// }

// createBaseCert creates and returns x509.Certificate (unsigned) and rsa.PrivateKey objects with basic paramters set.
func createBaseCert(subject pkix.Name, validFor time.Duration, keyLength int) (*x509.Certificate, *rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate private key using RSA: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the certificate serial number: %v", err)
	}

	cert := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	return &cert, privKey, nil
}

// setHosts parses the comma separated host name / IP list and adds them to Subject Alternate Name list of a server/hosting certificate.
func setHosts(host string, cert *x509.Certificate) {
	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}
}

// Parses PEM encoded X.509 certificate and private key pair into x509.Certificate and rsa.PrivateKey objects.
func parseCertAndKey(cert, key []byte) (c *x509.Certificate, k *rsa.PrivateKey, err error) {
	pc, _ := pem.Decode(cert)
	if c, err = x509.ParseCertificate(pc.Bytes); err != nil {
		err = fmt.Errorf("Failed to parse private key with error: %v", err)
		return
	}

	pk, _ := pem.Decode(key)
	if k, err = x509.ParsePKCS1PrivateKey(pk.Bytes); err != nil {
		err = fmt.Errorf("Failed to parse certificate with error: %v", err)
		return
	}

	return
}

// signAndEncodeCert signs a given certificate with given signing cert/key pair and encodes resulting signed cert and private key in PEM format and returns.
func signAndEncodeCert(signingCert *x509.Certificate, signingKey *rsa.PrivateKey, c *x509.Certificate, k *rsa.PrivateKey) (cert, key []byte, err error) {
	certDerBytes, err := x509.CreateCertificate(rand.Reader, c, signingCert, &k.PublicKey, signingKey)
	if err != nil {
		return
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDerBytes})
	key = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return
}
