// Package ca provides easy to use certificate authority related functions.
// This is a lightweight wrapper around "crypto/x509" package for
// creating CA certs, client certs, signing requests, and more.
//
// This package is mostly based on the example code provided at:
// http://golang.org/src/crypto/tls/generate_cert.go
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// GenCA generates a self-signed CA certificate.
//
// validFor = Validity period for the certificate.
// keyLength = Key length for the new certificate.
// cn, org = Common name and organization fields of the certificate.
//
// Returns PEM encoded X.509 certificate and private key pair.
//
// Note: While writing the binary cert/key pair to file system, it is useful to use standard naming like: 'cert.pem', 'key.pem'.
func GenCA(validFor time.Duration, keyLength int, cn, org string) (cert, key []byte, err error) {
	c, p, err := getBaseCert(validFor, keyLength, cn, org)
	c.IsCA = true
	c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	cert, key, err = signAndEncodeCert(c, p, c, p)
	return
}

// GenSigningCert generates an intermediate signing certificate for signing server or client certificates.
// Returns PEM encoded X.509 certificate and private key pair.
func GenSigningCert() (cert, key []byte, err error) {
	return nil, nil, nil
}

// GenServerCert generates a hosting certificate for servers using TLS.
// Returns PEM encoded X.509 certificate and private key pair.
func GenServerCert() (cert, key []byte, err error) {
	return nil, nil, nil
}

// GenClientCert generates a client certificate signed by the provided signing certificate.
// Generated certificate will have its extended key usage set to 'client authentication' and will be ready for use in TLS client authentication.
// Returns PEM encoded X.509 certificate and private key pair.
func GenClientCert(signCert *x509.Certificate, signKey *rsa.PrivateKey) (cert, key []byte, err error) {
	return nil, nil, nil
}

// getBaseCert creates and returns x509.Certificate (unsigned) and rsa.PrivateKey objects with basic paramters set.
func getBaseCert(validFor time.Duration, keyLength int, cn, org string) (*x509.Certificate, *rsa.PrivateKey, error) {
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
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
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

// genCert generates a PEM encoded X.509 certificate and private key pair (i.e. 'cert.pem', 'key.pem').
// This code is based on the sample from http://golang.org/src/crypto/tls/generate_cert.go (taken at Jan 30, 2015).
// If no private key is provided, the certificate is marked as self-signed CA.
// host = Comma-separated hostnames and IPs to generate a certificate for. i.e. "localhost,127.0.0.1"
// validFor = Validity period for the certificate. Defaults to time.Duration max (290 years).
// ca, caPriv = CA certificate/private key to sign the new certificate. If not given, the generated certificate will be a self-signed CA.
// keyLength = Key length for the new certificate. Defaults to 3248 bits RSA key.
// cn, org = Common name and organization fields of the certificate.
func genCert(host string, validFor time.Duration, ca *x509.Certificate, caPriv *rsa.PrivateKey, keyLength int, cn, org string) (pemBytes, privBytes []byte, err error) {
	cert, privKey, err := getBaseCert(validFor, keyLength, cn, org)
	setHosts(host, cert)

	cert.IsCA = ca == nil
	signerCert := cert
	signerPriv := privKey
	if cert.IsCA {
		cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	} else {
		cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		signerCert = ca
		signerPriv = caPriv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, cert, signerCert, &privKey.PublicKey, signerPriv)
	if err != nil {
		return nil, nil, err
	}

	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	return
}
