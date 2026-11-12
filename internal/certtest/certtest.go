// Package certtest generates throwaway certificates for tests.
package certtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Issued is a certificate together with its private key.
type Issued struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Issue creates a certificate signed by parent, or self-signed when parent is
// nil. It is valid for the two years ending at notAfter.
func Issue(t testing.TB, cn string, parent *Issued, isCA bool, notAfter time.Time) *Issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notAfter.AddDate(-2, 0, 0),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if !isCA {
		tmpl.DNSNames = []string{cn, "www." + cn}
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Issued{Cert: cert, Key: key}
}

// CertPEM returns the certificate as a PEM block.
func (i *Issued) CertPEM() *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: i.Cert.Raw}
}

// KeyPEM returns the private key as an unencrypted PKCS#8 PEM block.
func (i *Issued) KeyPEM(t testing.TB) *pem.Block {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(i.Key)
	if err != nil {
		t.Fatal(err)
	}
	return &pem.Block{Type: "PRIVATE KEY", Bytes: der}
}

// Request creates a CSR for subject and DNS names, signed by key.
func Request(t testing.TB, key crypto.Signer, subject pkix.Name, dns ...string) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// Tampered returns a copy of csr whose signature no longer verifies.
func Tampered(t testing.TB, csr *x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	bad := *csr
	bad.Signature = append([]byte(nil), csr.Signature...)
	bad.Signature[len(bad.Signature)-1] ^= 0xff
	return &bad
}

// RequestPEM returns the CSR as a PEM block.
func RequestPEM(csr *x509.CertificateRequest) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw}
}
