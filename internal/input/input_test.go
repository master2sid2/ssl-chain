package input_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/youmark/pkcs8"

	"github.com/master2sid2/ssl-chain/internal/certtest"
	"github.com/master2sid2/ssl-chain/internal/input"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pemBytes(blocks ...*pem.Block) []byte {
	var buf bytes.Buffer
	for _, b := range blocks {
		pem.Encode(&buf, b)
	}
	return buf.Bytes()
}

func TestRead(t *testing.T) {
	later := time.Now().AddDate(1, 0, 0)
	root := certtest.Issue(t, "Test Root", nil, true, later)
	leaf := certtest.Issue(t, "example.com", root, false, later)
	csr := certtest.Request(t, leaf.Key, pkix.Name{CommonName: "example.com"}, "example.com")

	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	writeFile(t, path("chain.pem"), pemBytes(leaf.CertPEM(), root.CertPEM()))
	writeFile(t, path("bundle.pem"), pemBytes(leaf.KeyPEM(t), leaf.CertPEM()))
	writeFile(t, path("leaf.key"), pemBytes(leaf.KeyPEM(t)))
	writeFile(t, path("leaf.der"), leaf.Cert.Raw)
	writeFile(t, path("req.csr"), pemBytes(certtest.RequestPEM(csr)))
	writeFile(t, path("new.csr"), pemBytes(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: csr.Raw}))
	writeFile(t, path("req.der"), csr.Raw)
	writeFile(t, path("everything.pem"), pemBytes(leaf.CertPEM(), certtest.RequestPEM(csr), leaf.KeyPEM(t)))
	writeFile(t, path("broken.csr"), pemBytes(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")}))
	writeFile(t, path("junk.txt"), []byte("not a certificate"))
	writeFile(t, path("broken.pem"), pemBytes(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))

	tests := []struct {
		name    string
		file    string
		certs   int
		csrs    int
		hasKey  bool
		wantErr bool
	}{
		{"PEM chain", "chain.pem", 2, 0, false, false},
		{"key and certificate together", "bundle.pem", 1, 0, true, false},
		{"key only", "leaf.key", 0, 0, true, false},
		{"DER certificate", "leaf.der", 1, 0, false, false},
		{"PEM CSR", "req.csr", 0, 1, false, false},
		{"old-style PEM CSR", "new.csr", 0, 1, false, false},
		{"DER CSR", "req.der", 0, 1, false, false},
		{"certificate, CSR and key in one file", "everything.pem", 1, 1, true, false},
		{"unrelated file", "junk.txt", 0, 0, false, false},
		{"malformed certificate", "broken.pem", 0, 0, false, true},
		{"malformed CSR", "broken.csr", 0, 0, false, true},
		{"missing file", "absent.crt", 0, 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := input.Read(path(tt.file))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(f.Certs) != tt.certs || len(f.CSRs) != tt.csrs {
				t.Errorf("got %d certificates and %d CSRs, want %d and %d", len(f.Certs), len(f.CSRs), tt.certs, tt.csrs)
			}
			if (f.Key != nil) != tt.hasKey {
				t.Errorf("has key = %v, want %v", f.Key != nil, tt.hasKey)
			}
		})
	}
}

func TestParseKey(t *testing.T) {
	owner := certtest.Issue(t, "example.com", nil, false, time.Now().AddDate(1, 0, 0))
	key := owner.Key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("secret")

	pkcs8DER, err := pkcs8.MarshalPrivateKey(key, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}
	legacy, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", sec1DER, pass, x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		block   *pem.Block
		pass    string
		asked   bool
		wantErr bool
	}{
		{"plain PKCS#8", owner.KeyPEM(t), "", false, false},
		{"plain PKCS#1 RSA", rsaPEM, "", false, false},
		{"plain SEC1", &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER}, "", false, false},
		{"encrypted PKCS#8", &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: pkcs8DER}, "secret", true, false},
		{"encrypted PKCS#8, wrong passphrase", &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: pkcs8DER}, "nope", true, true},
		{"legacy encrypted PEM", legacy, "secret", true, false},
		{"legacy encrypted PEM, wrong passphrase", legacy, "nope", true, true},
		{"garbage", &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}, "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asked := false
			got, err := input.ParseKey(tt.block, func() ([]byte, error) {
				asked = true
				return []byte(tt.pass), nil
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if asked != tt.asked {
				t.Errorf("passphrase asked = %v, want %v", asked, tt.asked)
			}
			want := crypto.PublicKey(&key.PublicKey)
			if tt.block == rsaPEM {
				want = &rsaKey.PublicKey
			}
			if err == nil && !got.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(want) {
				t.Error("parsed key differs from the original")
			}
			if input.Encrypted(tt.block) != tt.asked && !tt.wantErr {
				t.Errorf("Encrypted() = %v, want %v", input.Encrypted(tt.block), tt.asked)
			}
		})
	}
}
