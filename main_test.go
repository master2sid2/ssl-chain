package main

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/youmark/pkcs8"

	"github.com/master2sid2/ssl-chain/internal/certtest"
)

func writePEM(t *testing.T, path string, blocks ...*pem.Block) {
	t.Helper()
	var buf bytes.Buffer
	for _, b := range blocks {
		if err := pem.Encode(&buf, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	later := time.Now().AddDate(1, 0, 0)
	root := certtest.Issue(t, "Test Root", nil, true, later)
	leaf := certtest.Issue(t, "example.com", root, false, later)
	other := certtest.Issue(t, "other.example.com", root, false, later)

	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	writePEM(t, path("chain.pem"), leaf.CertPEM(), root.CertPEM())
	writePEM(t, path("leaf.crt"), leaf.CertPEM())
	writePEM(t, path("root.crt"), root.CertPEM())
	writePEM(t, path("leaf.key"), leaf.KeyPEM(t))
	writePEM(t, path("other.key"), other.KeyPEM(t))
	if err := os.WriteFile(path("junk.txt"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	csr := certtest.Request(t, leaf.Key, pkix.Name{CommonName: "example.com"}, "example.com", "www.example.com")
	writePEM(t, path("leaf.csr"), certtest.RequestPEM(csr))
	writePEM(t, path("bundle.pem"), leaf.CertPEM(), leaf.KeyPEM(t))
	encDER, err := pkcs8.MarshalPrivateKey(leaf.Key, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path("leaf.enc.key"), &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encDER})

	tests := []struct {
		name    string
		args    []string
		pass    string
		code    int
		wantOut string
		wantErr string
	}{
		{"single PEM chain", []string{path("chain.pem")}, "", exitOK, "Mode: Chain Check  (2 certificate(s))", ""},
		{"separate files", []string{path("leaf.crt"), path("root.crt")}, "", exitOK, "✓ Chain is VALID", ""},
		{"incomplete chain", []string{path("leaf.crt")}, "", exitIssues, "✗ Chain has ISSUES", ""},
		{"key matches", []string{path("leaf.crt"), path("leaf.key")}, "", exitOK, "✓ Key matches certificate", ""},
		{"key given first", []string{path("leaf.key"), path("leaf.crt")}, "", exitOK, "✓ Key matches certificate", ""},
		{"key differs", []string{path("leaf.crt"), path("other.key")}, "", exitIssues, "✗ Key does NOT match certificate", ""},
		{"certificate and key in one file", []string{path("bundle.pem")}, "", exitOK, "✓ Key matches certificate", ""},
		{"encrypted key", []string{path("leaf.crt"), path("leaf.enc.key")}, "secret", exitOK, "Key file: " + path("leaf.enc.key") + " (encrypted)", ""},
		{"wrong passphrase", []string{path("leaf.crt"), path("leaf.enc.key")}, "nope", exitUsage, "✗ decryption failed (wrong password?)", ""},
		{"CSR alone", []string{path("leaf.csr")}, "", exitOK, "✓ CSR signature is valid", ""},
		{"CSR and key", []string{path("leaf.csr"), path("leaf.key")}, "", exitOK, "✓ Key matches CSR", ""},
		{"CSR and foreign key", []string{path("leaf.csr"), path("other.key")}, "", exitIssues, "✗ Key does NOT match CSR", ""},
		{"certificate and CSR", []string{path("leaf.crt"), path("leaf.csr")}, "", exitOK, "✓ Certificate matches CSR", ""},
		{"all three", []string{path("leaf.crt"), path("leaf.csr"), path("leaf.key")}, "", exitOK, "✓ Certificate, CSR and key match", ""},
		{"two keys", []string{path("leaf.crt"), path("leaf.key"), path("other.key")}, "", exitUsage, "", "more than one private key"},
		{"two CSRs", []string{path("leaf.csr"), path("leaf.csr")}, "", exitUsage, "", "more than one CSR"},
		{"key alone", []string{path("leaf.key")}, "", exitUsage, "", "no certificate or CSR to match the key against"},
		{"not a certificate", []string{path("junk.txt")}, "", exitUsage, "", "no certificate, CSR or private key found"},
		{"missing file", []string{path("absent.crt")}, "", exitUsage, "", "no such file"},
		{"no arguments", nil, "", exitUsage, "", "Usage:"},
		{"help", []string{"--help"}, "", exitUsage, "", "Usage:"},
		{"version", []string{"--version"}, "", exitOK, "ssl-chain ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			ask := func() ([]byte, error) { return []byte(tt.pass), nil }
			code := run(tt.args, &out, &errOut, false, ask)
			if code != tt.code {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.code, errOut.String())
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout does not contain %q:\n%s", tt.wantOut, out.String())
			}
			if !strings.Contains(errOut.String(), tt.wantErr) {
				t.Errorf("stderr does not contain %q:\n%s", tt.wantErr, errOut.String())
			}
		})
	}
}
