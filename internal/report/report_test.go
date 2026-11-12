package report_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/master2sid2/ssl-chain/internal/certtest"
	"github.com/master2sid2/ssl-chain/internal/inspect"
	"github.com/master2sid2/ssl-chain/internal/report"
)

var now = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func TestChain(t *testing.T) {
	later := now.AddDate(1, 0, 0)

	root := certtest.Issue(t, "Test Root", nil, true, later)
	inter := certtest.Issue(t, "Test Intermediate", root, true, later)
	leaf := certtest.Issue(t, "example.com", inter, false, later)
	expiredLeaf := certtest.Issue(t, "example.com", inter, false, now.AddDate(0, -1, 0))
	soonLeaf := certtest.Issue(t, "example.com", inter, false, now.AddDate(0, 0, 10))
	longLeaf := certtest.Issue(t, "a-rather-long-host-name.subdomain.example.com", inter, false, later)
	fakeRoot := certtest.Issue(t, "Test Root", nil, true, later)
	notCA := certtest.Issue(t, "Not A CA", root, false, later)
	leafOfNotCA := certtest.Issue(t, "example.com", notCA, false, later)

	tests := []struct {
		name  string
		chain []*x509.Certificate
		want  []string
	}{
		{"full chain", []*x509.Certificate{leaf.Cert, inter.Cert, root.Cert}, []string{
			"  ▶ Mode: Chain Check  (3 certificate(s))",
			"  [1/3] Leaf Certificate (End-Entity)",
			"  SANs:  example.com, www.example.com",
			"    ↑ issuer matches next subject ✓",
			"  [2/3] Intermediate CA #1",
			"  CA:    Yes ✓",
			"  [3/3] Root CA",
			"  Self-Signed: Yes",
			"  [1→2] example.com → Test Intermediate  ✓ issuer matches subject",
			"  Root CA is self-signed  ✓",
			"  ✓ Chain is VALID",
		}},
		{"expired leaf", []*x509.Certificate{expiredLeaf.Cert, inter.Cert, root.Cert}, []string{
			"  Status: ✗ EXPIRED (expired 2026-05-01)",
			"  [1] example.com  ✗ EXPIRED",
			"  ✗ Chain has ISSUES",
		}},
		{"leaf expiring soon", []*x509.Certificate{soonLeaf.Cert, inter.Cert, root.Cert}, []string{
			"  Status: ⚠ expiring soon (expires in 10 days)",
			"  [1] example.com  ⚠ expires in 10 days",
			"  ✓ Chain is VALID",
		}},
		{"long name is shortened in the summary", []*x509.Certificate{longLeaf.Cert, inter.Cert, root.Cert}, []string{
			"  Subject: a-rather-long-host-name.subdomain.example.com",
			"  [1→2] a-rather-long-host-name.sub... → Test Intermediate  ✓ issuer matches subject",
		}},
		{"root alone", []*x509.Certificate{root.Cert}, []string{
			"  [1/1] Self-Signed / Leaf",
			"  CA:    Yes ✓",
			"  ✓ Chain is VALID",
		}},
		{"leaf only", []*x509.Certificate{leaf.Cert}, []string{
			"  [1/1] Self-Signed / Leaf",
			"  Status: ✓ valid (until 2027-06-01)",
			"  Root CA is NOT self-signed  ⚠ chain may be incomplete",
			"  ✗ Chain has ISSUES",
		}},
		{"wrong order", []*x509.Certificate{leaf.Cert, root.Cert, inter.Cert}, []string{
			"    ↑ issuer does NOT match next subject ✗",
			"      current issuer: CN=Test Intermediate",
			"      next subject:   CN=Test Root",
			"  [3/3] Root CA (not self-signed!)",
			"  [1→2] example.com → Test Root  ✗ BROKEN LINK: issuer ≠ subject",
			"         issuer:  CN=Test Intermediate",
			"         subject: CN=Test Root",
		}},
		{"forged root", []*x509.Certificate{leaf.Cert, inter.Cert, fakeRoot.Cert}, []string{
			"    ↑ issuer name matches, but signature does NOT verify ✗",
			"  [2→3] Test Intermediate → Test Root  ✗ signature does NOT verify",
		}},
		{"issuer is not a CA", []*x509.Certificate{leafOfNotCA.Cert, notCA.Cert, root.Cert}, []string{
			"  CA:    No ✗",
			"  [2] Not A CA  ✗ not a CA",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			report.New(&buf, false).Chain(inspect.AnalyzeChain(tt.chain, now))
			assertLines(t, buf.String(), tt.want)
		})
	}
}

func TestMatch(t *testing.T) {
	later := now.AddDate(1, 0, 0)
	a := certtest.Issue(t, "a.example.com", nil, false, later)
	b := certtest.Issue(t, "b.example.com", nil, false, later)
	csrA := certtest.Request(t, a.Key, pkix.Name{CommonName: "a.example.com"}, "a.example.com", "www.a.example.com")
	csrWider := certtest.Request(t, a.Key, pkix.Name{CommonName: "a.example.com"}, "a.example.com", "api.a.example.com")
	req := func(csr *x509.CertificateRequest) *inspect.Request {
		r := inspect.CheckRequest(csr)
		return &r
	}

	tests := []struct {
		name string
		in   report.MatchInput
		key  crypto.Signer
		want []string
	}{
		{"certificate and key", report.MatchInput{Cert: a.Cert, KeyFile: "a.key"}, a.Key, []string{
			"  ▶ Mode: Certificate + Key Match",
			"  Certificate",
			"  Subject: a.example.com",
			"  Key file: a.key",
			"  Key Match Result",
			"  Key type: ECDSA P-256",
			"  Match: ✓ certificate and key correspond",
			"  ✓ Key matches certificate",
		}},
		{"encrypted key that does not match", report.MatchInput{Cert: a.Cert, KeyFile: "b.key", Encrypted: true}, b.Key, []string{
			"  Key file: b.key (encrypted)",
			"  Match: ✗ public keys do NOT match",
			"  ✗ Key does NOT match certificate",
		}},
		{"CSR and key", report.MatchInput{Request: req(csrA), KeyFile: "a.key"}, a.Key, []string{
			"  ▶ Mode: CSR + Key Match",
			"  CSR",
			"  SANs:  a.example.com, www.a.example.com",
			"  Signature: ✓ valid (ECDSA-SHA256)",
			"  Key file: a.key",
			"  Match: ✓ CSR and key correspond",
			"  ✓ Key matches CSR",
		}},
		{"certificate and CSR", report.MatchInput{Cert: a.Cert, Request: req(csrA)}, nil, []string{
			"  ▶ Mode: Certificate + CSR Match",
			"  Match Result",
			"  Match: ✓ certificate and CSR correspond",
			"  Names: ✓ CN and SANs as requested",
			"  ✓ Certificate matches CSR",
		}},
		{"certificate lacks a requested name", report.MatchInput{Cert: a.Cert, Request: req(csrWider)}, nil, []string{
			"  Names: ⚠ requested, not in certificate: api.a.example.com",
			"  Names: ⚠ in certificate, not requested: www.a.example.com",
			"  ✓ Certificate matches CSR",
		}},
		{"all three", report.MatchInput{Cert: a.Cert, Request: req(csrA), KeyFile: "a.key"}, a.Key, []string{
			"  ▶ Mode: Certificate + CSR + Key Match",
			"  Cert ↔ Key: ✓ certificate and key correspond",
			"  CSR ↔ Key: ✓ CSR and key correspond",
			"  Cert ↔ CSR: ✓ certificate and CSR correspond",
			"  ✓ Certificate, CSR and key match",
		}},
		{"all three, foreign key", report.MatchInput{Cert: a.Cert, Request: req(csrA), KeyFile: "b.key"}, b.Key, []string{
			"  Cert ↔ Key: ✗ public keys do NOT match",
			"  Cert ↔ CSR: ✓ certificate and CSR correspond",
			"  ✗ Certificate, CSR and key do NOT match",
		}},
		{"tampered CSR", report.MatchInput{Request: req(certtest.Tampered(t, csrA)), KeyFile: "a.key"}, a.Key, []string{
			"  Signature: ✗ does NOT verify",
			"  ✗ CSR signature does NOT verify",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var csr *x509.CertificateRequest
			if tt.in.Request != nil {
				csr = tt.in.Request.CSR
			}
			var buf bytes.Buffer
			pr := report.New(&buf, false)
			pr.MatchHeader(tt.in)
			pr.MatchResult(tt.in, inspect.MatchParts(tt.in.Cert, csr, tt.key))
			assertLines(t, buf.String(), tt.want)
		})
	}
}

func TestRequest(t *testing.T) {
	owner := certtest.Issue(t, "a.example.com", nil, false, now.AddDate(1, 0, 0))
	csr := certtest.Request(t, owner.Key,
		pkix.Name{CommonName: "a.example.com", Organization: []string{"Example"}}, "a.example.com")

	tests := []struct {
		name string
		csr  *x509.CertificateRequest
		want []string
	}{
		{"valid", csr, []string{
			"  ▶ Mode: CSR Info",
			"  Subject: a.example.com",
			"  DN:    CN=a.example.com,O=Example",
			"  SANs:  a.example.com",
			"  Signature: ✓ valid (ECDSA-SHA256)",
			"  Key type: ECDSA P-256",
			"  ✓ CSR signature is valid",
		}},
		{"tampered", certtest.Tampered(t, csr), []string{
			"  Signature: ✗ does NOT verify",
			"  ✗ CSR signature does NOT verify",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			report.New(&buf, false).Request(inspect.CheckRequest(tt.csr))
			assertLines(t, buf.String(), tt.want)
		})
	}
}

func TestVersionAndFail(t *testing.T) {
	var buf bytes.Buffer
	pr := report.New(&buf, false)
	pr.Version("0.1.0", "abc1234", "2026-11-12")
	pr.Fail(errors.New("decryption failed (wrong password?)"))
	assertLines(t, buf.String(), []string{
		"ssl-chain 0.1.0",
		"  commit : abc1234",
		"  built  : 2026-11-12",
		"  ✗ decryption failed (wrong password?)",
	})
}

func TestColor(t *testing.T) {
	root := certtest.Issue(t, "Test Root", nil, true, now.AddDate(1, 0, 0))
	chain := inspect.AnalyzeChain([]*x509.Certificate{root.Cert}, now)

	var plain, colored bytes.Buffer
	report.New(&plain, false).Chain(chain)
	report.New(&colored, true).Chain(chain)

	if strings.Contains(plain.String(), "\x1b[") {
		t.Error("plain output contains escape sequences")
	}
	if !strings.Contains(colored.String(), "\x1b[1;32m✓ Chain is VALID\x1b[0m") {
		t.Errorf("coloured output lacks the green verdict:\n%q", colored.String())
	}
}

// assertLines checks that every wanted line is present as a whole line.
func assertLines(t *testing.T, out string, want []string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for _, w := range want {
		if !slices.Contains(lines, w) {
			t.Errorf("line %q not found in:\n%s", w, out)
		}
	}
}
