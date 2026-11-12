package inspect_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"slices"
	"testing"
	"time"

	"github.com/master2sid2/ssl-chain/internal/certtest"
	"github.com/master2sid2/ssl-chain/internal/inspect"
)

var now = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func TestAnalyzeChain(t *testing.T) {
	later := now.AddDate(1, 0, 0)

	root := certtest.Issue(t, "Test Root", nil, true, later)
	inter := certtest.Issue(t, "Test Intermediate", root, true, later)
	leaf := certtest.Issue(t, "example.com", inter, false, later)
	expiredLeaf := certtest.Issue(t, "example.com", inter, false, now.AddDate(0, -1, 0))
	futureLeaf := certtest.Issue(t, "example.com", inter, false, now.AddDate(5, 0, 0))
	soonLeaf := certtest.Issue(t, "example.com", inter, false, now.AddDate(0, 0, 10))

	// Same name as the real root, different key: names line up, signature does not.
	fakeRoot := certtest.Issue(t, "Test Root", nil, true, later)
	notCA := certtest.Issue(t, "Not A CA", root, false, later)
	leafOfNotCA := certtest.Issue(t, "example.com", notCA, false, later)

	tests := []struct {
		name  string
		chain []*x509.Certificate
		ok    bool
		check func(inspect.Chain) bool // the specific finding expected
	}{
		{"full chain", []*x509.Certificate{leaf.Cert, inter.Cert, root.Cert}, true,
			func(c inspect.Chain) bool { return c.Links[0].OK() && c.Links[1].OK() }},
		{"self-signed alone", []*x509.Certificate{root.Cert}, true,
			func(c inspect.Chain) bool { return c.RootSelfSigned() && len(c.Links) == 0 }},
		{"expired leaf", []*x509.Certificate{expiredLeaf.Cert, inter.Cert, root.Cert}, false,
			func(c inspect.Chain) bool { return c.Entries[0].Validity == inspect.Expired }},
		{"leaf expiring soon is still fine", []*x509.Certificate{soonLeaf.Cert, inter.Cert, root.Cert}, true,
			func(c inspect.Chain) bool {
				return c.Entries[0].Validity == inspect.ExpiringSoon && c.Entries[0].DaysLeft == 10 &&
					c.Entries[1].Validity == inspect.Valid
			}},
		{"leaf not yet valid", []*x509.Certificate{futureLeaf.Cert, inter.Cert, root.Cert}, false,
			func(c inspect.Chain) bool { return c.Entries[0].Validity == inspect.NotYetValid }},
		{"leaf only", []*x509.Certificate{leaf.Cert}, false,
			func(c inspect.Chain) bool { return !c.RootSelfSigned() }},
		{"missing root", []*x509.Certificate{leaf.Cert, inter.Cert}, false,
			func(c inspect.Chain) bool { return c.Links[0].OK() && !c.RootSelfSigned() }},
		{"wrong order", []*x509.Certificate{leaf.Cert, root.Cert, inter.Cert}, false,
			func(c inspect.Chain) bool { return !c.Links[0].NameMatch }},
		{"forged root", []*x509.Certificate{leaf.Cert, inter.Cert, fakeRoot.Cert}, false,
			func(c inspect.Chain) bool { return c.Links[1].NameMatch && c.Links[1].SigErr != nil }},
		{"issuer is not a CA", []*x509.Certificate{leafOfNotCA.Cert, notCA.Cert, root.Cert}, false,
			func(c inspect.Chain) bool { return c.NotCA(1) && !c.NotCA(0) && !c.NotCA(2) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := inspect.AnalyzeChain(tt.chain, now)
			if chain.OK() != tt.ok {
				t.Errorf("OK() = %v, want %v", chain.OK(), tt.ok)
			}
			if !tt.check(chain) {
				t.Errorf("expected finding is missing: %+v", chain)
			}
		})
	}
}

func TestMatchParts(t *testing.T) {
	later := now.AddDate(1, 0, 0)
	a := certtest.Issue(t, "a.example.com", nil, false, later)
	b := certtest.Issue(t, "b.example.com", nil, false, later)
	csrA := certtest.Request(t, a.Key, pkix.Name{CommonName: "a.example.com"}, "a.example.com", "www.a.example.com")
	csrB := certtest.Request(t, b.Key, pkix.Name{CommonName: "b.example.com"})

	type pair struct {
		a, b  inspect.Part
		match bool
	}
	tests := []struct {
		name  string
		cert  *x509.Certificate
		csr   *x509.CertificateRequest
		key   crypto.Signer
		ok    bool
		pairs []pair
	}{
		{"certificate and own key", a.Cert, nil, a.Key, true,
			[]pair{{inspect.Certificate, inspect.Key, true}}},
		{"certificate and foreign key", a.Cert, nil, b.Key, false,
			[]pair{{inspect.Certificate, inspect.Key, false}}},
		{"CSR and own key", nil, csrA, a.Key, true,
			[]pair{{inspect.CSR, inspect.Key, true}}},
		{"CSR and foreign key", nil, csrA, b.Key, false,
			[]pair{{inspect.CSR, inspect.Key, false}}},
		{"certificate and its CSR", a.Cert, csrA, nil, true,
			[]pair{{inspect.Certificate, inspect.CSR, true}}},
		{"certificate and someone else's CSR", a.Cert, csrB, nil, false,
			[]pair{{inspect.Certificate, inspect.CSR, false}}},
		{"all three match", a.Cert, csrA, a.Key, true, []pair{
			{inspect.Certificate, inspect.Key, true},
			{inspect.CSR, inspect.Key, true},
			{inspect.Certificate, inspect.CSR, true},
		}},
		{"key from elsewhere", a.Cert, csrA, b.Key, false, []pair{
			{inspect.Certificate, inspect.Key, false},
			{inspect.CSR, inspect.Key, false},
			{inspect.Certificate, inspect.CSR, true},
		}},
		{"tampered CSR", nil, certtest.Tampered(t, csrA), a.Key, false,
			[]pair{{inspect.CSR, inspect.Key, true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := inspect.MatchParts(tt.cert, tt.csr, tt.key)
			if m.OK() != tt.ok {
				t.Errorf("OK() = %v, want %v (CSR signature: %v)", m.OK(), tt.ok, m.CSRSigErr)
			}
			var got []pair
			for _, p := range m.Pairs {
				got = append(got, pair{p.A, p.B, p.Match})
			}
			if !slices.Equal(got, tt.pairs) {
				t.Errorf("pairs = %v, want %v", got, tt.pairs)
			}
			if m.KeyType != "ECDSA P-256" {
				t.Errorf("KeyType = %q", m.KeyType)
			}
		})
	}
}

func TestMatchPartsNames(t *testing.T) {
	cert := certtest.Issue(t, "a.example.com", nil, false, now.AddDate(1, 0, 0)) // SANs a. and www.a.

	tests := []struct {
		name    string
		cn      string
		dns     []string
		same    bool
		missing []string
		extra   []string
	}{
		{"exactly as requested", "a.example.com", []string{"a.example.com", "www.a.example.com"}, true, nil, nil},
		{"CN only in CSR, CA added www", "A.Example.com", nil, false, nil, []string{"www.a.example.com"}},
		{"name the CA dropped", "a.example.com", []string{"www.a.example.com", "api.a.example.com"}, false,
			[]string{"api.a.example.com"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := certtest.Request(t, cert.Key, pkix.Name{CommonName: tt.cn}, tt.dns...)
			n := inspect.MatchParts(cert.Cert, csr, nil).Names
			if n == nil {
				t.Fatal("Names not set")
			}
			if n.Same() != tt.same || !slices.Equal(n.Missing, tt.missing) || !slices.Equal(n.Extra, tt.extra) {
				t.Errorf("got same=%v missing=%v extra=%v, want %v %v %v",
					n.Same(), n.Missing, n.Extra, tt.same, tt.missing, tt.extra)
			}
		})
	}
}

func TestCheckRequest(t *testing.T) {
	owner := certtest.Issue(t, "a.example.com", nil, false, now.AddDate(1, 0, 0))
	csr := certtest.Request(t, owner.Key, pkix.Name{CommonName: "a.example.com"})

	if r := inspect.CheckRequest(csr); r.SigErr != nil || r.KeyType != "ECDSA P-256" {
		t.Errorf("valid CSR: SigErr = %v, KeyType = %q", r.SigErr, r.KeyType)
	}
	if r := inspect.CheckRequest(certtest.Tampered(t, csr)); r.SigErr == nil {
		t.Error("tampered CSR: signature verified")
	}
}
