package inspect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
)

// Request is a certificate signing request with its self-signature checked.
type Request struct {
	CSR     *x509.CertificateRequest
	KeyType string
	SigErr  error // non-nil when the CSR is not signed by its own key
}

// CheckRequest verifies that csr is signed by the key it carries, which is
// what proves the requester holds the private key.
func CheckRequest(csr *x509.CertificateRequest) Request {
	return Request{CSR: csr, KeyType: KeyType(csr.PublicKey), SigErr: csr.CheckSignature()}
}

// Part is one of the things a match check compares.
type Part int

const (
	Certificate Part = iota
	CSR
	Key
)

// Pair is the outcome of comparing the public keys of two parts.
type Pair struct {
	A, B  Part
	Match bool
}

// Names compares the names a certificate carries with those its CSR asked
// for. CAs may legitimately drop or add names, so differences are warnings.
type Names struct {
	CertCN, CSRCN string
	Missing       []string // requested in the CSR, absent from the certificate
	Extra         []string // in the certificate, not requested in the CSR
}

// CNDiffers reports whether the common names differ, ignoring case.
func (n Names) CNDiffers() bool { return !strings.EqualFold(n.CertCN, n.CSRCN) }

// Same reports whether the certificate carries exactly the requested names.
func (n Names) Same() bool {
	return !n.CNDiffers() && len(n.Missing) == 0 && len(n.Extra) == 0
}

// Match is the result of MatchParts.
type Match struct {
	KeyType   string
	Pairs     []Pair // only pairs where both parts were given
	Names     *Names // set when both a certificate and a CSR are given
	CSRSigErr error
}

// OK reports whether every compared pair matches and the CSR, if any, is
// properly self-signed.
func (m Match) OK() bool {
	if m.CSRSigErr != nil {
		return false
	}
	for _, p := range m.Pairs {
		if !p.Match {
			return false
		}
	}
	return true
}

// MatchParts compares the public keys of every pair among the given parts;
// any of cert, csr and key may be nil, but at least two should be set.
func MatchParts(cert *x509.Certificate, csr *x509.CertificateRequest, key crypto.Signer) Match {
	var m Match
	var pubs [3]crypto.PublicKey
	if cert != nil {
		pubs[Certificate] = cert.PublicKey
	}
	if csr != nil {
		pubs[CSR] = csr.PublicKey
		m.CSRSigErr = csr.CheckSignature()
	}
	if key != nil {
		pubs[Key] = key.Public()
	}

	// Report the private key's type when there is one: that is what the
	// user asked about. Otherwise any public key will do.
	for _, p := range []Part{Key, CSR, Certificate} {
		if pubs[p] != nil {
			m.KeyType = KeyType(pubs[p])
			break
		}
	}

	for _, pr := range [][2]Part{{Certificate, Key}, {CSR, Key}, {Certificate, CSR}} {
		a, b := pubs[pr[0]], pubs[pr[1]]
		if a == nil || b == nil {
			continue
		}
		m.Pairs = append(m.Pairs, Pair{A: pr[0], B: pr[1], Match: samePublicKey(a, b)})
	}

	if cert != nil && csr != nil {
		m.Names = compareNames(cert, csr)
	}
	return m
}

func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

func compareNames(cert *x509.Certificate, csr *x509.CertificateRequest) *Names {
	n := &Names{CertCN: cert.Subject.CommonName, CSRCN: csr.Subject.CommonName}

	certNames := nameSet(cert.Subject.CommonName, cert.DNSNames, cert.IPAddresses)
	requested := nameSet(csr.Subject.CommonName, csr.DNSNames, csr.IPAddresses)

	// The CSR's CN counts as requested, but a certificate is not expected to
	// repeat its own CN, so only its SANs can be "extra".
	for _, name := range orderedNames(csr.Subject.CommonName, csr.DNSNames, csr.IPAddresses) {
		if !certNames[strings.ToLower(name)] {
			n.Missing = append(n.Missing, name)
		}
	}
	for _, name := range orderedNames("", cert.DNSNames, cert.IPAddresses) {
		if !requested[strings.ToLower(name)] {
			n.Extra = append(n.Extra, name)
		}
	}
	return n
}

// orderedNames lists cn (if set), DNS names and IPs, without duplicates.
func orderedNames(cn string, dns []string, ips []net.IP) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if k := strings.ToLower(s); s != "" && !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	add(cn)
	for _, d := range dns {
		add(d)
	}
	for _, ip := range ips {
		add(ip.String())
	}
	return out
}

func nameSet(cn string, dns []string, ips []net.IP) map[string]bool {
	set := map[string]bool{}
	for _, s := range orderedNames(cn, dns, ips) {
		set[strings.ToLower(s)] = true
	}
	return set
}

// KeyType describes a public key, e.g. "RSA 2048-bit" or "ECDSA P-256".
func KeyType(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}
