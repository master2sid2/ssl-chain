// Package inspect checks certificate chains and whether certificates, CSRs
// and private keys belong together.
// It only produces findings; presenting them is the report package's job.
package inspect

import (
	"bytes"
	"crypto/x509"
	"time"
)

// Validity is where a certificate stands relative to its validity window.
type Validity int

const (
	Valid        Validity = iota
	ExpiringSoon          // valid, but less than SoonThreshold left
	Expired
	NotYetValid
)

// OK reports whether the certificate can be used right now.
func (v Validity) OK() bool { return v == Valid || v == ExpiringSoon }

// SoonThreshold is how close to its expiry a certificate starts to be
// reported as expiring soon.
const SoonThreshold = 30 * 24 * time.Hour

// Entry is one certificate of a chain together with what was found about it.
type Entry struct {
	Cert       *x509.Certificate
	Validity   Validity
	DaysLeft   int // whole days until NotAfter; meaningful while OK
	SelfSigned bool
}

// Link describes whether Entries[Parent] really issued Entries[Child].
type Link struct {
	Child, Parent int
	NameMatch     bool
	SigErr        error // only meaningful when NameMatch is true
}

// OK reports whether the parent's name and signature both check out.
func (l Link) OK() bool { return l.NameMatch && l.SigErr == nil }

// Chain is the result of AnalyzeChain.
type Chain struct {
	Entries []Entry
	Links   []Link
}

// AnalyzeChain checks the certificates in the order given: each one must be
// issued by the next, and the last one is expected to be a self-signed root.
func AnalyzeChain(certs []*x509.Certificate, now time.Time) Chain {
	var chain Chain
	for _, c := range certs {
		left := c.NotAfter.Sub(now)
		e := Entry{Cert: c, SelfSigned: isSelfSigned(c), DaysLeft: int(left.Hours() / 24)}
		switch {
		case now.After(c.NotAfter):
			e.Validity = Expired
		case now.Before(c.NotBefore):
			e.Validity = NotYetValid
		case left < SoonThreshold:
			e.Validity = ExpiringSoon
		}
		chain.Entries = append(chain.Entries, e)
	}
	for i := range len(certs) - 1 {
		child, parent := certs[i], certs[i+1]
		l := Link{Child: i, Parent: i + 1}
		if l.NameMatch = bytes.Equal(child.RawIssuer, parent.RawSubject); l.NameMatch {
			l.SigErr = parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
		}
		chain.Links = append(chain.Links, l)
	}
	return chain
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// RootSelfSigned reports whether the last certificate is self-signed.
func (c Chain) RootSelfSigned() bool {
	return len(c.Entries) > 0 && c.Entries[len(c.Entries)-1].SelfSigned
}

// NotCA reports whether entry i is used as an issuer without being a CA.
func (c Chain) NotCA(i int) bool {
	return i > 0 && !c.Entries[i].Cert.IsCA
}

// OK reports whether the chain has no issues at all.
func (c Chain) OK() bool {
	if !c.RootSelfSigned() {
		return false
	}
	for i, e := range c.Entries {
		if !e.Validity.OK() || c.NotCA(i) {
			return false
		}
	}
	for _, l := range c.Links {
		if !l.OK() {
			return false
		}
	}
	return true
}
