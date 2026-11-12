// Package report renders inspection results as terminal output.
package report

import (
	"cmp"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/master2sid2/ssl-chain/internal/inspect"
)

const (
	title       = "SSL Certificate Chain Inspector"
	bannerWidth = 51
	ruleWidth   = 55
	labelWidth  = 6
	nameWidth   = 30 // longest name shown in the chain summary
	dateLayout  = "2006-01-02"
)

// Printer writes reports to a single destination.
type Printer struct {
	w io.Writer
	p painter
}

// New returns a Printer writing to w, with ANSI colours when color is set.
func New(w io.Writer, color bool) *Printer {
	return &Printer{w: w, p: painter{on: color}}
}

// Version prints the program version and build details.
func (pr *Printer) Version(version, commit, date string) {
	pr.line("ssl-chain %s", pr.p.bold(version))
	pr.line("  commit : %s", pr.p.dim(commit))
	pr.line("  built  : %s", pr.p.dim(date))
}

// Fail prints an error that stopped a check half-way, such as a wrong
// passphrase, below the part of the report already printed.
func (pr *Printer) Fail(err error) {
	pr.line("")
	pr.line("  %s", pr.p.badBold("✗ "+err.Error()))
	pr.line("")
}

// Chain prints the per-certificate breakdown and the validation summary.
func (pr *Printer) Chain(c inspect.Chain) {
	p := pr.p
	n := len(c.Entries)

	pr.header(fmt.Sprintf("Mode: Chain Check  (%d certificate(s))", n))

	for i, e := range c.Entries {
		pr.section(fmt.Sprintf("[%d/%d]", i+1, n), role(i, n, e.SelfSigned))
		pr.identity(e.Cert)
		switch {
		case e.Cert.IsCA:
			pr.field("CA:", p.good("Yes ✓"))
		case i > 0:
			pr.field("CA:", p.bad("No ✗"))
		}
		if e.SelfSigned {
			pr.field("Self-Signed:", "Yes")
		}
		pr.field("Status:", pr.validity(e))
		if i < len(c.Links) {
			pr.linkHint(c, c.Links[i])
		}
		pr.line("")
	}

	pr.banner("Chain Validation Summary", false)
	for _, l := range c.Links {
		child, parent := c.Entries[l.Child].Cert, c.Entries[l.Parent].Cert
		pr.line("  [%d→%d] %s → %s  %s", l.Child+1, l.Parent+1,
			shortName(child.Subject), shortName(parent.Subject), pr.linkVerdict(l))
		if !l.NameMatch {
			pr.line("         issuer:  %s", p.dim(child.Issuer.String()))
			pr.line("         subject: %s", p.dim(parent.Subject.String()))
		}
	}
	for i, e := range c.Entries {
		name := shortName(e.Cert.Subject)
		switch e.Validity {
		case inspect.Expired:
			pr.line("  [%d] %s  %s", i+1, name, p.bad("✗ EXPIRED"))
		case inspect.NotYetValid:
			pr.line("  [%d] %s  %s", i+1, name, p.bad("✗ NOT YET VALID"))
		case inspect.ExpiringSoon:
			pr.line("  [%d] %s  %s", i+1, name, p.warn("⚠ expires in "+days(e.DaysLeft)))
		}
		if c.NotCA(i) {
			pr.line("  [%d] %s  %s", i+1, name, p.bad("✗ not a CA"))
		}
	}
	if c.RootSelfSigned() {
		pr.line("  Root CA is self-signed  %s", p.good("✓"))
	} else {
		pr.line("  Root CA is NOT self-signed  %s", p.warn("⚠ chain may be incomplete"))
	}
	pr.line("")
	if c.OK() {
		pr.line("  %s", p.goodBold("✓ Chain is VALID"))
	} else {
		pr.line("  %s", p.badBold("✗ Chain has ISSUES"))
	}
	pr.line("")
}

// Request prints what a CSR asks for and whether its signature verifies.
func (pr *Printer) Request(r inspect.Request) {
	pr.header("Mode: CSR Info")
	pr.section("", "CSR")
	pr.request(r)
	pr.field("Key type:", r.KeyType)
	pr.line("")
	if r.SigErr == nil {
		pr.line("  %s", pr.p.goodBold("✓ CSR signature is valid"))
	} else {
		pr.line("  %s", pr.p.badBold("✗ CSR signature does NOT verify"))
	}
	pr.line("")
}

// MatchInput is what a match check was given; Cert and Request may be nil,
// KeyFile is empty when no key was given.
type MatchInput struct {
	Cert      *x509.Certificate
	Request   *inspect.Request
	KeyFile   string
	Encrypted bool
}

func (in MatchInput) parts() []string {
	var parts []string
	if in.Cert != nil {
		parts = append(parts, "Certificate")
	}
	if in.Request != nil {
		parts = append(parts, "CSR")
	}
	if in.KeyFile != "" {
		parts = append(parts, "Key")
	}
	return parts
}

// MatchHeader prints what is about to be compared. It comes before the
// result so an encrypted key's passphrase is asked for in context.
func (pr *Printer) MatchHeader(in MatchInput) {
	pr.header("Mode: " + strings.Join(in.parts(), " + ") + " Match")
	if in.Cert != nil {
		pr.section("", "Certificate")
		pr.identity(in.Cert)
	}
	if in.Request != nil {
		if in.Cert != nil {
			pr.line("")
		}
		pr.section("", "CSR")
		pr.request(*in.Request)
	}
	if in.KeyFile != "" {
		file := in.KeyFile
		if in.Encrypted {
			file += pr.p.warn(" (encrypted)")
		}
		pr.field("Key file:", file)
	}
	pr.line("")
}

// MatchResult prints the outcome of comparing the parts listed in in.
func (pr *Printer) MatchResult(in MatchInput, m inspect.Match) {
	p := pr.p
	if in.KeyFile != "" {
		pr.banner("Key Match Result", false)
	} else {
		pr.banner("Match Result", false)
	}
	pr.field("Key type:", m.KeyType)
	for _, pair := range m.Pairs {
		label := "Match:"
		if len(m.Pairs) > 1 {
			label = pairLabel(pair)
		}
		if pair.Match {
			pr.field(label, p.good(fmt.Sprintf("✓ %s and %s correspond", noun(pair.A), noun(pair.B))))
		} else {
			pr.field(label, p.bad("✗ public keys do NOT match"))
		}
	}
	if m.Names != nil {
		pr.names(*m.Names)
	}
	pr.line("")
	if m.OK() {
		pr.line("  %s", p.goodBold("✓ "+matchVerdict(m, true)))
	} else {
		pr.line("  %s", p.badBold("✗ "+matchVerdict(m, false)))
	}
	pr.line("")
}

func (pr *Printer) names(n inspect.Names) {
	p := pr.p
	if n.Same() {
		pr.field("Names:", p.good("✓ CN and SANs as requested"))
		return
	}
	if n.CNDiffers() {
		pr.field("Names:", fmt.Sprintf("%s (certificate: %s, CSR: %s)", p.warn("⚠ CN differs"),
			cmp.Or(n.CertCN, "none"), cmp.Or(n.CSRCN, "none")))
	}
	if len(n.Missing) > 0 {
		pr.field("Names:", p.warn("⚠ requested, not in certificate:")+" "+strings.Join(n.Missing, ", "))
	}
	if len(n.Extra) > 0 {
		pr.field("Names:", p.warn("⚠ in certificate, not requested:")+" "+strings.Join(n.Extra, ", "))
	}
}

func matchVerdict(m inspect.Match, ok bool) string {
	if m.CSRSigErr != nil {
		return "CSR signature does NOT verify"
	}
	if len(m.Pairs) != 1 {
		if ok {
			return "Certificate, CSR and key match"
		}
		return "Certificate, CSR and key do NOT match"
	}
	var subject, object string
	switch pair := m.Pairs[0]; {
	case pair.A == inspect.Certificate && pair.B == inspect.CSR:
		subject, object = "Certificate", "CSR"
	case pair.A == inspect.CSR:
		subject, object = "Key", "CSR"
	default:
		subject, object = "Key", "certificate"
	}
	if ok {
		return subject + " matches " + object
	}
	return subject + " does NOT match " + object
}

func noun(p inspect.Part) string {
	switch p {
	case inspect.Certificate:
		return "certificate"
	case inspect.CSR:
		return "CSR"
	default:
		return "key"
	}
}

func pairLabel(p inspect.Pair) string {
	short := map[inspect.Part]string{inspect.Certificate: "Cert", inspect.CSR: "CSR", inspect.Key: "Key"}
	return short[p.A] + " ↔ " + short[p.B] + ":"
}

func (pr *Printer) line(format string, args ...any) {
	fmt.Fprintf(pr.w, format+"\n", args...)
}

// header prints the title banner and the mode line.
func (pr *Printer) header(mode string) {
	pr.line("")
	pr.banner(title, true)
	pr.line("")
	pr.line("  %s %s", pr.p.cyan("▶"), pr.p.bold(mode))
	pr.line("")
}

func (pr *Printer) banner(text string, centered bool) {
	bar := pr.p.white(strings.Repeat("═", bannerWidth))
	indent := 2
	if centered {
		indent = (bannerWidth - len(text)) / 2
	}
	pr.line("%s", bar)
	pr.line("%s%s", strings.Repeat(" ", indent), pr.p.white(text))
	pr.line("%s", bar)
}

// section prints a block heading; index is the optional "[1/3]" prefix.
func (pr *Printer) section(index, text string) {
	if index != "" {
		index = pr.p.white(index) + " "
	}
	pr.line("  %s%s", index, pr.p.cyan(text))
	pr.line("  %s", pr.p.dim(strings.Repeat("─", ruleWidth)))
}

// field prints "label value". Short labels are padded to a narrow column and
// long ones are not, so values only line up for "SANs:", "CA:" and the like;
// this is the tool's established look.
func (pr *Printer) field(label, value string) {
	pr.line("  %s %s", pr.p.dim(fmt.Sprintf("%-*s", labelWidth, label)), value)
}

func (pr *Printer) identity(c *x509.Certificate) {
	pr.field("Subject:", displayName(c.Subject))
	pr.field("Issuer:", displayName(c.Issuer))
	if sans := subjectAltNames(c.DNSNames, c.IPAddresses); len(sans) > 0 {
		pr.field("SANs:", strings.Join(sans, ", "))
	}
}

func (pr *Printer) request(r inspect.Request) {
	csr := r.CSR
	pr.field("Subject:", displayName(csr.Subject))
	if dn := csr.Subject.String(); dn != "CN="+csr.Subject.CommonName {
		pr.field("DN:", dn)
	}
	if sans := subjectAltNames(csr.DNSNames, csr.IPAddresses); len(sans) > 0 {
		pr.field("SANs:", strings.Join(sans, ", "))
	}
	if r.SigErr == nil {
		pr.field("Signature:", pr.p.good("✓ valid")+" ("+csr.SignatureAlgorithm.String()+")")
	} else {
		pr.field("Signature:", pr.p.bad("✗ does NOT verify"))
	}
}

func (pr *Printer) validity(e inspect.Entry) string {
	switch e.Validity {
	case inspect.Expired:
		return pr.p.bad("✗ EXPIRED") + " (expired " + e.Cert.NotAfter.Format(dateLayout) + ")"
	case inspect.NotYetValid:
		return pr.p.bad("✗ NOT YET VALID") + " (from " + e.Cert.NotBefore.Format(dateLayout) + ")"
	case inspect.ExpiringSoon:
		return pr.p.warn("⚠ expiring soon") + " (expires in " + days(e.DaysLeft) + ")"
	default:
		return pr.p.good("✓ valid") + " (until " + e.Cert.NotAfter.Format(dateLayout) + ")"
	}
}

// linkHint prints the line under a certificate saying whether the next one
// issued it, with both names spelled out when they differ.
func (pr *Printer) linkHint(c inspect.Chain, l inspect.Link) {
	p := pr.p
	switch {
	case l.OK():
		pr.line("    %s%s", p.plain("↑ issuer matches next subject "), p.good("✓"))
	case l.NameMatch:
		pr.line("    %s%s%s", p.bad("↑"), p.plain(" issuer name matches, but signature does NOT verify "), p.bad("✗"))
	default:
		pr.line("    %s%s%s", p.bad("↑"), p.plain(" issuer does NOT match next subject "), p.bad("✗"))
		pr.line("      %s %s", p.dim("current issuer:"), c.Entries[l.Child].Cert.Issuer)
		pr.line("      %s %s", p.dim("next subject:  "), c.Entries[l.Parent].Cert.Subject)
	}
}

func (pr *Printer) linkVerdict(l inspect.Link) string {
	switch {
	case l.OK():
		return pr.p.good("✓ issuer matches subject")
	case l.NameMatch:
		return pr.p.bad("✗ signature does NOT verify")
	default:
		return pr.p.bad("✗ BROKEN LINK: issuer ≠ subject")
	}
}

func role(i, n int, selfSigned bool) string {
	switch {
	case n == 1:
		return "Self-Signed / Leaf"
	case i == 0:
		return "Leaf Certificate (End-Entity)"
	case i == n-1 && selfSigned:
		return "Root CA"
	case i == n-1:
		return "Root CA (not self-signed!)"
	default:
		return fmt.Sprintf("Intermediate CA #%d", i)
	}
}

func days(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func displayName(n pkix.Name) string {
	return cmp.Or(n.CommonName, n.String(), "(empty)")
}

// shortName keeps summary lines readable when names are long.
func shortName(n pkix.Name) string {
	name := []rune(displayName(n))
	if len(name) <= nameWidth {
		return string(name)
	}
	return string(name[:nameWidth-3]) + "..."
}

func subjectAltNames(dns []string, ips []net.IP) []string {
	sans := append([]string(nil), dns...)
	for _, ip := range ips {
		sans = append(sans, ip.String())
	}
	return sans
}
