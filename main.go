package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"github.com/youmark/pkcs8"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func green(s string) string  { return colorGreen + s + colorReset }
func red(s string) string    { return colorRed + s + colorReset }
func yellow(s string) string { return colorYellow + s + colorReset }
func cyan(s string) string   { return colorCyan + s + colorReset }
func bold(s string) string   { return colorBold + s + colorReset }
func dim(s string) string    { return colorDim + s + colorReset }

type FileType int

const (
	FileUnknown FileType = iota
	FileCert
	FileKey
)

type ParsedFile struct {
	Path        string
	Type        FileType
	Certs       []*x509.Certificate
	Key         interface{} // *rsa.PrivateKey | *ecdsa.PrivateKey | *pem.Block (if encrypted)
	IsEncrypted bool
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var files []ParsedFile
	for _, path := range os.Args[1:] {
		pf, err := parseFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, red("✗ Error reading %s: %v\n"), path, err)
			os.Exit(1)
		}
		files = append(files, pf)
	}

	var allCerts []*x509.Certificate
	var keyFile *ParsedFile

	for i, pf := range files {
		switch pf.Type {
		case FileCert:
			allCerts = append(allCerts, pf.Certs...)
		case FileKey:
			if keyFile != nil {
				fmt.Fprintf(os.Stderr, red("✗ Multiple key files provided, expected at most one\n"))
				os.Exit(1)
			}
			keyFile = &files[i]
		case FileUnknown:
			fmt.Fprintf(os.Stderr, red("✗ %s: unrecognized file (not a certificate or private key)\n"), pf.Path)
			os.Exit(1)
		}
	}

	printHeader()

	if keyFile != nil {
		if len(allCerts) == 0 {
			fmt.Fprintf(os.Stderr, red("✗ Key file provided but no certificate found\n"))
			os.Exit(1)
		}
		runKeyCheck(allCerts, keyFile)
	} else {
		if len(allCerts) == 0 {
			fmt.Fprintf(os.Stderr, red("✗ No certificates found\n"))
			os.Exit(1)
		}
		runChainCheck(allCerts)
	}
}

// ─── File parsing ─────────────────────────────────────────────────────────────

func parseFile(path string) (ParsedFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ParsedFile{}, err
	}

	pf := ParsedFile{Path: path}
	rest := data

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return ParsedFile{}, fmt.Errorf("failed to parse certificate: %w", err)
			}
			pf.Certs = append(pf.Certs, cert)
			pf.Type = FileCert

		case "RSA PRIVATE KEY":
			if x509.IsEncryptedPEMBlock(block) {
				pf.Key = block
				pf.IsEncrypted = true
			} else {
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return ParsedFile{}, fmt.Errorf("failed to parse RSA key: %w", err)
				}
				pf.Key = key
			}
			pf.Type = FileKey

		case "EC PRIVATE KEY":
			if x509.IsEncryptedPEMBlock(block) {
				pf.Key = block
				pf.IsEncrypted = true
			} else {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					return ParsedFile{}, fmt.Errorf("failed to parse EC key: %w", err)
				}
				pf.Key = key
			}
			pf.Type = FileKey

		case "PRIVATE KEY": // PKCS#8 unencrypted
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return ParsedFile{}, fmt.Errorf("failed to parse PKCS8 key: %w", err)
			}
			pf.Key = key
			pf.Type = FileKey

		case "ENCRYPTED PRIVATE KEY": // PKCS#8 encrypted
			pf.Key = block
			pf.IsEncrypted = true
			pf.Type = FileKey
		}
	}

	// Fallback: try raw DER cert
	if pf.Type == FileUnknown {
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			pf.Certs = append(pf.Certs, cert)
			pf.Type = FileCert
		}
	}

	return pf, nil
}

// ─── Key decryption ───────────────────────────────────────────────────────────

func decryptKey(pf *ParsedFile) error {
	block, ok := pf.Key.(*pem.Block)
	if !ok {
		return fmt.Errorf("internal: expected *pem.Block for encrypted key")
	}

	fmt.Fprintf(os.Stderr, "  %s Key is encrypted. Enter password: ", yellow("🔑"))
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	switch block.Type {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY":
		// Legacy PEM encryption (DEK-Info header) — handled by stdlib
		der, err := x509.DecryptPEMBlock(block, passBytes)
		if err != nil {
			return fmt.Errorf("decryption failed (wrong password?): %w", err)
		}
		if block.Type == "RSA PRIVATE KEY" {
			key, err := x509.ParsePKCS1PrivateKey(der)
			if err != nil {
				return err
			}
			pf.Key = key
		} else {
			key, err := x509.ParseECPrivateKey(der)
			if err != nil {
				return err
			}
			pf.Key = key
		}

	case "ENCRYPTED PRIVATE KEY":
		// PKCS#8 with PBES2/AES — requires github.com/youmark/pkcs8
		key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, passBytes)
		if err != nil {
			return fmt.Errorf("decryption failed (wrong password?): %w", err)
		}
		pf.Key = key

	default:
		return fmt.Errorf("unsupported encrypted key type: %s", block.Type)
	}

	pf.IsEncrypted = false
	return nil
}

// ─── Key check mode ───────────────────────────────────────────────────────────

func runKeyCheck(certs []*x509.Certificate, keyFile *ParsedFile) {
	cert := certs[0]

	fmt.Printf("  %s %s\n\n", cyan("▶"), bold("Mode: Certificate + Key Match"))

	fmt.Printf("  %s\n", bold("Certificate"))
	fmt.Printf("  %s\n", strings.Repeat("─", 55))
	fmt.Printf("  %-14s %s\n", dim("Subject:"), cert.Subject.CommonName)
	fmt.Printf("  %-14s %s\n", dim("Issuer:"), cert.Issuer.CommonName)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("  %-14s %s\n", dim("SANs:"), strings.Join(cert.DNSNames, ", "))
	}
	encLabel := ""
	if keyFile.IsEncrypted {
		encLabel = yellow(" (encrypted)")
	}
	fmt.Printf("  %-14s %s%s\n\n", dim("Key file:"), keyFile.Path, encLabel)

	// Decrypt if needed
	if keyFile.IsEncrypted {
		if err := decryptKey(keyFile); err != nil {
			fmt.Printf("\n  %s\n\n", bold(red("✗ "+err.Error())))
			return
		}
	}

	fmt.Printf("%s\n", bold("═══════════════════════════════════════════════════"))
	fmt.Printf("%s\n", bold("  Key Match Result"))
	fmt.Printf("%s\n", bold("═══════════════════════════════════════════════════"))

	match, keyType, err := certMatchesKey(cert, keyFile.Key)
	fmt.Printf("  %-14s %s\n", dim("Key type:"), keyType)

	if err != nil {
		fmt.Printf("  %-14s %s\n", dim("Match:"), red("✗ ERROR: "+err.Error()))
		fmt.Printf("\n  %s\n\n", bold(red("✗ Cannot verify key match")))
		return
	}

	if match {
		fmt.Printf("  %-14s %s\n", dim("Match:"), green("✓ certificate and key correspond"))
		fmt.Printf("\n  %s\n\n", bold(green("✓ Key matches certificate")))
	} else {
		fmt.Printf("  %-14s %s\n", dim("Match:"), red("✗ public keys do NOT match"))
		fmt.Printf("\n  %s\n\n", bold(red("✗ Key does NOT match certificate")))
	}
}

func certMatchesKey(cert *x509.Certificate, key interface{}) (bool, string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		certPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false, "RSA", fmt.Errorf("certificate does not contain an RSA public key")
		}
		match := k.PublicKey.N.Cmp(certPub.N) == 0 && k.PublicKey.E == certPub.E
		return match, fmt.Sprintf("RSA %d-bit", k.N.BitLen()), nil

	case *ecdsa.PrivateKey:
		certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, "ECDSA", fmt.Errorf("certificate does not contain an ECDSA public key")
		}
		match := k.PublicKey.X.Cmp(certPub.X) == 0 && k.PublicKey.Y.Cmp(certPub.Y) == 0
		return match, fmt.Sprintf("ECDSA %s", k.Curve.Params().Name), nil

	default:
		return false, "unknown", fmt.Errorf("unsupported key type %T", key)
	}
}

// ─── Chain check mode ─────────────────────────────────────────────────────────

func runChainCheck(chain []*x509.Certificate) {
	fmt.Printf("  %s %s\n\n", cyan("▶"), bold(fmt.Sprintf("Mode: Chain Check  (%d certificate(s))", len(chain))))

	for i, cert := range chain {
		printCertInfo(cert, i, len(chain))

		if i+1 < len(chain) {
			next := chain[i+1]
			linkOK := cert.Issuer.String() == next.Subject.String()
			if linkOK {
				fmt.Printf("    %s issuer matches next subject %s\n", green("↑"), green("✓"))
			} else {
				fmt.Printf("    %s issuer does NOT match next subject %s\n", red("↑"), red("✗"))
				fmt.Printf("      %s %s\n", dim("current  issuer:"), cert.Issuer.String())
				fmt.Printf("      %s %s\n", dim("not expected subject:"), next.Subject.String())
			}
		}

		fmt.Println()
	}

	printChainValidation(chain)
}

func printCertInfo(cert *x509.Certificate, index int, total int) {
	now := time.Now()
	isExpired := now.After(cert.NotAfter)
	isNotYetValid := now.Before(cert.NotBefore)
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()

	var roleLabel string
	switch {
	case index == 0 && total == 1:
		roleLabel = "Self-Signed / Leaf"
	case index == 0:
		roleLabel = "Leaf Certificate (End-Entity)"
	case index == total-1 && isSelfSigned:
		roleLabel = "Root CA"
	case index == total-1:
		roleLabel = "Root CA (not self-signed!)"
	default:
		roleLabel = fmt.Sprintf("Intermediate CA #%d", index)
	}

	fmt.Printf("  %s %s\n", bold(fmt.Sprintf("[%d/%d]", index+1, total)), bold(cyan(roleLabel)))
	fmt.Printf("  %s\n", strings.Repeat("─", 55))
	fmt.Printf("  %-14s %s\n", dim("Subject:"), cert.Subject.CommonName)
	fmt.Printf("  %-14s %s\n", dim("Issuer:"), cert.Issuer.CommonName)

	if len(cert.DNSNames) > 0 {
		fmt.Printf("  %-14s %s\n", dim("SANs:"), strings.Join(cert.DNSNames, ", "))
	}
	if cert.IsCA {
		fmt.Printf("  %-14s %s\n", dim("CA:"), green("Yes ✓"))
	}
	if isSelfSigned {
		fmt.Printf("  %-14s %s\n", dim("Self-Signed:"), yellow("Yes"))
	}

	fmt.Printf("  %-14s ", dim("Status:"))
	switch {
	case isExpired:
		fmt.Printf("%s (expired %s)\n", red("✗ EXPIRED"), cert.NotAfter.Format("2006-01-02"))
	case isNotYetValid:
		fmt.Printf("%s (from %s)\n", red("✗ NOT YET VALID"), cert.NotBefore.Format("2006-01-02"))
	default:
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft < 30 {
			fmt.Printf("%s (expires in %d days)\n", yellow("⚠ expiring soon"), daysLeft)
		} else {
			fmt.Printf("%s (until %s)\n", green("✓ valid"), cert.NotAfter.Format("2006-01-02"))
		}
	}
}

func printChainValidation(chain []*x509.Certificate) {
	fmt.Printf("%s\n", bold("═══════════════════════════════════════════════════"))
	fmt.Printf("%s\n", bold("  Chain Validation Summary"))
	fmt.Printf("%s\n", bold("═══════════════════════════════════════════════════"))

	allOK := true
	now := time.Now()

	for i := 0; i < len(chain)-1; i++ {
		curr := chain[i]
		next := chain[i+1]
		linkOK := curr.Issuer.String() == next.Subject.String()
		label := fmt.Sprintf("  [%d→%d] %s → %s",
			i+1, i+2,
			shortName(curr.Subject.CommonName),
			shortName(next.Subject.CommonName),
		)
		if linkOK {
			fmt.Printf("%s  %s\n", label, green("✓ issuer matches subject"))
		} else {
			fmt.Printf("%s  %s\n", label, red("✗ BROKEN LINK: issuer ≠ subject"))
			fmt.Printf("         issuer:  %s\n", dim(curr.Issuer.String()))
			fmt.Printf("         subject: %s\n", dim(next.Subject.String()))
			allOK = false
		}
	}

	for i, cert := range chain {
		if now.After(cert.NotAfter) {
			fmt.Printf("  [%d] %s  %s\n", i+1, shortName(cert.Subject.CommonName), red("✗ EXPIRED"))
			allOK = false
		} else if now.Before(cert.NotBefore) {
			fmt.Printf("  [%d] %s  %s\n", i+1, shortName(cert.Subject.CommonName), red("✗ NOT YET VALID"))
			allOK = false
		}
	}

	if len(chain) > 0 {
		root := chain[len(chain)-1]
		if root.Subject.String() == root.Issuer.String() {
			fmt.Printf("  Root CA is self-signed  %s\n", green("✓"))
		} else {
			fmt.Printf("  Root CA is NOT self-signed  %s\n", yellow("⚠ chain may be incomplete"))
			allOK = false
		}
	}

	fmt.Println()
	if allOK {
		fmt.Printf("  %s\n\n", bold(green("✓ Chain is VALID")))
	} else {
		fmt.Printf("  %s\n\n", bold(red("✗ Chain has ISSUES")))
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func printHeader() {
	fmt.Printf("\n%s\n", bold("═══════════════════════════════════════════════════"))
	fmt.Printf("%s\n", bold("          SSL Certificate Chain Inspector"))
	fmt.Printf("%s\n\n", bold("═══════════════════════════════════════════════════"))
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  ssl_chain chain.pem                    # chain check (single PEM with multiple certs)\n")
	fmt.Fprintf(os.Stderr, "  ssl_chain cert.crt [intermediate.crt]  # chain check (separate files)\n")
	fmt.Fprintf(os.Stderr, "  ssl_chain cert.crt cert.key            # key match check\n")
	fmt.Fprintf(os.Stderr, "  ssl_chain cert.crt cert.key            # key match (prompts if encrypted)\n")
}

func shortName(name string) string {
	if len(name) > 30 {
		return name[:27] + "..."
	}
	return name
}
