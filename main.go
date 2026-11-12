// Command ssl-chain inspects a certificate chain, a certificate signing
// request, or checks that a certificate, a CSR and a private key belong
// together.
package main

import (
	"cmp"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/master2sid2/ssl-chain/internal/input"
	"github.com/master2sid2/ssl-chain/internal/inspect"
	"github.com/master2sid2/ssl-chain/internal/report"
)

const (
	exitOK     = 0
	exitIssues = 1
	exitUsage  = 2
)

// Set by the Makefile through -ldflags; see buildInfo for the fallbacks.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	color := os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, color, askPassphrase))
}

func run(args []string, out, errOut io.Writer, color bool, ask input.PassphraseFunc) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage(errOut)
		return exitUsage
	}
	printer := report.New(out, color)
	if args[0] == "-v" || args[0] == "--version" {
		printer.Version(buildInfo())
		return exitOK
	}

	var (
		certs    []*x509.Certificate
		csrs     []*x509.CertificateRequest
		keyFiles []input.File
	)
	for _, path := range args {
		f, err := input.Read(path)
		if err != nil {
			fmt.Fprintf(errOut, "error: %v\n", err)
			return exitUsage
		}
		if f.Empty() {
			fmt.Fprintf(errOut, "error: %s: no certificate, CSR or private key found\n", path)
			return exitUsage
		}
		certs = append(certs, f.Certs...)
		csrs = append(csrs, f.CSRs...)
		if f.Key != nil {
			keyFiles = append(keyFiles, f)
		}
	}
	if len(keyFiles) > 1 {
		fmt.Fprintf(errOut, "error: more than one private key given (%s, %s)\n", keyFiles[0].Path, keyFiles[1].Path)
		return exitUsage
	}
	if len(csrs) > 1 {
		fmt.Fprintln(errOut, "error: more than one CSR given")
		return exitUsage
	}

	switch {
	case len(keyFiles) == 0 && len(csrs) == 0:
		chain := inspect.AnalyzeChain(certs, time.Now())
		printer.Chain(chain)
		return exitCode(chain.OK())

	case len(keyFiles) == 0 && len(certs) == 0:
		req := inspect.CheckRequest(csrs[0])
		printer.Request(req)
		return exitCode(req.SigErr == nil)

	case len(certs) == 0 && len(csrs) == 0:
		fmt.Fprintf(errOut, "error: %s: no certificate or CSR to match the key against\n", keyFiles[0].Path)
		return exitUsage
	}

	// Match mode: compare whatever was given, the first certificate standing
	// for the whole chain.
	var in report.MatchInput
	var csr *x509.CertificateRequest
	if len(certs) > 0 {
		in.Cert = certs[0]
	}
	if len(csrs) > 0 {
		csr = csrs[0]
		req := inspect.CheckRequest(csr)
		in.Request = &req
	}
	if len(keyFiles) > 0 {
		in.KeyFile = keyFiles[0].Path
		in.Encrypted = input.Encrypted(keyFiles[0].Key)
	}
	printer.MatchHeader(in)

	var key crypto.Signer
	if len(keyFiles) > 0 {
		var err error
		if key, err = input.ParseKey(keyFiles[0].Key, ask); err != nil {
			printer.Fail(err)
			return exitUsage
		}
	}
	match := inspect.MatchParts(in.Cert, csr, key)
	printer.MatchResult(in, match)
	return exitCode(match.OK())
}

func exitCode(ok bool) int {
	if ok {
		return exitOK
	}
	return exitIssues
}

func usage(w io.Writer) {
	name := filepath.Base(os.Args[0])
	fmt.Fprintf(w, `Usage:
  %[1]s chain.pem                        # chain check (single PEM with multiple certs)
  %[1]s cert.crt [intermediate.crt ...]  # chain check (separate files)
  %[1]s cert.crt cert.key                # key match (prompts password if encrypted)
  %[1]s request.csr                      # CSR info and signature check
  %[1]s request.csr cert.key             # CSR and key match
  %[1]s cert.crt request.csr [cert.key]  # certificate, CSR (and key) match
  %[1]s --version                        # show version
`, name)
}

// buildInfo returns the version, commit and build date. Values from the
// Makefile win; otherwise they come from what the Go toolchain recorded,
// which covers "go install ...@v0.1.0" and plain "go build" in a checkout.
func buildInfo() (v, c, d string) {
	v, c, d = version, commit, date
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = strings.TrimPrefix(bi.Main.Version, "v")
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				c = cmp.Or(c, s.Value[:min(7, len(s.Value))])
			case "vcs.time":
				d = cmp.Or(d, s.Value[:min(10, len(s.Value))])
			}
		}
	}
	return v, cmp.Or(c, "none"), cmp.Or(d, "unknown")
}

func askPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("key is encrypted and stdin is not a terminal")
	}
	fmt.Fprint(os.Stderr, "  🔑 Key is encrypted. Enter password: ")
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return pass, err
}
