// Package input reads certificates, certificate requests and private keys
// from files.
package input

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/youmark/pkcs8"
)

// PassphraseFunc supplies the passphrase for an encrypted key. It is called
// at most once, and only when the key really is encrypted.
type PassphraseFunc func() ([]byte, error)

// File is what one file given on the command line contains.
type File struct {
	Path  string
	Certs []*x509.Certificate
	CSRs  []*x509.CertificateRequest
	Key   *pem.Block // first private key block, if any
}

// Empty reports whether nothing usable was found in the file.
func (f File) Empty() bool {
	return len(f.Certs) == 0 && len(f.CSRs) == 0 && f.Key == nil
}

// Read loads every certificate and certificate request from path, PEM or a
// single DER object, and remembers the first private key block without
// parsing it.
func Read(path string) (File, error) {
	f := File{Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return f, fmt.Errorf("%s: certificate #%d: %w", path, len(f.Certs)+1, err)
			}
			f.Certs = append(f.Certs, cert)
		case block.Type == "CERTIFICATE REQUEST" || block.Type == "NEW CERTIFICATE REQUEST":
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return f, fmt.Errorf("%s: certificate request #%d: %w", path, len(f.CSRs)+1, err)
			}
			f.CSRs = append(f.CSRs, csr)
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			if f.Key == nil {
				f.Key = block
			}
		}
	}

	// Not PEM at all: .crt/.cer/.csr files are often plain DER.
	if f.Empty() {
		if cert, err := x509.ParseCertificate(data); err == nil {
			f.Certs = append(f.Certs, cert)
		} else if csr, err := x509.ParseCertificateRequest(data); err == nil {
			f.CSRs = append(f.CSRs, csr)
		}
	}
	return f, nil
}

// Encrypted reports whether a private key block needs a passphrase.
func Encrypted(block *pem.Block) bool {
	return block.Type == "ENCRYPTED PRIVATE KEY" || x509.IsEncryptedPEMBlock(block) //nolint:staticcheck
}

// ParseKey decodes a private key block in PKCS#8, PKCS#1 or SEC1 form,
// asking for a passphrase when the block is encrypted.
func ParseKey(block *pem.Block, ask PassphraseFunc) (crypto.Signer, error) {
	der := block.Bytes

	switch {
	case block.Type == "ENCRYPTED PRIVATE KEY":
		pass, err := ask()
		if err != nil {
			return nil, err
		}
		key, err := pkcs8.ParsePKCS8PrivateKey(der, pass)
		if err != nil {
			return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
		}
		return asSigner(key)

	// Legacy "Proc-Type: 4,ENCRYPTED" keys. The API is deprecated because the
	// format is weak, but such keys are still common and we only read them.
	case x509.IsEncryptedPEMBlock(block): //nolint:staticcheck
		pass, err := ask()
		if err != nil {
			return nil, err
		}
		der, err = x509.DecryptPEMBlock(block, pass) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
		}
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return asSigner(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported or malformed private key")
}

func asSigner(key any) (crypto.Signer, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return signer, nil
}
