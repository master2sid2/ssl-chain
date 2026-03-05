# ssl_chain

A CLI tool for inspecting and validating SSL/TLS certificate chains and private key matching.

## Features

- **Chain validation** — checks that each certificate's issuer matches the subject of the next certificate in the chain
- **Key matching** — verifies that a private key corresponds to a certificate
- **Encrypted key support** — prompts for password if the key is encrypted (legacy PEM and PKCS#8)
- **Expiry awareness** — highlights expired certificates and warns when expiry is within 30 days
- **Multiple input formats** — PEM (single file with full chain or separate files), DER
- **Colored output** — green for OK, red for issues, yellow for warnings

## Installation

```bash
git clone https://github.com/you/ssl_chain
cd ssl_chain

go mod tidy
make build

# or install globally
make install
```

## Usage

```bash
# Chain check — single PEM file containing the full chain
./ssl_chain chain.pem

# Chain check — separate files in order: leaf → intermediate → root
./ssl_chain cert.crt intermediate.crt root.crt

# Key match — check that a private key corresponds to a certificate
./ssl_chain cert.crt cert.key

# Key match — encrypted key (will prompt for password)
./ssl_chain cert.crt cert.key.enc

# Show version
./ssl_chain --version
```

## Example Output

**Chain check:**
```
═══════════════════════════════════════════════════
          SSL Certificate Chain Inspector
═══════════════════════════════════════════════════

  ▶ Mode: Chain Check  (4 certificate(s))

  [1/4] Leaf Certificate (End-Entity)
  ───────────────────────────────────────────────────────
  Subject:       client.example.com
  Issuer:        InCommon RSA Server CA 2
  SANs:          client.example.com
  Status:        ✓ valid (until 2025-11-01)
    ↑ issuer matches next subject ✓

  [2/4] Intermediate CA #1
  ───────────────────────────────────────────────────────
  Subject:       InCommon RSA Server CA 2
  Issuer:        USERTrust RSA Certification Authority
  CA:            Yes ✓
  Status:        ✓ valid (until 2030-05-30)
    ↑ issuer matches next subject ✓
  ...

═══════════════════════════════════════════════════
  Chain Validation Summary
═══════════════════════════════════════════════════
  [1→2] client.example.com → InCommon RSA...    ✓ issuer matches subject
  [2→3] InCommon RSA...  → USERTrust RSA...   ✓ issuer matches subject
  [3→4] USERTrust RSA... → AAA Certificate... ✓ issuer matches subject
  Root CA is self-signed  ✓

  ✓ Chain is VALID
```

**Key match:**
```
  ▶ Mode: Certificate + Key Match

  Certificate
  ───────────────────────────────────────────────────────
  Subject:       client.example.com
  Issuer:        InCommon RSA Server CA 2
  Key file:      client.key

═══════════════════════════════════════════════════
  Key Match Result
═══════════════════════════════════════════════════
  Key type:      RSA 2048-bit
  Match:         ✓ certificate and key correspond

  ✓ Key matches certificate
```

## Supported Key Types

| PEM Header | Encrypted | How it's handled |
|---|---|---|
| `RSA PRIVATE KEY` | No | stdlib |
| `RSA PRIVATE KEY` + DEK-Info | **Yes** | stdlib (`x509.DecryptPEMBlock`) |
| `EC PRIVATE KEY` | No | stdlib |
| `EC PRIVATE KEY` + DEK-Info | **Yes** | stdlib (`x509.DecryptPEMBlock`) |
| `PRIVATE KEY` | No | stdlib (PKCS#8) |
| `ENCRYPTED PRIVATE KEY` | **Yes** | `github.com/youmark/pkcs8` |

## Building

```bash
make build      # compile binary
make install    # compile and copy to /usr/local/bin
make clean      # remove binary
make version    # print version info
make help       # list all targets
```

To release a new version, edit the `VERSION` file:
```bash
echo "0.0.2" > VERSION
make build
```

## Dependencies

- [`golang.org/x/term`](https://pkg.go.dev/golang.org/x/term) — password input without echo
- [`github.com/youmark/pkcs8`](https://github.com/youmark/pkcs8) — PKCS#8 encrypted key decryption

## License

MIT
