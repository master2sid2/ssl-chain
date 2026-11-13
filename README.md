# ssl-chain

[![CI](https://github.com/master2sid2/ssl-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/master2sid2/ssl-chain/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/master2sid2/ssl-chain)](https://github.com/master2sid2/ssl-chain/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/master2sid2/ssl-chain)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small CLI that answers a few questions about TLS files before you deploy
them:

- **Is this chain complete and in the right order?**
- **Does this private key belong to this certificate?**
- **What does this CSR ask for, and do the certificate, CSR and key belong
  together?**

It reads local files only and never connects anywhere.

## Install

```bash
go install github.com/master2sid2/ssl-chain@latest
```

Or download a binary from the [releases](https://github.com/master2sid2/ssl-chain/releases)
page, or build from source (see [Build](#build)).

## Usage

```
ssl-chain chain.pem                        # chain check (single PEM with multiple certs)
ssl-chain cert.crt [intermediate.crt ...]  # chain check (separate files)
ssl-chain cert.crt cert.key                # key match (prompts password if encrypted)
ssl-chain request.csr                      # CSR info and signature check
ssl-chain request.csr cert.key             # CSR and key match
ssl-chain cert.crt request.csr [cert.key]  # certificate, CSR (and key) match
ssl-chain --version                        # show version
```

The mode is picked from what the files contain, in any order:

| Files contain | Mode |
|---|---|
| certificates only | chain check |
| one CSR only | CSR info |
| a private key and/or a CSR, plus anything else | match check |

A file may hold several things at once, for example a certificate together
with its key. At most one private key and one CSR may be given.

### Chain check

Certificates are checked in the order given — leaf first, root last.

```
$ ssl-chain fullchain.pem

═══════════════════════════════════════════════════
          SSL Certificate Chain Inspector
═══════════════════════════════════════════════════

  ▶ Mode: Chain Check  (3 certificate(s))

  [1/3] Leaf Certificate (End-Entity)
  ───────────────────────────────────────────────────────
  Subject: forms.example.com
  Issuer: Demo TLS RSA CA G1
  SANs:  forms.example.com, www.forms.example.com
  Status: ⚠ expiring soon (expires in 12 days)
    ↑ issuer matches next subject ✓

  [2/3] Intermediate CA #1
  ───────────────────────────────────────────────────────
  Subject: Demo TLS RSA CA G1
  Issuer: Demo Root G2
  CA:    Yes ✓
  Status: ✓ valid (until 2031-09-17)
    ↑ issuer matches next subject ✓

  [3/3] Root CA
  ───────────────────────────────────────────────────────
  Subject: Demo Root G2
  Issuer: Demo Root G2
  CA:    Yes ✓
  Self-Signed: Yes
  Status: ✓ valid (until 2036-10-10)

═══════════════════════════════════════════════════
  Chain Validation Summary
═══════════════════════════════════════════════════
  [1→2] forms.example.com → Demo TLS RSA CA G1  ✓ issuer matches subject
  [2→3] Demo TLS RSA CA G1 → Demo Root G2  ✓ issuer matches subject
  [1] forms.example.com  ⚠ expires in 12 days
  Root CA is self-signed  ✓

  ✓ Chain is VALID
```

What is checked:

| Check | Reported as |
|---|---|
| Each certificate's issuer is the next certificate's subject | `✗ BROKEN LINK: issuer ≠ subject`, with both names |
| Each certificate is really signed by the next one's key | `✗ signature does NOT verify` |
| Every certificate is inside its validity window | `✗ EXPIRED`, `✗ NOT YET VALID` |
| Less than 30 days left (a warning, not an issue) | `⚠ expiring soon` |
| Every issuer is a CA | `✗ not a CA` |
| The last certificate is self-signed | `⚠ chain may be incomplete` |

The chain is not validated against the system trust store: a complete chain
ending in a private root is reported as valid.

### Key match

```
$ ssl-chain forms.example.com.crt forms.example.com.key

═══════════════════════════════════════════════════
          SSL Certificate Chain Inspector
═══════════════════════════════════════════════════

  ▶ Mode: Certificate + Key Match

  Certificate
  ───────────────────────────────────────────────────────
  Subject: forms.example.com
  Issuer: Demo TLS RSA CA G1
  SANs:  forms.example.com, www.forms.example.com
  Key file: forms.example.com.key

═══════════════════════════════════════════════════
  Key Match Result
═══════════════════════════════════════════════════
  Key type: RSA 2048-bit
  Match: ✓ certificate and key correspond

  ✓ Key matches certificate
```

RSA, ECDSA and Ed25519 keys are supported, in PKCS#1, SEC1 and PKCS#8 form.
For an encrypted key (PKCS#8 or legacy `Proc-Type: 4,ENCRYPTED`) the passphrase
is asked for on the terminal and is never taken from arguments or environment.

### CSR

A CSR on its own shows what it requests and whether it is signed by its own
key, which proves the requester holds the private key:

```
$ ssl-chain forms.example.com.csr

  ▶ Mode: CSR Info

  CSR
  ───────────────────────────────────────────────────────
  Subject: forms.example.com
  DN:    CN=forms.example.com,O=Example,C=UA
  SANs:  forms.example.com, api.forms.example.com
  Signature: ✓ valid (SHA256-RSA)
  Key type: RSA 2048-bit

  ✓ CSR signature is valid
```

Given together with a key and/or a certificate, every pair is compared by
public key. With a certificate and a CSR the names are compared too; CAs may
add or drop names, so differences are warnings and do not fail the check:

```
$ ssl-chain forms.example.com.crt forms.example.com.csr forms.example.com.key
  ...
═══════════════════════════════════════════════════
  Key Match Result
═══════════════════════════════════════════════════
  Key type: RSA 2048-bit
  Cert ↔ Key: ✓ certificate and key correspond
  CSR ↔ Key: ✓ CSR and key correspond
  Cert ↔ CSR: ✓ certificate and CSR correspond
  Names: ⚠ requested, not in certificate: api.forms.example.com
  Names: ⚠ in certificate, not requested: www.forms.example.com

  ✓ Certificate, CSR and key match
```

When a chain is given in match mode, its first certificate is the one compared.

## Input formats

- PEM files with any mix of `CERTIFICATE`, `CERTIFICATE REQUEST` (or
  `NEW CERTIFICATE REQUEST`) and private key blocks.
- A single DER-encoded certificate or CSR.

| Key PEM header | Encrypted | Notes |
|---|---|---|
| `PRIVATE KEY` | no | PKCS#8: RSA, ECDSA, Ed25519 |
| `ENCRYPTED PRIVATE KEY` | yes | PKCS#8 with PBES2 |
| `RSA PRIVATE KEY` | optional | PKCS#1, legacy `Proc-Type: 4,ENCRYPTED` |
| `EC PRIVATE KEY` | optional | SEC1, legacy `Proc-Type: 4,ENCRYPTED` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Chain is valid / CSR signature is valid / everything matches |
| `1` | Chain has issues / CSR signature is invalid / something does not match |
| `2` | Bad arguments, unreadable input or wrong passphrase |

## Colours

Output is coloured when stdout is a terminal. Set `NO_COLOR=1` to turn colours
off; they are off automatically when the output is piped or redirected.

## Build

Requires Go 1.26+.

```bash
make build      # bin/ssl-chain, version taken from the VERSION file
make test       # unit tests
make lint       # go vet and gofmt check
make install    # copy to /usr/local/bin (PREFIX=... to change)
make dist       # release binaries for Linux, macOS and Windows in dist/
```

Releases on GitHub are built by [GoReleaser](https://goreleaser.com) in GitHub
Actions when a `v*` tag is pushed; the tag must match the `VERSION` file.
`make dist` builds the same binaries locally.

## Layout

```
main.go             argument handling, mode selection, exit codes, version
internal/input      reading certificates, CSRs and keys from PEM/DER files
internal/inspect    chain, CSR and match checks; returns findings, prints nothing
internal/report     terminal rendering and colours
internal/certtest   certificate generator shared by the tests
```

## License

[MIT](LICENSE)
