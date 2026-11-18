#!/bin/sh
# Throwaway CA, intermediate, server certificate, key and CSR for the demo
# recording, written to the current directory. Nothing here is committed.
set -e
q() { "$@" >/dev/null 2>&1; }
ec="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
printf 'basicConstraints=critical,CA:TRUE\n' > ca.ext
printf 'subjectAltName=DNS:shop.example.com,DNS:www.shop.example.com\n' > leaf.ext

q openssl req -x509 $ec -keyout root.key -out root.crt -days 3650 \
  -subj "/O=Example/CN=Example Root CA" -addext basicConstraints=critical,CA:TRUE
q openssl req $ec -keyout int.key -out int.csr -subj "/O=Example/CN=Example Issuing CA"
q openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out int.crt -days 1825 -extfile ca.ext
q openssl req -newkey rsa:2048 -nodes -keyout shop.key -out shop.csr \
  -subj "/O=Example/CN=shop.example.com" \
  -addext "subjectAltName=DNS:shop.example.com,DNS:www.shop.example.com"
q openssl x509 -req -in shop.csr -CA int.crt -CAkey int.key -CAcreateserial \
  -out shop.crt -days 397 -extfile leaf.ext
cat shop.crt int.crt root.crt > fullchain.pem
rm -f ca.ext leaf.ext int.csr int.key root.key ./*.srl
