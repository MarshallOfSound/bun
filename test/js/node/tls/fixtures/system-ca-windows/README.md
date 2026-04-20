# system-ca-windows fixtures

Three-tier PKI used by `test-use-system-ca-windows-intermediate.test.ts`:

- `root-cert.pem` — self-signed root CA ("Bun Test System CA Root")
- `int-cert.pem` — intermediate CA signed by root ("Bun Test System CA Intermediate")
- `leaf-cert.pem` / `leaf-key.pem` — server cert for `localhost`, signed by the intermediate

Validity is 100 years so these shouldn't need rotating.

To regenerate:

```sh
openssl genrsa -out root-key.pem 2048
openssl req -x509 -new -key root-key.pem -sha256 -days 36500 -out root-cert.pem \
  -subj "/CN=Bun Test System CA Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl genrsa -out int-key.pem 2048
openssl req -new -key int-key.pem -out int.csr -subj "/CN=Bun Test System CA Intermediate"
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > int-ext.cnf
openssl x509 -req -in int.csr -CA root-cert.pem -CAkey root-key.pem -CAcreateserial \
  -out int-cert.pem -days 36500 -sha256 -extfile int-ext.cnf

openssl genrsa -out leaf-key.pem 2048
openssl req -new -key leaf-key.pem -out leaf.csr -subj "/CN=localhost"
printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n" > leaf-ext.cnf
openssl x509 -req -in leaf.csr -CA int-cert.pem -CAkey int-key.pem -CAcreateserial \
  -out leaf-cert.pem -days 36500 -sha256 -extfile leaf-ext.cnf
```

After regenerating, update the SHA-1 thumbprints in the test file:

```sh
openssl x509 -in root-cert.pem -noout -fingerprint -sha1
openssl x509 -in int-cert.pem  -noout -fingerprint -sha1
```
