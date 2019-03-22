
create initial root CA certificate:

```bash
openssl req -x509 -new -nodes -extensions v3_ca -key ../private/dec.ca.key.pem -days 1024 -out ca-root.pem -sha512
```

You need to use the openssl.cnf provided in this repo. It has the extended key usage enabled for signing certificates.

