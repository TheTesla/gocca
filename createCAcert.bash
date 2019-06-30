#!/bin/bash

CAKEY=/var/www/api/ca/private/dec.ca.key.pem
CACRT=/var/www/api/ca/certs/ca-root.pem
CAPUB=/var/www/html/.

openssl genrsa -out $CAKEY 4096

#openssl req -new -nodes -subj "/C=US/ST=CA/O=MyOrg/CN=mydomain.com" -key $CAKEY -sha256 -days 1024 -out ca.csr #-reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:mydomain.com,DNS:tld."))

#openssl x509 -req -in ca.csr -signkey $CAKEY -out $CACRT -extensions SAN -extfile <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:mydomain.com,DNS:tld."))

openssl req -x509 -new -nodes -subj "/C=US/ST=CA/O=MyOrg/CN=mydomain.com" -key $CAKEY -sha256 -days 1024 -out $CACRT -extensions SAN -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:mydomain.com,DNS:tld.\nkeyUsage = cRLSign, keyCertSign\nbasicConstraints = critical,CA:true\n"))

cp $CACRT $CAPUB

