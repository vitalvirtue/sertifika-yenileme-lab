#!/bin/sh
# Pebble'ın ACME API'sinin dinleyeceği TLS sertifikası için küçük bir yönetim CA'sı üretir.
set -e
mkdir -p ca && cd ca
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mgmt-ca.key -out mgmt-ca.crt -days 30 \
  -subj "/CN=Lab Yonetim CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout pebble.key -out pebble.csr -subj "/CN=127.0.0.1"
printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" > ext.cnf
openssl x509 -req -in pebble.csr -CA mgmt-ca.crt -CAkey mgmt-ca.key -CAcreateserial -out pebble.crt -days 30 -extfile ext.cnf
echo "ca/ hazır"
