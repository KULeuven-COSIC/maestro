#!/bin/bash
set -e
mkdir -p keys
cd keys
#openssl genpkey -algorithm x25519 > p1.key
#openssl genpkey -algorithm x25519 > p2.key
#openssl genpkey -algorithm x25519 > p3.key
for i in {1..3}
do
    openssl genpkey -algorithm ED25519 > p$i.key
    openssl req -new -out req.csr -key p$i.key -sha256 -nodes -extensions v3_req -reqexts SAN -config ../openssl-config.txt
    #-subj "/C=XX/O=MPC Org/OU=P1/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"
    openssl x509 -req  -days 3650 -in req.csr -signkey p$i.key -out p$i.pem -extfile ../openssl-config.txt -extensions SAN
done
rm req.csr


#openssl req -x509 -key key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/O=MPC Org/OU=P1/CN=P1"