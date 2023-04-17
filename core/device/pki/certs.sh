echo "Generating ROOT certificate..."
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 10000 -nodes -out TROOT.crt -keyout TROOT.key -subj "/CN=FDO TEST ROOT/emailAddress=info@webauthn.works/O=Webauthn Works/C=NZ/L=Tauranga"


echo "Generating INTERMEDIATE certificate..."

echo "basicConstraints=CA:TRUE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out intermediate_certificate.param
openssl ecparam -in intermediate_certificate.param -genkey -noout -out intermediate_certificate.key
openssl req -new -key intermediate_certificate.key -out intermediate_certificate.csr -nodes -sha256 -subj "/CN=FDO TEST INTERMEDIATE/emailAddress=info@webauthn.works/O=Webauthn Works/C=NZ/L=Tauranga"
openssl x509 -req -days 10000 -in intermediate_certificate.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 02 -out intermediate_certificate.crt -extfile extensionsInfo.cnf


# echo "Generating BATCH certificate..."

# echo "basicConstraints=CA:FALSE
# subjectKeyIdentifier = hash" > extensionsInfo.cnf

# openssl ecparam -name prime256v1 -out batch_certificate.param
# openssl ecparam -in batch_certificate.param -genkey -noout -out batch_certificate.key
# openssl req -new -key batch_certificate.key -out batch_certificate.csr -nodes -sha256 -subj "/CN=EXAMPLE BATCH KEY/emailAddress=example@example.com/O=Example ORG/OU=Example/C=US/ST=MY/L=Wakefield"
# openssl x509 -req -days 3650 -in batch_certificate.csr -CA intermediate_certificate.crt -CAkey intermediate_certificate.key -set_serial 01 -out batch_certificate.crt -extfile extensionsInfo.cnf