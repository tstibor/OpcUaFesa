# 1. Create the target directory
mkdir -p certs && cd certs

# 2. Generate Server Private Key (PEM) and Certificate (PEM -> DER)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server_key.pem \
  -out server_cert.pem \
  -days 365 \
  -subj "/CN=MockServer/O=FESA" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,URI:urn:fesa:mockserver"

openssl x509 -outform der -in server_cert.pem -out server_cert.der

# 3. Generate Client Private Key (PEM) and Certificate (PEM -> DER)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout client_key.pem \
  -out client_cert.pem \
  -days 365 \
  -subj "/CN=OpcUaClient/O=FESA" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,URI:urn:fesa:client"

openssl x509 -outform der -in client_cert.pem -out client_cert.der

# 4. Remove intermediate PEM certificate files
rm server_cert.pem client_cert.pem
