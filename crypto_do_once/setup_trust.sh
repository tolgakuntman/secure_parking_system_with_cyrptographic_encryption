#!/bin/bash

# Ensure script runs from correct directory
if [ "$(basename "$PWD")" != "crypto_do_once" ]; then
    echo "Please run this script from the 'crypto_do_once' directory."
    exit 1
fi

# Stop on any error
set -e

echo "Setting up PKI infrastructure (separate CA and server keystores)..."

###########################################
# Variables
###########################################

ROOT_CA_ALIAS="root_ca"
ROOT_CA_KEYSTORE="root_ca_keystore.p12"
ROOT_CA_PASSWORD="capassword"

SERVER_ALIAS="cauth_server"
SERVER_KEYSTORE="cauth_server_keystore.p12"
SERVER_PASSWORD="serverpassword"

TRUSTSTORE_PASSWORD="trustpassword"
VALIDITY_DAYS=3650

SERVER_CN="172.20.0.10"
SERVER_ORG="Private Parking"
SERVER_COUNTRY="BE"

###########################################
# Cleanup existing files
###########################################

rm -f "$ROOT_CA_KEYSTORE" "$SERVER_KEYSTORE"
rm -f cauth_truststore.p12 sp_truststore.p12 ho_truststore.p12 co_truststore.p12 fake_cauth_truststore.p12 fake_cauth_keystore.p12
rm -f root_ca.crt server.csr server.crt fake_server.csr fake_server.crt

###########################################
# 1. Create Root CA keystore + self-signed certificate
###########################################

echo "1. Creating Root CA private key + self-signed certificate..."

keytool -genkeypair \
    -alias "$ROOT_CA_ALIAS" \
    -keyalg RSA \
    -keysize 4096 \
    -validity "$VALIDITY_DAYS" \
    -keystore "$ROOT_CA_KEYSTORE" \
    -storepass "$ROOT_CA_PASSWORD" \
    -keypass "$ROOT_CA_PASSWORD" \
    -dname "CN=Root CA, O=National Authority, C=Country Code" \
    -ext BasicConstraints:critical=ca:true \
    -ext KeyUsage:critical=keyCertSign,cRLSign

###########################################
# 2. Export Root CA certificate
###########################################

echo "2. Exporting Root CA certificate (root_ca.crt)..."

keytool -exportcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore "$ROOT_CA_KEYSTORE" \
    -storepass "$ROOT_CA_PASSWORD" \
    -file root_ca.crt \
    -rfc

###########################################
# 3. Create server private key and keystore
###########################################

echo "3. Creating server private key in its own keystore..."

keytool -genkeypair \
    -alias "$SERVER_ALIAS" \
    -keyalg RSA \
    -keysize 4096 \
    -validity "$VALIDITY_DAYS" \
    -keystore "$SERVER_KEYSTORE" \
    -storepass "$SERVER_PASSWORD" \
    -keypass "$SERVER_PASSWORD" \
    -dname "CN=$SERVER_CN, O=$SERVER_ORG, C=$SERVER_COUNTRY" \
    -ext BasicConstraints:critical=ca:true,pathlen:0 \
    -ext KeyUsage:critical=keyCertSign,cRLSign,digitalSignature,keyEncipherment \
    -ext ExtendedKeyUsage=serverAuth,clientAuth
###########################################
# 4. Generate CSR for server
###########################################

echo "4. Generating CSR for server..."

keytool -certreq \
    -alias "$SERVER_ALIAS" \
    -keystore "$SERVER_KEYSTORE" \
    -storepass "$SERVER_PASSWORD" \
    -file server.csr \
    -ext BasicConstraints:critical=ca:true,pathlen:0 \
    -ext KeyUsage:critical=keyCertSign,cRLSign,digitalSignature,keyEncipherment \
    -ext ExtendedKeyUsage=serverAuth,clientAuth

###########################################
# 5. Sign server CSR using Root CA
###########################################

echo "5. Signing server certificate with Root CA..."

keytool -gencert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore "$ROOT_CA_KEYSTORE" \
    -storepass "$ROOT_CA_PASSWORD" \
    -infile server.csr \
    -outfile server.crt \
    -validity "$VALIDITY_DAYS" \
    -ext BasicConstraints:critical=ca:true,pathlen:0 \
    -ext KeyUsage:critical=keyCertSign,cRLSign,digitalSignature,keyEncipherment \
    -ext ExtendedKeyUsage=serverAuth,clientAuth \
    -rfc

###########################################
# 6. Import Root CA certificate into server keystore
###########################################

echo "6. Importing Root CA certificate into server keystore..."

keytool -importcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore "$SERVER_KEYSTORE" \
    -storepass "$SERVER_PASSWORD" \
    -file root_ca.crt \
    -noprompt

###########################################
# 7. Import signed server certificate
###########################################

echo "7. Importing CA-signed server certificate..."

keytool -importcert \
    -alias "$SERVER_ALIAS" \
    -keystore "$SERVER_KEYSTORE" \
    -storepass "$SERVER_PASSWORD" \
    -file server.crt \
    -noprompt

###########################################
# 8. Create truststores for server + all clients
###########################################

echo "8. Creating truststores..."

keytool -importcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore cauth_truststore.p12 \
    -storepass "$TRUSTSTORE_PASSWORD" \
    -file root_ca.crt \
    -noprompt

keytool -importcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore sp_truststore.p12 \
    -storepass "$TRUSTSTORE_PASSWORD" \
    -file root_ca.crt \
    -noprompt

keytool -importcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore ho_truststore.p12 \
    -storepass "$TRUSTSTORE_PASSWORD" \
    -file root_ca.crt \
    -noprompt

keytool -importcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore co_truststore.p12 \
    -storepass "$TRUSTSTORE_PASSWORD" \
    -file root_ca.crt \
    -noprompt

# Create fake-cauth truststore (for testing scenarios)
keytool -importcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore fake_cauth_truststore.p12 \
    -storepass "$TRUSTSTORE_PASSWORD" \
    -file root_ca.crt \
    -noprompt

###########################################
# 9. Create fake-cauth keystore (for testing)
###########################################

echo "9. Creating fake-cauth keystore for testing scenarios..."

# Generate fake-cauth's own key pair
keytool -genkeypair \
    -alias "fake_cauth_server" \
    -keyalg RSA \
    -keysize 4096 \
    -validity "$VALIDITY_DAYS" \
    -keystore fake_cauth_keystore.p12 \
    -storepass "$SERVER_PASSWORD" \
    -keypass "$SERVER_PASSWORD" \
    -dname "CN=$SERVER_CN, O=Fake Authority, C=$SERVER_COUNTRY" \
    -ext BasicConstraints:critical=ca:true,pathlen:0 \
    -ext KeyUsage:critical=keyCertSign,cRLSign,digitalSignature,keyEncipherment \
    -ext ExtendedKeyUsage=serverAuth,clientAuth

# Generate CSR for fake-cauth
keytool -certreq \
    -alias "fake_cauth_server" \
    -keystore fake_cauth_keystore.p12 \
    -storepass "$SERVER_PASSWORD" \
    -file fake_server.csr \
    -ext BasicConstraints:critical=ca:true,pathlen:0 \
    -ext KeyUsage:critical=keyCertSign,cRLSign,digitalSignature,keyEncipherment \
    -ext ExtendedKeyUsage=serverAuth,clientAuth

# Sign fake-cauth's certificate with Root CA
keytool -gencert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore "$ROOT_CA_KEYSTORE" \
    -storepass "$ROOT_CA_PASSWORD" \
    -infile fake_server.csr \
    -outfile fake_server.crt \
    -validity "$VALIDITY_DAYS" \
    -ext BasicConstraints:critical=ca:true,pathlen:0 \
    -ext KeyUsage:critical=keyCertSign,cRLSign,digitalSignature,keyEncipherment \
    -ext ExtendedKeyUsage=serverAuth,clientAuth \
    -rfc

# Import Root CA certificate into fake-cauth keystore
keytool -importcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore fake_cauth_keystore.p12 \
    -storepass "$SERVER_PASSWORD" \
    -file root_ca.crt \
    -noprompt

# Import signed fake-cauth certificate
keytool -importcert \
    -alias "fake_cauth_server" \
    -keystore fake_cauth_keystore.p12 \
    -storepass "$SERVER_PASSWORD" \
    -file fake_server.crt \
    -noprompt

###########################################
# Cleanup
###########################################

echo "10. Cleaning up CSR and intermediate files..."
rm -f server.csr server.crt fake_server.csr fake_server.crt

###########################################
# Summary
###########################################

echo ""
echo "PKI Setup Complete!"
echo ""
echo "Created files:"
echo "  - $ROOT_CA_KEYSTORE (Root CA private key + Root CA certificate)"
echo "  - $SERVER_KEYSTORE (Server private key + CA-signed certificate)"
echo "  - root_ca.crt (public CA certificate)"
echo "  - cauth_truststore.p12 (server truststore)"
echo "  - sp_truststore.p12 (client truststore)"
echo "  - ho_truststore.p12 (homeowner truststore)"
echo "  - co_truststore.p12 (carowner truststore)"
echo "  - fake_cauth_keystore.p12 (fake-cauth keystore for testing)"
echo "  - fake_cauth_truststore.p12 (fake-cauth truststore for testing)"
echo ""
echo "Client keystores (SP/HO/CO) will be created during enrollment."
echo ""

echo "=== Server Keystore Contents ==="
keytool -list -keystore "$SERVER_KEYSTORE" -storepass "$SERVER_PASSWORD"

echo ""
echo "=== CA Truststore (example) ==="
keytool -list -keystore cauth_truststore.p12 -storepass "$TRUSTSTORE_PASSWORD"
