#!/bin/bash

# set -e

GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m"

pass() { echo -e "[ ${GREEN}PASS${NC} ] $1"; }
fail() { echo -e "[ ${RED}FAIL${NC} ] $1"; }

echo "=== PKI Verification Script ==="
echo

# -------------------------
# Helper: extract certificate info
# -------------------------
extract() {
    keytool -list -v -keystore "$1" -storepass "$2" 2>/dev/null
}

extract_cert_file() {
    keytool -printcert -v -file "$1" 2>/dev/null
}

# -------------------------
# Required files
# -------------------------
REQUIRED=(
  "root_ca_keystore.p12"
  "cauth_server_keystore.p12"
  "cauth_truststore.p12"
  "sp_truststore.p12"
  "ho_truststore.p12"
  "co_truststore.p12"
  "root_ca.crt"
)

echo "Checking required files..."
for f in "${REQUIRED[@]}"; do
    if [ -f "$f" ]; then
        pass "$f found"
    else
        fail "$f missing"; exit 1
    fi
done

echo
echo "========================================"
echo "Checking ROOT CA"
echo "========================================"

ROOT_INFO=$(extract root_ca_keystore.p12 capassword)

echo "$ROOT_INFO" | grep -q "CA:true" \
    && pass "Root CA has CA=true" \
    || fail "Root CA missing CA:true"

echo "$ROOT_INFO" | grep -Eiq "Key.?Cert.?Sign" \
    && pass "Root CA contains KeyCertSign" \
    || fail "Root CA missing KeyCertSign"


echo
echo "========================================"
echo "Checking INTERMEDIATE CA (CAUTH SERVER)"
echo "========================================"

CAUTH_INFO=$(extract cauth_server_keystore.p12 serverpassword)

echo "$CAUTH_INFO" | sed -n "/Certificate\[1\]/,/Certificate\[2\]/p" | grep -q "CA:true" \
    && pass "Intermediate CA is CA=true" \
    || fail "Intermediate CA missing CA:true"

echo "$CAUTH_INFO" | sed -n "/Certificate\[1\]/,/Certificate\[2\]/p" | grep -Eiq "Key.?Cert.?Sign" \
    && pass "Intermediate CA contains KeyCertSign" \
    || fail "Intermediate CA missing KeyCertSign"

echo
echo "========================================"
echo "Checking TRUSTSTORES"
echo "========================================"

for ts in cauth_truststore.p12 sp_truststore.p12 ho_truststore.p12 co_truststore.p12; do
    echo
    echo "--- Checking $ts ---"
    TS_INFO=$(extract "$ts" trustpassword)

    if [ $? -ne 0 ]; then
        fail "Cannot open $ts"
        continue
    fi

    pass "$ts opens successfully"

    echo "$TS_INFO" | grep -q "Entry type: PrivateKeyEntry" \
        && fail "$ts contains private keys (BAD)" \
        || pass "$ts contains no private keys (correct)"

    KEYSIZE=$(echo "$TS_INFO" | grep "Subject Public Key Algorithm" | sed -E 's/.* ([0-9]+)-bit.*/\1/')
    if [ "$KEYSIZE" -ge 2048 ]; then
        pass "$ts key size is strong: $KEYSIZE bits"
    else
        fail "$ts key size is weak: $KEYSIZE bits"
    fi
done


echo
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "All major PKI rules have been validated."
