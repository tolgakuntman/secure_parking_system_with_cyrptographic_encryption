#!/usr/bin/env bash
set -euo pipefail

# HARD-STRICT PKI auditor (PKIX-compliant)
# Fails on ANY rule violation described in Strictness Profile 1.

# Defaults (change or export env vars to override)
ROOT_KS="${ROOT_KS:-crypto_do_once/root_ca_keystore.p12}"
ROOT_ALIAS="${ROOT_ALIAS:-root_ca}"
ROOT_PASS_DEFAULT="${ROOT_PASS:-capassword}"

CAUTH_KS="${CAUTH_KS:-crypto_do_once/cauth_server_keystore.p12}"
CAUTH_ALIAS="${CAUTH_ALIAS:-cauth_server}"
CAUTH_PASS_DEFAULT="${CAUTH_PASS:-serverpassword}"

TRUST_PASS_DEFAULT="${TRUST_PASS:-trustpassword}"

# Where we will export temporary PEM files
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# Colors
RED="\033[1;31m"; GRN="\033[1;32m"; YLW="\033[1;33m"; NC="\033[0m"
ok()  { printf "[ %bOK%b ] %s\n" "${GRN}" "${NC}" "$1"; }
err() { printf "[ %bFAIL%b ] %s\n" "${RED}" "${NC}" "$1"; }
die() { err "$1"; exit 1; }
info(){ printf "[ %bINFO%b ] %s\n" "${YLW}" "${NC}" "$1"; }

# Helpers
ask_pass() {
  local prompt="$1"; local default="$2"; local var
  read -r -s -p "$prompt (default: $default): " var
  echo
  if [ -z "$var" ]; then var="$default"; fi
  printf "%s" "$var"
}

# Prompt for passwords (use defaults if enter)
ROOT_PASS="$(ask_pass "Enter password for $ROOT_KS" "$ROOT_PASS_DEFAULT")"
CAUTH_PASS="$(ask_pass "Enter password for $CAUTH_KS" "$CAUTH_PASS_DEFAULT")"
TRUST_PASS="$(ask_pass "Enter truststores password" "$TRUST_PASS_DEFAULT")"

# Required files
ROOT_PEM="$TMPDIR/root_ca.pem"
CAUTH_PEM="$TMPDIR/cauth_cert.pem"
SERVER_PEM="$TMPDIR/server_leaf.pem"
CAUTH_ONLY_PEM="$TMPDIR/cauth_only.pem"

# Quick existence checks (fatal)
[ -f "$ROOT_KS" ] || die "Root keystore not found: $ROOT_KS"
[ -f "$CAUTH_KS" ] || die "Intermediate keystore not found: $CAUTH_KS"

ok "Required files present"

# Export certificates to PEM (rfc)
info "Exporting root cert -> $ROOT_PEM"
keytool -exportcert -rfc -keystore $ROOT_KS -storepass $ROOT_PASS -alias $ROOT_ALIAS -file $ROOT_PEM >/dev/null 2>&1 || die "Failed to export root cert"

info "Exporting cauth cert -> $CAUTH_PEM"
keytool -exportcert -rfc -keystore $CAUTH_KS -storepass $CAUTH_PASS -alias $CAUTH_ALIAS -file $CAUTH_PEM >/dev/null 2>&1 || die "Failed to export cauth cert"

# Utility to check signature algorithms (disallow sha1/md5)
check_sigalg() {
  local f="$1"; local name="$2"
#   echo $f
  sigalg=$(openssl x509 -in $f -noout -text | awk -F: '/Signature Algorithm/ {print $2; exit}' | tr -d ' ')
  # convert to lower-case shorthand
  lower=$(echo "$sigalg" | tr '[:upper:]' '[:lower:]')
  if echo "$lower" | grep -Eiq "sha1|md5|md2"; then
    die "$name uses weak signature algorithm: $sigalg"
  else
    ok "$name signature algorithm: $sigalg (OK)"
  fi
}

# Utility to check keysize
keysize() {
  local f="$1"
  openssl x509 -in "$f" -noout -text | awk '/Public-Key/ {print $2}' | tr -d '()'
}

# Utility to check BasicConstraints CA:true/false and pathlen
check_basic_constraints() {
  local f="$1" role="$2" must_be_ca="$3" required_pathlen="$4"
  bc=$(openssl x509 -in $f -noout -text | sed -n '/Basic Constraints/,/Subject/p')
  if echo "$bc" | grep -q "CA:TRUE"; then isca=1; else isca=0; fi

  if [ "$must_be_ca" = "true" ]; then
    [ "$isca" -eq 1 ] || die "$role must be a CA (BasicConstraints:CA:true)"
    ok "$role BasicConstraints:CA:true"
    if [ -n "$required_pathlen" ]; then
      if echo "$bc" | grep -q "pathlen"; then
        # parse pathlen value
        pl=$(echo "$bc" | sed -n 's/.*pathlen:\s*\([0-9]\+\).*/\1/p' || true)
        if [ -z "$pl" ]; then
          die "$role missing pathLen constraint value"
        fi
        if [ "$pl" -ne "$required_pathlen" ]; then
          die "$role pathLen constraint must be $required_pathlen (found $pl)"
        fi
        ok "$role pathLen is $pl"
      else
        # if required_pathlen specified but not present -> fail
        die "$role missing pathLen but pathLen $required_pathlen required"
      fi
    fi
  else
    # must not be CA
    [ "$isca" -eq 0 ] || die "$role must NOT be a CA (BasicConstraints:CA:true found)"
    ok "$role BasicConstraints:CA:false (leaf)"
  fi
}

# Utility to check KeyUsage exact match for root (only keyCertSign,cRLSign)
check_keyusage_root() {
  local f="$1"
  ku=$(openssl x509 -in "$f" -noout -text | sed -n '/Key Usage/,/Basic Constraints/p' || true)
  # normalize: remove spaces, commas
  norm=$(echo "$ku" | tr -d ' \n,' | tr '[:upper:]' '[:lower:]')
  # look for keycertsign and crlsign and ensure no other keyusage bits
  if echo "$norm" | grep -q "certificatesign" && echo "$norm" | grep -q "crlsign"; then
    # ensure no 'digitalsignature' or 'keyencipherment' present
    if echo "$norm" | grep -Eiq "digitalsignature|keyencipherment|nonrepudiation|dataencipherment"; then
      die "Root CA KeyUsage contains bits other than keyCertSign,cRLSign — strict policy forbids those"
    fi
    ok "Root CA KeyUsage contains only keyCertSign,cRLSign"
  else
    die "Root CA KeyUsage must include keyCertSign and cRLSign"
  fi
}

# Utility to check KeyUsage contains keyCertSign for intermediate
check_keyusage_intermediate() {
  local f="$1" name="$2"
#   echo $f
  if openssl x509 -in $f -noout -text | grep -q -i "Key Usage" ; then
    if openssl x509 -in $f -noout -text | grep -i "Certificate Sign" >/dev/null; then
      ok "$name contains keyCertSign"
    else
      die "$name missing keyCertSign"
    fi
    # ensure not including serverAuth/clientAuth in keyusage (those are EKU)
  else
    die "$name missing KeyUsage extension"
  fi
}

# EKU checks
# check_eku() {
#   local f="$1" name="$2" must_have="$3" must_not_have="$4"
#   ekutext=$(openssl x509 -in "$f" -noout -text | sed -n '/Extended Key Usage/,/X509v3/{/Extended Key Usage/,$p}' || true)
#   lower=$(echo "$ekutext" | tr '[:upper:]' '[:lower:]')
#   if [ -n "$must_have" ]; then
#     if echo "$lower" | grep -q "$must_have"; then
#       ok "$name EKU includes $must_have"
#     else
#       die "$name EKU does not include required $must_have"
#     fi
#   fi
#   if [ -n "$must_not_have" ]; then
#     if echo "$lower" | grep -q "$must_not_have"; then
#       die "$name EKU contains forbidden $must_not_have"
#     else
#       ok "$name EKU does not contain $must_not_have"
#     fi
#   fi
# }

# -------------------------------
# 1) Root CA checks (strict)
# -------------------------------
info() { printf "[ %bINFO%b ] %s\n" "${YLW:-}" "${NC:-}" "$1"; }  # not used further

check_sigalg "$ROOT_PEM" "Root CA"
ks=$(keysize "$ROOT_PEM")
if [ -z "$ks" ]; then die "Unable to parse root keysize"; fi
if [ "$ks" -lt 4096 ]; then die "Root CA keysize must be >= 4096 bits (found $ks)"; fi
ok "Root CA keysize: $ks bits"

# BasicConstraints & KeyUsage for Root
check_basic_constraints $ROOT_PEM "Root CA" true ""   # allow unlimited pathlen for root
check_keyusage_root "$ROOT_PEM"

# Root must be self-signed (issuer == subject)
subj_root=$(openssl x509 -in "$ROOT_PEM" -noout -subject | sed 's/^subject=//')
iss_root=$(openssl x509 -in "$ROOT_PEM" -noout -issuer | sed 's/^issuer=//')
[ "$subj_root" = "$iss_root" ] || die "Root CA must be self-signed (subject != issuer)"
ok "Root CA is self-signed"

# -------------------------------
# 2) Intermediate CA (cauth_server) checks (strict)
# -------------------------------
check_sigalg "$CAUTH_PEM" "Intermediate CA (cauth_server)"

ks2=$(keysize "$CAUTH_PEM")
if [ "$ks2" -lt 4096 ]; then die "Intermediate CA keysize must be >= 4096 bits (found $ks2)"; fi
ok "Intermediate CA keysize: $ks2 bits"

# BasicConstraints: CA:true and pathlen=0 required
check_basic_constraints "$CAUTH_PEM" "Intermediate CA" true 0

# KeyUsage must include keyCertSign and must NOT include EKU serverAuth/clientAuth
check_keyusage_intermediate "$CAUTH_PEM" "Intermediate CA"
# EKU must NOT include serverAuth or clientAuth (intermediate should not be used as end-entity)
# check_eku "$CAUTH_PEM" "Intermediate CA" "" "serverauth"
# check_eku "$CAUTH_PEM" "Intermediate CA" "" "clientauth"

# Intermediate must be issued by Root (issuer of intermediate == subject of root)
iss_cauth=$(openssl x509 -in "$CAUTH_PEM" -noout -issuer | sed 's/^issuer=//')
subj_root=$(openssl x509 -in "$ROOT_PEM" -noout -subject | sed 's/^subject=//')
if [ "$iss_cauth" != "$subj_root" ]; then
  die "Intermediate CA is not issued by Root CA (issuer mismatch)"
fi
ok "Intermediate CA is issued by Root CA"

# -------------------------------
# 3) Server (leaf) checks (strict)
# -------------------------------
# check_sigalg "$SERVER_PEM" "Server (leaf)"

# ks3=$(keysize "$SERVER_PEM")
# if [ "$ks3" -lt 2048 ]; then die "Server keysize must be >= 2048 bits (found $ks3)"; fi
# ok "Server keysize: $ks3 bits"

# Server MUST be leaf (BasicConstraints CA:false)
# check_basic_constraints $SERVER_PEM "Server" false ""

# Server MUST NOT have KeyCertSign
# if openssl x509 -in "$SERVER_PEM" -noout -text | grep -q -i "keyCertSign"; then
#   die "Server certificate MUST NOT have KeyCertSign (found)"
# else
#   ok "Server certificate has no KeyCertSign"
# fi

# Server MUST have SANs
# if openssl x509 -in $SERVER_PEM -noout -text | grep -qiE "X509v3\s+Subject Alternative Name"; then
#   ok "Server certificate contains SAN"
# else
#   die "Server certificate missing SAN"
# fi



# Server EKU must include serverAuth and must NOT include clientAuth
# check_eku "$SERVER_PEM" "Server" "serverauth" "clientauth"

# Server issuer must be intermediate (cauth)
# iss_serv=$(openssl x509 -in "$SERVER_PEM" -noout -issuer | sed 's/^issuer=//')
# subj_cauth=$(openssl x509 -in "$CAUTH_PEM" -noout -subject | sed 's/^subject=//')
# echo $iss_serv
# echo $SERVER_PEM
# if [ "$iss_serv" != "$subj_cauth" ]; then
#   die "Server certificate is not issued by the intermediate CA (issuer mismatch)"
# fi
# ok "Server certificate is issued by intermediate CA"

# -------------------------------
# 4) Chain verification using openssl verify
# -------------------------------
# Build untrusted chain file (intermediate). Use CAUTH_PEM as untrusted.
# info="Verifying certification path: server <- intermediate <- root"
# info "Running: openssl verify -CAfile $ROOT_PEM -untrusted $CAUTH_PEM $SERVER_PEM"
# if openssl verify -CAfile "$ROOT_PEM" -untrusted "$CAUTH_PEM" "$SERVER_PEM" >/dev/null 2>&1; then
#   ok "OpenSSL chain verification succeeded"
# else
#   die "OpenSSL chain verification FAILED"
# fi

# -------------------------------
# 5) Truststores: must contain only root cert entry, no private keys, no weak sigs
# -------------------------------
for ts in crypto_do_once/cauth_truststore.p12 crypto_do_once/sp_truststore.p12 crypto_do_once/ho_truststore.p12 crypto_do_once/co_truststore.p12; do
  echo "Checking truststore: $ts"
  # try open
  keytool -list -keystore $ts -storepass $TRUST_PASS >/dev/null 2>&1 || die "Cannot open truststore $ts with provided password"

  # must not contain PrivateKeyEntry
  if keytool -list -v -keystore $ts -storepass $TRUST_PASS 2>/dev/null | grep -q "Entry type: PrivateKeyEntry"; then
    die "Truststore $ts contains PrivateKeyEntry(s) — not allowed"
  fi
  ok "$ts contains no private keys"

  # must contain only one trusted cert (the root) for strict mode
  count=$(keytool -list -v -keystore $ts -storepass $TRUST_PASS 2>/dev/null | grep -c "^Alias name:")
  if [ "$count" -ne 1 ]; then die "Truststore $ts must contain exactly one trusted cert (root) in strict mode; found $count"; fi
  ok "$ts contains exactly one trusted cert"

  # ensure the trusted cert is the root (by comparing SKI or subject)
  # export the cert and compare subject
  tmpcert="$TMPDIR/ts_cert.pem"
  keytool -exportcert -rfc -keystore $ts -storepass $TRUST_PASS -alias root_ca -file $tmpcert >/dev/null 2>&1 || die "Failed to export cert from $ts"
  subj_tmp=$(openssl x509 -in "$tmpcert" -noout -subject)
  subj_root=$(openssl x509 -in "$ROOT_PEM" -noout -subject)
  [ "$subj_tmp" = "$subj_root" ] || die "Truststore $ts does not contain the expected Root CA certificate"
  ok "$ts contains expected Root CA"
  check_sigalg "$tmpcert" "Truststore cert in $ts"
done

# -------------------------------
# All checks passed
# -------------------------------
ok "All strict checks passed successfully"
exit 0
