#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./gen_meshcore_keys.sh MyLabel
# Output:
#   pubkeys.txt line  (32-byte pubkey, 64 hex)
#   privkeys.txt line (64-byte expanded privkey, 128 hex)

LABEL="${1:-}"
if [[ -z "${LABEL}" ]]; then
  echo "Usage: $0 <Label>" >&2
  exit 1
fi

# Temp files
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT
PRIV_PEM="${TMPDIR}/priv.pem"
PUB_PEM="${TMPDIR}/pub.pem"

# 1) Generate Ed25519 private key (PKCS#8 PEM) and public key
openssl genpkey -algorithm ED25519 -out "${PRIV_PEM}" >/dev/null 2>&1
openssl pkey -in "${PRIV_PEM}" -pubout -out "${PUB_PEM}" >/dev/null 2>&1

# 2) Extract raw 32-byte public key (last 32 bytes of SPKI DER for Ed25519)
PUB_HEX="$(
  openssl pkey -pubin -in "${PUB_PEM}" -outform DER \
    | tail -c 32 \
    | xxd -p -c 32 \
    | tr -d '\n'
)"

# 3) Extract 32-byte seed from OpenSSL textual output (ED25519 Private-Key: priv:)
SEED_HEX="$(
  openssl pkey -in "${PRIV_PEM}" -noout -text \
    | awk '
        /priv:/{p=1; next}
        /pub:/{p=0}
        p { gsub(/[ \t:]/,""); printf "%s", $0 }
      '
)"

# Sanity check: must be 32 bytes (64 hex chars)
if [[ ${#SEED_HEX} -ne 64 ]]; then
  echo "ERROR: expected 32-byte seed (64 hex chars), got ${#SEED_HEX} hex chars" >&2
  exit 2
fi

# 4) Compute MeshCore/Android-style expanded private key:
#    expanded = clamp(SHA512(seed)[0:32]) || SHA512(seed)[32:64]
EXP_HEX="$(
  python3 - <<PY
import hashlib
seed = bytes.fromhex("${SEED_HEX}")
h = hashlib.sha512(seed).digest()
a = bytearray(h[:32])
a[0] &= 248
a[31] &= 63
a[31] |= 64
expanded = bytes(a) + h[32:]
print(expanded.hex())
PY
)"

# Sanity check: must be 64 bytes (128 hex chars)
if [[ ${#EXP_HEX} -ne 128 ]]; then
  echo "ERROR: expected 64-byte expanded key (128 hex chars), got ${#EXP_HEX} hex chars" >&2
  exit 3
fi

# Output ready-to-paste lines
echo "pubkeys.txt:"
echo "${LABEL} ${PUB_HEX}"
echo
echo "privkeys.txt (android style / expanded 64B):"
echo "${LABEL} ${EXP_HEX}"
