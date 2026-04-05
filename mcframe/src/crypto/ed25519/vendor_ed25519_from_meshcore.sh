#!/usr/bin/env bash
set -euo pipefail

MC_DIR="${1:-}"
if [[ -z "${MC_DIR}" ]]; then
  echo "Usage: $0 /path/to/MeshCore" >&2
  exit 1
fi

if [[ -d "${MC_DIR}/lib/ed25519" ]]; then
  SRC="${MC_DIR}/lib/ed25519"
elif [[ -d "${MC_DIR}/MeshCore/lib/ed25519" ]]; then
  SRC="${MC_DIR}/MeshCore/lib/ed25519"
else
  echo "ERROR: Could not find lib/ed25519 in ${MC_DIR}" >&2
  exit 2
fi

DEST="$(cd "$(dirname "$0")" && pwd)"

# MeshCore's ed25519_derive_pub is implemented in keypair.c and depends on sha512.*
files=(
  ed_25519.h
  fixedint.h
  fe.h fe.c
  ge.h ge.c
  precomp_data.h
  key_exchange.c
  keypair.c
  sha512.h sha512.c
)

for f in "${files[@]}"; do
  if [[ ! -f "${SRC}/${f}" ]]; then
    echo "ERROR: Missing ${SRC}/${f}" >&2
    exit 3
  fi
  cp -v "${SRC}/${f}" "${DEST}/${f}"
done

echo "Vendored ed25519 sources into: ${DEST}" >&2
