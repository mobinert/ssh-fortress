#!/usr/bin/env bash
# SSH Fortress — SSH key rotation helper
# Generates a new Ed25519 key, installs to server, and retires the old one.
# Usage: bash rotate_keys.sh <user@host> [--key-comment "email"]

set -euo pipefail

TARGET="${1:-}"
COMMENT="${2:-rotated-$(date +%Y%m%d)}"
KEY_DIR="${HOME}/.ssh"
NEW_KEY="${KEY_DIR}/id_ed25519_$(date +%Y%m%d_%H%M%S)"

[[ -z "${TARGET}" ]] && { echo "Usage: $0 <user@host> [key-comment]"; exit 1; }

echo "Generating new Ed25519 key: ${NEW_KEY}"
ssh-keygen -t ed25519 -f "${NEW_KEY}" -C "${COMMENT}" -N ""
chmod 600 "${NEW_KEY}" "${NEW_KEY}.pub"

echo "Copying public key to ${TARGET}..."
ssh-copy-id -i "${NEW_KEY}.pub" "${TARGET}"

echo "Testing new key..."
ssh -i "${NEW_KEY}" -o "PasswordAuthentication=no" "${TARGET}" "echo 'Key rotation test: OK'"

echo ""
echo "New key installed and tested: ${NEW_KEY}"
echo "Old keys can be removed from ~/.ssh/authorized_keys on the server once verified."
echo ""
echo "To use the new key by default, add to ~/.ssh/config:"
echo "  Host ${TARGET%%@*}"
echo "      IdentityFile ${NEW_KEY}"
echo "      IdentitiesOnly yes"
