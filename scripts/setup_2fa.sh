#!/usr/bin/env bash
# SSH Fortress — Google Authenticator (TOTP) 2FA setup
# Usage: sudo bash setup_2fa.sh [username]

set -euo pipefail

[[ "${EUID}" -ne 0 ]] && { echo "Run as root"; exit 1; }

USERNAME="${1:-$(logname 2>/dev/null || whoami)}"
USER_HOME=$(getent passwd "${USERNAME}" | cut -d: -f6)

echo "Setting up Google Authenticator 2FA for user: ${USERNAME}"

# Install libpam-google-authenticator
if command -v apt-get &>/dev/null; then
    apt-get install -y libpam-google-authenticator
elif command -v dnf &>/dev/null; then
    dnf install -y google-authenticator
fi

# Run as the target user
sudo -u "${USERNAME}" google-authenticator \
    --time-based \
    --disallow-reuse \
    --force \
    --rate-limit=3 \
    --rate-time=30 \
    --window-size=3 \
    --secret="${USER_HOME}/.google_authenticator" \
    --qr-mode=utf8

# Update PAM sshd for 2FA
SSHD_PAM=/etc/pam.d/sshd
if ! grep -q "pam_google_authenticator" "${SSHD_PAM}"; then
    # Insert after first auth line
    sed -i '1s/^/auth required pam_google_authenticator.so nullok\n/' "${SSHD_PAM}"
fi

# Enable ChallengeResponseAuthentication in sshd_config
SSHD_CONF=/etc/ssh/sshd_config
sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "${SSHD_CONF}"
grep -q "ChallengeResponseAuthentication" "${SSHD_CONF}" || \
    echo "ChallengeResponseAuthentication yes" >> "${SSHD_CONF}"

# Require both key + TOTP
grep -q "AuthenticationMethods" "${SSHD_CONF}" || \
    echo "AuthenticationMethods publickey,keyboard-interactive" >> "${SSHD_CONF}"

sshd -t && systemctl reload sshd
echo "2FA setup complete for ${USERNAME}. Test in a NEW terminal before closing this one."
