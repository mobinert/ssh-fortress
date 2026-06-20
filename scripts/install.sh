#!/usr/bin/env bash
# SSH Fortress — Installation script
# Usage: sudo bash install.sh [--prefix /opt/ssh-fortress] [--config /etc/ssh-fortress]
# Tested on: Ubuntu 22.04+, Debian 12+, RHEL 8/9, Rocky Linux 8/9, AlmaLinux 8/9

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/ssh-fortress}"
CONFIG_DIR="${CONFIG_DIR:-/etc/ssh-fortress}"
LOG_DIR="/var/log/ssh-fortress"
LIB_DIR="/var/lib/ssh-fortress"
RUN_DIR="/var/run"
VENV_DIR="${INSTALL_DIR}/venv"
SERVICE_USER="root"
PYTHON="${PYTHON:-python3}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ "${EUID}" -ne 0 ]] && error "Run as root: sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         SSH Fortress Installer           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID:-0}"
    else
        error "Cannot detect OS. /etc/os-release not found."
    fi
}
detect_os
info "Detected OS: ${OS_ID} ${OS_VERSION}"

# ── Install system dependencies ───────────────────────────────────────────────
install_deps() {
    info "Installing system dependencies..."
    case "${OS_ID}" in
        ubuntu|debian|linuxmint)
            apt-get update -qq
            apt-get install -y --no-install-recommends \
                python3 python3-pip python3-venv python3-dev \
                nftables iptables fail2ban rsyslog \
                libgeoip-dev git curl jq
            ;;
        rhel|centos|rocky|almalinux|fedora)
            dnf install -y \
                python3 python3-pip python3-devel \
                nftables iptables fail2ban rsyslog \
                GeoIP-devel git curl jq
            ;;
        *)
            warn "Unknown OS '${OS_ID}'. Skipping dependency install — install manually."
            ;;
    esac
}
install_deps

# ── Create directories ────────────────────────────────────────────────────────
info "Creating directories..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}" "${LIB_DIR}"
chmod 750 "${LOG_DIR}" "${LIB_DIR}"

# ── Copy project files ────────────────────────────────────────────────────────
info "Copying files to ${INSTALL_DIR}..."
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    "${PROJECT_DIR}/" "${INSTALL_DIR}/"

# ── Python virtualenv ──────────────────────────────────────────────────────────
info "Creating Python virtual environment..."
"${PYTHON}" -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip wheel
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"

# ── Config ────────────────────────────────────────────────────────────────────
if [[ ! -f "${CONFIG_DIR}/settings.yaml" ]]; then
    info "Installing default config to ${CONFIG_DIR}/settings.yaml"
    cp "${INSTALL_DIR}/config/settings.yaml" "${CONFIG_DIR}/settings.yaml"
    chmod 640 "${CONFIG_DIR}/settings.yaml"
fi

# ── fail2ban integration ──────────────────────────────────────────────────────
info "Installing fail2ban rules..."
cp "${INSTALL_DIR}/config/fail2ban/jail.local" /etc/fail2ban/jail.d/ssh-fortress.local
cp "${INSTALL_DIR}/config/fail2ban/sshd-fortress.conf" /etc/fail2ban/filter.d/sshd-fortress.conf
systemctl enable --now fail2ban 2>/dev/null || true
systemctl reload fail2ban 2>/dev/null || true

# ── rsyslog integration ────────────────────────────────────────────────────────
info "Installing rsyslog config..."
cp "${INSTALL_DIR}/config/siem/rsyslog-siem.conf" /etc/rsyslog.d/10-ssh-fortress.conf
systemctl restart rsyslog 2>/dev/null || true

# ── nftables baseline ──────────────────────────────────────────────────────────
info "Applying initial nftables rules..."
"${VENV_DIR}/bin/python" "${INSTALL_DIR}/main.py" harden --config "${CONFIG_DIR}/settings.yaml" || \
    warn "Hardening failed — check errors above and run manually after configuring settings.yaml"

# ── Systemd service ────────────────────────────────────────────────────────────
info "Installing systemd service..."
cp "${INSTALL_DIR}/systemd/ssh-fortress.service" /etc/systemd/system/
cp "${INSTALL_DIR}/systemd/ssh-fortress-monitor.timer" /etc/systemd/system/

cat > /etc/systemd/system/ssh-fortress-monitor.service << EOF
[Unit]
Description=SSH Fortress — daily key audit
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/main.py keys audit --config ${CONFIG_DIR}/settings.yaml
EOF

# Patch the service with our paths
sed -i "s|/opt/ssh-fortress|${INSTALL_DIR}|g" /etc/systemd/system/ssh-fortress.service
sed -i "s|/etc/ssh-fortress/settings.yaml|${CONFIG_DIR}/settings.yaml|g" \
    /etc/systemd/system/ssh-fortress.service

systemctl daemon-reload
systemctl enable ssh-fortress
systemctl enable ssh-fortress-monitor.timer
systemctl start ssh-fortress

# ── Final status ──────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            SSH Fortress installed successfully!           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Config  : ${CONFIG_DIR}/settings.yaml"
echo "  Logs    : ${LOG_DIR}/"
echo "  Service : systemctl status ssh-fortress"
echo "  CLI     : ${VENV_DIR}/bin/python ${INSTALL_DIR}/main.py --help"
echo ""
echo "  IMPORTANT: Edit ${CONFIG_DIR}/settings.yaml to configure:"
echo "    • SIEM backends (Elasticsearch, Splunk, Syslog...)"
echo "    • Alert channels (Email, Slack, PagerDuty...)"
echo "    • Geo-blocking country list"
echo "    • Whitelist IPs"
echo ""
echo "  Then restart: systemctl restart ssh-fortress"
echo ""
