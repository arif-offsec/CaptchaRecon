#!/usr/bin/env bash
# CaptchaRecon — Uninstaller

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
fail() { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

[[ $EUID -ne 0 ]] && fail "Run as root: sudo bash uninstall.sh"

echo ""
echo -e "${BOLD}${RED}Uninstalling CaptchaRecon...${RESET}"
echo ""

pip3 uninstall captcharecon -y --quiet 2>/dev/null && ok "Python package removed" || true
rm -rf  /opt/captcharecon   && ok "Install directory removed" || true
rm -f   /usr/local/bin/captcharecon && ok "CLI symlink removed" || true
rm -f   /usr/local/share/man/man1/captcharecon.1.gz && ok "Man page removed" || true
mandb -q 2>/dev/null || true

echo ""
read -rp "Remove config at /etc/captcharecon? [y/N]: " ans
[[ "${ans,,}" == "y" ]] && rm -rf /etc/captcharecon && ok "Config removed"

echo ""
echo -e "${BOLD}${GREEN}CaptchaRecon uninstalled.${RESET}"
echo ""
