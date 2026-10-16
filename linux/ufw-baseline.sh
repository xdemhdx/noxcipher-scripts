#!/usr/bin/env bash
# ufw-baseline.sh - default-deny host firewall with SSH kept open
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Installs ufw if missing, sets default deny inbound / allow outbound, allows
# SSH on the port sshd actually uses (optionally only from one CIDR), opens any
# extra ports, turns logging on and enables the firewall. Safe to re-run.
#
# Usage:
#   ufw-baseline.sh [--allow 443,514/udp,8000:8080/tcp] [--ssh-from 10.0.0.0/8] [--dry-run]
#   Ports without a protocol are opened for both TCP and UDP.

set -euo pipefail

VERSION="1.0.3"
ALLOW=""; SSH_FROM=""; DRY_RUN=0

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'; else G=""; Y=""; R=""; D=""; N=""; fi
info() { printf '%s[info]%s %s\n' "$D" "$N" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --allow) ALLOW="${2:-}"; shift 2 ;;
    --ssh-from) SSH_FROM="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: ufw-baseline.sh [--allow 443,514/udp] [--ssh-from CIDR] [--dry-run]"; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."

run() { if [ "$DRY_RUN" = 1 ]; then info "would run: $*" >&2; else "$@"; fi; }

if ! command -v ufw >/dev/null; then
  if command -v apt-get >/dev/null; then run apt-get install -y ufw >/dev/null; [ "$DRY_RUN" = 1 ] || ok "installed ufw"
  else die "ufw not installed and apt isn't available. Install ufw (or use firewalld) first."; fi
fi

# Find the real SSH port(s)
ssh_ports=$( { sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null || true; } | awk '$1=="port"{print $2}' | sort -u | tr '\n' ' ' || true)
[ -n "$ssh_ports" ] || ssh_ports="22"
info "SSH port(s): $ssh_ports"

if [ -n "$SSH_FROM" ] && ! [[ "$SSH_FROM" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
  die "--ssh-from must be an IPv4 address or CIDR"
fi
if [ -n "$SSH_FROM" ] && [ -n "${SSH_CLIENT:-}" ]; then
  me=${SSH_CLIENT%% *}
  warn "You're connected from $me. Make sure it's inside $SSH_FROM or you'll lose access."
fi

run ufw default deny incoming >/dev/null
run ufw default allow outgoing >/dev/null
ok "defaults: deny incoming, allow outgoing"

for p in $ssh_ports; do
  if [ -n "$SSH_FROM" ]; then run ufw allow proto tcp from "$SSH_FROM" to any port "$p" comment 'ssh (ufw-baseline)' >/dev/null; ok "ssh $p/tcp from $SSH_FROM"
  else run ufw allow "$p"/tcp comment 'ssh (ufw-baseline)' >/dev/null; ok "ssh $p/tcp from anywhere"; fi
done

IFS=',' read -r -a extras <<<"$ALLOW"
for e in "${extras[@]}"; do
  e="${e// /}"; [ -n "$e" ] || continue
  if [[ "$e" =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]]; then
    if [[ "$e" == *:* && "$e" != */* ]]; then
      run ufw allow "$e"/tcp comment 'ufw-baseline' >/dev/null; run ufw allow "$e"/udp comment 'ufw-baseline' >/dev/null
    else
      run ufw allow "$e" comment 'ufw-baseline' >/dev/null
    fi
    ok "allowed $e"
  else
    warn "skipped '$e' (use 443, 514/udp or 8000:8080/tcp)"
  fi
done

run ufw logging on >/dev/null
run ufw --force enable >/dev/null
echo
[ "$DRY_RUN" = 1 ] && { ok "Dry run complete."; exit 0; }
ufw status verbose | sed 's/^/  /'
ok "Firewall enabled. Test a new SSH session before closing this one."
