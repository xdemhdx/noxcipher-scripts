#!/usr/bin/env bash
# ssh-harden.sh - apply a hardened sshd configuration, with automatic rollback
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Writes a drop-in (/etc/ssh/sshd_config.d/99-noxcipher-hardening.conf):
# no root login, key-only auth, modern ciphers/MACs/KEX (filtered to what your
# OpenSSH supports), shorter login grace. Backs up sshd_config first, validates
# with `sshd -t`, and rolls back automatically if validation fails.
#
# Refuses to disable password auth unless the invoking user has an
# authorized_keys file, so you don't lock yourself out. Keep your current
# session open and test a NEW login before closing it.
#
# Usage:
#   ssh-harden.sh [--port 2222] [--allow-users alice,bob] [--force] [--dry-run]
#   ssh-harden.sh --rollback

set -euo pipefail

VERSION="2.0.1"
PORT=""; ALLOW_USERS=""; ROLLBACK=0; FORCE=0; DRY_RUN=0
CONF=/etc/ssh/sshd_config
DROPIN_DIR=/etc/ssh/sshd_config.d
DROPIN="$DROPIN_DIR/99-noxcipher-hardening.conf"
BACKUP_DIR=/etc/ssh/noxcipher-backups

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'; else G=""; Y=""; R=""; D=""; N=""; fi
info() { printf '%s[info]%s %s\n' "$D" "$N" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:-}"; shift 2 ;;
    --allow-users) ALLOW_USERS="${2:-}"; shift 2 ;;
    --rollback) ROLLBACK=1; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: ssh-harden.sh [--port N] [--allow-users a,b] [--force] [--dry-run] | --rollback"; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."
command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || die "sshd not found. Is openssh-server installed?"
SSHD=$(command -v sshd || echo /usr/sbin/sshd)

restart_ssh() {
  systemctl daemon-reload 2>/dev/null || true
  # Ubuntu 22.10+ uses socket activation: the listening port comes from ssh.socket,
  # which a generator rebuilds from sshd_config on daemon-reload.
  if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    systemctl restart ssh.socket && ok "restarted ssh.socket"
  fi
  if systemctl list-unit-files ssh.service >/dev/null 2>&1 && systemctl cat ssh.service >/dev/null 2>&1; then
    systemctl restart ssh.service && ok "restarted ssh.service"
  elif systemctl cat sshd.service >/dev/null 2>&1; then
    systemctl restart sshd.service && ok "restarted sshd.service"
  else
    service ssh restart 2>/dev/null || service sshd restart
  fi
}

latest_backup() { find "$BACKUP_DIR" -maxdepth 1 -name 'sshd_config.*' ! -name '*.dropin' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true; }

if [ "$ROLLBACK" = 1 ]; then
  b=$(latest_backup)
  [ -n "$b" ] || [ -f "$DROPIN" ] || die "Nothing to roll back: no backup and no drop-in found."
  rm -f "$DROPIN" && info "removed $DROPIN"
  if [ -n "$b" ]; then cp -p "$b" "$CONF" && ok "restored $CONF from $b"; fi
  "$SSHD" -t || die "Restored config doesn't validate. Check $CONF manually."
  restart_ssh
  ok "Rollback complete."
  exit 0
fi

# --- safety: don't lock the operator out ---
op_user="${SUDO_USER:-root}"
op_home=$(getent passwd "$op_user" | cut -d: -f6)
if [ "$op_user" = root ] && [ "$FORCE" != 1 ]; then
  die "You're running as root directly. This sets PermitRootLogin no, so log in as a sudo user and run it with sudo (or use --force)."
fi
if [ ! -s "$op_home/.ssh/authorized_keys" ] && [ "$FORCE" != 1 ]; then
  die "No $op_home/.ssh/authorized_keys for $op_user. Add your public key first (ssh-copy-id), or re-run with --force."
fi
if [ -n "$PORT" ]; then
  [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port must be 1-65535"
fi
if [ -n "$ALLOW_USERS" ] && [ "$op_user" != root ] && ! tr ',' '\n' <<<"$ALLOW_USERS" | grep -qx "$op_user"; then
  [ "$FORCE" = 1 ] || die "--allow-users doesn't include you ($op_user). Add yourself or use --force."
fi

# --- build algorithm lists from what this OpenSSH supports ---
pick() { # pick <ssh -Q type> <preferred...>
  local type=$1; shift; local have out=()
  have=$(ssh -Q "$type" 2>/dev/null || true)
  for a in "$@"; do grep -qx "$a" <<<"$have" && out+=("$a"); done
  (IFS=,; echo "${out[*]}")
}
KEX=$(pick kex sntrup761x25519-sha512@openssh.com mlkem768x25519-sha256 curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group16-sha512 diffie-hellman-group18-sha512)
CIPHERS=$(pick cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)
MACS=$(pick mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com)

content="# Managed by ssh-harden.sh $VERSION ($(date -Is)). Remove this file or run --rollback to undo.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2"
[ -n "$KEX" ] && content+=$'\n'"KexAlgorithms $KEX"
[ -n "$CIPHERS" ] && content+=$'\n'"Ciphers $CIPHERS"
[ -n "$MACS" ] && content+=$'\n'"MACs $MACS"
[ -n "$PORT" ] && content+=$'\n'"Port $PORT"
[ -n "$ALLOW_USERS" ] && content+=$'\n'"AllowUsers ${ALLOW_USERS//,/ }"

if [ "$DRY_RUN" = 1 ]; then
  info "Dry run. Would write $DROPIN:"; echo "$content" | sed 's/^/    /'; exit 0
fi

# --- apply ---
mkdir -p "$BACKUP_DIR" "$DROPIN_DIR"; chmod 700 "$BACKUP_DIR"
bk="$BACKUP_DIR/sshd_config.$(date +%Y%m%d-%H%M%S)"
cp -p "$CONF" "$bk" && ok "backup: $bk"
[ -f "$DROPIN" ] && cp -p "$DROPIN" "$bk.dropin"

# Drop-ins only work if sshd_config includes them, before other settings (first value wins)
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$CONF"; then
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$CONF" && info "added Include line to top of $CONF"
fi

printf '%s\n' "$content" > "$DROPIN"; chmod 644 "$DROPIN"

if ! "$SSHD" -t 2>/tmp/ssh-harden.err; then
  warn "sshd -t failed: $(cat /tmp/ssh-harden.err)"
  rm -f "$DROPIN"; cp -p "$bk" "$CONF"
  [ -f "$bk.dropin" ] && cp -p "$bk.dropin" "$DROPIN"
  die "Rolled back. Nothing was changed."
fi
ok "configuration validates"

# Effective values check: another drop-in earlier in the order could override ours
eff=$("$SSHD" -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|port) ' || true)
grep -q '^passwordauthentication no' <<<"$eff" || warn "Effective PasswordAuthentication isn't 'no'. Another file in $DROPIN_DIR may set it first."

if [ -n "$PORT" ]; then
  if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then ufw allow "$PORT"/tcp >/dev/null && ok "ufw: allowed $PORT/tcp"; fi
  warn "Port changed to $PORT. Allow it in any cloud NSG / firewall before you disconnect."
fi

restart_ssh
echo
echo "$eff" | sed 's/^/  effective: /'
ok "Hardening applied. Keep this session open and test a new login: ssh ${PORT:+-p $PORT }$op_user@<host>"
echo "  Undo: sudo bash ssh-harden.sh --rollback"
