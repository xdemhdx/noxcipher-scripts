#!/usr/bin/env bash
# disk-cleanup.sh - free disk space fast on a Linux server
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Cleans package manager caches, vacuums the systemd journal, removes temp
# files older than 7 days from /tmp and /var/tmp, and reports space reclaimed
# per step. Run as root.
#
# Usage:
#   disk-cleanup.sh [--journal-days 14] [--tmp-days 7] [--dry-run]

set -euo pipefail

VERSION="1.1.2"
JOURNAL_DAYS=14
TMP_DAYS=7
DRY_RUN=0

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; B=$'\e[1m'; N=$'\e[0m'; else G=""; Y=""; R=""; D=""; B=""; N=""; fi
info() { printf '%s[info]%s %s\n' "$D" "$N" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --journal-days) JOURNAL_DAYS="${2:-}"; shift 2 ;;
    --tmp-days) TMP_DAYS="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: disk-cleanup.sh [--journal-days 14] [--tmp-days 7] [--dry-run]"; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ "$JOURNAL_DAYS" =~ ^[0-9]+$ ]] || die "--journal-days must be a number"
[[ "$TMP_DAYS" =~ ^[0-9]+$ ]] || die "--tmp-days must be a number"
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."

used_kb() { df -Pk / | awk 'NR==2 {print $3}'; }
human() { numfmt --to=iec --suffix=B "$(( $1 * 1024 ))" 2>/dev/null || echo "${1}KB"; }
du_kb() { du -sk "$@" 2>/dev/null | awk '{s+=$1} END {print s+0}'; }

total=0
step() { # step "label" before_kb
  local after; after=$(used_kb)
  local diff=$(( $2 - after )); [ "$diff" -lt 0 ] && diff=0
  total=$(( total + diff ))
  ok "$1: $(human "$diff") freed"
}

echo "${B}Disk before:${N}"; df -h / | sed 's/^/  /'
[ "$DRY_RUN" = 1 ] && info "Dry run: reporting only, nothing is deleted."
echo

# 1. Package caches
if command -v apt-get >/dev/null; then
  if [ "$DRY_RUN" = 1 ]; then info "apt cache: $(human "$(du_kb /var/cache/apt/archives)") would be cleaned"
  else b=$(used_kb); apt-get clean -y >/dev/null; apt-get autoremove -y --purge >/dev/null 2>&1 || warn "apt autoremove failed (skipped)"; step "apt cache + unused packages" "$b"; fi
elif command -v dnf >/dev/null; then
  if [ "$DRY_RUN" = 1 ]; then info "dnf cache: $(human "$(du_kb /var/cache/dnf)") would be cleaned"
  else b=$(used_kb); dnf clean all -q; step "dnf cache" "$b"; fi
elif command -v yum >/dev/null; then
  if [ "$DRY_RUN" = 1 ]; then info "yum cache: $(human "$(du_kb /var/cache/yum)") would be cleaned"
  else b=$(used_kb); yum clean all -q; step "yum cache" "$b"; fi
fi

# 2. systemd journal
if command -v journalctl >/dev/null; then
  if [ "$DRY_RUN" = 1 ]; then info "journal is $(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMGT]?B?' | head -1); entries older than ${JOURNAL_DAYS}d would be vacuumed"
  else b=$(used_kb); journalctl --vacuum-time="${JOURNAL_DAYS}d" >/dev/null 2>&1; step "journal (older than ${JOURNAL_DAYS}d)" "$b"; fi
fi

# 3. Old temp files (regular files only, same filesystem, skip sockets/locks in use)
for d in /tmp /var/tmp; do
  [ -d "$d" ] || continue
  if [ "$DRY_RUN" = 1 ]; then
    n=$(find "$d" -xdev -type f -mtime +"$TMP_DAYS" 2>/dev/null | wc -l)
    info "$d: $n files older than ${TMP_DAYS}d would be removed"
  else
    b=$(used_kb); find "$d" -xdev -type f -mtime +"$TMP_DAYS" -delete 2>/dev/null || true; step "$d (older than ${TMP_DAYS}d)" "$b"
  fi
done

# 4. Rotated logs that are already compressed and old
if [ "$DRY_RUN" = 1 ]; then
  info "/var/log: $(find /var/log -xdev -type f \( -name '*.gz' -o -name '*.[0-9]' \) -mtime +"$JOURNAL_DAYS" 2>/dev/null | wc -l) rotated logs older than ${JOURNAL_DAYS}d would be removed"
else
  b=$(used_kb); find /var/log -xdev -type f \( -name '*.gz' -o -name '*.[0-9]' \) -mtime +"$JOURNAL_DAYS" -delete 2>/dev/null || true; step "old rotated logs in /var/log" "$b"
fi

echo
echo "${B}Disk after:${N}"; df -h / | sed 's/^/  /'
[ "$DRY_RUN" = 1 ] || ok "Total reclaimed: $(human "$total")"

# Biggest directories, to show where the rest of the space went
echo; echo "${B}Largest directories under /var:${N}"
du -xh --max-depth=2 /var 2>/dev/null | sort -rh | head -8 | sed 's/^/  /'
