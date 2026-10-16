#!/usr/bin/env bash
# log-rotate.sh - rotate, compress and prune logs in a directory
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Compresses *.log files that haven't been written to in the last day and
# aren't held open by a process, then deletes compressed archives older
# than --keep days. Safe to run from cron.
#
# Usage:
#   log-rotate.sh --path /var/log/myapp [--keep 14] [--compress gzip|zstd] [--pattern '*.log'] [--dry-run]
#
# Example cron (daily at 02:15):
#   15 2 * * * /usr/local/bin/log-rotate.sh --path /var/log/myapp --keep 14 >> /var/log/log-rotate.log 2>&1

set -euo pipefail

VERSION="1.4.0"
LOG_DIR=""
KEEP=7
COMPRESS="gzip"
PATTERN="*.log"
DRY_RUN=0

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'; else G=""; Y=""; R=""; D=""; N=""; fi
info() { printf '%s[info]%s %s\n' "$D" "$N" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  sed -n '2,13p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true
  echo "Options: --path DIR (required)  --keep DAYS (7)  --compress gzip|zstd  --pattern GLOB  --dry-run  --version"
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --path) LOG_DIR="${2:-}"; shift 2 ;;
    --keep) KEEP="${2:-}"; shift 2 ;;
    --compress) COMPRESS="${2:-}"; shift 2 ;;
    --pattern) PATTERN="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) usage 0 ;;
    *) warn "Unknown option: $1"; usage 1 ;;
  esac
done

[ -n "$LOG_DIR" ] || die "--path is required"
[ -d "$LOG_DIR" ] || die "Not a directory: $LOG_DIR"
[[ "$KEEP" =~ ^[0-9]+$ ]] || die "--keep must be a whole number of days"
case "$COMPRESS" in
  gzip) EXT="gz"; command -v gzip >/dev/null || die "gzip not installed" ;;
  zstd) EXT="zst"; command -v zstd >/dev/null || die "zstd not installed (apt install zstd)" ;;
  *) die "--compress must be gzip or zstd" ;;
esac

# How do we tell if a file is still open?
OPEN_CHECK=""
if command -v lsof >/dev/null; then OPEN_CHECK="lsof"
elif command -v fuser >/dev/null; then OPEN_CHECK="fuser"
else warn "Neither lsof nor fuser found: can't check for open files, so only files untouched for 1+ day are rotated."; fi

is_open() {
  case "$OPEN_CHECK" in
    lsof)  lsof -- "$1" >/dev/null 2>&1 ;;
    fuser) fuser -s -- "$1" 2>/dev/null ;;
    *)     return 1 ;;
  esac
}

bytes() { stat -c %s -- "$1" 2>/dev/null || echo 0; }
human() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "${1}B"; }

[ "$DRY_RUN" = 1 ] && info "Dry run: nothing will be changed."
info "Directory: $LOG_DIR | pattern: $PATTERN | keep: ${KEEP}d | compress: $COMPRESS"

rotated=0; skipped=0; deleted=0; freed=0
stamp="$(date +%Y%m%d-%H%M%S)"

# 1. Compress quiet, closed log files
while IFS= read -r -d '' f; do
  if is_open "$f"; then
    info "skip (open by a process): $(basename -- "$f")"; skipped=$((skipped + 1)); continue
  fi
  target="${f}.${stamp}.${EXT}"
  size=$(bytes "$f")
  if [ "$DRY_RUN" = 1 ]; then
    info "would compress: $(basename -- "$f") ($(human "$size"))"
  else
    if [ "$COMPRESS" = gzip ]; then gzip -c -- "$f" > "$target"; else zstd -q -c -- "$f" > "$target"; fi
    touch -r "$f" -- "$target"
    new=$(bytes "$target")
    rm -f -- "$f"
    freed=$((freed + size - new))
    ok "compressed: $(basename -- "$f") -> $(basename -- "$target")"
  fi
  rotated=$((rotated + 1))
done < <(find "$LOG_DIR" -maxdepth 1 -type f -name "$PATTERN" -mmin +1440 -print0)

# 2. Prune old archives
while IFS= read -r -d '' a; do
  size=$(bytes "$a")
  if [ "$DRY_RUN" = 1 ]; then
    info "would delete: $(basename -- "$a") ($(human "$size"))"
  else
    rm -f -- "$a"; freed=$((freed + size)); ok "deleted: $(basename -- "$a")"
  fi
  deleted=$((deleted + 1))
done < <(find "$LOG_DIR" -maxdepth 1 -type f \( -name "${PATTERN}.*.gz" -o -name "${PATTERN}.*.zst" \) -mtime +"$KEEP" -print0)

echo
if [ "$DRY_RUN" = 1 ]; then
  ok "Dry run complete: $rotated to compress, $skipped open (skipped), $deleted to delete."
else
  ok "Done: $rotated compressed, $skipped open (skipped), $deleted deleted, $(human "$freed") freed."
fi
