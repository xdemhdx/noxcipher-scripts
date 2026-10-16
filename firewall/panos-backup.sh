#!/usr/bin/env bash
# panos-backup.sh - export running config from a Palo Alto firewall or Panorama via the XML API
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Exports running-config.xml (and optionally the device state bundle), names it
# by hostname and timestamp, prints a short change summary against the last
# backup and keeps the newest N.
#
# Generate an API key for a read-only admin:
#   curl -k -X POST 'https://<fw>/api/?type=keygen' --data-urlencode 'user=<user>' --data-urlencode 'password=<pass>'
#
# Usage:
#   PAN_KEY=xxxx panos-backup.sh --host 198.51.100.1 [--keep 30] [--dir ./panos-backups] [--state] [--insecure]
#
# Prefer the PAN_KEY environment variable over --key, which shows in ps and shell history.

set -euo pipefail

VERSION="1.1.0"
HOST=""; KEY="${PAN_KEY:-}"; KEEP=30; DIR="./panos-backups"; STATE=0; INSECURE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --key) KEY="${2:-}"; shift 2; echo "[warn] --key is visible in ps/history; prefer PAN_KEY." >&2 ;;
    --keep) KEEP="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --state) STATE=1; shift ;;
    --insecure) INSECURE=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: PAN_KEY=... panos-backup.sh --host IP [--keep 30] [--dir DIR] [--state] [--insecure]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$HOST" ] || { echo "--host is required" >&2; exit 2; }
[ -n "$KEY" ] || { echo "No API key. Set PAN_KEY or pass --key." >&2; exit 2; }
[[ "$KEEP" =~ ^[0-9]+$ ]] && [ "$KEEP" -ge 1 ] || { echo "--keep must be 1 or more" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

CURL=(curl -sS --max-time 120 -H "X-PAN-KEY: $KEY")
[ "$INSECURE" = 1 ] && CURL+=(-k)
API="https://$HOST/api/"
mkdir -p "$DIR"; chmod 700 "$DIR"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

# Hostname and version
info=$("${CURL[@]}" -G "$API" --data-urlencode 'type=op' --data-urlencode 'cmd=<show><system><info></info></system></show>' || true)
if [ -z "$info" ]; then echo "Couldn't connect to $API (TLS error? add --insecure for a self-signed certificate)." >&2; exit 1; fi
if grep -q 'status="error"' <<<"$info"; then echo "API error: $(grep -oE '<msg>.*</msg>|<line>[^<]*' <<<"$info" | head -1)" >&2; exit 1; fi
hostname=$(grep -oE '<hostname>[^<]+' <<<"$info" | head -1 | cut -d'>' -f2 || true)
swver=$(grep -oE '<sw-version>[^<]+' <<<"$info" | head -1 | cut -d'>' -f2 || true)
name="${hostname:-$HOST}"

# Running config
code=$("${CURL[@]}" -o "$tmp" -w '%{http_code}' -G "$API" --data-urlencode 'type=export' --data-urlencode 'category=configuration' || true)
if [ "$code" != 200 ] || ! head -c 300 "$tmp" | grep -q '<config'; then
  echo "Export failed (HTTP $code). Response starts with:" >&2; head -c 300 "$tmp" >&2; echo >&2; exit 1
fi
stamp=$(date +%Y%m%d-%H%M%S)
out="$DIR/${name}_${stamp}.xml"
prev=$(ls -1t "$DIR/${name}"_*.xml 2>/dev/null | head -1 || true)
cp "$tmp" "$out"; chmod 600 "$out"
echo "Saved $out ($(wc -c <"$out") bytes, PAN-OS ${swver:-unknown})"

if [ "$STATE" = 1 ]; then
  st="$DIR/${name}_${stamp}_device-state.tgz"
  code=$("${CURL[@]}" -o "$st" -w '%{http_code}' -G "$API" --data-urlencode 'type=export' --data-urlencode 'category=device-state' || true)
  if [ "$code" = 200 ] && [ -s "$st" ]; then chmod 600 "$st"; echo "Saved $st"; else rm -f "$st"; echo "[warn] device state export failed (HTTP $code)" >&2; fi
fi

if [ -n "$prev" ]; then
  # pretty-print one element per line so the diff is readable
  norm() { sed -e 's/></>\n</g' "$1" | grep -vE '<(phash|key|password|secret)>'; }
  changes=$(diff <(norm "$prev") <(norm "$out") | grep -cE '^[<>]' || true)
  if [ "${changes:-0}" -eq 0 ]; then echo "No changes since $(basename "$prev")."
  else
    echo "$changes changed line(s) since $(basename "$prev"). First changes:"
    diff <(norm "$prev") <(norm "$out") | grep -E '^[<>]' | head -40 | sed 's/^/  /'
  fi
fi

mapfile -t old < <(ls -1t "$DIR/${name}"_*.xml 2>/dev/null | tail -n +"$((KEEP + 1))")
for f in "${old[@]}"; do rm -f -- "$f" "${f%.xml}_device-state.tgz"; done
[ "${#old[@]}" -gt 0 ] && echo "Removed ${#old[@]} old backup(s), keeping $KEEP."
exit 0
