#!/usr/bin/env bash
# fortigate-backup.sh - FortiGate config backup over the REST API, with retention and diff
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Downloads the full configuration with a read-only API token, saves it with a
# timestamp, prints what changed since the last backup (encrypted secrets are
# ignored because FortiOS re-salts them on every export) and keeps the newest N.
#
# Create a REST API admin with a read-only profile (System > Administrators >
# Create New > REST API Admin) and restrict trusted hosts to this machine.
#
# Usage:
#   FGT_TOKEN=xxxx fortigate-backup.sh --host 192.0.2.1[:8443] [--keep 30] [--dir ./fortigate-backups] [--vdom root] [--insecure]
#
# Prefer the FGT_TOKEN environment variable over --token, which shows in ps and shell history.

set -euo pipefail

VERSION="1.3.0"
HOST=""; TOKEN="${FGT_TOKEN:-}"; KEEP=30; DIR="./fortigate-backups"; VDOM=""; INSECURE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2; echo "[warn] --token is visible in ps/history; prefer FGT_TOKEN." >&2 ;;
    --keep) KEEP="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --vdom) VDOM="${2:-}"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: FGT_TOKEN=... fortigate-backup.sh --host IP[:PORT] [--keep 30] [--dir DIR] [--vdom NAME] [--insecure]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$HOST" ] || { echo "--host is required" >&2; exit 2; }
[ -n "$TOKEN" ] || { echo "No API token. Set FGT_TOKEN or pass --token." >&2; exit 2; }
[[ "$KEEP" =~ ^[0-9]+$ ]] && [ "$KEEP" -ge 1 ] || { echo "--keep must be 1 or more" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

CURL=(curl -sS --max-time 60 -H "Authorization: Bearer $TOKEN")
[ "$INSECURE" = 1 ] && CURL+=(-k)
if [ -n "$VDOM" ]; then SCOPE="scope=vdom&vdom=$VDOM"; else SCOPE="scope=global"; fi

mkdir -p "$DIR"; chmod 700 "$DIR"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

# FortiOS up to 7.2 uses GET; 7.4+ also accepts POST with a JSON body (GET is deprecated there).
code=$("${CURL[@]}" -o "$tmp" -w '%{http_code}' "https://$HOST/api/v2/monitor/system/config/backup?$SCOPE" || true)
if [ "$code" = 401 ] || [ "$code" = 403 ]; then echo "HTTP $code: token rejected, or this host isn't in the API admin's trusted hosts." >&2; exit 1; fi
if [ "$code" != 000 ] && [ "$code" != 200 ] || ! head -c 200 "$tmp" | grep -q '#config-version'; then
  body=$([ -n "$VDOM" ] && echo "{\"destination\":\"file\",\"scope\":\"vdom\",\"vdom\":\"$VDOM\"}" || echo '{"destination":"file","scope":"global"}')
  code=$("${CURL[@]}" -o "$tmp" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$body" "https://$HOST/api/v2/monitor/system/config/backup" || true)
fi
if [ "$code" = 000 ]; then echo "Couldn't connect to https://$HOST (TLS error? add --insecure for a self-signed certificate)." >&2; exit 1; fi
if [ "$code" = 401 ] || [ "$code" = 403 ]; then echo "HTTP $code: token rejected, or this host isn't in the API admin's trusted hosts." >&2; exit 1; fi
if [ "$code" != 200 ] || ! head -c 200 "$tmp" | grep -q '#config-version'; then
  echo "Backup failed (HTTP $code). Response starts with:" >&2; head -c 300 "$tmp" >&2; echo >&2; exit 1
fi

hostname=$(grep -m1 -oE 'set hostname "[^"]+"' "$tmp" | sed 's/set hostname "\(.*\)"/\1/' || true)
model=$(head -1 "$tmp" | grep -oE '#config-version=[^:]+' | cut -d= -f2 || true)
name="${hostname:-${HOST%%:*}}"
out="$DIR/${name}_$(date +%Y%m%d-%H%M%S).conf"
prev=$(ls -1t "$DIR/${name}"_*.conf 2>/dev/null | head -1 || true)
cp "$tmp" "$out"; chmod 600 "$out"
echo "Saved $out ($(wc -c <"$out") bytes, ${model:-unknown version})"

if [ -n "$prev" ]; then
  filt() { grep -vE '^#conf_file_ver=| ENC |^#buildno|^#global_vdom' "$1"; }
  changes=$(diff -u <(filt "$prev") <(filt "$out") | grep -E '^[+-][^+-]' || true)
  if [ -z "$changes" ]; then echo "No changes since $(basename "$prev")."
  else echo "Changes since $(basename "$prev"):"; echo "$changes" | head -100 | sed 's/^/  /'; fi
fi

# Retention
mapfile -t old < <(ls -1t "$DIR/${name}"_*.conf 2>/dev/null | tail -n +"$((KEEP + 1))")
for f in "${old[@]}"; do rm -f -- "$f"; done
[ "${#old[@]}" -gt 0 ] && echo "Removed ${#old[@]} old backup(s), keeping $KEEP."
exit 0
