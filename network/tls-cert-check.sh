#!/usr/bin/env bash
# tls-cert-check.sh - certificate expiry, chain and TLS versions for one or many endpoints
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# For each host: days to expiry, subject, issuer, SANs, whether the chain
# verifies, and which TLS versions the endpoint accepts. Exits 1 if any
# certificate is expired, inside the warning window, or fails to verify, so it
# works as a cron or pipeline check.
#
# Usage:
#   tls-cert-check.sh --host vpn.example.com[:443] [--warn 30]
#   tls-cert-check.sh --host hosts.txt [--warn 30]      # one host[:port] per line, # for comments

set -uo pipefail

VERSION="1.1.0"
TARGET=""; WARN=30; DEFAULT_PORT=443

while [ $# -gt 0 ]; do
  case "$1" in
    --host) TARGET="${2:-}"; shift 2 ;;
    --warn) WARN="${2:-}"; shift 2 ;;
    --port) DEFAULT_PORT="${2:-}"; shift 2 ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: tls-cert-check.sh --host HOST[:PORT]|FILE [--warn 30] [--port 443]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$TARGET" ] || { echo "--host is required" >&2; exit 2; }
[[ "$WARN" =~ ^[0-9]+$ ]] || { echo "--warn must be a number of days" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; B=$'\e[1m'; N=$'\e[0m'; else G=""; Y=""; R=""; D=""; B=""; N=""; fi

if [ -f "$TARGET" ]; then mapfile -t list < <(grep -vE '^\s*(#|$)' "$TARGET"); else list=("$TARGET"); fi

bad=0
for entry in "${list[@]}"; do
  entry="${entry// /}"
  host="${entry%%:*}"; port="${entry##*:}"; [ "$port" = "$entry" ] && port=$DEFAULT_PORT
  echo "${B}$host:$port${N}"
  raw=$(echo | timeout 10 openssl s_client -connect "$host:$port" -servername "$host" -showcerts 2>/dev/null)
  cert=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/{p;/-----END CERTIFICATE-----/q}' <<<"$raw")
  if [ -z "$cert" ]; then echo "  ${R}FAIL${N}  no certificate (connection failed or not TLS)"; bad=$((bad+1)); echo; continue; fi

  end=$(openssl x509 -noout -enddate <<<"$cert" | cut -d= -f2)
  end_s=$(date -d "$end" +%s 2>/dev/null || echo 0)
  days=$(( (end_s - $(date +%s)) / 86400 ))
  subj=$(openssl x509 -noout -subject -nameopt RFC2253 <<<"$cert" | sed 's/^subject=//')
  iss=$(openssl x509 -noout -issuer -nameopt RFC2253 <<<"$cert" | sed 's/^issuer=//')
  sans=$(openssl x509 -noout -ext subjectAltName <<<"$cert" 2>/dev/null | tail -n +2 | sed 's/DNS://g; s/^ *//' | tr -d '\n')
  verify=$(grep -oE 'Verify return code: [0-9]+ \([^)]*\)' <<<"$raw" | head -1)
  chain=$(grep -c 'BEGIN CERTIFICATE' <<<"$raw")

  if [ "$days" -lt 0 ]; then echo "  ${R}FAIL${N}  expired $(( -days )) day(s) ago ($end)"; bad=$((bad+1))
  elif [ "$days" -lt "$WARN" ]; then echo "  ${Y}WARN${N}  expires in $days day(s) ($end)"; bad=$((bad+1))
  else echo "  ${G}PASS${N}  expires in $days day(s) ($end)"; fi
  if [[ "$verify" == *"code: 0 "* ]]; then echo "  ${G}PASS${N}  chain verifies ($chain cert(s) sent)"
  else echo "  ${R}FAIL${N}  ${verify:-chain not verified} ($chain cert(s) sent; missing intermediate?)"; bad=$((bad+1)); fi
  if [ -n "$sans" ] && ! tr ',' '\n' <<<"$sans" | sed 's/^ *//' | grep -qxE "$host|\*\.${host#*.}"; then
    echo "  ${R}FAIL${N}  $host isn't in the SANs"; bad=$((bad+1))
  fi
  echo "  ${D}subject:${N} $subj"
  echo "  ${D}issuer: ${N} $iss"
  [ -n "$sans" ] && echo "  ${D}SANs:   ${N} $sans"

  vers=""
  for v in tls1 tls1_1 tls1_2 tls1_3; do
    if echo | timeout 6 openssl s_client -connect "$host:$port" -servername "$host" "-$v" >/dev/null 2>&1; then vers+="${v/tls1/TLS1.0} "; fi
  done
  vers=$(sed 's/TLS1.0_1/TLS1.1/; s/TLS1.0_2/TLS1.2/; s/TLS1.0_3/TLS1.3/' <<<"$vers")
  echo "  ${D}TLS:    ${N} ${vers:-none detected}"
  if [[ "$vers" == *"TLS1.0 "* || "$vers" == *"TLS1.1"* ]]; then echo "  ${Y}WARN${N}  TLS 1.0/1.1 accepted"; fi
  echo
done

[ "$bad" -eq 0 ] && echo "${G}All checks passed.${N}" || echo "${Y}$bad issue(s).${N}"
[ "$bad" -eq 0 ]
