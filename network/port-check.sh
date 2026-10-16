#!/usr/bin/env bash
# port-check.sh - test TCP/UDP reachability to hosts and ports, with timing
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# No nmap or telnet needed: TCP uses bash's /dev/tcp, UDP uses nc if present.
# Exit code is 0 only if every TCP check succeeds.
#
# Usage:
#   port-check.sh --hosts 10.0.0.5,10.0.0.6 --ports 514,22 [--udp] [--timeout 3]

set -uo pipefail

VERSION="1.0.0"
HOSTS=""; PORTS=""; UDP=0; TIMEOUT=3

while [ $# -gt 0 ]; do
  case "$1" in
    --hosts) HOSTS="${2:-}"; shift 2 ;;
    --ports) PORTS="${2:-}"; shift 2 ;;
    --udp) UDP=1; shift ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: port-check.sh --hosts h1,h2 --ports p1,p2 [--udp] [--timeout 3]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$HOSTS" ] && [ -n "$PORTS" ] || { echo "--hosts and --ports are required" >&2; exit 2; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "--timeout must be whole seconds" >&2; exit 2; }

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G=""; Y=""; R=""; B=""; N=""; fi
proto=$([ "$UDP" = 1 ] && echo udp || echo tcp)
if [ "$UDP" = 1 ] && ! command -v nc >/dev/null; then echo "UDP checks need nc (sudo apt install -y netcat-openbsd)" >&2; exit 2; fi

printf '%s%-32s %-7s %-6s %-14s %s%s\n' "$B" "HOST" "PORT" "PROTO" "RESULT" "TIME" "$N"
fails=0
IFS=',' read -r -a hl <<<"$HOSTS"; IFS=',' read -r -a pl <<<"$PORTS"
for h in "${hl[@]}"; do
  h="${h// /}"; [ -n "$h" ] || continue
  if ! getent hosts "$h" >/dev/null 2>&1 && ! [[ "$h" =~ ^[0-9.]+$ ]]; then
    printf '%-32s %-7s %-6s %s%-14s%s %s\n' "$h" "-" "$proto" "$R" "NO DNS" "$N" "-"; fails=$((fails+1)); continue
  fi
  for p in "${pl[@]}"; do
    p="${p// /}"; [[ "$p" =~ ^[0-9]+$ ]] || continue
    t0=$(date +%s%N)
    if [ "$UDP" = 1 ]; then
      if nc -u -z -w "$TIMEOUT" "$h" "$p" 2>/dev/null; then res="open|filtered"; col=$Y; else res="closed"; col=$R; fi
    else
      if timeout "$TIMEOUT" bash -c "</dev/tcp/$h/$p" 2>/dev/null; then res="open"; col=$G; else res="closed/filtered"; col=$R; fails=$((fails+1)); fi
    fi
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    printf '%-32s %-7s %-6s %s%-14s%s %sms\n' "$h" "$p" "$proto" "$col" "$res" "$N" "$ms"
  done
done
[ "$UDP" = 1 ] && echo && echo "UDP can't confirm 'open': no reply looks the same as a silent firewall. 'closed' means an ICMP port-unreachable came back."
[ "$fails" -eq 0 ]
