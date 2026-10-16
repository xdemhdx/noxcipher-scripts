#!/usr/bin/env bash
# fortigate-syslog-check.sh - verify a FortiGate is sending CEF to your forwarder
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Reads the FortiGate's syslogd settings over the REST API (server, port,
# mode, format, facility, source IP) and checks them against the forwarder.
# Run it ON the forwarder as root and it also captures live packets from the
# FortiGate for a few seconds, which proves which side of the pipeline is
# broken.
#
# Usage:
#   FGT_TOKEN=xxxx fortigate-syslog-check.sh --host 192.0.2.1 [--forwarder 10.0.0.5] [--port 514] [--capture 20] [--insecure]
#   Use --capture 0 to skip the packet capture.

set -uo pipefail

VERSION="0.9.1"
HOST=""; FWD=""; PORT=514; TOKEN="${FGT_TOKEN:-}"; CAPTURE=20; INSECURE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --forwarder) FWD="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --capture) CAPTURE="${2:-}"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: FGT_TOKEN=... fortigate-syslog-check.sh --host IP [--forwarder IP] [--port 514] [--capture 20] [--insecure]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$HOST" ] || { echo "--host is required" >&2; exit 2; }

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'; else G=""; Y=""; R=""; D=""; N=""; fi
pass() { printf '  %sPASS%s  %s\n' "$G" "$N" "$*"; }
warn() { printf '  %sWARN%s  %s\n' "$Y" "$N" "$*"; }
fail() { printf '  %sFAIL%s  %s\n' "$R" "$N" "$*"; FAILS=$((FAILS+1)); }
FAILS=0

# Which protocols listen on a port: uses ss, falls back to /proc/net (prints tcp/udp lines)
listen_protos() {
  local p=$1 hex; hex=$(printf '%04X' "$p")
  if command -v ss >/dev/null; then
    ss -lntuH 2>/dev/null | awk -v p=":$p" '$5 ~ p"$" {print $1}' | sort -u
  else
    awk -v h=":$hex" 'FNR>1 && $2 ~ h"$" && $4=="0A" {print "tcp"; exit}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
    awk -v h=":$hex" 'FNR>1 && $2 ~ h"$" && $4=="07" {print "udp"; exit}' /proc/net/udp /proc/net/udp6 2>/dev/null
  fi
}

# Default forwarder = this machine's primary IP
if [ -z "$FWD" ]; then FWD=$(hostname -I 2>/dev/null | awk '{print $1}'); fi
LOCAL=0; hostname -I 2>/dev/null | tr ' ' '\n' | grep -qx "$FWD" && LOCAL=1

echo "FortiGate $HOST -> forwarder ${FWD:-?}:$PORT"
src_ip=""

# 1. FortiGate settings
if [ -n "$TOKEN" ]; then
  CURL=(curl -sS --max-time 20 -H "Authorization: Bearer $TOKEN"); [ "$INSECURE" = 1 ] && CURL+=(-k)
  js=$("${CURL[@]}" "https://$HOST/api/v2/cmdb/log.syslogd/setting" 2>/dev/null || true)
  val() { grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" <<<"$js" | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/'; }
  if [ -z "$js" ]; then fail "couldn't reach the FortiGate API (TLS? try --insecure; trusted hosts?)"
  elif ! grep -q '"results"' <<<"$js"; then fail "API error: $(head -c 200 <<<"$js")"
  else
    status=$(val status); server=$(val server); port=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' <<<"$js" | head -1 | grep -oE '[0-9]+$')
    mode=$(val mode); format=$(val format); facility=$(val facility); src_ip=$(val source-ip)
    [ "$status" = enable ] && pass "syslogd status: enable" || fail "syslogd status: ${status:-?} (config log syslogd setting -> set status enable)"
    [ "$server" = "$FWD" ] && pass "server: $server" || fail "server is '${server:-empty}', expected $FWD"
    [ "${port:-514}" = "$PORT" ] && pass "port: ${port:-514}" || fail "port is $port, forwarder listens on $PORT"
    [ "$format" = cef ] && pass "format: cef" || fail "format is '${format:-default}', must be cef for CommonSecurityLog (set format cef)"
    case "$mode" in udp) pass "mode: udp";; reliable) pass "mode: reliable (TCP). Make sure the forwarder listens on TCP $PORT";; legacy-reliable) warn "mode: legacy-reliable (RFC 3195). Prefer udp or reliable";; *) warn "mode: ${mode:-?}";; esac
    pass "facility: ${facility:-local7} (the CEF DCR must collect this facility)"
    if [ -n "$src_ip" ] && [ "$src_ip" != "0.0.0.0" ]; then pass "source-ip: $src_ip"; else warn "source-ip not set: logs come from the egress interface IP, not necessarily $HOST"; fi
  fi
else
  warn "no token (FGT_TOKEN): skipping the FortiGate settings check"
  echo "        On the FortiGate CLI run:  show log syslogd setting"
fi

# 2. Forwarder listening
if [ "$LOCAL" = 1 ]; then
  lp=$(listen_protos "$PORT")
  grep -q udp <<<"$lp" && pass "forwarder listening on UDP $PORT" || warn "nothing listening on UDP $PORT here"
  grep -q tcp <<<"$lp" && pass "forwarder listening on TCP $PORT" || warn "nothing listening on TCP $PORT here"
elif [ -n "$FWD" ] && timeout 5 bash -c "</dev/tcp/$FWD/$PORT" 2>/dev/null; then
  pass "forwarder $FWD accepts TCP $PORT"
else
  warn "can't confirm the forwarder is listening (run this script on the forwarder for a full check)"
fi

# 3. Live capture on the forwarder
if [ "$LOCAL" = 1 ] && [ "$CAPTURE" != 0 ]; then
  if [ "$(id -u)" -ne 0 ] || ! command -v tcpdump >/dev/null; then
    warn "skipping capture (needs root and tcpdump: sudo apt install -y tcpdump)"
  else
    filt="port $PORT"; [ -n "$src_ip" ] && [ "$src_ip" != "0.0.0.0" ] && filt="host $src_ip and port $PORT"
    echo "  ${D}capturing '$filt' for ${CAPTURE}s...${N}"
    cap=$(timeout "$CAPTURE" tcpdump -nn -l -i any -c 20 -A "$filt" 2>/dev/null || true)
    n=$(grep -cE ' > [0-9.]+\.'"$PORT"':' <<<"$cap" || true)
    if [ "${n:-0}" -gt 0 ]; then
      srcs=$(grep -oE 'IP [0-9.]+\.[0-9]+ >' <<<"$cap" | awk '{print $2}' | sed 's/\.[0-9]*$//' | sort -u | tr '\n' ' ')
      pass "$n packet(s) received from: $srcs"
      grep -q 'CEF:0|Fortinet' <<<"$cap" && pass "payload is CEF from Fortinet" || warn "packets arrived but no 'CEF:0|Fortinet' payload seen (format not cef?)"
    else
      fail "no packets on $filt in ${CAPTURE}s: check routing/firewalls between the FortiGate and $FWD, or generate traffic on the FortiGate"
    fi
  fi
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "No failures."; else echo "$FAILS failure(s)."; fi
echo "Then confirm in Sentinel:"
echo "  CommonSecurityLog | where TimeGenerated > ago(30m) | where DeviceVendor == \"Fortinet\" | summarize count() by DeviceName, Computer"
[ "$FAILS" -eq 0 ]
