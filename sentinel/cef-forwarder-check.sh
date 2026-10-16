#!/usr/bin/env bash
# cef-forwarder-check.sh - health check for a CEF / Syslog forwarder using the Azure Monitor Agent
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Checks, in order: AMA service and version, Arc agent (if present), syslog
# daemon, listener on the CEF port, the rsyslog/syslog-ng -> AMA forwarding
# config, AMA's local listener, DCRs downloaded (and whether one collects CEF),
# outbound reachability to Azure Monitor, time sync, disk space for the AMA
# buffer, and the host firewall. Prints a pass/warn/fail table with a fix for
# each failure.
#
# Usage:
#   cef-forwarder-check.sh [--port 514] [--send-test] [--json]

set -uo pipefail

VERSION="3.2.0"
PORT=514; SEND_TEST=0; JSON=0
AMA_CFG=/etc/opt/microsoft/azuremonitoragent/config-cache/configchunks
AMA_EVENTS=/var/opt/microsoft/azuremonitoragent

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:-}"; shift 2 ;;
    --send-test) SEND_TEST=1; shift ;;
    --json) JSON=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: cef-forwarder-check.sh [--port 514] [--send-test] [--json]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "--port must be a number" >&2; exit 2; }

if [ -t 1 ] && [ "$JSON" = 0 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; B=$'\e[1m'; N=$'\e[0m'; else G=""; Y=""; R=""; D=""; B=""; N=""; fi

RESULTS=()   # status|check|detail|fix
add() { RESULTS+=("$1|$2|$3|${4:-}"); }
pass() { add PASS "$1" "$2"; }
warnr() { add WARN "$1" "$2" "${3:-}"; }
fail() { add FAIL "$1" "$2" "${3:-}"; }

tcp_ok() { timeout 5 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

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

[ "$(id -u)" -eq 0 ] || warnr "Running as root" "not root: some checks may be incomplete" "Re-run with sudo"

# 1. AMA service
if systemctl list-unit-files azuremonitoragent.service >/dev/null 2>&1 && systemctl cat azuremonitoragent.service >/dev/null 2>&1; then
  ver=$( (dpkg-query -W -f='${Version}' azuremonitoragent 2>/dev/null || rpm -q --qf '%{VERSION}' azuremonitoragent 2>/dev/null) | head -1)
  if systemctl is-active --quiet azuremonitoragent; then pass "AMA service" "active, version ${ver:-unknown}"
  else fail "AMA service" "installed but not running" "sudo systemctl restart azuremonitoragent; journalctl -u azuremonitoragent -n 50"; fi
else
  fail "AMA service" "azuremonitoragent not installed" "Install AMA from the CEF via AMA connector (create a DCR targeting this machine)"
fi

# 2. Arc agent (on-prem forwarders)
if command -v azcmagent >/dev/null; then
  st=$(azcmagent show 2>/dev/null | awk -F': *' '/Agent Status/{print $2; exit}')
  if [ "$st" = "Connected" ]; then pass "Arc agent" "Connected"
  else fail "Arc agent" "status: ${st:-unknown}" "azcmagent show; azcmagent check --location <region>"; fi
fi

# 3. Syslog daemon
daemon=""
if systemctl is-active --quiet rsyslog 2>/dev/null; then daemon=rsyslog; pass "Syslog daemon" "rsyslog active"
elif systemctl is-active --quiet syslog-ng 2>/dev/null; then daemon=syslog-ng; pass "Syslog daemon" "syslog-ng active"
else fail "Syslog daemon" "neither rsyslog nor syslog-ng is running" "sudo apt install -y rsyslog && sudo systemctl enable --now rsyslog"; fi

# 4. Listener on the CEF port
listen=$(listen_protos "$PORT" | sort -u | tr '\n' ' ')
if [[ "$listen" == *udp* && "$listen" == *tcp* ]]; then pass "Listening on $PORT" "TCP and UDP"
elif [ -n "$listen" ]; then warnr "Listening on $PORT" "only: $listen" "Run the Sentinel forwarder install script to enable both TCP and UDP"
else fail "Listening on $PORT" "nothing listening on port $PORT" "Run the forwarder install script from the CEF via AMA connector page"; fi

# 5. Forwarding config to AMA
fwd=""
for f in /etc/rsyslog.d/10-azuremonitoragent-omfwd.conf /etc/rsyslog.d/10-azuremonitoragent.conf /etc/syslog-ng/conf.d/azuremonitoragent-tcp.conf /etc/syslog-ng/conf.d/azuremonitoragent.conf; do
  [ -f "$f" ] && fwd="$f" && break
done
if [ -n "$fwd" ]; then pass "Forwarding to AMA" "$fwd"
else fail "Forwarding to AMA" "no AMA forwarding config found for ${daemon:-the syslog daemon}" "AMA writes this when a Syslog/CEF DCR is associated. Check the DCR association, then restart AMA"; fi

# 6. AMA local listener (rsyslog/syslog-ng forward to it on 28330)
if listen_protos 28330 | grep -q tcp; then pass "AMA local listener" "127.0.0.1:28330"
else warnr "AMA local listener" "port 28330 not listening" "Normal on some AMA versions that use a Unix socket; otherwise restart AMA"; fi

# 7. DCRs downloaded
if [ -d "$AMA_CFG" ] && ls "$AMA_CFG"/*.json >/dev/null 2>&1; then
  n=$(ls "$AMA_CFG"/*.json 2>/dev/null | wc -l)
  if grep -qs 'CommonSecurityLog' "$AMA_CFG"/*.json; then pass "DCR config" "$n config chunk(s), CEF stream present"
  else warnr "DCR config" "$n config chunk(s), but no CommonSecurityLog stream" "Associate a CEF via AMA DCR with this machine, wait ~5 min"; fi
else
  fail "DCR config" "no DCR config downloaded" "Check the DCR association and outbound access to *.handler.control.monitor.azure.com"
fi

# 8. Outbound to Azure Monitor
if tcp_ok global.handler.control.monitor.azure.com 443; then pass "Azure Monitor control" "global.handler.control.monitor.azure.com:443 reachable"
else fail "Azure Monitor control" "can't reach global.handler.control.monitor.azure.com:443" "Allow outbound 443 (AzureMonitor service tag) and disable TLS inspection for AMA endpoints"; fi
if [ -d "$AMA_CFG" ]; then
  for h in $(grep -ohsE '[a-z0-9-]+\.ods\.opinsights\.azure\.com|[a-z0-9.-]+\.ingest\.monitor\.azure\.com' "$AMA_CFG"/*.json | sort -u | head -3); do
    if tcp_ok "$h" 443; then pass "Ingestion endpoint" "$h:443 reachable"
    else fail "Ingestion endpoint" "can't reach $h:443" "Allow outbound 443 to this host (or check private link DNS)"; fi
  done
fi

# 9. Time sync (TLS and TimeGenerated depend on it)
if command -v timedatectl >/dev/null; then
  if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then pass "Time sync" "NTP synchronized ($(date +%Z))"
  else warnr "Time sync" "clock not NTP-synchronized" "sudo timedatectl set-ntp true"; fi
fi

# 10. Disk space for the AMA buffer
dir=$AMA_EVENTS; [ -d "$dir" ] || dir=/var
pct=$(df -P "$dir" | awk 'NR==2 {gsub("%","",$5); print $5}')
if [ "${pct:-0}" -ge 90 ]; then fail "Disk space" "$dir is ${pct}% full" "Free space; AMA stops buffering when the disk is full"
elif [ "${pct:-0}" -ge 80 ]; then warnr "Disk space" "$dir is ${pct}% full" "Keep at least 10 GB free for the AMA buffer"
else pass "Disk space" "$dir is ${pct}% full"; fi

# 11. Host firewall
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
  if ufw status 2>/dev/null | grep -qE "^$PORT(/(tcp|udp))?\s+ALLOW"; then pass "Host firewall" "ufw allows $PORT"
  else fail "Host firewall" "ufw is active and doesn't allow $PORT" "sudo ufw allow $PORT/udp && sudo ufw allow $PORT/tcp"; fi
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  if firewall-cmd --list-ports 2>/dev/null | grep -qE "\b$PORT/(tcp|udp)"; then pass "Host firewall" "firewalld allows $PORT"
  else fail "Host firewall" "firewalld is active and doesn't list $PORT" "sudo firewall-cmd --add-port=$PORT/udp --add-port=$PORT/tcp --permanent && sudo firewall-cmd --reload"; fi
else
  pass "Host firewall" "no active ufw/firewalld"
fi

# 12. Optional test event
TEST_ID=""
if [ "$SEND_TEST" = 1 ]; then
  TEST_ID="nx-test-$(date +%s)"
  msg="CEF:0|NoxCipher|ForwarderCheck|$VERSION|100|Forwarder health check|3|src=127.0.0.1 dst=127.0.0.1 msg=$TEST_ID"
  if command -v logger >/dev/null && logger --udp -n 127.0.0.1 -P "$PORT" -p local4.warning -t CEF "$msg" 2>/dev/null; then
    pass "Test event" "sent $TEST_ID to 127.0.0.1:$PORT (local4.warning)"
  else
    fail "Test event" "couldn't send with logger" "Install util-linux or send manually"
  fi
fi

# ---- output ----
fails=0; warns=0
for r in "${RESULTS[@]}"; do case "${r%%|*}" in FAIL) fails=$((fails+1));; WARN) warns=$((warns+1));; esac; done

if [ "$JSON" = 1 ]; then
  esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
  printf '{"host":"%s","port":%s,"failures":%s,"warnings":%s,"testId":"%s","checks":[' "$(hostname)" "$PORT" "$fails" "$warns" "$TEST_ID"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r s c d f <<<"$r"
    [ $first = 1 ] || printf ','; first=0
    printf '{"status":"%s","check":"%s","detail":"%s","fix":"%s"}' "$s" "$(esc "$c")" "$(esc "$d")" "$(esc "$f")"
  done
  printf ']}\n'
else
  echo "${B}CEF forwarder check${N} ${D}($(hostname), port $PORT)${N}"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r s c d f <<<"$r"
    case "$s" in PASS) col=$G;; WARN) col=$Y;; *) col=$R;; esac
    printf '  %s%-4s%s  %-22s %s\n' "$col" "$s" "$N" "$c" "$d"
    [ -n "$f" ] && printf '        %s-> %s%s\n' "$D" "$f" "$N"
  done
  echo
  echo "  $fails failure(s), $warns warning(s)"
  if [ -n "$TEST_ID" ]; then
    echo; echo "  Find the test event in Sentinel (allow 5-10 min):"
    echo "    CommonSecurityLog | where TimeGenerated > ago(30m) | where Message has \"$TEST_ID\""
  fi
fi
[ "$fails" -eq 0 ]
