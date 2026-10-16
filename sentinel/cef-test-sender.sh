#!/usr/bin/env bash
# cef-test-sender.sh - send sample FortiGate / PAN-OS CEF messages to a forwarder
# NoxCipher Scripts | https://scripts.noxcipher.site | MIT
#
# Builds realistic CEF messages in FortiGate and Palo Alto formats, tags each
# with a unique run ID, sends them to a syslog/CEF forwarder and prints the KQL
# to confirm they landed and parsed in CommonSecurityLog. Uses documentation IP
# ranges only.
#
# Usage:
#   cef-test-sender.sh --target 10.0.0.5 [--vendor fortinet|paloalto|both] [--count 5]
#                      [--port 514] [--proto udp|tcp] [--facility local4]

set -euo pipefail

VERSION="1.2.0"
TARGET=""; VENDOR="both"; COUNT=5; PORT=514; PROTO="udp"; FACILITY="local4"

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2 ;;
    --vendor) VENDOR="${2:-}"; shift 2 ;;
    --count) COUNT="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --proto) PROTO="${2:-}"; shift 2 ;;
    --facility) FACILITY="${2:-}"; shift 2 ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) echo "Usage: cef-test-sender.sh --target IP [--vendor fortinet|paloalto|both] [--count 5] [--port 514] [--proto udp|tcp] [--facility local4]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$TARGET" ] || { echo "--target is required" >&2; exit 2; }
[[ "$COUNT" =~ ^[0-9]+$ ]] && [ "$COUNT" -ge 1 ] && [ "$COUNT" -le 10000 ] || { echo "--count must be 1-10000" >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "--port must be a number" >&2; exit 2; }
case "$VENDOR" in fortinet|paloalto|both) ;; *) echo "--vendor must be fortinet, paloalto or both" >&2; exit 2 ;; esac
case "$PROTO" in udp|tcp) ;; *) echo "--proto must be udp or tcp" >&2; exit 2 ;; esac
case "$FACILITY" in local[0-7]|user|daemon|auth|authpriv|syslog) ;; *) echo "--facility should be local0-local7, user, daemon, auth, authpriv or syslog" >&2; exit 2 ;; esac

RUN="nx$(date +%s)"
HOST=$(hostname)
sent=0

fgt_msg() {
  local i=$1
  local src="192.0.2.$(( (i % 200) + 10 ))" sport=$(( 40000 + i )) act dpt
  local ports=(443 3389 22 445 80)
  dpt=${ports[$(( i % 5 ))]}; act=$([ $(( i % 3 )) -eq 0 ] && echo deny || echo accept)
  echo "CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward $act|3|deviceExternalId=FGTNXTEST0000001 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=root src=$src spt=$sport deviceInboundInterface=wan1 dst=10.10.20.$(( (i % 50) + 5 )) dpt=$dpt deviceOutboundInterface=internal proto=6 act=$act FTNTFGTpolicyid=$(( i % 20 )) FTNTFGTservice=TCP-$dpt out=$(( i * 37 )) in=$(( i * 91 )) msg=$RUN-$i"
}
pan_msg() {
  local i=$1
  local src="198.51.100.$(( (i % 200) + 10 ))" act
  act=$([ $(( i % 2 )) -eq 0 ] && echo reset-both || echo alert)
  echo "CEF:0|Palo Alto Networks|PAN-OS|11.1.2|vulnerability|THREAT|8|rt=$(date -u '+%b %d %Y %H:%M:%S') GMT deviceExternalId=PANNXTEST0001 src=$src dst=203.0.113.$(( (i % 50) + 5 )) cs1Label=Rule cs1=dmz-web-inbound app=web-browsing cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone cs4=untrust cs5Label=Destination Zone cs5=dmz spt=$(( 50000 + i )) dpt=443 proto=tcp act=$act request=\"Test Signature (NoxCipher)\" cat=code-execution msg=$RUN-$i"
}

send() {
  local m=$1
  if command -v logger >/dev/null; then
    logger --"$PROTO" -n "$TARGET" -P "$PORT" -p "$FACILITY.warning" -t CEF --rfc3164 "$m"
  else
    printf '<%d>%s %s CEF: %s\n' "$(( ( $(facnum) * 8 ) + 4 ))" "$(date '+%b %e %H:%M:%S')" "$HOST" "$m" > "/dev/$PROTO/$TARGET/$PORT"
  fi
}
facnum() { case "$FACILITY" in local*) echo $(( 16 + ${FACILITY#local} ));; user) echo 1;; daemon) echo 3;; auth) echo 4;; syslog) echo 5;; authpriv) echo 10;; esac; }

if [ "$PROTO" = tcp ] && ! timeout 5 bash -c "</dev/tcp/$TARGET/$PORT" 2>/dev/null; then
  echo "Can't open TCP $TARGET:$PORT. Is the forwarder listening and reachable?" >&2; exit 1
fi

echo "Sending $COUNT message(s) per vendor to $TARGET:$PORT/$PROTO as $FACILITY.warning (run id $RUN)"
for i in $(seq 1 "$COUNT"); do
  if [ "$VENDOR" != paloalto ]; then send "$(fgt_msg "$i")"; sent=$((sent+1)); fi
  if [ "$VENDOR" != fortinet ]; then send "$(pan_msg "$i")"; sent=$((sent+1)); fi
  [ "$COUNT" -gt 50 ] && sleep 0.01
done
echo "Sent $sent message(s)."
[ "$PROTO" = udp ] && echo "(UDP gives no delivery confirmation. If nothing arrives, check the forwarder with cef-forwarder-check.sh.)"
cat <<EOF

Check in Sentinel (allow 5-10 minutes):

  CommonSecurityLog
  | where TimeGenerated > ago(1h)
  | where Message startswith "$RUN"
  | summarize Events = count(), Parsed = countif(isnotempty(SourceIP)) by DeviceVendor, DeviceProduct

If Events > 0 but Parsed is 0, the messages arrived but didn't parse as CEF.
If nothing arrives and Syslog has them, the facility is collected by a Syslog DCR, not the CEF DCR:

  Syslog | where TimeGenerated > ago(1h) | where SyslogMessage has "$RUN"
EOF
