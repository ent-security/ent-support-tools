#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
#
# test-platform-connectivity.sh
# ------------------------------------------------------------------------------
# macOS / Linux counterpart of Test-PlatformConnectivity.ps1: diagnoses
# connectivity from this machine to the ent platform an endpoint reports to.
#
# Runs, in order: proxy info, DNS resolution, TCP connect, TLS handshake, and an
# unauthenticated GET to https://<address>:<port>/health (the endpoint the agent
# uses for its platform health check). Prints a hint for each failed stage.
#
# SAFE / READ-ONLY: it opens a connection and issues a single unauthenticated
# GET /health. It sends no credentials, stores nothing, and changes nothing.
#
# USAGE
#   ./test-platform-connectivity.sh -a <platform-host> [-p <port>] [-t <seconds>]
#   ./test-platform-connectivity.sh -c <agent-config.json>
#
#   -a, --address   Platform hostname or IP (the "address" of a server entry in
#                   the agent configuration).
#   -p, --port      Platform port. Defaults to 443 (same default as the agent).
#   -c, --config    Agent config JSON; address/port are read from servers[0].
#   -t, --timeout   Per-stage timeout in seconds. Default 5.
#
# REQUIRES: bash + curl. Reading --config uses jq, python3 or plutil (macOS),
#           whichever is available.
#
# EXIT CODES: 0 = all checks passed   1 = a check failed   2 = usage error
# ------------------------------------------------------------------------------

set -u

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; RST=""
fi
FAILED=0
result() { # result <stage> <ok:0|1> <detail>
  if [ "$2" -eq 0 ]; then printf '%s[ PASS ]%s %s - %s\n' "$GRN" "$RST" "$1" "$3"
  else printf '%s[ FAIL ]%s %s - %s\n' "$RED" "$RST" "$1" "$3"; FAILED=1; fi
}
hint()   { printf '         %shint: %s%s\n' "$YEL" "$1" "$RST"; }
detail() { printf '         %s\n' "$1"; }
usage()  { sed -n '/^# USAGE/,/^# REQUIRES/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2; }

ADDRESS=""; PORT=""; CONFIG=""; TIMEOUT=5
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--address) [ $# -ge 2 ] || usage; ADDRESS="$2"; shift 2 ;;
    -p|--port)    [ $# -ge 2 ] || usage; PORT="$2"; shift 2 ;;
    -c|--config)  [ $# -ge 2 ] || usage; CONFIG="$2"; shift 2 ;;
    -t|--timeout) [ $# -ge 2 ] || usage; TIMEOUT="$2"; shift 2 ;;
    -h|--help)    usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

# Reads servers[0].<field> from the agent config with whatever JSON tool exists.
config_field() {
  local field="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -er ".servers[0].$field // empty" "$CONFIG" 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys
v=json.load(open(sys.argv[1]))["servers"][0].get(sys.argv[2])
print(v) if v not in (None, "") else sys.exit(1)' "$CONFIG" "$field" 2>/dev/null
  elif command -v plutil >/dev/null 2>&1; then
    plutil -extract "servers.0.$field" raw -o - "$CONFIG" 2>/dev/null
  else
    echo "reading --config needs jq, python3 or plutil" >&2; exit 2
  fi
}
if [ -n "$CONFIG" ]; then
  [ -r "$CONFIG" ] || { echo "cannot read config file: $CONFIG" >&2; exit 2; }
  [ -n "$ADDRESS" ] || ADDRESS=$(config_field address)
  [ -n "$PORT" ] || PORT=$(config_field port)
  [ -n "$ADDRESS" ] || { echo "no servers[0].address in $CONFIG" >&2; exit 2; }
fi
[ -n "$ADDRESS" ] || { echo "Specify --address or --config." >&2; usage; }
PORT="${PORT:-443}"
case "$PORT" in ''|*[!0-9]*) echo "invalid port: $PORT" >&2; exit 2 ;; esac
case "$TIMEOUT" in ''|*[!0-9]*) echo "invalid timeout: $TIMEOUT" >&2; exit 2 ;; esac

# Bracket IPv6 literals for URLs.
URLHOST="$ADDRESS"
case "$ADDRESS" in *:*) URLHOST="[$ADDRESS]" ;; esac

echo "Platform connectivity check: ${ADDRESS}:${PORT}"
echo "Host: $(hostname)  User: $(id -un)  OS: $(uname -sr)  Time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo

# --- Proxy / environment -----------------------------------------------------
for v in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; do
  eval "val=\${$v:-}"
  [ -n "$val" ] && echo "Env proxy: $v=$val"
done
if command -v scutil >/dev/null 2>&1; then
  SCPROXY=$(scutil --proxy 2>/dev/null)
  sc() { printf '%s\n' "$SCPROXY" | awk -v k="$1" '$1==k {print $3; exit}'; }
  if [ "$(sc HTTPSEnable)" = "1" ]; then echo "System HTTPS proxy: $(sc HTTPSProxy):$(sc HTTPSPort)"
  else echo "System HTTPS proxy: none"; fi
  [ "$(sc ProxyAutoConfigEnable)" = "1" ] && echo "System proxy auto-config (PAC): $(sc ProxyAutoConfigURLString)"
elif command -v gsettings >/dev/null 2>&1; then
  echo "GNOME proxy mode: $(gsettings get org.gnome.system.proxy mode 2>/dev/null || echo unknown)"
fi
echo

# --- 1. DNS ------------------------------------------------------------------
is_ip() { printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$|:'; }
resolve() {
  if command -v getent >/dev/null 2>&1; then
    getent ahosts "$1" 2>/dev/null | awk '{print $1}' | awk '!seen[$0]++'
  elif command -v dscacheutil >/dev/null 2>&1; then
    dscacheutil -q host -a name "$1" 2>/dev/null | awk '/^ip(v6)?_address:/{print $2}' | awk '!seen[$0]++'
  elif command -v host >/dev/null 2>&1; then
    host "$1" 2>/dev/null | awk '/has (IPv6 )?address/{print $NF}'
  fi
}
IP=""
if is_ip "$ADDRESS"; then
  IP="$ADDRESS"
  result DNS 0 "$ADDRESS is an IP literal, skipping resolution"
else
  ADDRS=$(resolve "$ADDRESS")
  if [ -n "$ADDRS" ]; then
    # Prefer IPv4, like the Windows script.
    IP=$(printf '%s\n' "$ADDRS" | grep -E '^[0-9.]+$' | head -1)
    [ -n "$IP" ] || IP=$(printf '%s\n' "$ADDRS" | head -1)
    result DNS 0 "$ADDRESS -> $(printf '%s\n' "$ADDRS" | paste -sd, - | sed 's/,/, /g')"
  else
    result DNS 1 "could not resolve $ADDRESS"
    hint "Check the address for typos, this machine's DNS servers, and VPN/split-DNS."
    if command -v scutil >/dev/null 2>&1; then
      detail "DNS servers: $(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | awk '!seen[$0]++' | paste -sd' ' -)"
    elif [ -r /etc/resolv.conf ]; then
      detail "DNS servers: $(awk '/^nameserver/{print $2}' /etc/resolv.conf | paste -sd' ' -)"
    fi
  fi
fi

# curl --resolve pins the resolved IP so every later stage tests the same host.
PIN=()
[ -n "$IP" ] && ! is_ip "$ADDRESS" && PIN=(--resolve "${ADDRESS}:${PORT}:${IP}")
case "$IP" in *:*) IPURL="[$IP]" ;; *) IPURL="$IP" ;; esac

# --- 2. TCP ------------------------------------------------------------------
TCP_OK=1
if [ -n "$IP" ]; then
  # telnet:// makes curl open a bare TCP connection; -m ends it once connected.
  # Exit 28 with a non-zero connect time means the connection was made.
  OUT=$(curl -s --noproxy '*' --connect-timeout "$TIMEOUT" -m "$((TIMEOUT + 1))" -o /dev/null \
        -w '%{time_connect} %{local_ip} %{local_port}' "telnet://${IPURL}:${PORT}" </dev/null 2>/dev/null)
  RC=$?
  read -r T_CONN L_IP L_PORT <<EOF
$OUT
EOF
  if { [ "$RC" -eq 0 ] || [ "$RC" -eq 28 ]; } && [ "${T_CONN:-0}" != "0.000000" ] && [ -n "${T_CONN:-}" ]; then
    TCP_OK=0
    result TCP 0 "connected to ${IP}:${PORT} in $(awk -v t="$T_CONN" 'BEGIN{printf "%d", t*1000}') ms (local ${L_IP}:${L_PORT})"
  elif [ "$RC" -eq 28 ]; then
    result TCP 1 "${IP}:${PORT} - timed out after ${TIMEOUT}s"
    hint 'Timeout usually means a firewall drop; "connection refused" means nothing is listening on that port.'
  else
    result TCP 1 "${IP}:${PORT} - connection refused or unreachable (curl exit $RC)"
    hint 'Timeout usually means a firewall drop; "connection refused" means nothing is listening on that port.'
  fi
fi

# --- 3. TLS ------------------------------------------------------------------
if [ "$TCP_OK" -eq 0 ]; then
  BASE="https://${URLHOST}:${PORT}/"
  VERB=$(curl -sv -k --noproxy '*' ${PIN[@]+"${PIN[@]}"} --connect-timeout "$TIMEOUT" -m "$TIMEOUT" -o /dev/null "$BASE" 2>&1 </dev/null)
  RC=$?
  field() { printf '%s\n' "$VERB" | sed -n "s/^\* .*$1: //p" | head -1 | tr -d '\r'; }
  PROTO=$(printf '%s\n' "$VERB" | sed -n 's/^\* SSL connection using \([^ ]*\).*/\1/p' | head -1)
  SUBJECT=$(field subject); ISSUER=$(field issuer); EXPIRE=$(field 'expire date')
  if [ -n "$PROTO" ] || [ -n "$SUBJECT" ]; then
    result TLS 0 "${PROTO:-TLS}, subject '${SUBJECT:-?}', expires ${EXPIRE:-?}"
    detail "issuer: ${ISSUER:-?}"
    curl -s --noproxy '*' ${PIN[@]+"${PIN[@]}"} --connect-timeout "$TIMEOUT" -m "$TIMEOUT" -o /dev/null "$BASE" </dev/null 2>/dev/null
    case $? in
      60|51|58|77|83) printf '         %scertificate validation: NOT trusted by this machine (the agent only tolerates this when disableSslVerification is set)%s\n' "$YEL" "$RST" ;;
      *) detail "certificate validation: trusted by this machine" ;;
    esac
    # Leaf certificate expiry, when curl can export the chain (%{certs}, curl 7.88+).
    CERTS=$(curl -sk --noproxy '*' ${PIN[@]+"${PIN[@]}"} -m "$TIMEOUT" -o /dev/null -w '%{certs}' "$BASE" 2>/dev/null </dev/null)
    case "$CERTS" in
      -----BEGIN*)
        if command -v openssl >/dev/null 2>&1 && ! printf '%s\n' "$CERTS" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
          printf '         %sserver certificate is EXPIRED%s\n' "$RED" "$RST"
        fi ;;
    esac
    case "$(printf '%s' "$ISSUER" | tr 'A-Z' 'a-z')" in
      # Inspection products only; public CAs (including Cloudflare's) are not flagged.
      *zscaler*|*netskope*|*palo*alto*|*prisma*|*forcepoint*|*skyhigh*|*mcafee*|*bluecoat*|*blue\ coat*|*fortinet*|*fortigate*|*sophos*|*umbrella*|*check*point*|*"gateway ca"*)
        hint "the certificate is issued by an HTTPS-inspection product, so a TLS-inspecting proxy is in the path." ;;
    esac
  else
    result TLS 1 "handshake failed (curl exit $RC)"
    hint "Port may be plain HTTP, or a TLS-inspecting proxy / old TLS version is in the way."
  fi
fi

# --- 4. HTTPS /health --------------------------------------------------------
if [ -n "$IP" ]; then
  URL="https://${URLHOST}:${PORT}/health"
  BODY_FILE=$(mktemp "${TMPDIR:-/tmp}/ent-health.XXXXXX")
  # Like the agent, don't verify the server cert on /health; honour proxy env vars.
  OUT=$(curl -sS -k ${PIN[@]+"${PIN[@]}"} --connect-timeout "$TIMEOUT" -m "$TIMEOUT" -o "$BODY_FILE" \
        -w '%{http_code} %{time_total}' "$URL" 2>&1 </dev/null)
  RC=$?
  CODE=${OUT%% *}; TT=${OUT##* }
  if [ "$RC" -eq 0 ]; then
    MS=$(awk -v t="$TT" 'BEGIN{printf "%d", t*1000}')
    if [ "$CODE" -ge 200 ] && [ "$CODE" -lt 300 ]; then OK=0; else OK=1; fi
    result HEALTH "$OK" "GET $URL -> $CODE in $MS ms"
    BODY=$(head -c 300 "$BODY_FILE" | tr -d '\r' | tr '\n' ' ')
    [ "$(wc -c < "$BODY_FILE")" -gt 300 ] && BODY="${BODY}..."
    [ -n "$BODY" ] && detail "body: $BODY"
    [ "$OK" -eq 1 ] && hint "5xx/502/503 from a load balancer means the platform service behind it is down or unhealthy; 407 means an authenticating proxy."
  else
    result HEALTH 1 "GET $URL - $(printf '%s' "$OUT" | sed -n 's/^curl: ([0-9]*) //p' | head -1)"
  fi
  rm -f "$BODY_FILE"
fi

echo
if [ "$FAILED" -ne 0 ]; then
  printf '%sResult: one or more checks FAILED%s\n' "$RED" "$RST"; exit 1
fi
printf '%sResult: all checks passed%s\n' "$GRN" "$RST"; exit 0
