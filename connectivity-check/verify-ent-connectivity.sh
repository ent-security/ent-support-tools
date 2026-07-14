#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ent Security, Inc.
#
# verify-ent-connectivity.sh
# ------------------------------------------------------------------------------
# Checks a workstation's connectivity to its ent tenant admin API and pinpoints
# the common "the portal loads but every request CORS-fails" cause: a corporate
# TLS-inspection / Secure Web Gateway / Zero-Trust proxy (Cloudflare, Zscaler,
# Netskope, Palo Alto, Forcepoint, ...) that re-signs HTTPS with a CA the browser
# does not trust.
#
# SAFE / READ-ONLY: it only issues GET and OPTIONS requests to *your own* tenant
# endpoint. It sends no credentials and changes nothing.
#
# USAGE
#   ./verify-ent-connectivity.sh <admin-api-url> [portal-origin]
#
#   <admin-api-url>  The API host your portal talks to. Copy it from a failing
#                    request in the browser DevTools -> Network tab. It looks like:
#                        https://admin.<cluster>.<tenant>.prod.ent.ai
#   [portal-origin]  The portal you log in to. Defaults to https://operator.ent.ai
#
#   Example:
#     ./verify-ent-connectivity.sh https://admin.abc123def456.11111111-2222-3333-4444-555555555555.prod.ent.ai
#
# REQUIRES: bash + curl (present on macOS and Linux; on Windows use Git Bash or WSL).
#           openssl is optional and only adds extra certificate detail.
#
# EXIT CODES: 0 = all clear   1 = problem found   2 = usage error
# ------------------------------------------------------------------------------

set -u

# --- pretty output -----------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLU=$'\033[36m'; RST=$'\033[0m'
else
  BOLD=""; RED=""; GRN=""; YEL=""; BLU=""; RST=""
fi
PROBLEM=0
section() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$RST"; }
pass()    { printf '  %s[ PASS ]%s %s\n' "$GRN" "$RST" "$1"; }
warn()    { printf '  %s[ WARN ]%s %s\n' "$YEL" "$RST" "$1"; PROBLEM=1; }
fail()    { printf '  %s[ FAIL ]%s %s\n' "$RED" "$RST" "$1"; PROBLEM=1; }
info()    { printf '  %s[ info ]%s %s\n' "$BLU" "$RST" "$1"; }

# --- args --------------------------------------------------------------------
if [ $# -lt 1 ]; then
  echo "usage: $0 <admin-api-url> [portal-origin]" >&2
  echo "       admin-api-url e.g. https://admin.<cluster>.<tenant>.prod.ent.ai" >&2
  exit 2
fi
ADMIN_INPUT="$1"
PORTAL_ORIGIN="${2:-https://operator.ent.ai}"

# normalize: strip scheme, path, and any :port -> bare host
HOST=$(printf '%s' "$ADMIN_INPUT" | sed -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#/.*$##' -e 's#:[0-9]*$##')
PORTAL_HOST=$(printf '%s' "$PORTAL_ORIGIN" | sed -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#/.*$##' -e 's#:[0-9]*$##')
# canonical origin (scheme + host) used for the CORS Origin header
PORTAL_ORIGIN="https://${PORTAL_HOST}"

printf '%sent connectivity check%s\n' "$BOLD" "$RST"
printf '  admin API host : %s\n' "$HOST"
printf '  portal origin  : %s\n' "$PORTAL_ORIGIN"
printf '  time (UTC)     : %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"

# =============================================================================
section "1. DNS resolution"
resolve_ips() {
  local h="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short "$h" A 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$'
  elif command -v host >/dev/null 2>&1; then
    host "$h" 2>/dev/null | awk '/has address/{print $NF}'
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$h" 2>/dev/null | awk '/^Address: /{print $2}'
  fi
}
IPS=$(resolve_ips "$HOST")
if [ -z "$IPS" ]; then
  # last resort: let curl resolve and report the IP it used
  IPS=$(curl -s --max-time 10 -o /dev/null -w '%{remote_ip}' "https://$HOST/" 2>/dev/null)
fi
if [ -z "$IPS" ]; then
  fail "could not resolve $HOST — DNS is blocked/filtered on this network"
else
  CGNAT=0
  for ip in $IPS; do
    o1=${ip%%.*}; r=${ip#*.}; o2=${r%%.*}
    if [ "$o1" = "100" ] && [ "$o2" -ge 64 ] 2>/dev/null && [ "$o2" -le 127 ] 2>/dev/null; then CGNAT=1; fi
  done
  info "resolves to: $(printf '%s ' $IPS)"
  if [ "$CGNAT" -eq 1 ]; then
    warn "IP is in 100.64.0.0/10 (carrier-grade NAT). Real ent endpoints are public AWS IPs."
    warn "  -> your traffic is being routed through a Zero-Trust/SASE agent (e.g. Cloudflare WARP, Zscaler)."
  else
    pass "resolves to public address(es)"
  fi
fi

# =============================================================================
section "2. TCP + TLS (as a strict client, like the browser)"
# strict = no -k: fails if the presented cert is not trusted (this is what a browser does)
# Only the HTTP status is used downstream; STRICT_RC (curl's exit code) drives the
# diagnosis — exit 60 already distinguishes an untrusted/intercepted cert (see below).
S_CODE=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' "https://$HOST/" 2>/dev/null)
STRICT_RC=$?

case "$STRICT_RC" in
  0)  pass "TCP+TLS OK; server returned HTTP $S_CODE (any status = reached the server); cert trusted by this machine" ;;
  6)  fail "DNS resolution failed (curl 6) — host blocked at the resolver" ;;
  7)  fail "connection refused (curl 7) — a firewall/proxy is rejecting port 443 to this host" ;;
  28) fail "connection timed out (curl 28) — egress firewall is black-holing this host" ;;
  35) fail "TLS handshake failed (curl 35) — a proxy is resetting the TLS connection to this host" ;;
  60) warn "cert NOT trusted by this machine (curl 60) — TLS interception with an untrusted CA (see step 3)" ;;
  56) fail "connection reset mid-stream (curl 56) — a proxy/firewall dropped the connection" ;;
  *)  fail "curl exit $STRICT_RC connecting to https://$HOST/ (see: curl -v https://$HOST/)" ;;
esac

# =============================================================================
section "3. Certificate issuer  (detects TLS inspection / MITM)"
# -k so we can always read the presented cert, even if this machine doesn't trust it.
VERB=$(curl -sv -k --max-time 15 -o /dev/null "https://$HOST/" 2>&1)
ISSUER=$(printf '%s\n' "$VERB"  | sed -n 's/^\* .*issuer: //p'  | head -1 | tr -d '\r')
SUBJECT=$(printf '%s\n' "$VERB" | sed -n 's/^\* .*subject: //p' | head -1 | tr -d '\r')
EXPIRE=$(printf '%s\n' "$VERB"  | sed -n 's/^\* .*expire date: //p' | head -1 | tr -d '\r')
SRV_HDR=$(printf '%s\n' "$VERB" | grep -i '^< server:' | head -1 | tr -d '\r')
CF_TEAM=$(printf '%s\n' "$VERB" | grep -i '^< cf-team:' | head -1)
CF_DUR=$(printf '%s\n'  "$VERB" | grep -i 'server-timing:.*cfreqdur' | head -1)

[ -n "$SUBJECT" ] && info "cert subject : $SUBJECT"
[ -n "$EXPIRE" ]  && info "cert expires : $EXPIRE"
[ -n "$SRV_HDR" ] && info "origin server: $(printf '%s' "$SRV_HDR" | sed 's/^< //I')"

VENDOR=""
EDGE="unknown"
issuer_lc=$(printf '%s' "$ISSUER" | tr 'A-Z' 'a-z')
if [ -z "$ISSUER" ]; then
  warn "could not read the server certificate (connection likely blocked before TLS)"
  EDGE="blocked"
else
  info "cert issuer  : $ISSUER"
  case "$issuer_lc" in
    *amazon*)                        EDGE="direct" ;;
    *cloudflare*)                    EDGE="inspect"; VENDOR="Cloudflare Zero Trust" ;;
    *zscaler*)                       EDGE="inspect"; VENDOR="Zscaler" ;;
    *netskope*)                      EDGE="inspect"; VENDOR="Netskope" ;;
    *palo*alto*|*prisma*)            EDGE="inspect"; VENDOR="Palo Alto" ;;
    *forcepoint*)                    EDGE="inspect"; VENDOR="Forcepoint" ;;
    *mcafee*|*skyhigh*)              EDGE="inspect"; VENDOR="Skyhigh/McAfee" ;;
    *symantec*|*broadcom*|*bluecoat*|*blue?coat*) EDGE="inspect"; VENDOR="Symantec/BlueCoat" ;;
    *fortinet*|*fortigate*)          EDGE="inspect"; VENDOR="Fortinet" ;;
    *sophos*)                        EDGE="inspect"; VENDOR="Sophos" ;;
    *cisco*|*umbrella*|*opendns*)    EDGE="inspect"; VENDOR="Cisco Umbrella" ;;
    *check*point*)                   EDGE="inspect"; VENDOR="Check Point" ;;
    *)                               EDGE="inspect"; VENDOR="a corporate/unknown CA" ;;
  esac

  if [ "$EDGE" = "direct" ]; then
    pass "issued by Amazon — you are connecting DIRECTLY to the ent endpoint (no interception)"
  else
    warn "cert is re-signed by ${VENDOR} — a TLS-inspection proxy is in the path (this is the usual culprit)"
  fi
fi
[ -n "$CF_TEAM" ] || [ -n "$CF_DUR" ] && info "Cloudflare Zero Trust headers present in response (cf-team / cfReqDur)"

# =============================================================================
section "4. CORS preflight  (is the ent server configured for your portal?)"
# -k so local trust doesn't mask the server's actual headers.
CORS=$(curl -s -k --max-time 15 -o /dev/null -D - -X OPTIONS \
  -H "Origin: $PORTAL_ORIGIN" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: authorization" \
  "https://$HOST/admin/users/search?size=1" 2>/dev/null)
CORS_STATUS=$(printf '%s\n' "$CORS" | sed -n '1s#.*\([0-9][0-9][0-9]\).*#\1#p' | head -1)
ACAO=$(printf '%s\n' "$CORS" | awk 'BEGIN{IGNORECASE=1}/^access-control-allow-origin:/{sub(/^[^:]*:[ ]*/,"");print;exit}' | tr -d '\r')
if [ -z "$CORS" ]; then
  warn "no response to the CORS preflight (blocked before reaching the server)"
elif [ "$ACAO" = "$PORTAL_ORIGIN" ] || [ "$ACAO" = "*" ]; then
  pass "server allows your origin (Access-Control-Allow-Origin: $ACAO, preflight HTTP ${CORS_STATUS:-?})"
elif [ -n "$ACAO" ]; then
  warn "server allows a DIFFERENT origin ($ACAO) than your portal ($PORTAL_ORIGIN) — are you on the right portal URL?"
else
  info "preflight returned HTTP ${CORS_STATUS:-?} without an Allow-Origin header via this path"
  info "  (if step 3 showed interception, the proxy may be stripping/altering it)"
fi

# =============================================================================
section "5. Portal reachability  (control check)"
P_CODE=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' "$PORTAL_ORIGIN/" 2>/dev/null)
P_RC=$?
if [ "$P_RC" -eq 0 ] && [ -n "$P_CODE" ] && [ "$P_CODE" != "000" ]; then
  pass "portal $PORTAL_ORIGIN reachable (HTTP $P_CODE)"
  if [ "$EDGE" = "inspect" ] || [ "$EDGE" = "blocked" ]; then
    info "portal loads but the admin API is intercepted/blocked -> the failure is specific to the API host, not the network in general"
  fi
else
  warn "portal $PORTAL_ORIGIN not reachable either (curl $P_RC / HTTP ${P_CODE:-none})"
fi

# =============================================================================
section "VERDICT"
if [ "$EDGE" = "direct" ] && [ "$STRICT_RC" = "0" ]; then
  pass "Connectivity is clean end-to-end from this machine."
  echo
  echo "  If the browser STILL fails while this script passes, the problem is browser-specific:"
  echo "    - a browser extension / content blocker, or"
  echo "    - Firefox using its own certificate store (see the browser note below)."
elif [ "$EDGE" = "inspect" ]; then
  echo "  ${BOLD}Root cause: a TLS-inspection proxy (${VENDOR}) is re-signing HTTPS to the ent API host.${RST}"
  echo
  if [ "$STRICT_RC" = "0" ]; then
    echo "  This machine (curl/OS) TRUSTS that proxy CA, so curl works. But a browser will fail"
    echo "  UNLESS the browser also trusts the proxy CA. Firefox is the usual victim: it keeps its"
    echo "  OWN certificate store, separate from the OS/keychain, so it rejects the re-signed cert and"
    echo "  every request shows \"CORS request did not succeed / NS_ERROR_DOM_BAD_URI\"."
  else
    echo "  This machine does NOT trust the proxy CA (curl also failed), so nothing can connect until"
    echo "  the proxy CA is trusted or interception is disabled for this host."
  fi
  echo
  echo "  ${BOLD}Fix (fastest, per user):${RST}"
  echo "    - Firefox: about:config -> set  security.enterprise_roots.enabled = true"
  echo "               (or import the proxy's CA under Settings > Privacy & Security > Certificates > Authorities)"
  echo "    - Or open the portal in Chrome/Edge/Safari (they use the OS trust store)."
  echo "    - Or test from off the corporate network (e.g. a phone hotspot) to confirm."
  echo
  echo "  ${BOLD}Fix (proper, per IT / proxy admin):${RST}"
  echo "    - Add a Do-Not-Inspect / TLS-decryption bypass for  *.prod.ent.ai  so the genuine"
  echo "      Amazon-issued certificate reaches the browser untouched (no per-user CA work), and/or"
  echo "    - Distribute the proxy's inspection CA to browsers via managed policy (incl. Firefox)."
  echo "    - Ensure no web-filter/DLP policy blocks  *.prod.ent.ai."
else
  echo "  ${BOLD}The ent API host is not reachable from this machine.${RST}"
  echo "  A firewall / DNS filter / proxy on this network is blocking it. Ask IT to allow  *.prod.ent.ai"
  echo "  (host: $HOST) and re-run. See the FAIL lines above for the exact stage that broke."
fi

echo
echo "  ${BOLD}Browser note:${RST} this script tests the OS/curl network path. Browsers can differ —"
echo "  especially Firefox, which does not use the OS certificate store by default. Always confirm the"
echo "  fix in the actual browser, and for a deeper look use the browser's DevTools > Network tab."
echo

exit $PROBLEM
