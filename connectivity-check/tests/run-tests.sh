#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Tests for test-platform-connectivity.sh against local servers (no network needed).
# Starts a self-signed HTTPS server and a plain HTTP server on 127.0.0.1, then
# checks the script's stage results and exit codes.
#
# REQUIRES: bash, curl, openssl, python3.
# USAGE:    ./tests/run-tests.sh [bash-binary]   (e.g. /bin/bash to test bash 3.2)

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../test-platform-connectivity.sh"
BASH_BIN="${1:-bash}"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ent-conn-test.XXXXXX")
PIDS=()
cleanup() { for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 2 -subj "/CN=localhost" >/dev/null 2>&1 || { echo "openssl failed"; exit 1; }

cat > "$WORK/server.py" <<'PY'
import http.server, ssl, sys
mode, status, portfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}' if status == 200 else b'{"status":"unavailable"}'
        self.send_response(status if self.path == "/health" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
if mode == "tls":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[4], sys.argv[5])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
PY

start() { # start <name> <mode> <status>  (runs in this shell so PIDS is kept)
  python3 "$WORK/server.py" "$2" "$3" "$WORK/$1.port" "$WORK/cert.pem" "$WORK/key.pem" >/dev/null 2>&1 &
  PIDS+=($!); disown "$!" 2>/dev/null
}
wait_port() { for _ in $(seq 1 50); do [ -s "$WORK/$1.port" ] && break; sleep 0.1; done; cat "$WORK/$1.port"; }
start ok tls 200; start bad tls 503; start plain http 200
OK_PORT=$(wait_port ok); BAD_PORT=$(wait_port bad); HTTP_PORT=$(wait_port plain)
# A port that was just free: bind and release it.
CLOSED_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

PASSES=0; FAILS=0
check() { # check <name> <expected-exit> <grep-pattern>... -- <script args>
  local name="$1" want="$2"; shift 2
  local pats=()
  while [ "$1" != "--" ]; do pats+=("$1"); shift; done; shift
  local out rc
  out=$("$BASH_BIN" "$SCRIPT" "$@" 2>&1); rc=$?
  local ok=1
  [ "$rc" -eq "$want" ] || ok=0
  for p in ${pats[@]+"${pats[@]}"}; do printf '%s\n' "$out" | grep -Eq -- "$p" || { ok=0; echo "    missing: $p"; }; done
  if [ "$ok" -eq 1 ]; then PASSES=$((PASSES+1)); echo "ok   - $name"
  else FAILS=$((FAILS+1)); echo "FAIL - $name (exit $rc, want $want)"; printf '%s\n' "$out" | sed 's/^/    | /'; fi
}

check "healthy platform by IP" 0 \
  'PASS \] DNS - 127.0.0.1 is an IP literal' 'PASS \] TCP - connected to 127.0.0.1' \
  "PASS \] TLS - .*subject 'CN=localhost'" 'NOT trusted by this machine' \
  'PASS \] HEALTH - GET https://127.0.0.1:[0-9]+/health -> 200' 'body: \{"status":"ok"\}' 'all checks passed' \
  -- -a 127.0.0.1 -p "$OK_PORT" -t 3

check "healthy platform by hostname" 0 'PASS \] DNS - localhost -> ' 'PASS \] HEALTH' \
  -- --address localhost --port "$OK_PORT" --timeout 3

printf '{"servers":[{"address":"127.0.0.1","port":%s}]}\n' "$OK_PORT" > "$WORK/config.json"
check "address and port from agent config" 0 "check: 127.0.0.1:$OK_PORT" 'all checks passed' \
  -- -c "$WORK/config.json" -t 3

check "unhealthy platform (503)" 1 'FAIL \] HEALTH - .*-> 503' 'load balancer' 'one or more checks FAILED' \
  -- -a 127.0.0.1 -p "$BAD_PORT" -t 3

check "plain HTTP port fails TLS" 1 'PASS \] TCP' 'FAIL \] TLS - handshake failed' 'plain HTTP' \
  -- -a 127.0.0.1 -p "$HTTP_PORT" -t 3

check "nothing listening" 1 'FAIL \] TCP - 127.0.0.1:[0-9]+ - connection refused' \
  -- -a 127.0.0.1 -p "$CLOSED_PORT" -t 3

check "unresolvable host" 1 'FAIL \] DNS - could not resolve' 'DNS servers:' \
  -- -a ent-platform.invalid -t 3

check "usage: no address" 2 'Specify --address or --config' --
check "usage: bad port" 2 'invalid port' -- -a 127.0.0.1 -p abc
check "usage: unreadable config" 2 'cannot read config file' -- -c "$WORK/missing.json"
printf '{"servers":[]}\n' > "$WORK/empty.json"
check "usage: config without servers" 2 'no servers\[0\].address' -- -c "$WORK/empty.json"

echo
echo "$PASSES passed, $FAILS failed ($("$BASH_BIN" --version | head -1))"
[ "$FAILS" -eq 0 ]
