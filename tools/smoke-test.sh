#!/usr/bin/env bash
# Boot a KestrelPro image and check the basics: DNS answers, a block-list domain is blocked,
# the admin UI serves, the engine is up and signed in to the DNS server.
# Usage: tools/smoke-test.sh IMAGE [PLATFORM]     e.g. tools/smoke-test.sh kestrelpro:dev linux/arm64
# Uses localhost-only ports 15353 (DNS), 18580 (admin) and 18590 (engine); cleans up after itself.
set -euo pipefail
IMAGE=${1:?usage: smoke-test.sh IMAGE [PLATFORM]}
PLATFORM=${2:-}
NAME=kestrelpro-smoke-$$
PW=smoke-$$-pw
fail() { echo "FAIL: $*"; docker logs --tail 40 "$NAME" 2>&1 | sed 's/^/    /'; exit 1; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" ${PLATFORM:+--platform "$PLATFORM"} \
  -p 127.0.0.1:15353:53/udp -p 127.0.0.1:15353:53/tcp -p 127.0.0.1:18580:80 -p 127.0.0.1:18590:8090 \
  -e FTLCONF_webserver_api_password="$PW" -e KESTREL_ENGINE_PORT=18590 \
  -e OLLAMA_URL=http://127.0.0.1:9 -e CADENCE=eco "$IMAGE" >/dev/null

# Emulated platforms start slowly.
for _ in $(seq 1 120); do
  docker logs "$NAME" 2>&1 | grep -q "Serving on" && break
  docker ps -q -f "name=$NAME" | grep -q . || fail "container exited"
  sleep 3
done
docker logs "$NAME" 2>&1 | grep -q "Serving on" || fail "engine didn't start within 6 minutes"
echo "ok: started ($(docker exec "$NAME" uname -m))"

resolve() { dig +short +time=3 +tries=3 -p 15353 @127.0.0.1 "$1" | tail -1; }
ip=$(resolve example.com); [ -n "$ip" ] && [ "$ip" != "0.0.0.0" ] || fail "example.com didn't resolve ($ip)"
echo "ok: DNS answers (example.com -> $ip)"
for _ in $(seq 1 20); do [ "$(resolve doubleclick.net)" = "0.0.0.0" ] && break; sleep 3; done
[ "$(resolve doubleclick.net)" = "0.0.0.0" ] || fail "doubleclick.net wasn't blocked by the default list"
echo "ok: block list active (doubleclick.net -> 0.0.0.0)"

code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18580/admin/login)
[ "$code" = 200 ] || fail "admin UI returned $code"
grep -q 'KestrelPro' <(curl -s http://127.0.0.1:18580/admin/login) || fail "admin UI isn't KestrelPro-branded"
echo "ok: admin UI (KestrelPro login page)"

curl -s http://127.0.0.1:18590/admin/api/kestrel/healthz | grep -q '"engine":"kestrelpro"' || fail "engine health check"
auth=$(curl -s -X POST http://127.0.0.1:18580/api/auth -d "{\"password\":\"$PW\"}")
sid=$(echo "$auth" | sed -n 's/.*"sid":"\([^"]*\)".*/\1/p')
[ -n "$sid" ] || fail "couldn't sign in to the admin API"
status=$(curl -s -b "sid=$sid" http://127.0.0.1:18590/admin/api/kestrel/status)
curl -s -X DELETE -H "X-FTL-SID: $sid" http://127.0.0.1:18580/api/auth >/dev/null
echo "$status" | grep -q '"reviewed_total"' || fail "engine status with an admin session: $status"
if echo "$status" | grep -q 'credentials\|rejected the engine'; then fail "engine can't sign in to the DNS server"; fi
echo "ok: engine accepts the admin session and reaches the DNS server"
echo "PASS: $IMAGE${PLATFORM:+ ($PLATFORM)}"
