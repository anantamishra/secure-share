#!/usr/bin/env bash
# End-to-end test against a throwaway instance on a scratch data dir.
# Usage: bin/e2e.sh [port]   — exits non-zero if any assertion fails.
# Leaves its temp dir and its php -S process behind on purpose; both are
# disposable and cleaning them up automatically is not worth the footgun.
set -uo pipefail
PORT="${1:-8799}"; B="http://127.0.0.1:$PORT"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
FAIL=0
ok(){ if [ "$2" = "$3" ]; then printf '  ok   %-38s %s\n' "$1" "$2"; else printf '  FAIL %-38s got=%s want=%s\n' "$1" "$2" "$3"; FAIL=1; fi; }

cat > "$TMP/env" <<EOF
APP_KEY=$(php -r 'echo bin2hex(random_bytes(32));')
APP_URL=$B
DATA_DIR=$TMP/data
EOF
export APP_ENV_FILE="$TMP/env"
PW="$(php "$ROOT/bin/staff.php" add tester@instawp.com | sed -n 2p)"
php -S "127.0.0.1:$PORT" -t "$ROOT/public" "$ROOT/public/index.php" >"$TMP/srv.log" 2>&1 &
for _ in $(seq 1 15); do sleep 1; curl -sf -m 2 -o /dev/null "$B/healthz" && break; done

J="$TMP/jar"
csrf(){ grep -o 'name="csrf" value="[a-f0-9]\{32\}"' | head -1 | grep -o '[a-f0-9]\{32\}'; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

ok "health"                     "$(curl -s $B/healthz)" '{"ok":true}'
ok "dashboard needs login"      "$(code $B/)" "302"
ok "audit needs login"          "$(code $B/audit)" "302"

T=$(curl -s -c "$J" "$B/login" | csrf)
ok "bad password refused"       "$(curl -s -b $J -c $J -d "csrf=$T&email=tester@instawp.com&password=wrong" $B/login | grep -c 'Wrong email or password')" "1"
ok "csrf enforced on login"     "$(code -b $J -d 'csrf=bogus&email=tester@instawp.com&password=x' $B/login)" "400"
T=$(curl -s -b "$J" -c "$J" "$B/login" | csrf)
ok "login"                      "$(code -b $J -c $J -d "csrf=$T&email=tester@instawp.com&password=$PW" $B/login)" "302"

T=$(curl -s -b "$J" -c "$J" "$B/new" | csrf)
ok "no ssh/cpanel/ftp option"   "$(curl -s -b $J $B/new | grep -ciE 'value="(ssh|cpanel|ftp)')" "0"
ok "tier-1 gate: no bug ref"    "$(curl -s -b $J -d "csrf=$T&ticket_id=1&need=wp_admin&ttl=172800&failed_path=x&bug_ref=" $B/new | grep -c 'Every field is required')" "1"
ok "tier-1 gate: no path"       "$(curl -s -b $J -d "csrf=$T&ticket_id=1&need=wp_admin&ttl=172800&failed_path=&bug_ref=t1" $B/new | grep -c 'Every field is required')" "1"
ok "rejects unknown need"       "$(curl -s -b $J -d "csrf=$T&ticket_id=1&need=ssh&ttl=172800&failed_path=x&bug_ref=t1" $B/new | grep -c 'Every field is required')" "1"
ok "rejects unlisted ttl"       "$(curl -s -b $J -d "csrf=$T&ticket_id=1&need=wp_admin&ttl=99999999&failed_path=x&bug_ref=t1" $B/new | grep -c 'Every field is required')" "1"

LINK=$(curl -s -b "$J" -d "csrf=$T&ticket_id=3340&need=wp_admin&ttl=172800&failed_path=popup&bug_ref=tsk_a91f2e713b9e7587" "$B/new" | grep -o "$B/s/[a-f0-9]\{48\}" | head -1)
ok "link issued"                "$([ -n "$LINK" ] && echo yes || echo no)" "yes"
ok "bad token 404s"             "$(code $B/s/$(printf 'a%.0s' {1..48}))" "404"
ok "customer form is public"    "$(code $LINK)" "200"
ok "form warns off ssh"         "$(curl -s $LINK | grep -c 'never ask you for SSH')" "1"
ok "empty submit refused"       "$(curl -s -d 'login_url=&username=&password=' $LINK | grep -c 'Every field except Notes')" "1"

curl -s -o /dev/null --data-urlencode 'password=p@ss"w\ord«»é' --data-urlencode 'login_url=https://example.com/wp-login.php' --data-urlencode 'username=iwp_temp' --data-urlencode 'notes=n' "$LINK"
DB="$TMP/data/handoff.sqlite"
ok "link is single use"         "$(code $LINK)" "410"
ok "stored base64 only"         "$(sqlite3 "$DB" "SELECT ciphertext GLOB '[A-Za-z0-9+/=]*' FROM requests WHERE id=1")" "1"
ok "no plaintext on disk"       "$(grep -lc 'p@ss' "$DB"* 2>/dev/null | wc -l)" "0"

T=$(curl -s -b "$J" -c "$J" "$B/r/1" | csrf)
OUT=$(curl -s -b "$J" -d "csrf=$T&action=reveal" "$B/r/1")
ok "reveal returns secret"      "$(echo "$OUT" | grep -c 'p@ss&quot;w\\ord«»é')" "1"
ok "reveal flags rotation"      "$(echo "$OUT" | grep -c 'Rotation owed')" "1"
ok "rotation names app pw"      "$(echo "$OUT" | grep -c 'usermeta')" "1"
ok "burned: second read fails"  "$(curl -s -b $J -d "csrf=$T&action=reveal" $B/r/1 | grep -c 'Nothing to read')" "1"
ok "ciphertext destroyed"       "$(sqlite3 "$DB" "SELECT ifnull(ciphertext,'NULL') FROM requests WHERE id=1")" "NULL"
ok "read is audited"            "$(sqlite3 "$DB" "SELECT count(*) FROM audit WHERE action='credential.read' AND actor='tester@instawp.com'")" "1"

T=$(curl -s -b "$J" -c "$J" "$B/new" | csrf)
L2=$(curl -s -b "$J" -d "csrf=$T&ticket_id=9999&need=wp_app_password&ttl=3600&failed_path=x&bug_ref=t2" "$B/new" | grep -o "$B/s/[a-f0-9]\{48\}" | head -1)
curl -s -o /dev/null --data-urlencode 'password=expireme' --data-urlencode 'login_url=https://e.com' --data-urlencode 'username=u' "$L2"
sqlite3 "$DB" "UPDATE requests SET expires_at = 1 WHERE ticket_id='9999'"
php "$ROOT/bin/sweep.php" > /dev/null
ok "expired is purged"          "$(sqlite3 "$DB" "SELECT status||':'||ifnull(ciphertext,'NULL') FROM requests WHERE ticket_id='9999'")" "expired:NULL"
ok "expiry flags rotation"      "$(sqlite3 "$DB" "SELECT count(*) FROM audit WHERE action='rotation.flagged' AND ticket_id='9999'")" "1"
ok "expired link is dead"       "$(code $L2)" "410"

# --- ALLOW_INFRA_CREDENTIALS: off is the shipped default, on is the gated path ---
# The "no ssh option" and "rejects unknown need (ssh)" assertions above ran with the
# flag OFF, so they are the proof that the gate actually holds.
echo "ALLOW_INFRA_CREDENTIALS=1" >> "$TMP/env"
P2=$((PORT+50)); B2="http://127.0.0.1:$P2"; J2="$TMP/jar2"
sed -i "s#^APP_URL=.*#APP_URL=$B2#" "$TMP/env"
php -S "127.0.0.1:$P2" -t "$ROOT/public" "$ROOT/public/index.php" >"$TMP/srv2.log" 2>&1 &
for _ in $(seq 1 15); do sleep 1; curl -sf -m 2 -o /dev/null "$B2/healthz" && break; done
T=$(curl -s -c "$J2" "$B2/login" | csrf)
curl -s -b "$J2" -c "$J2" -o /dev/null -d "csrf=$T&email=tester@instawp.com&password=$PW" "$B2/login"
T=$(curl -s -b "$J2" -c "$J2" "$B2/new" | csrf)
ok "flag on: ssh is offered"     "$(curl -s -b $J2 $B2/new | grep -c 'value="ssh"')" "1"
ok "flag on: staff sees warning"  "$(curl -s -b $J2 $B2/new | grep -c 'SSH collection is switched ON')" "1"
L3=$(curl -s -b "$J2" -d "csrf=$T&ticket_id=7777&need=ssh&ttl=3600&failed_path=no+wp+route&bug_ref=t3" "$B2/new" | grep -o "$B2/s/[a-f0-9]\{48\}" | head -1)
ok "flag on: ssh link issued"     "$([ -n "$L3" ] && echo yes || echo no)" "yes"
ok "flag on: ssh fields shown"    "$(curl -s $L3 | grep -c 'name="host"')" "1"
ok "flag on: customer warned"     "$(curl -s $L3 | grep -c 'change this password once we are done')" "1"
ok "flag on: port is optional"    "$(curl -s -d 'host=1.2.3.4&username=u&password=p&port=' $L3 | grep -c 'Thank you')" "1"
DB2="$TMP/data/handoff.sqlite"
ID3=$(php -r '$d=new PDO("sqlite:'"$DB2"'"); foreach($d->query("SELECT id FROM requests WHERE ticket_id=\"7777\"") as $r) echo $r["id"];')
T=$(curl -s -b "$J2" -c "$J2" "$B2/r/$ID3" | csrf)
OUT3=$(curl -s -b "$J2" -d "csrf=$T&action=reveal" "$B2/r/$ID3")
ok "flag on: ssh secret returned"  "$(echo "$OUT3" | grep -c '1.2.3.4')" "1"
ok "flag on: ssh rotation wording" "$(echo "$OUT3" | grep -c 'server password')" "1"
ok "flag on: no usermeta wording"  "$(echo "$OUT3" | grep -c 'usermeta')" "0"

sed -i "s/^APP_KEY=.*/APP_KEY=$(php -r 'echo bin2hex(random_bytes(32));')/" "$TMP/env"
ok "wrong key -> loud failure"  "$(php -r 'require "'"$ROOT"'/src/bootstrap.php"; env_load(getenv("APP_ENV_FILE")); require "'"$ROOT"'/src/crypto.php"; try { unseal(base64_encode(random_bytes(24)), base64_encode(random_bytes(60))); echo "silent"; } catch (Throwable $e) { echo "threw"; }')" "threw"

echo; if [ $FAIL -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi; exit $FAIL
