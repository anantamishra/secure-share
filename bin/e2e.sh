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
# BSD sed (macOS) requires a suffix argument to -i; GNU sed does not.
sedi() {
    if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi
}

cat > "$TMP/env" <<EOF
APP_KEY=$(php -r 'echo bin2hex(random_bytes(32));')
APP_URL=$B
DATA_DIR=$TMP/data
ALLOW_INFRA_CREDENTIALS=0
EOF
export APP_ENV_FILE="$TMP/env"
PW="$(php "$ROOT/bin/staff.php" add tester@instawp.com | sed -n 2p)"
# PHP_CLI_SERVER_WORKERS: php -S is single-threaded by default, which silently makes
# every concurrency assertion below vacuous -- requests would just queue and each one
# would "win" its race alone. With workers the single-use test can actually fail.
PHP_CLI_SERVER_WORKERS=8 php -S "127.0.0.1:$PORT" -t "$ROOT/public" "$ROOT/public/index.php" >"$TMP/srv.log" 2>&1 &
for _ in $(seq 1 15); do sleep 1; curl -sf -m 2 -o /dev/null "$B/healthz" && break; done

J="$TMP/jar"
csrf(){ grep -o 'name="csrf" value="[a-f0-9]\{32\}"' | head -1 | grep -o '[a-f0-9]\{32\}'; }
code(){ curl -s -m 20 -o /dev/null -w '%{http_code}' "$@"; }

ok "health"                     "$(curl -s -m 20 $B/healthz)" '{"ok":true}'
ok "dashboard needs login"      "$(code $B/)" "302"
ok "audit needs login"          "$(code $B/audit)" "302"

T=$(curl -s -m 20 -c "$J" "$B/login" | csrf)
ok "bad password refused"       "$(curl -s -m 20 -b $J -c $J -d "csrf=$T&email=tester@instawp.com&password=wrong" $B/login | grep -c 'Wrong email or password')" "1"
ok "csrf enforced on login"     "$(code -b $J -d 'csrf=bogus&email=tester@instawp.com&password=x' $B/login)" "400"
T=$(curl -s -m 20 -b "$J" -c "$J" "$B/login" | csrf)
ok "login"                      "$(code -b $J -c $J -d "csrf=$T&email=tester@instawp.com&password=$PW" $B/login)" "302"

T=$(curl -s -m 20 -b "$J" -c "$J" "$B/new" | csrf)
ok "no ssh/cpanel/ftp option"   "$(curl -s -m 20 -b $J $B/new | grep -ciE 'value="(ssh|cpanel|ftp)')" "0"
ok "tier-1 gate: no bug ref"    "$(curl -s -m 20 -b $J -d "csrf=$T&ticket_id=1&need=wp_admin&ttl=172800&failed_path=x&bug_ref=" $B/new | grep -c 'Every field is required')" "1"
ok "tier-1 gate: no path"       "$(curl -s -m 20 -b $J -d "csrf=$T&ticket_id=1&need=wp_admin&ttl=172800&failed_path=&bug_ref=t1" $B/new | grep -c 'Every field is required')" "1"
ok "rejects unknown need"       "$(curl -s -m 20 -b $J -d "csrf=$T&ticket_id=1&need=ssh&ttl=172800&failed_path=x&bug_ref=t1" $B/new | grep -c 'Every field is required')" "1"
ok "rejects unlisted ttl"       "$(curl -s -m 20 -b $J -d "csrf=$T&ticket_id=1&need=wp_admin&ttl=99999999&failed_path=x&bug_ref=t1" $B/new | grep -c 'Every field is required')" "1"

LINK=$(curl -s -m 20 -b "$J" -d "csrf=$T&ticket_id=3340&need=wp_admin&ttl=172800&failed_path=popup&bug_ref=tsk_a91f2e713b9e7587" "$B/new" | grep -o "$B/s/[a-f0-9]\{48\}" | head -1)
ok "link issued"                "$([ -n "$LINK" ] && echo yes || echo no)" "yes"
ok "bad token 404s"             "$(code $B/s/$(printf 'a%.0s' {1..48}))" "404"
ok "customer form is public"    "$(code $LINK)" "200"
ok "no never-ask box"           "$(curl -s -m 20 $LINK | grep -c 'never ask you')" "0"
ok "share picker on form"       "$(curl -s -m 20 $LINK | grep -c 'name="share"')" "3"
ok "empty submit refused"       "$(curl -s -m 20 -d 'login_url=&username=&password=' $LINK | grep -c 'Every field except Notes')" "1"

curl -s -m 20 -o /dev/null --data-urlencode 'password=p@ss"w\ord«»é' --data-urlencode 'login_url=https://example.com/wp-login.php' --data-urlencode 'username=iwp_temp' --data-urlencode 'notes=n' "$LINK"
DB="$TMP/data/handoff.sqlite"
ok "link is single use"         "$(code $LINK)" "410"
ok "stored base64 only"         "$(sqlite3 "$DB" "SELECT ciphertext NOT GLOB '*[^A-Za-z0-9+/=]*' FROM requests WHERE id=1")" "1"
ok "no plaintext on disk"       "$(grep -q 'p@ss' "$DB"* 2>/dev/null && echo 1 || echo 0)" "0"

T=$(curl -s -m 20 -b "$J" -c "$J" "$B/r/1" | csrf)
OUT=$(curl -s -m 20 -b "$J" -d "csrf=$T&action=reveal" "$B/r/1")
ok "reveal returns secret"      "$(echo "$OUT" | grep -c 'p@ss&quot;w\\ord«»é')" "1"
ok "reveal flags rotation"      "$(echo "$OUT" | grep -c 'Rotation owed')" "1"
ok "rotation names app pw"      "$(echo "$OUT" | grep -c 'usermeta')" "1"
ok "burned: second read fails"  "$(curl -s -m 20 -b $J -d "csrf=$T&action=reveal" $B/r/1 | grep -c 'Nothing to read')" "1"
ok "ciphertext destroyed"       "$(sqlite3 "$DB" "SELECT ifnull(ciphertext,'NULL') FROM requests WHERE id=1")" "NULL"
ok "read is audited"            "$(sqlite3 "$DB" "SELECT count(*) FROM audit WHERE action='credential.read' AND actor='tester@instawp.com'")" "1"
ok "missing share is once"      "$(sqlite3 "$DB" "SELECT share FROM requests WHERE id=1")" "once"

T=$(curl -s -m 20 -b "$J" -c "$J" "$B/new" | csrf)
LKEEP=$(curl -s -m 20 -b "$J" -d "csrf=$T&ticket_id=4401&need=wp_admin&ttl=3600&failed_path=x&bug_ref=keep" "$B/new" | grep -o "$B/s/[a-f0-9]\{48\}" | head -1)
curl -s -m 20 -o /dev/null --data-urlencode 'password=keepme' --data-urlencode 'login_url=https://k.com' --data-urlencode 'username=u' --data-urlencode 'share=1d' "$LKEEP"
KID=$(sqlite3 "$DB" "SELECT id FROM requests WHERE ticket_id='4401'")
ok "timed share stored"         "$(sqlite3 "$DB" "SELECT share FROM requests WHERE id=$KID")" "1d"
ok "timed expiry ~1 day"        "$(sqlite3 "$DB" "SELECT CASE WHEN expires_at-submitted_at BETWEEN 86390 AND 86410 THEN 1 ELSE 0 END FROM requests WHERE id=$KID")" "1"
T=$(curl -s -m 20 -b "$J" -c "$J" "$B/r/$KID" | csrf)
ok "timed first reveal"         "$(curl -s -m 20 -b $J -d "csrf=$T&action=reveal" $B/r/$KID | grep -c 'keepme')" "1"
ok "timed ciphertext kept"      "$(sqlite3 "$DB" "SELECT CASE WHEN ciphertext IS NULL THEN 0 ELSE 1 END FROM requests WHERE id=$KID")" "1"
ok "timed still submitted"      "$(sqlite3 "$DB" "SELECT status FROM requests WHERE id=$KID")" "submitted"
ok "timed second reveal"        "$(curl -s -m 20 -b $J -d "csrf=$T&action=reveal" $B/r/$KID | grep -c 'keepme')" "1"
ok "timed reread audited"       "$(sqlite3 "$DB" "SELECT count(*) FROM audit WHERE action='credential.reread' AND request_id=$KID")" "1"

T=$(curl -s -m 20 -b "$J" -c "$J" "$B/new" | csrf)
L2=$(curl -s -m 20 -b "$J" -d "csrf=$T&ticket_id=9999&need=wp_app_password&ttl=3600&failed_path=x&bug_ref=t2" "$B/new" | grep -o "$B/s/[a-f0-9]\{48\}" | head -1)
curl -s -m 20 -o /dev/null --data-urlencode 'password=expireme' --data-urlencode 'login_url=https://e.com' --data-urlencode 'username=u' "$L2"
sqlite3 "$DB" "UPDATE requests SET expires_at = 1 WHERE ticket_id='9999'"
php "$ROOT/bin/sweep.php" > /dev/null
ok "expired is purged"          "$(sqlite3 "$DB" "SELECT status||':'||ifnull(ciphertext,'NULL') FROM requests WHERE ticket_id='9999'")" "expired:NULL"
ok "expiry flags rotation"      "$(sqlite3 "$DB" "SELECT count(*) FROM audit WHERE action='rotation.flagged' AND ticket_id='9999'")" "1"
ok "expired link is dead"       "$(code $L2)" "410"

# --- staff JSON API -----------------------------------------------------------
TOKEN=$(php "$ROOT/bin/staff.php" token tester@instawp.com | sed -n 2p)
ok "api token minted"           "$([ -n "$TOKEN" ] && echo yes || echo no)" "yes"
ok "api needs bearer"           "$(code $B/api/v1/me)" "401"
ok "api rejects junk token"     "$(code -H 'Authorization: Bearer iwp_0000000000000000000000000000000000000000000000000000000000000000' $B/api/v1/me)" "401"
ok "api me"                     "$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" $B/api/v1/me | grep -c 'tester@instawp.com')" "1"
ok "api rejects ssh when off"   "$(code -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"ticket_id":"1","need":"ssh","ttl":3600,"failed_path":"x","bug_ref":"t"}' $B/api/v1/requests)" "400"
ok "api tier-1 gate"            "$(code -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"ticket_id":"1","need":"wp_admin","ttl":3600,"failed_path":"x"}' $B/api/v1/requests)" "400"
AR=$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"ticket_id":"8801","need":"wp_admin","ttl":3600,"failed_path":"api","bug_ref":"api1"}' "$B/api/v1/requests")
ok "api mint pending"           "$(echo "$AR" | grep -c '"status":"pending"')" "1"
ALINK=$(echo "$AR" | grep -o "$B/s/[a-f0-9]\{48\}" | head -1)
ok "api link issued"            "$([ -n "$ALINK" ] && echo yes || echo no)" "yes"
AID=$(echo "$AR" | php -r '$j=json_decode(stream_get_contents(STDIN),true); echo $j["data"]["id"]??"";')
curl -s -m 20 -o /dev/null --data-urlencode 'password=apipw' --data-urlencode 'login_url=https://a.com' --data-urlencode 'username=u' "$ALINK"
ok "api reveal secret"          "$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" -X POST "$B/api/v1/requests/$AID/reveal" | grep -c 'apipw')" "1"
ok "api second reveal 409"      "$(code -H "Authorization: Bearer $TOKEN" -X POST $B/api/v1/requests/$AID/reveal)" "409"

AR2=$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"ticket_id":"8802","need":"wp_admin","ttl":3600,"failed_path":"api","bug_ref":"api2"}' "$B/api/v1/requests")
ALINK2=$(echo "$AR2" | grep -o "$B/s/[a-f0-9]\{48\}" | head -1)
AID2=$(echo "$AR2" | php -r '$j=json_decode(stream_get_contents(STDIN),true); echo $j["data"]["id"]??"";')
curl -s -m 20 -o /dev/null --data-urlencode 'password=keepapi' --data-urlencode 'login_url=https://a.com' --data-urlencode 'username=u' --data-urlencode 'share=2d' "$ALINK2"
ok "api timed share 2d"         "$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" "$B/api/v1/requests/$AID2" | grep -c '"share":"2d"')" "1"
ok "api timed first reveal"     "$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" -X POST "$B/api/v1/requests/$AID2/reveal" | grep -c 'keepapi')" "1"
ok "api timed second reveal"    "$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" -X POST "$B/api/v1/requests/$AID2/reveal" | grep -c 'keepapi')" "1"
ok "api list by ticket"         "$(curl -s -m 20 -H "Authorization: Bearer $TOKEN" "$B/api/v1/requests?ticket_id=8801" | grep -c '"status":"read"')" "1"
php "$ROOT/bin/staff.php" add apigone@instawp.com > /dev/null
TOK2=$(php "$ROOT/bin/staff.php" token apigone@instawp.com | sed -n 2p)
ok "api other token works"      "$(code -H "Authorization: Bearer $TOK2" $B/api/v1/me)" "200"
php "$ROOT/bin/staff.php" disable apigone@instawp.com > /dev/null
ok "api disabled token 401"     "$(code -H "Authorization: Bearer $TOK2" $B/api/v1/me)" "401"

# --- ALLOW_INFRA_CREDENTIALS: SSH ships ON; 0 is the off-switch ---
# The "no ssh option" and "rejects unknown need (ssh)" assertions above ran with the
# flag forced OFF, so they are the proof that the off-switch actually holds.
sedi "s/^ALLOW_INFRA_CREDENTIALS=.*/ALLOW_INFRA_CREDENTIALS=1/" "$TMP/env"
P2=$((PORT+50)); B2="http://127.0.0.1:$P2"; J2="$TMP/jar2"
sedi "s#^APP_URL=.*#APP_URL=$B2#" "$TMP/env"
PHP_CLI_SERVER_WORKERS=8 php -S "127.0.0.1:$P2" -t "$ROOT/public" "$ROOT/public/index.php" >"$TMP/srv2.log" 2>&1 &
for _ in $(seq 1 15); do sleep 1; curl -sf -m 2 -o /dev/null "$B2/healthz" && break; done
T=$(curl -s -m 20 -c "$J2" "$B2/login" | csrf)
curl -s -m 20 -b "$J2" -c "$J2" -o /dev/null -d "csrf=$T&email=tester@instawp.com&password=$PW" "$B2/login"
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new" | csrf)
ok "flag on: ssh is offered"     "$(curl -s -m 20 -b $J2 $B2/new | grep -c 'value="ssh"')" "1"
ok "flag on: staff sees warning"  "$(curl -s -m 20 -b $J2 $B2/new | grep -c 'SSH / SFTP is a last resort')" "1"
L3=$(curl -s -m 20 -b "$J2" -d "csrf=$T&ticket_id=7777&need=ssh&ttl=3600&failed_path=no+wp+route&bug_ref=t3" "$B2/new" | grep -o "$B2/s/[a-f0-9]\{48\}" | head -1)
ok "flag on: ssh link issued"     "$([ -n "$L3" ] && echo yes || echo no)" "yes"
ok "flag on: ssh fields shown"    "$(curl -s -m 20 $L3 | grep -c 'name="host"')" "1"
ok "flag on: customer warned"     "$(curl -s -m 20 $L3 | grep -c 'change this password once we are done')" "1"
ok "flag on: port is optional"    "$(curl -s -m 20 -d 'host=1.2.3.4&username=u&password=p&port=' $L3 | grep -c 'Thank you')" "1"
DB2="$TMP/data/handoff.sqlite"
ID3=$(php -r '$d=new PDO("sqlite:'"$DB2"'"); foreach($d->query("SELECT id FROM requests WHERE ticket_id=\"7777\"") as $r) echo $r["id"];')
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/r/$ID3" | csrf)
OUT3=$(curl -s -m 20 -b "$J2" -d "csrf=$T&action=reveal" "$B2/r/$ID3")
ok "flag on: ssh secret returned"  "$(echo "$OUT3" | grep -c '1.2.3.4')" "1"
ok "flag on: ssh rotation wording" "$(echo "$OUT3" | grep -c 'server password')" "1"
ok "flag on: no usermeta wording"  "$(echo "$OUT3" | grep -c 'usermeta')" "0"

# --- regression guards added after the 2026-09-07 security review ------------------
# Every assertion below covers an axis the original 38 could not express. They were
# entirely sequential (so no concurrency bug was reachable), never sent an
# X-Forwarded-For, never disabled a staff account, and never let a link expire without
# being submitted. A green run without these said nothing about any of it.
# These run last: the throttle assertions deliberately exhaust a bucket.

# B1 -- burn-on-read must hold when two engineers click at the same instant.
# The old code read the status, checked it, then wrote unconditionally, so both won.
# Three things this needs to be a real test, each learned by watching it pass wrongly:
#   - distinct logins (PHP serialises requests that share one session file),
#   - PHP_CLI_SERVER_WORKERS on the server (otherwise requests just queue), and
#   - curl_multi rather than shell background jobs, which do not start closely enough
#     together to reach the compare-and-set. Verified by deleting the CAS and watching
#     this assertion go red.
sqlite3 "$DB2" "DELETE FROM throttle"   # harness only: these logins are not an attack
RACERS=""
for i in $(seq 1 12); do
  PWX=$(php "$ROOT/bin/staff.php" add "race$i@instawp.com" | sed -n 2p)
  Tt=$(curl -s -m 20 -c "$TMP/jr$i" "$B2/login" | csrf)
  curl -s -m 20 -o /dev/null -b "$TMP/jr$i" -c "$TMP/jr$i" -d "csrf=$Tt&email=race$i@instawp.com&password=$PWX" "$B2/login"
done

RACEWINS=0
for round in 1 2 3; do
  T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new" | csrf)
  LR=$(curl -s -m 20 -b "$J2" -d "csrf=$T&ticket_id=515$round&need=wp_admin&ttl=3600&failed_path=race&bug_ref=b1" "$B2/new" | grep -o "$B2/s/[a-f0-9]\{48\}" | head -1)
  curl -s -m 20 -o /dev/null --data-urlencode "password=RACEWINNER$round" --data-urlencode 'login_url=https://r.com' --data-urlencode 'username=u' "$LR"
  RID=$(sqlite3 "$DB2" "SELECT id FROM requests WHERE ticket_id='515$round'")
  PAIRS=""
  for i in $(seq 1 12); do
    C=$(curl -s -m 20 -b "$TMP/jr$i" -c "$TMP/jr$i" "$B2/r/$RID" | csrf)
    PAIRS="$PAIRS $TMP/jr$i:$C"
  done
  HITS=$(php -d display_errors=stderr "$ROOT/bin/race.php" "$B2/r/$RID" "RACEWINNER$round" $PAIRS | tail -n 1 | tr -d '[:space:]')
  RACEWINS=$((RACEWINS + HITS))
done
# 3 requests, 12 simultaneous readers each: exactly 3 reads in total, never 4.
# NOTE: this is a smoke test, not the falsifier. Removing the compare-and-set does NOT
# make it fail on this hardware -- the losers reach the route's cheap status pre-check
# after the winner has committed, so the guard is never exercised over HTTP. Verified by
# deleting the CAS and watching all 49 assertions still pass. The real falsifier is the
# direct claim assertion below; keep both, and do not read a green run here as evidence
# that single-use holds.
ok "single-use holds concurrently" "$RACEWINS" "3"
ok "reads recorded match reveals"  "$(sqlite3 "$DB2" "SELECT count(*) FROM audit WHERE action='credential.read' AND ticket_id LIKE '515%'")" "3"

# THE falsifier for burn-on-read: claim the same row twice, bypassing the route's
# pre-check. The second claim must lose. With `WHERE id=?` alone both claims win and
# this goes red -- which is exactly the two-engineers-at-once bug.
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new" | csrf)
LC=$(curl -s -m 20 -b "$J2" -d "csrf=$T&ticket_id=5199&need=wp_admin&ttl=3600&failed_path=x&bug_ref=cas" "$B2/new" | grep -o "$B2/s/[a-f0-9]\{48\}" | head -1)
curl -s -m 20 -o /dev/null --data-urlencode 'password=CLAIMME' --data-urlencode 'login_url=https://c.com' --data-urlencode 'username=u' "$LC"
CID=$(sqlite3 "$DB2" "SELECT id FROM requests WHERE ticket_id='5199'")
ok "second claim on a row loses"   "$(php -r '
    require "'"$ROOT"'/src/bootstrap.php"; env_load(getenv("APP_ENV_FILE"));
    $id = (int)$argv[1];
    $a = claim_credential_read($id, "first@instawp.com")  ? "won" : "lost";
    $b = claim_credential_read($id, "second@instawp.com") ? "won" : "lost";
    echo "$a/$b";
' "$CID")" "won/lost"

# B4 -- disabling a staff account must end an ALREADY-OPEN session, not just block login.
sqlite3 "$DB2" "DELETE FROM throttle"   # the 12 race logins above filled the IP bucket
PWD5=$(php "$ROOT/bin/staff.php" add gone@instawp.com | sed -n 2p)
Tt=$(curl -s -m 20 -c "$TMP/jg" "$B2/login" | csrf)
curl -s -m 20 -o /dev/null -b "$TMP/jg" -c "$TMP/jg" -d "csrf=$Tt&email=gone@instawp.com&password=$PWD5" "$B2/login"
ok "disabled: session works first" "$(code -b $TMP/jg $B2/audit)" "200"
php "$ROOT/bin/staff.php" disable gone@instawp.com > /dev/null
ok "disabled: session is revoked"  "$(code -b $TMP/jg $B2/audit)" "302"

# I1 -- an expired link the customer NEVER used must not tell them to rotate anything.
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new" | csrf)
curl -s -m 20 -o /dev/null -b "$J2" -d "csrf=$T&ticket_id=6161&need=wp_admin&ttl=3600&failed_path=x&bug_ref=i1" "$B2/new"
sqlite3 "$DB2" "UPDATE requests SET expires_at=1 WHERE ticket_id='6161'"
php "$ROOT/bin/sweep.php" > /dev/null
ok "no nag for unused link"        "$(sqlite3 "$DB2" "SELECT count(*) FROM audit WHERE action='rotation.flagged' AND ticket_id='6161'")" "0"

# I5 -- a second submission must not overwrite the first.
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new" | csrf)
L5=$(curl -s -m 20 -b "$J2" -d "csrf=$T&ticket_id=6262&need=wp_admin&ttl=3600&failed_path=x&bug_ref=i5" "$B2/new" | grep -o "$B2/s/[a-f0-9]\{48\}" | head -1)
curl -s -m 20 -o /dev/null --data-urlencode 'password=FIRSTONE' --data-urlencode 'login_url=https://a.com' --data-urlencode 'username=u' "$L5"
ok "double submit refused"         "$(code --data-urlencode 'password=SECONDONE' --data-urlencode 'login_url=https://a.com' --data-urlencode 'username=u' $L5)" "410"

# I2 -- invalid UTF-8 used to make json_encode return false and fatal inside seal().
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new" | csrf)
L6=$(curl -s -m 20 -b "$J2" -d "csrf=$T&ticket_id=6363&need=wp_admin&ttl=3600&failed_path=x&bug_ref=i2" "$B2/new" | grep -o "$B2/s/[a-f0-9]\{48\}" | head -1)
ok "invalid utf-8 does not fatal"  "$(printf 'login_url=https://a.com&username=u&password=%%FFbad' | curl -s -m 20 -o /dev/null -w '%{http_code}' --data-binary @- "$L6")" "200"
ok "invalid utf-8 was stored"      "$(sqlite3 "$DB2" "SELECT status FROM requests WHERE ticket_id='6363'")" "submitted"

# B3 -- X-Forwarded-For must not buy a fresh throttle bucket. LAST: it exhausts one.
sqlite3 "$DB2" "DELETE FROM throttle"
for i in $(seq 1 11); do
  Tt=$(curl -s -m 20 -b "$TMP/jx" -c "$TMP/jx" "$B2/login" | csrf)
  curl -s -m 20 -o /dev/null -b "$TMP/jx" -c "$TMP/jx" -H "X-Forwarded-For: 10.9.$i.$i" \
       -d "csrf=$Tt&email=nobody@instawp.com&password=wrong" "$B2/login"
done
Tt=$(curl -s -m 20 -b "$TMP/jx" -c "$TMP/jx" "$B2/login" | csrf)
ok "XFF cannot bypass throttle"    "$(code -b $TMP/jx -c $TMP/jx -H 'X-Forwarded-For: 10.9.77.77' -d "csrf=$Tt&email=nobody@instawp.com&password=wrong" $B2/login)" "429"
ok "audit ip is not forgeable"     "$(sqlite3 "$DB2" "SELECT count(*) FROM audit WHERE ip LIKE '10.9.%'")" "0"

sedi "s/^APP_KEY=.*/APP_KEY=$(php -r 'echo bin2hex(random_bytes(32));')/" "$TMP/env"
ok "wrong key -> loud failure"  "$(php -r 'require "'"$ROOT"'/src/bootstrap.php"; env_load(getenv("APP_ENV_FILE")); require "'"$ROOT"'/src/crypto.php"; try { unseal(base64_encode(random_bytes(24)), base64_encode(random_bytes(60))); echo "silent"; } catch (Throwable $e) { echo "threw"; }')" "threw"

echo; if [ $FAIL -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi; exit $FAIL
