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
PHPD="-d display_errors=0 -d log_errors=1 -d error_log=$TMP/php-errors.log"
PHP_CLI_SERVER_WORKERS=8 php $PHPD -S "127.0.0.1:$PORT" -t "$ROOT/public" "$ROOT/public/index.php" >"$TMP/srv.log" 2>&1 &
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
PHP_CLI_SERVER_WORKERS=8 php $PHPD -S "127.0.0.1:$P2" -t "$ROOT/public" "$ROOT/public/index.php" >"$TMP/srv2.log" 2>&1 &
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

# --- OUTBOUND SHARES: a link that DELIVERS a secret instead of collecting one ---
ok "compose page needs login"      "$(code $B2/new-share)" "302"

# S1 -- plain message, view once. The GET/POST split is the point: a mail gateway
# that prefetches the link must not be able to burn the message before the customer.
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
V1=$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9001" -F "message=hunter2-PLAINTEXT" -F "view=once" -F "ttl=3600" "$B2/new-share" | grep -o "$B2/v/[a-f0-9]\{48\}" | head -1)
ok "share link issued"             "$([ -n "$V1" ] && echo yes || echo no)" "yes"
ok "share stored as outbound"      "$(sqlite3 "$DB2" "SELECT direction FROM requests WHERE ticket_id='9001'")" "out"
ok "share message encrypted"       "$(sqlite3 "$DB2" "SELECT count(*) FROM requests WHERE ticket_id='9001' AND ciphertext LIKE '%hunter2%'")" "0"
ok "GET does not open the share"   "$(curl -s -m 20 "$V1" | grep -c 'Open the message')" "1"
ok "GET leaks no plaintext"        "$(curl -s -m 20 "$V1" | grep -c 'hunter2-PLAINTEXT')" "0"
ok "GET left it unopened"          "$(sqlite3 "$DB2" "SELECT status FROM requests WHERE ticket_id='9001'")" "pending"
ok "POST opens the share"          "$(curl -s -m 20 -d '' "$V1" | grep -c 'hunter2-PLAINTEXT')" "1"
ok "opened share is destroyed"     "$(sqlite3 "$DB2" "SELECT status||':'||ifnull(ciphertext,'NULL') FROM requests WHERE ticket_id='9001'")" "read:NULL"
ok "second open refused"           "$(code -d '' $V1)" "410"
ok "share view is audited"         "$(sqlite3 "$DB2" "SELECT count(*) FROM audit WHERE action='share.viewed'")" "1"

# S2 -- passphrase gate
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
V2=$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9002" -F "message=locked-SECRET" -F "view=once" -F "ttl=3600" -F "passphrase=correct-horse" "$B2/new-share" | grep -o "$B2/v/[a-f0-9]\{48\}" | head -1)
ok "locked share asks for pass"    "$(curl -s -m 20 "$V2" | grep -c 'name="pass"')" "1"
ok "passphrase not in the page"    "$(curl -s -m 20 "$V2" | grep -c 'correct-horse')" "0"
ok "wrong passphrase refused"      "$(curl -s -m 20 -d 'pass=nope' "$V2" | grep -c 'not right')" "1"
ok "wrong passphrase leaks none"   "$(curl -s -m 20 -d 'pass=nope' "$V2" | grep -c 'locked-SECRET')" "0"
ok "right passphrase opens"        "$(curl -s -m 20 --data-urlencode 'pass=correct-horse' "$V2" | grep -c 'locked-SECRET')" "1"

# S3 -- guessing costs the secret, not just time
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
V3=$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9003" -F "message=burn-ME" -F "view=once" -F "ttl=3600" -F "passphrase=another-one" "$B2/new-share" | grep -o "$B2/v/[a-f0-9]\{48\}" | head -1)
for _ in $(seq 1 5); do curl -s -m 20 -o /dev/null -d 'pass=wrong' "$V3"; done
ok "destroyed after 5 attempts"    "$(sqlite3 "$DB2" "SELECT status||':'||ifnull(ciphertext,'NULL') FROM requests WHERE ticket_id='9003'")" "expired:NULL"
ok "right pass too late"           "$(code --data-urlencode 'pass=another-one' $V3)" "410"
ok "destruction is audited"        "$(sqlite3 "$DB2" "SELECT count(*) FROM audit WHERE action='share.destroyed.attempts'")" "1"

# S4 -- attachment: encrypted at rest, fetched on a grant, purged with the message
printf 'ATTACHED-FILE-BODY' > "$TMP/secret.txt"
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
V4=$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9004" -F "message=see attached" -F "view=once" -F "ttl=3600" -F "attachment=@$TMP/secret.txt" "$B2/new-share" | grep -o "$B2/v/[a-f0-9]\{48\}" | head -1)
ok "attachment recorded"           "$(sqlite3 "$DB2" "SELECT file_name FROM requests WHERE ticket_id='9004'")" "secret.txt"
ok "attachment encrypted at rest"  "$(grep -rl 'ATTACHED-FILE-BODY' "$TMP/data/blobs" 2>/dev/null | wc -l | tr -d ' ')" "0"
OUT4=$(curl -s -m 20 -d '' "$V4")
D4=$(echo "$OUT4" | grep -o "$B2/v/[a-f0-9]\{48\}/f/[a-f0-9]\{48\}" | head -1)
ok "download grant issued"         "$([ -n "$D4" ] && echo yes || echo no)" "yes"
ok "attachment downloads"          "$(curl -s -m 20 "$D4")" "ATTACHED-FILE-BODY"
ok "download is an attachment"     "$(curl -s -m 20 -D - -o /dev/null "$D4" | grep -ci 'content-disposition: attachment')" "1"
ok "download is never inline type" "$(curl -s -m 20 -D - -o /dev/null "$D4" | grep -ci 'content-type: application/octet-stream')" "1"
TOK4="${V4##*/}"
ok "forged grant refused"          "$(code $B2/v/$TOK4/f/$(php -r 'echo str_repeat("a",48);'))" "410"
sqlite3 "$DB2" "UPDATE requests SET dl_expires=strftime('%s','now')-10 WHERE ticket_id='9004'"
php "$ROOT/bin/sweep.php" > /dev/null
ok "attachment purged with grant"  "$(ls "$TMP/data/blobs" | wc -l | tr -d ' ')" "0"
ok "expired grant refuses file"    "$(code $D4)" "410"

# S5 -- the two directions must never serve each other's tokens
TOK1="${V1##*/}"
ok "outbound token on /s/ diverts" "$(code $B2/s/$TOK1)" "302"
ok "inbound token on /v/ diverts"  "$(code $B2/v/${L3##*/})" "302"

# S6 -- staff cannot read back what they sent; that is what makes view-once true
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
V5=$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9005" -F "message=staff-MUST-NOT-SEE" -F "view=once" -F "ttl=3600" "$B2/new-share" | grep -o "$B2/v/[a-f0-9]\{48\}" | head -1)
OID=$(sqlite3 "$DB2" "SELECT id FROM requests WHERE ticket_id='9005'")
ok "staff detail hides content"    "$(curl -s -m 20 -b "$J2" "$B2/o/$OID" | grep -c 'staff-MUST-NOT-SEE')" "0"
ok "staff detail has no reveal"    "$(curl -s -m 20 -b "$J2" "$B2/o/$OID" | grep -c 'action=reveal')" "0"
ok "outbound id on /r/ diverts"    "$(code -b $J2 $B2/r/$OID)" "302"
ok "share is still unopened"       "$(sqlite3 "$DB2" "SELECT status FROM requests WHERE id=$OID")" "pending"

# S7 -- an outbound share has nothing for the CUSTOMER to rotate
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
curl -s -m 20 -o /dev/null -b "$J2" -F "csrf=$T" -F "ticket_id=9006" -F "message=x" -F "view=once" -F "ttl=3600" "$B2/new-share"
sqlite3 "$DB2" "UPDATE requests SET expires_at=strftime('%s','now')-10 WHERE ticket_id='9006'"
php "$ROOT/bin/sweep.php" > /dev/null
ok "outbound expires and purges"   "$(sqlite3 "$DB2" "SELECT status FROM requests WHERE ticket_id='9006'")" "expired"
ok "no rotation nag for outbound"  "$(sqlite3 "$DB2" "SELECT ifnull(rotation_flagged_at,'NONE') FROM requests WHERE ticket_id='9006'")" "NONE"

# S8 -- 'keep' stays openable, and keeps its ciphertext to do it
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
V7=$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9007" -F "message=reopen-ME" -F "view=keep" -F "ttl=3600" "$B2/new-share" | grep -o "$B2/v/[a-f0-9]\{48\}" | head -1)
ok "keep mode first open"          "$(curl -s -m 20 -d '' "$V7" | grep -c 'reopen-ME')" "1"
ok "keep mode second open"         "$(curl -s -m 20 -d '' "$V7" | grep -c 'reopen-ME')" "1"
ok "keep mode kept its ciphertext" "$(sqlite3 "$DB2" "SELECT CASE WHEN ciphertext IS NULL THEN 0 ELSE 1 END FROM requests WHERE ticket_id='9007'")" "1"

# S9 -- compose validation
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
ok "empty share refused"           "$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9008" -F "message=" -F "view=once" -F "ttl=3600" "$B2/new-share" | grep -c 'so is a message or an attachment')" "1"
T=$(curl -s -m 20 -b "$J2" -c "$J2" "$B2/new-share" | csrf)
ok "short passphrase refused"      "$(curl -s -m 20 -b "$J2" -F "csrf=$T" -F "ticket_id=9008" -F "message=x" -F "view=once" -F "ttl=3600" -F "passphrase=abc" "$B2/new-share" | grep -c 'at least 6')" "1"
ok "share csrf enforced"           "$(code -b $J2 -F 'csrf=bogus' -F 'ticket_id=9009' -F 'message=x' -F 'view=once' -F 'ttl=3600' $B2/new-share)" "400"
ok "no share minted on refusal"    "$(sqlite3 "$DB2" "SELECT count(*) FROM requests WHERE ticket_id IN ('9008','9009')")" "0"

# S10 -- staff API parity, and the separation between the two collections
TOKA=$(php "$ROOT/bin/staff.php" token tester@instawp.com | sed -n 2p)
SH=$(curl -s -m 20 -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' -d '{"ticket_id":"9100","message":"api-SECRET","ttl":3600,"view":"once"}' "$B2/api/v1/shares")
ok "api share created"             "$(echo "$SH" | grep -c '"direction":"out"')" "1"
ok "api share returns a url"       "$(echo "$SH" | grep -c '"url"')" "1"
ok "api share never echoes body"   "$(echo "$SH" | grep -c 'api-SECRET')" "0"
SID=$(sqlite3 "$DB2" "SELECT id FROM requests WHERE ticket_id='9100'")
ok "api requests exclude shares"   "$(curl -s -m 20 -H "Authorization: Bearer $TOKA" "$B2/api/v1/requests?ticket_id=9100" | grep -c '"id"')" "0"
ok "api reveal refuses a share"    "$(code -X POST -H "Authorization: Bearer $TOKA" $B2/api/v1/requests/$SID/reveal)" "404"
ok "api share fetch works"         "$(curl -s -m 20 -H "Authorization: Bearer $TOKA" "$B2/api/v1/shares/$SID" | grep -c '"passphrase":false')" "1"
B64=$(printf 'B64BODY' | base64)
SHB=$(curl -s -m 20 -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' -d "{\"ticket_id\":\"9101\",\"message\":\"m\",\"ttl\":3600,\"attachment\":{\"name\":\"a.txt\",\"content_b64\":\"$B64\"}}" "$B2/api/v1/shares")
ok "api share takes a b64 file"    "$(echo "$SHB" | grep -c '"name":"a.txt"')" "1"
# Over OUR limit but inside the server's: the app rejects it with a JSON 400.
php -r '$b = base64_encode(str_repeat("x", 5.5*1048576)); file_put_contents("'"$TMP"'/big.json", json_encode(["ticket_id"=>"9102","ttl"=>3600,"attachment"=>["name"=>"big.bin","content_b64"=>$b]]));'
BLOBS=$(ls "$TMP/data/blobs" 2>/dev/null | wc -l | tr -d ' ')
ok "api rejects oversize b64"      "$(code -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' --data-binary @"$TMP/big.json" $B2/api/v1/shares)" "400"
ok "oversize left no row"          "$(sqlite3 "$DB2" "SELECT count(*) FROM requests WHERE ticket_id='9102'")" "0"
ok "oversize wrote no blob"        "$(ls "$TMP/data/blobs" 2>/dev/null | wc -l | tr -d ' ')" "$BLOBS"
# Over the SERVER's limit: PHP discards the body before we run, so the route never
# sees it. Answering 200-with-a-PHP-warning is what this asserts against.
php -r '$b = base64_encode(str_repeat("x", 9*1048576)); file_put_contents("'"$TMP"'/huge.json", json_encode(["ticket_id"=>"9103","ttl"=>3600,"attachment"=>["name"=>"huge.bin","content_b64"=>$b]]));'
HUGE=$(curl -s -m 30 -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' --data-binary @"$TMP/huge.json" "$B2/api/v1/shares")
ok "api 413s over post_max_size"   "$(code -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' --data-binary @"$TMP/huge.json" $B2/api/v1/shares)" "413"
ok "413 is json, not a warning"    "$(echo "$HUGE" | grep -c '"code":"too_large"')" "1"
ok "413 leaked no php warning"     "$(echo "$HUGE" | grep -ci 'content-length of')" "0"
ok "api share delete expires it"   "$(code -X DELETE -H "Authorization: Bearer $TOKA" $B2/api/v1/shares/$SID)" "200"
ok "deleted share is dead"         "$(sqlite3 "$DB2" "SELECT status FROM requests WHERE id=$SID")" "expired"


sedi "s/^APP_KEY=.*/APP_KEY=$(php -r 'echo bin2hex(random_bytes(32));')/" "$TMP/env"
ok "wrong key -> loud failure"  "$(php -r 'require "'"$ROOT"'/src/bootstrap.php"; env_load(getenv("APP_ENV_FILE")); require "'"$ROOT"'/src/crypto.php"; try { unseal(base64_encode(random_bytes(24)), base64_encode(random_bytes(60))); echo "silent"; } catch (Throwable $e) { echo "threw"; }')" "threw"

echo; if [ $FAIL -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi; exit $FAIL
