# InstaWP — secure credential handoff

Single-use, expiring credential transport for support tickets. Replaces asking a customer
for credentials in the ticket body, where they live permanently in the FreeScout database,
the mail store, agent notification copies, and the customer's own Sent folder.

Ticket → link → customer submits → one engineer reads once → destroyed → rotation nag.

## Deliberate limits

- **WordPress first; SSH as a last resort.** A temporary admin account or an application password
  is the default ask. SSH/SFTP is also offered, for source servers where there is no WordPress-level
  route. Hide it with `ALLOW_INFRA_CREDENTIALS=0`. cPanel and FTP have no fields at all.
- **A link cannot be minted without naming which product path failed and a bug reference.**
  Asking for a credential is a last resort; when it substitutes for a diagnosis it buries the
  defect that caused it. That gate is the point of the tool, not friction to route around.
- **Read once.** Opening a credential destroys the stored copy and records the reader.
- **The rotation nag names the application password separately.** Application passwords live in
  `usermeta` and survive a password change, so "change your password" alone leaves our access
  live on the customer's site.

## Layout

    public/index.php   front controller (all routes)
    src/bootstrap.php  config, SQLite schema, audit, throttle
    src/crypto.php     libsodium secretbox; stores base64, never raw binary
    src/auth.php       staff sessions, CSRF
    src/rotation.php   the rotation nag (shared by web sweep and cron)
    src/freescout.php  optional FreeScout note write-back
    src/views.php      layout + verbatim credential rendering
    src/api.php        staff JSON API (/api/v1)
    src/requests.php   mint + reveal, shared by web and API
    freescout-module/  drop-in FreeScout module (in-ticket mint button)
    bin/staff.php      add/disable/list/token/revoke-token staff
    bin/sweep.php      cron: purge expired, fire rotation nags
    bin/e2e.sh         29 end-to-end assertions

## Config — `/home/instapod/handoff.env` (chmod 600, OUTSIDE the checkout)

    APP_KEY=<64 hex chars>          # 32 bytes. See the warning below.
    APP_URL=https://<host>
    DATA_DIR=/home/instapod/handoff-data
    FREESCOUT_API_URL=...           # optional; already includes /api
    FREESCOUT_API_KEY=...           # optional
    FREESCOUT_USER_ID=1             # optional
    ALLOW_INFRA_CREDENTIALS=1       # 0 hides SSH/SFTP. cPanel/FTP are never offered.

⚠ **`APP_KEY` must never be regenerated.** An InstaPods git deploy rebuilds `.env` from
`.env.example`, which is why config lives outside the app directory. If the key changes, every
stored credential becomes permanently unreadable — the app fails loudly rather than returning
garbage, but the data is gone. Because nothing is stored longer than 48 hours, losing the key
costs at most the in-flight requests; that is the intended trade, and it is why the key is not
copied anywhere else.

## Pod notes (InstaPods)

- `pdo_sqlite` is **not** in the stock PHP image: `sudo apt-get install -y php8.4-sqlite3`.
- nginx docroot defaults to the repo root — must point at `app/public`.
- php-fpm runs as `www-data` while files are owned by `instapod`; set `user`/`group` to
  `instapod` in the pool config (leave `listen.owner` as www-data).
- Sessions are stored under `DATA_DIR/sessions`, not the distro default, which php-fpm may not own.

## Operating

    php bin/staff.php add <email>      # prints a one-time password; they change it at /settings
    php bin/staff.php token <email>    # prints a Bearer token for /api/v1 (invalidates the previous one)
    php bin/staff.php revoke-token <email>
    php bin/staff.php disable <email>
    php bin/sweep.php                  # cron, every 15 min

## Staff API

JSON, Bearer auth, same policy as the web UI (Tier-1 gate, burn-on-read, field allowlist).
The customer still submits through the HTML form — there is no public submit API.

    php bin/staff.php token you@instawp.com   # prints the token on line 2

    Authorization: Bearer iwp_<64 hex>

| | |
|---|---|
| `GET /api/v1/health` | Unauthenticated. Same idea as `/healthz`. |
| `GET /api/v1/me` | Who the token belongs to. |
| `GET /api/v1/meta` | Allowed `need` values and TTLs. |
| `POST /api/v1/requests` | Mint a link. Body: `ticket_id`, `need`, `failed_path`, `bug_ref`, `ttl`. |
| `GET /api/v1/requests` | List. Query: `status`, `ticket_id`. |
| `GET /api/v1/requests/{id}` | One request. Includes `url` only while `pending`. Never ciphertext. |
| `POST /api/v1/requests/{id}/reveal` | Read once and destroy. Returns `fields`. Second call is `409`. |
| `GET /api/v1/audit` | Last 300 audit rows. |

Example:

```bash
TOKEN=$(php bin/staff.php token you@instawp.com | sed -n 2p)
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ticket_id":"3340","need":"wp_admin","failed_path":"connect popup never opens","bug_ref":"tsk_a91","ttl":172800}' \
  "$APP_URL/api/v1/requests"
```

Behind php-fpm, pass the header through: `fastcgi_param HTTP_AUTHORIZATION $http_authorization;`

## FreeScout

Two layers. Neither puts the credential in the ticket.

**1. Internal notes (this app).** Optional. Set `FREESCOUT_API_URL` (already includes `/api`),
`FREESCOUT_API_KEY`, and `FREESCOUT_USER_ID`. Mint, customer submit, reveal, and rotation each
post an internal note. `ticket_id` must be the conversation **id** in `/conversation/123`, not
the visible `#number`.

**2. In-ticket mint button.** Copy `freescout-module/SecureHandoff` into FreeScout’s `Modules/`
directory and activate it. Settings → Secure Handoff takes this app’s `APP_URL` and a staff
Bearer token (`php bin/staff.php token …`). The sidebar requires the same Tier-1 fields as the
web UI. Agents copy or insert the customer link; they still open this app to read a submitted
secret once. See `freescout-module/SecureHandoff/README.md`.

## Tests

    bash bin/e2e.sh 8799

38 assertions covering auth, CSRF, the Tier-1 gate, the field allowlist, single-use links,
burn-on-read, expiry purge, the rotation nag, audit rows, and that a wrong `APP_KEY` fails loudly
rather than silently. The suite runs the whole flow twice — once with `ALLOW_INFRA_CREDENTIALS`
off (proving the off-switch holds: SSH is not offered and a hand-crafted `need=ssh` POST is refused)
and once with it on (proving the SSH path and its distinct rotation wording).
