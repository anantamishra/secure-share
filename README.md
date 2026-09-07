# InstaWP — secure credential handoff

Single-use, expiring credential transport for support tickets. Replaces asking a customer
for credentials in the ticket body, where they live permanently in the FreeScout database,
the mail store, agent notification copies, and the customer's own Sent folder.

Ticket → link → customer submits → one engineer reads once → destroyed → rotation nag.

## Deliberate limits

- **WordPress only, by default.** A temporary admin account or an application password. SSH/SFTP
  fields exist in the code but are gated behind `ALLOW_INFRA_CREDENTIALS` and **ship off**. That flag
  is not a feature toggle — it is decision D1 in the credential-request rule, which sits with the
  owner. Do not turn it on without that sign-off recorded, and note that turning it on also changes
  the anti-phishing line the customer sees ("we will never ask you for SSH…"), which must stay true.
  cPanel and FTP have no fields at all.
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
    bin/staff.php      add/disable/list staff
    bin/sweep.php      cron: purge expired, fire rotation nags
    bin/e2e.sh         29 end-to-end assertions

## Config — `/home/instapod/handoff.env` (chmod 600, OUTSIDE the checkout)

    APP_KEY=<64 hex chars>          # 32 bytes. See the warning below.
    APP_URL=https://<host>
    DATA_DIR=/home/instapod/handoff-data
    FREESCOUT_API_URL=...           # optional; already includes /api
    FREESCOUT_API_KEY=...           # optional
    FREESCOUT_USER_ID=1             # optional
    ALLOW_INFRA_CREDENTIALS=0       # gated: SSH/SFTP fields. See "Deliberate limits".

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

    php bin/staff.php add <email>      # prints a one-time password; they change it at /password
    php bin/staff.php disable <email>
    php bin/sweep.php                  # cron, every 15 min

## Tests

    bash bin/e2e.sh 8799

38 assertions covering auth, CSRF, the Tier-1 gate, the field allowlist, single-use links,
burn-on-read, expiry purge, the rotation nag, audit rows, and that a wrong `APP_KEY` fails loudly
rather than silently. The suite runs the whole flow twice — once with `ALLOW_INFRA_CREDENTIALS`
off (proving the gate holds: SSH is not offered and a hand-crafted `need=ssh` POST is refused) and
once with it on (proving the SSH path, its distinct rotation wording, and the customer warning).
