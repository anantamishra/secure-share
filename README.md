# InstaWP — secure credential handoff

Single-use, expiring credential transport for support tickets. Replaces asking a customer
for credentials in the ticket body, where they live permanently in the FreeScout database,
the mail store, agent notification copies, and the customer's own Sent folder.

Ticket → link → customer submits → one engineer reads once → destroyed → rotation nag.

It runs in both directions. A **request** collects a secret *from* the customer. A **share**
delivers one *to* them — a message, a file, or both, behind a link that opens once. Same table,
same key, same burn-on-read; `direction` is the only thing that separates them.

## Deliberate limits

- **WordPress first; SSH as a last resort.** A temporary admin account or an application password
  is the default ask. SSH/SFTP is also offered, for source servers where there is no WordPress-level
  route. Hide it with `ALLOW_INFRA_CREDENTIALS=0`. cPanel and FTP have no fields at all.
- **A link cannot be minted without naming which product path failed and a bug reference.**
  Asking for a credential is a last resort; when it substitutes for a diagnosis it buries the
  defect that caused it. That gate is the point of the tool, not friction to route around.
- **Read once.** Opening a credential destroys the stored copy and records the reader.
- **A share is opened by a click, never by a GET.** Mail gateways and chat previewers fetch
  every URL in a message before a human sees it. If a GET opened a view-once share, the
  customer's own security software would burn it first, and the secret would have been read by
  a machine nobody can question afterwards.
- **Staff cannot read a share back.** There is no reveal on `/o/{id}` and no API endpoint for
  it. An outbound secret that any signed-in agent could replay for the whole TTL is not
  view-once, whatever the customer was told.
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
    src/shares.php     outbound: compose, open-once, attachments, passphrase
    freescout-module/  drop-in FreeScout module (in-ticket mint button)
    bin/staff.php      add/disable/list/token/revoke-token staff
    bin/sweep.php      cron: purge expired, fire rotation nags
    bin/e2e.sh         142 end-to-end assertions
    CHANGELOG.md       what changed, per version

## Config — `/home/instapod/handoff.env` (chmod 600, OUTSIDE the checkout)

    APP_KEY=<64 hex chars>          # 32 bytes. See the warning below.
    APP_URL=https://<host>
    DATA_DIR=/home/instapod/handoff-data
    FREESCOUT_API_URL=...           # optional; already includes /api
    FREESCOUT_API_KEY=...           # optional
    FREESCOUT_USER_ID=1             # optional
    ALLOW_INFRA_CREDENTIALS=1       # 0 hides SSH/SFTP. cPanel/FTP are never offered.
    MAX_UPLOAD_MB=5                 # optional; ceiling for a share attachment

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
- Share attachments are written to `DATA_DIR/blobs`, encrypted, one file per token.
- **`upload_max_filesize` and `post_max_size` must both exceed `MAX_UPLOAD_MB`.** The stock
  values (2M and 8M) are below the 5 MB default, and the API's base64 encoding inflates a body
  by a third on top of that. A POST over `post_max_size` is discarded by PHP *before* any of
  this code runs — the front controller detects that and returns a 413 rather than letting the
  route act on an empty body, but the only real fix is to raise the limits.
- `display_errors` must be **Off**. A startup warning is printed before the front controller
  runs, which sends headers and turns a clean error response into a 200 with PHP's warning in
  the body.

## Versioning

`APP_VERSION` in `src/bootstrap.php` is the only place the version is written down.
Semver against the HTTP surface staff and the API depend on: a new endpoint or capability
is a minor, a change that breaks an existing caller is a major. **Bump it in the same commit
as the change it describes** — a version bumped afterwards in a release commit of its own
tells you a release happened but not which code it covers. `CHANGELOG.md` carries the detail.

Where to read it back:

    staff footer            every signed-in page
    GET /api/v1/me          "version": "1.1.0"

Deliberately **not** on `/healthz` or `/api/v1/health`. Both are unauthenticated, and
naming the exact build to anyone who can reach the host tells them which advisories to
try. Ops already has a token (`php bin/staff.php token …`); checking a deploy is one
authenticated call.

`freescout-module/SecureHandoff/module.json` versions independently — it is installed
into someone else's FreeScout on their schedule, not deployed with this app.

## Operating

    php bin/staff.php add <email>      # prints a one-time password; they change it at /settings
    php bin/staff.php token <email>    # prints a Bearer token for /api/v1 (invalidates the previous one)
    php bin/staff.php revoke-token <email>
    php bin/staff.php disable <email>
    php bin/sweep.php                  # cron, every 15 min

## Sending something to the customer

`/new-share` mints a link that *delivers*. Message, attachment, or both.

    Ticket → compose → link → customer clicks through → opened once → destroyed

Unlike a credential request this is **not** gated on a bug reference. That gate exists because
asking a customer for a credential substitutes for a diagnosis and buries the defect that
caused it. Sending a customer a password we generated is not that act, and requiring a bug
reference for it would be friction with no policy behind it. A ticket number is still required.

- **Opening is a POST.** The link shows a confirmation page; the click is what opens it. This
  is what stops a link scanner in the customer's mailbox from burning the message first.
- **Passphrase (optional, recommended).** The threat model is inverted here: an intercepted
  *inbound* link is an empty form, but an outbound link **is** the secret. A passphrase passed
  out of band — spoken on the call, sent by SMS — closes that. Five wrong attempts destroy the
  content rather than merely throttling it: a public link plus a short passphrase is worth
  grinding, and destruction makes a guessing attempt cost a resend instead of the secret.
  It gates access; it does not derive the key. `APP_KEY` still decrypts everything, as it does
  everywhere else here — deriving from the passphrase would claim a defence against compromise
  of our own disk that nothing else in this app offers.
- **Attachments** are encrypted with the same key and written to `DATA_DIR/blobs`, never into
  SQLite. Opening the message mints a 15-minute download grant, because the file cannot be
  handed over in the same response that renders the page. The message is destroyed on open
  either way; `bin/sweep.php` drops the file when the grant lapses.
- **Nothing rotates afterwards.** The rotation nag never fires on a share. There is nothing on
  the customer's side to change, and telling them to reads as a breach notice for an event that
  did not happen.

Staff see `/o/{id}`: status, expiry, whether a passphrase was set and how many wrong attempts
it has taken, the attachment's name — and not the content.

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
| `POST /api/v1/shares` | Send a secure message. Body: `ticket_id`, `message`, `ttl`, `view`, `passphrase`, `attachment`. |
| `GET /api/v1/shares` | List. Query: `status`, `ticket_id`. |
| `GET /api/v1/shares/{id}` | One share. `url` only while it is still openable. Never the content. |
| `DELETE /api/v1/shares/{id}` | Destroy it now. |

`/requests` and `/shares` are disjoint: a share id passed to `/requests/{id}` is a 404, and so is
the reverse. There is deliberately **no** reveal endpoint for a share. `attachment` is
`{"name": "...", "content_b64": "..."}`; base64 inflates the body by a third, so a 5 MB file
needs `post_max_size` well above it.

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

The sidebar mints **requests only**. Sending a secure message is done from `/new-share` in this
app, or through `POST /api/v1/shares`. Putting it in the module would mean handling a file
upload inside FreeScout's request cycle — a separate piece of work, not done here.

## Tests

    bash bin/e2e.sh 8799

142 assertions covering auth, CSRF, the Tier-1 gate, the field allowlist, single-use links,
burn-on-read, expiry purge, the rotation nag, audit rows, and that a wrong `APP_KEY` fails loudly
rather than silently.

59 of those cover outbound shares: that a GET does not open one, that opening destroys it, that
a wrong passphrase leaks nothing and five destroy the content, that an attachment is unreadable
on disk and is purged when its grant lapses, that neither direction will serve the other's token
or id, that staff cannot read a share back, that no rotation nag fires, and that both size
ceilings — ours and the server's — refuse cleanly instead of half-succeeding. The suite runs the whole flow twice — once with `ALLOW_INFRA_CREDENTIALS`
off (proving the off-switch holds: SSH is not offered and a hand-crafted `need=ssh` POST is refused)
and once with it on (proving the SSH path and its distinct rotation wording).
