# Changelog

Semver against the HTTP surface staff and the API depend on. `APP_VERSION` in
`src/bootstrap.php` is the source of truth; it is bumped in the same commit as the
change it describes, not afterwards in a release commit of its own.

`freescout-module/SecureHandoff` versions independently — it is installed into
someone else's FreeScout on their schedule, not deployed with this app.

## 1.1.0

Outbound shares: the app now runs in both directions.

### Added
- Send a customer a message, a file, or both, behind a link that opens once
  (`/new-share`, `/v/{token}`, `/o/{id}`).
- Optional per-link passphrase, passed to the customer out of band. Five wrong
  attempts destroy the content rather than only throttling it.
- Attachments up to `MAX_UPLOAD_MB` (default 5), encrypted with the same key and
  written to `DATA_DIR/blobs`, never into SQLite. Opening the message mints a
  15-minute download grant; the sweep drops the file when it lapses.
- Staff API: `POST|GET /api/v1/shares`, `GET|DELETE /api/v1/shares/{id}`. There is
  deliberately no reveal endpoint — a share any agent could replay is not view-once.
- `MAX_UPLOAD_MB` config key. `version` on `GET /api/v1/me`, and in the staff footer.

### Changed
- The dashboard lists both directions, with direction-aware status wording and one
  filter row whose counts are scoped by the active filter.
- `GET /api/v1/requests` and `/api/v1/requests/{id}` are now inbound-only; a share id
  passed to them is a 404, and the reverse is too.
- The rotation nag never fires on an outbound share. There is nothing on the
  customer's side to rotate.

### Fixed
- Every response now carries `Cache-Control: no-store`. The staff pages had been
  getting cache headers by accident — `current_staff()` starts a session and PHP's
  `session_cache_limiter` emits them on the way out — while the customer routes,
  which never start a session, shipped with none at all. That included the `/v/`
  response rendering the decrypted message, so a view-once share was destroyed in our
  database but still sat in the customer's on-disk browser cache, re-renderable with
  the back button and retainable by a TLS-terminating proxy on their side.
- A request body over `post_max_size` is discarded by PHP before any of this code
  runs, with `$_POST`, `$_FILES` and `php://input` all empty and no catchable error.
  The API answered 200 with a PHP warning in place of the JSON, and the web form
  blamed the agent's session via a CSRF failure. The front controller now returns 413.

### Operational
- `upload_max_filesize` and `post_max_size` must both exceed `MAX_UPLOAD_MB`. The
  stock 2M/8M are below the 5 MB default, and base64 inflates an API body by a third.
- `display_errors` must be Off: a startup warning prints before the front controller
  runs, which sends headers and turns a clean error into a 200 with the warning in it.

## 1.0.0

Single-use, expiring credential handoff for support tickets. Mint a link from a
ticket, the customer submits, one engineer reads once, the copy is destroyed, and the
rotation nag names the application password separately. Staff API, FreeScout notes
and in-ticket mint button, SQLite + libsodium, `ALLOW_INFRA_CREDENTIALS` off-switch.
