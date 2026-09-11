<?php
declare(strict_types=1);

/**
 * InstaWP secure credential handoff — bootstrap.
 *
 * Config and data both live OUTSIDE the checkout (/home/instapod/...), because an
 * InstaPods deploy regenerates the app directory. If APP_KEY were to change, every
 * stored ciphertext would become permanently unreadable with no error at write time.
 */

/**
 * What the form is allowed to collect.
 *
 * WordPress options are always available: a temporary admin account and an
 * application password are both scoped and individually revocable.
 *
 * SSH/SFTP is also offered by default. It is a last resort — an SSH credential
 * is broad, reusable, and cannot be revoked without collateral damage, and on
 * an agency ticket it is usually their client's server. Set
 * ALLOW_INFRA_CREDENTIALS=0 to hide it. cPanel and FTP have no fields at all.
 */
function infra_enabled(): bool {
    $v = strtolower((string)cfg('ALLOW_INFRA_CREDENTIALS', '1'));
    return !in_array($v, ['0', 'false', 'no', 'off'], true);
}

function needs(): array {
    $n = [
        'wp_admin'        => 'WordPress administrator account (temporary)',
        'wp_app_password' => 'WordPress application password',
    ];
    if (infra_enabled()) {
        $n['ssh'] = 'SSH / SFTP account (source server)';
    }
    return $n;
}

/** Field label map for a given need, in the order the customer sees them. */
function fields_for(string $need): array {
    return match ($need) {
        'ssh' => [
            'host'      => 'Server hostname or IP',
            'port'      => 'Port',
            'username'  => 'Username',
            'password'  => 'Password or private key',
        ],
        'wp_app_password' => [
            'login_url' => 'Site URL',
            'username'  => 'Username',
            'password'  => 'Application password',
        ],
        default => [
            'login_url' => 'Login URL',
            'username'  => 'Username',
            'password'  => 'Password',
        ],
    };
}

/** Fields the customer may leave blank. */
function optional_fields(string $need): array {
    return $need === 'ssh' ? ['port'] : [];
}

function ttl_choices(): array {
    return [3600 => '1 hour', 21600 => '6 hours', 86400 => '24 hours', 172800 => '48 hours'];
}

/** How the customer wants the submitted secret kept. Default is view-once. */
function share_choices(): array {
    return [
        'once' => 'View once',
        '1d'   => 'Expire in 1 day',
        '2d'   => 'Expire in 2 days',
    ];
}

function share_seconds(string $share): ?int {
    return match ($share) {
        '1d' => 86400,
        '2d' => 172800,
        default => null,
    };
}

function share_is_once(array $r): bool {
    return (($r['share'] ?? 'once') === 'once');
}

function share_from_post(): string {
    $s = (string)($_POST['share'] ?? 'once');
    return isset(share_choices()[$s]) ? $s : 'once';
}

function share_label(array|string $r): string {
    $key = is_array($r) ? (string)($r['share'] ?? 'once') : $r;
    return share_choices()[$key] ?? 'View once';
}

/**
 * How long an OUTBOUND share stays openable, reusing the same `share` column.
 *
 * Deliberately not merged into share_choices(): that list is rendered as the
 * customer's radio group on the inbound form, and 'keep' has no meaning there.
 */
function view_choices(): array {
    return [
        'once' => 'View once, then destroy',
        'keep' => 'Can be re-opened until it expires',
    ];
}

function view_is_once(array $r): bool {
    return (($r['share'] ?? 'once') !== 'keep');
}

function view_label(array|string $r): string {
    $key = is_array($r) ? (string)($r['share'] ?? 'once') : $r;
    return view_choices()[$key] ?? 'View once, then destroy';
}

/** Outbound = we are sending the secret. Inbound = the customer is. */
function is_outbound(array $r): bool {
    return (string)($r['direction'] ?? 'in') === 'out';
}

/** Ceiling for a share attachment. php.ini may impose a lower one of its own. */
/** Parse a php.ini shorthand size ("8M", "512K") into bytes. */
function ini_bytes(string $key): int {
    $v = trim((string)ini_get($key));
    if ($v === '') return 0;
    $n = (int)$v;
    return match (strtolower(substr($v, -1))) {
        'g'     => $n * 1073741824,
        'm'     => $n * 1048576,
        'k'     => $n * 1024,
        default => $n,
    };
}

/**
 * True when PHP threw the body away before we ran.
 *
 * A POST over post_max_size never reaches userland: $_POST, $_FILES and
 * php://input are all EMPTY and no error is raised that we can catch. Without
 * this check the request falls through to whatever the route does with empty
 * input — on the API that was a 200 with a PHP warning in place of the JSON, and
 * on the web form it was a CSRF failure telling the agent their session was bad
 * when the truth was that their attachment was too big.
 */
function post_exceeded_limit(): bool {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') return false;
    $max = ini_bytes('post_max_size');
    if ($max <= 0) return false;
    return (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > $max;
}

function max_upload_bytes(): int {
    $mb = (int)cfg('MAX_UPLOAD_MB', '5');
    if ($mb < 1)   $mb = 1;
    if ($mb > 100) $mb = 100;
    return $mb * 1048576;
}

/** Shared list sort: ready first, then awaiting, then read, then expired. */
function requests_list_order_sql(int $limit = 100): string {
    return " ORDER BY CASE status WHEN 'submitted' THEN 0 WHEN 'pending' THEN 1 WHEN 'read' THEN 2 ELSE 3 END, created_at DESC LIMIT $limit";
}

function env_load(string $path): void {
    if (!is_readable($path)) return;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || !str_contains($line, '=')) continue;
        [$k, $v] = explode('=', $line, 2);
        $k = trim($k);
        $v = trim($v, " \t\n\r\0\x0B\"'");
        if (getenv($k) === false) putenv("$k=$v");
    }
}

function cfg(string $k, ?string $default = null): ?string {
    $v = getenv($k);
    return ($v === false || $v === '') ? $default : $v;
}

function data_dir(): string {
    $d = cfg('DATA_DIR', '/home/instapod/handoff-data');
    if (!is_dir($d)) mkdir($d, 0700, true);
    return $d;
}

/**
 * Encrypted share attachments live on disk, not in SQLite.
 *
 * A 5 MB attachment inlined as a BLOB is a 5 MB row that WAL has to copy on every
 * checkpoint, in a database whose other rows are a few hundred bytes. On disk the
 * bytes are also destroyed by an unlink() we can see succeed, rather than by a
 * DELETE that leaves the pages readable until SQLite happens to reuse them.
 *
 * The file is named for the request token and nothing else, so there is no path
 * derived from anything a customer supplies.
 */
function blob_dir(): string {
    $d = data_dir() . '/blobs';
    if (!is_dir($d)) mkdir($d, 0700, true);
    return $d;
}

function blob_path(string $token): ?string {
    if (!preg_match('/^[a-f0-9]{48}$/', $token)) return null;
    return blob_dir() . '/' . $token . '.bin';
}

function blob_put(string $token, string $bytes): void {
    $p = blob_path($token);
    if ($p === null) throw new RuntimeException('Refusing to write a blob for a malformed token.');
    // Write-then-rename: a half-written attachment is never visible under the real
    // name, so a crash mid-upload cannot produce a blob that fails to decrypt.
    $tmp = $p . '.part';
    if (file_put_contents($tmp, $bytes, LOCK_EX) === false) {
        throw new RuntimeException('Could not store the attachment.');
    }
    @chmod($tmp, 0600);
    if (!rename($tmp, $p)) {
        @unlink($tmp);
        throw new RuntimeException('Could not store the attachment.');
    }
}

function blob_exists(string $token): bool {
    $p = blob_path($token);
    return $p !== null && is_file($p);
}

function blob_get(string $token): ?string {
    $p = blob_path($token);
    if ($p === null || !is_file($p)) return null;
    $b = file_get_contents($p);
    return $b === false ? null : $b;
}

/** Safe to call for any row: inbound requests simply have no blob to unlink. */
function blob_delete(string $token): void {
    $p = blob_path($token);
    if ($p === null) return;
    @unlink($p);
    @unlink($p . '.part');
}

function db(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;
    $pdo = new PDO('sqlite:' . data_dir() . '/handoff.sqlite', null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA foreign_keys=ON');
    // Concurrent readers/writers are normal here (two engineers, cron, the customer).
    // Without this SQLite throws "database is locked" immediately, which used to take
    // the audit write down with it -- see the failure handler in public/index.php.
    $pdo->exec('PRAGMA busy_timeout=5000');
    migrate($pdo);
    return $pdo;
}

function migrate(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        pass_hash TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL UNIQUE,
        ticket_id TEXT NOT NULL,
        site_url TEXT,
        need TEXT NOT NULL,
        failed_path TEXT NOT NULL,
        bug_ref TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        submitted_at INTEGER,
        read_at INTEGER,
        read_by TEXT,
        purged_at INTEGER,
        rotation_flagged_at INTEGER,
        status TEXT NOT NULL DEFAULT 'pending',
        share TEXT NOT NULL DEFAULT 'once',
        nonce BLOB,
        ciphertext BLOB
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        request_id INTEGER,
        ticket_id TEXT,
        ip TEXT,
        detail TEXT
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS throttle (
        k TEXT NOT NULL, at INTEGER NOT NULL
    )");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_throttle ON throttle(k, at)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_req_status ON requests(status, expires_at)");
    $staffCols = array_column($pdo->query("PRAGMA table_info(staff)")->fetchAll(), 'name');
    if (!in_array('api_token_hash', $staffCols, true)) {
        $pdo->exec("ALTER TABLE staff ADD COLUMN api_token_hash TEXT");
        $pdo->exec("ALTER TABLE staff ADD COLUMN api_token_at INTEGER");
    }
    if (!in_array('name', $staffCols, true)) {
        $pdo->exec("ALTER TABLE staff ADD COLUMN name TEXT");
    }
    $reqCols = array_column($pdo->query("PRAGMA table_info(requests)")->fetchAll(), 'name');
    if (!in_array('share', $reqCols, true)) {
        $pdo->exec("ALTER TABLE requests ADD COLUMN share TEXT NOT NULL DEFAULT 'once'");
    }
    // Outbound shares. The default on `direction` is what makes every pre-existing
    // row an inbound request without a data migration.
    foreach ([
        'direction'  => "direction TEXT NOT NULL DEFAULT 'in'",
        'pass_hash'  => 'pass_hash TEXT',
        'pass_fails' => 'pass_fails INTEGER NOT NULL DEFAULT 0',
        'file_name'  => 'file_name TEXT',
        'file_size'  => 'file_size INTEGER',
        'file_mime'  => 'file_mime TEXT',
        'dl_token'   => 'dl_token TEXT',
        'dl_expires' => 'dl_expires INTEGER',
    ] as $col => $ddl) {
        if (!in_array($col, $reqCols, true)) $pdo->exec("ALTER TABLE requests ADD COLUMN $ddl");
    }
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_req_direction ON requests(direction, status)");
}

function audit(string $actor, string $action, ?int $reqId = null, ?string $ticket = null, ?string $detail = null): void {
    $st = db()->prepare("INSERT INTO audit (at,actor,action,request_id,ticket_id,ip,detail)
                         VALUES (?,?,?,?,?,?,?)");
    $st->execute([time(), $actor, $action, $reqId, $ticket, client_ip(), $detail]);
}

/**
 * The caller's IP, used to key the login throttle and to fill the audit trail.
 *
 * X-Forwarded-For is attacker-controlled unless the request actually came from our
 * own proxy, so it is honoured ONLY when REMOTE_ADDR is a trusted proxy. Taking the
 * leftmost entry -- the previous behaviour -- let anyone forge it and rotate it, which
 * made the login throttle a no-op and the audit ip column attacker-chosen.
 *
 * We take the RIGHTMOST entry, not the leftmost: nginx's $proxy_add_x_forwarded_for
 * APPENDS the peer address to whatever the client already sent, so the last hop is the
 * only one our proxy vouches for. Everything to the left of it is client-supplied.
 */
function client_ip(): string {
    $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    if ($remote === '') return 'cli';

    // Defaults to EMPTY on purpose: fail closed. Behind nginx->php-fpm REMOTE_ADDR is
    // 127.0.0.1 for every request, so defaulting to trusting loopback would trust a
    // forged X-Forwarded-For from anyone -- which is the bug this function exists to fix.
    // Set TRUSTED_PROXIES only after confirming the proxy APPENDS (nginx's
    // $proxy_add_x_forwarded_for); we then take the rightmost hop, the only one it vouches
    // for. If it is unset, the per-account login throttle is the meaningful limit, since
    // every request looks like it comes from the proxy.
    $trusted = array_filter(array_map('trim', explode(',', (string)cfg('TRUSTED_PROXIES', ''))));
    if (in_array($remote, $trusted, true) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $hops = array_filter(array_map('trim', explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR'])));
        $last = $hops ? end($hops) : false;
        if ($last !== false && filter_var($last, FILTER_VALIDATE_IP)) return $last;
    }
    return $remote;
}

/**
 * Claim the single read of a credential. Returns true for the ONE caller that wins.
 *
 * This is the whole of the "read once" guarantee. It must stay a compare-and-set: the
 * caller's earlier status check is only an optimisation, and two requests can both pass
 * it before either writes. Extracted from the route so it can be falsified directly --
 * through HTTP the pre-check masks a missing guard and the test passes either way.
 */
function claim_credential_read(int $id, string $staff): bool {
    $st = db()->prepare("UPDATE requests SET status='read', read_at=?, read_by=?, nonce=NULL, ciphertext=NULL
                         WHERE id=? AND status='submitted'");
    $st->execute([time(), $staff, $id]);
    return $st->rowCount() === 1;
}

/**
 * Defer work until after the response has been sent.
 *
 * The reveal path used to destroy the ciphertext and then make two blocking 15s
 * FreeScout calls BEFORE echoing the plaintext, so a slow or unreachable FreeScout
 * meant the engineer got zero bytes while the only copy of the credential was already
 * gone. Anything that talks to a third party belongs here, after the bytes are out.
 */
function defer(callable $fn): void {
    // Self-registering: bin/sweep.php is a second entrypoint and would otherwise queue
    // work that nothing ever drains.
    if (empty($GLOBALS['__deferred']) && empty($GLOBALS['__deferred_registered'])) {
        $GLOBALS['__deferred_registered'] = true;
        register_shutdown_function('run_deferred');
    }
    $GLOBALS['__deferred'][] = $fn;
}

function run_deferred(): void {
    $queue = $GLOBALS['__deferred'] ?? [];
    $GLOBALS['__deferred'] = [];
    if (!$queue) return;
    // Release the client first, then do the slow work.
    if (function_exists('fastcgi_finish_request')) {
        @fastcgi_finish_request();
    } else {
        while (ob_get_level() > 0) @ob_end_flush();
        @flush();
    }
    foreach ($queue as $fn) {
        // Best effort by definition: the response is already sent, so a failure here
        // must never surface as a broken page.
        try { $fn(); } catch (Throwable $e) { /* deliberately swallowed */ }
    }
}

/** Bounded attempts per key within a window. Returns false when over the limit. */
function throttle_ok(string $key, int $limit, int $windowSec): bool {
    $pdo = db();
    $pdo->prepare("DELETE FROM throttle WHERE at < ?")->execute([time() - 86400]);
    $st = $pdo->prepare("SELECT COUNT(*) c FROM throttle WHERE k = ? AND at > ?");
    $st->execute([$key, time() - $windowSec]);
    if ((int)$st->fetch()['c'] >= $limit) return false;
    $pdo->prepare("INSERT INTO throttle (k, at) VALUES (?,?)")->execute([$key, time()]);
    return true;
}

function csp_nonce(): string {
    static $n = null;
    return $n ??= bin2hex(random_bytes(16));
}

function h(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $to): never {
    header('Location: ' . $to);
    exit;
}
