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
 * The WordPress options are always available: a temporary admin account and an
 * application password are both scoped and individually revocable.
 *
 * The infrastructure options (SSH/SFTP) are gated behind ALLOW_INFRA_CREDENTIALS
 * and ship OFF. They are not a feature toggle — they are decision D1 in
 * KB runbooks/what-support-may-ask-a-customer-to-send, which is with the owner.
 * Do not flip this on without that sign-off recorded. Unlike a WordPress
 * credential, an SSH credential is broad, reusable, and cannot be revoked without
 * collateral damage — and on an agency ticket it is usually their client's server,
 * with the person whose data is at risk not in the conversation.
 */
function infra_enabled(): bool {
    return in_array(strtolower((string)cfg('ALLOW_INFRA_CREDENTIALS', '0')), ['1', 'true', 'yes'], true);
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

function h(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $to): never {
    header('Location: ' . $to);
    exit;
}
