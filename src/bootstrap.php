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

function client_ip(): string {
    foreach (['HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $k) {
        if (!empty($_SERVER[$k])) return trim(explode(',', $_SERVER[$k])[0]);
    }
    return 'cli';
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
