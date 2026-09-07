<?php
declare(strict_types=1);

function session_start_secure(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    // Keep sessions inside our own data dir rather than the distro default, which
    // php-fpm may not own. On InstaPods php-fpm and the app files run as different
    // users unless corrected, and an unwritable session path breaks login with a
    // warning rather than an error.
    $sess = data_dir() . '/sessions';
    if (!is_dir($sess)) mkdir($sess, 0700, true);
    session_save_path($sess);
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        // Driven by our own configured APP_URL as well as the request, so the flag does
        // not silently drop if the proxy ever stops sending X-Forwarded-Proto.
        'secure'   => str_starts_with((string)cfg('APP_URL', ''), 'https://')
                      || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
                      || (($_SERVER['HTTPS'] ?? '') === 'on'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_name('iwp_handoff');
    session_start();
}

/** Staff sessions expire on their own. Session files here are never garbage-collected
 *  (gc_probability is 0 on Debian/Ubuntu and the distro sweeper only looks at the ini
 *  path, not our DATA_DIR/sessions), so without this a session file is immortal. */
const STAFF_SESSION_MAX_AGE = 43200; // 12 hours

function current_staff(): ?string {
    session_start_secure();
    $email = $_SESSION['staff_email'] ?? null;
    if ($email === null) return null;
    $since = (int)($_SESSION['login_at'] ?? 0);
    if ($since <= 0 || (time() - $since) > STAFF_SESSION_MAX_AGE) {
        staff_logout();
        return null;
    }
    return $email;
}

/**
 * Every staff page goes through here, so this is the only place that can notice a
 * member has been offboarded. It re-checks `active` on each request: checking it at
 * login only meant `bin/staff.php disable` did nothing to anyone already signed in,
 * and their session then never expired either.
 */
function require_staff(): string {
    $e = current_staff();
    if ($e === null) redirect('/login');
    $st = db()->prepare("SELECT 1 FROM staff WHERE email = ? AND active = 1");
    $st->execute([$e]);
    if (!$st->fetchColumn()) {
        audit($e, 'staff.session.revoked');
        staff_logout();
        redirect('/login');
    }
    return $e;
}

function staff_login(string $email, string $password): bool {
    $st = db()->prepare("SELECT * FROM staff WHERE email = ? AND active = 1");
    $st->execute([strtolower(trim($email))]);
    $row = $st->fetch();
    // Always spend the hash time, so a missing account and a wrong password
    // are not distinguishable by response timing.
    $hash = $row['pass_hash'] ?? '$2y$12$' . str_repeat('.', 53);
    if (!password_verify($password, $hash) || !$row) return false;
    session_start_secure();
    session_regenerate_id(true);
    $_SESSION['staff_email'] = $row['email'];
    $_SESSION['login_at']    = time();
    return true;
}

function staff_logout(): void {
    session_start_secure();
    $_SESSION = [];
    session_destroy();
}

/** @return array<string,mixed>|null */
function staff_account(string $email): ?array {
    $st = db()->prepare("SELECT email, name, pass_hash, active FROM staff WHERE email = ?");
    $st->execute([$email]);
    $row = $st->fetch();
    return $row ?: null;
}

function staff_verify_password(string $email, string $password): bool {
    $row = staff_account($email);
    return $row !== null && password_verify($password, (string)$row['pass_hash']);
}

function staff_display_name(?array $row, string $email): string {
    $name = trim((string)($row['name'] ?? ''));
    return $name !== '' ? $name : $email;
}

function csrf_token(): string {
    session_start_secure();
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(16));
}

function csrf_check(): void {
    session_start_secure();
    $given = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', (string)$given)) {
        http_response_code(400);
        exit('Bad CSRF token. Reload the form and try again.');
    }
}
