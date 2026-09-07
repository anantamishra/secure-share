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
        'secure'   => (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
                      || (($_SERVER['HTTPS'] ?? '') === 'on'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_name('iwp_handoff');
    session_start();
}

function current_staff(): ?string {
    session_start_secure();
    return $_SESSION['staff_email'] ?? null;
}

function require_staff(): string {
    $e = current_staff();
    if ($e === null) redirect('/login');
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
    return true;
}

function staff_logout(): void {
    session_start_secure();
    $_SESSION = [];
    session_destroy();
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
