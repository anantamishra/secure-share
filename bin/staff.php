<?php
declare(strict_types=1);
require __DIR__ . '/../src/bootstrap.php';
env_load(getenv('APP_ENV_FILE') ?: '/home/instapod/handoff.env');

$cmd = $argv[1] ?? '';
if ($cmd === 'add') {
    $email = strtolower(trim((string)($argv[2] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) exit("usage: staff.php add <email>\n");
    $pw = bin2hex(random_bytes(9));
    db()->prepare("INSERT INTO staff (email,pass_hash,active,created_at) VALUES (?,?,1,?)
                   ON CONFLICT(email) DO UPDATE SET pass_hash=excluded.pass_hash, active=1")
        ->execute([$email, password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12]), time()]);
    audit('cli', 'staff.added', null, null, $email);
    echo "$email\n$pw\n";
} elseif ($cmd === 'disable') {
    db()->prepare("UPDATE staff SET active=0 WHERE email=?")->execute([strtolower(trim((string)$argv[2]))]);
    audit('cli', 'staff.disabled', null, null, (string)$argv[2]);
    echo "disabled\n";
} elseif ($cmd === 'list') {
    foreach (db()->query("SELECT email,active,created_at FROM staff ORDER BY email")->fetchAll() as $s) {
        printf("%-34s %s  added %s\n", $s['email'], $s['active'] ? 'active ' : 'DISABLED', gmdate('Y-m-d', (int)$s['created_at']));
    }
} else {
    exit("usage: staff.php add|disable|list\n");
}
