<?php
// Cron entrypoint. The web front controller sweeps on every request too, so this
// only matters for a quiet period with no traffic — which is exactly when an
// expired credential would otherwise sit in the database unpurged.
declare(strict_types=1);
require __DIR__ . '/../src/bootstrap.php';
env_load(getenv('APP_ENV_FILE') ?: '/home/instapod/handoff.env');
require __DIR__ . '/../src/crypto.php';
require __DIR__ . '/../src/freescout.php';
require __DIR__ . '/../src/rotation.php';

$pdo = db();
$st = $pdo->prepare("SELECT * FROM requests WHERE expires_at < ? AND status IN ('pending','submitted','read')");
$st->execute([time()]);
$n = 0;
foreach ($st->fetchAll() as $r) {
    $pdo->prepare("UPDATE requests SET status='expired', purged_at=?, nonce=NULL, ciphertext=NULL WHERE id=?")
        ->execute([time(), $r['id']]);
    audit('cron', 'request.expired.purged', (int)$r['id'], $r['ticket_id']);
    // Only nag when the customer actually sent something. The web sweep has always had
    // this guard and this one did not, so an expired PENDING link produced a note telling
    // the customer to rotate a password they never submitted -- and asserting we had it.
    // False nags are how staff learn to ignore the real ones.
    if ($r['submitted_at'] !== null) flag_rotation((int)$r['id']);
    $n++;
}
echo "purged $n\n";
