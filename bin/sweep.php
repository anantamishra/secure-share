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

echo 'purged ' . purge_expired('cron') . "\n";
