<?php
/**
 * Fires N reveal POSTs at one request as close to simultaneously as the machine allows,
 * and prints how many of them received the plaintext.
 *
 * Shell background jobs are not a tight enough start to expose the burn-on-read race:
 * the losers reach the cheap status pre-check after the winner has already written, so
 * the compare-and-set never gets exercised and the test passes with the guard removed.
 * curl_multi dispatches all handles in one event loop, which does reach it.
 *
 * Usage: php bin/race.php <url> <needle> <jar1:csrf1> <jar2:csrf2> ...
 * Prints: <count of responses containing the needle>
 */
declare(strict_types=1);
$url = $argv[1]; $needle = $argv[2];
$pairs = array_slice($argv, 3);

$mh = curl_multi_init();
$handles = [];
foreach ($pairs as $p) {
    [$jar, $csrf] = explode(':', $p, 2);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query(['csrf' => $csrf, 'action' => 'reveal']),
        CURLOPT_COOKIEFILE     => $jar,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 20,
    ]);
    curl_multi_add_handle($mh, $ch);
    $handles[] = $ch;
}
do { $status = curl_multi_exec($mh, $running); if ($running) curl_multi_select($mh, 1.0); }
while ($running && $status === CURLM_OK);

$hits = 0;
foreach ($handles as $ch) {
    if (str_contains((string)curl_multi_getcontent($ch), $needle)) $hits++;
    curl_multi_remove_handle($mh, $ch); curl_close($ch);
}
curl_multi_close($mh);
echo $hits, "\n";
