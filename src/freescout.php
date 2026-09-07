<?php
declare(strict_types=1);

/**
 * Optional FreeScout write-back. Degrades to a no-op when unconfigured, so the
 * app is fully usable before anyone hands it an API key.
 *
 * Note: FREESCOUT_API_URL already includes /api — appending /api yourself returns
 * HTTP 405 with an empty body, which reads like an auth failure and is not one.
 */
function freescout_note(string $ticketId, string $text): bool {
    $base = cfg('FREESCOUT_API_URL');
    $key  = cfg('FREESCOUT_API_KEY');
    $user = cfg('FREESCOUT_USER_ID', '1');
    if ($base === null || $key === null || !ctype_digit($ticketId)) return false;

    $ch = curl_init(rtrim($base, '/') . '/conversations/' . $ticketId . '/threads');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'X-FreeScout-API-Key: ' . $key],
        CURLOPT_POSTFIELDS     => json_encode([
            'type' => 'note', 'text' => $text, 'user' => (int)$user,
        ]),
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    $ok = $code >= 200 && $code < 300;
    audit('system', $ok ? 'freescout.note.posted' : 'freescout.note.failed', null, $ticketId,
          $ok ? null : "HTTP $code " . substr((string)$body, 0, 200));
    return $ok;
}
