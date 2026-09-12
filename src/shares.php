<?php
declare(strict_types=1);

/**
 * Outbound shares — the mirror of a credential request.
 *
 * A request collects a secret FROM the customer. A share delivers one TO them:
 * staff write a message, optionally attach a file, the app mints a link, and the
 * customer opens it once. Same table, same master key, same burn-on-read — the
 * `direction` column is the whole of the difference, so expiry, purge, audit and
 * the dashboard did not have to be written twice.
 *
 * The threat model is inverted, which is why a share can carry a passphrase and a
 * request cannot. An intercepted INBOUND link is worthless — it is an empty form.
 * An OUTBOUND link *is* the secret, so whoever reads the customer's mailbox has it.
 * The passphrase is passed out of band (spoken on the call, sent by SMS) and closes
 * exactly that gap.
 *
 * The passphrase gates access; it does not derive the key. APP_KEY still decrypts
 * everything, as it does everywhere else in this app. Deriving from the passphrase
 * would also defend against a compromise of our own disk, which nothing else here
 * claims to do — pretending otherwise on this one route would be a security
 * property nobody could rely on.
 */

/** How long the attachment stays fetchable after the message has been opened. */
const SHARE_DOWNLOAD_GRANT = 900;

/** Wrong passphrases before the content is destroyed rather than merely throttled. */
const SHARE_MAX_PASS_FAILS = 5;

function share_fields_valid(string $ticket, string $message, string $view, int $ttl, bool $hasFile): bool {
    return $ticket !== ''
        && ($message !== '' || $hasFile)
        && isset(view_choices()[$view])
        && isset(ttl_choices()[$ttl]);
}

function view_from_post(): string {
    $v = (string)($_POST['view'] ?? 'once');
    return isset(view_choices()[$v]) ? $v : 'once';
}

/**
 * Strip an uploaded filename back to something safe to write into a
 * Content-Disposition header and never to a path.
 */
function share_safe_filename(string $name): string {
    $name = str_replace(['/', '\\', "\0"], '_', $name);
    $name = basename($name);
    $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name) ?? '';
    $name = trim($name, " .\t");
    if ($name === '') $name = 'attachment';
    if (strlen($name) > 150) {
        $ext  = pathinfo($name, PATHINFO_EXTENSION);
        $stem = substr(pathinfo($name, PATHINFO_FILENAME), 0, 140);
        $name = $ext === '' ? $stem : $stem . '.' . substr($ext, 0, 9);
    }
    return $name;
}

/**
 * Normalise $_FILES for one field.
 *
 * @return array{name:string,size:int,mime:string,bytes:string}|string|null
 *         null when nothing was attached, a message string on refusal.
 */
function share_file_from_upload(string $field): array|string|null {
    $f = $_FILES[$field] ?? null;
    if (!is_array($f) || ($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) return null;

    $limitMb = max_upload_bytes() / 1048576;
    switch ((int)$f['error']) {
        case UPLOAD_ERR_OK:
            break;
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE:
            return 'That file is too large. The limit is ' . rtrim(rtrim(number_format($limitMb, 1), '0'), '.') . ' MB.';
        case UPLOAD_ERR_PARTIAL:
            return 'The upload did not finish. Try again.';
        default:
            return 'The upload failed. Try again, or send the message without a file.';
    }
    // is_uploaded_file is the guard that stops a crafted $_FILES entry naming an
    // arbitrary readable path (/home/instapod/handoff.env, say) and having us
    // encrypt it and hand it to a customer.
    if (!is_uploaded_file((string)$f['tmp_name'])) {
        return 'The upload failed. Try again, or send the message without a file.';
    }
    if ((int)$f['size'] > max_upload_bytes()) {
        return 'That file is too large. The limit is ' . rtrim(rtrim(number_format($limitMb, 1), '0'), '.') . ' MB.';
    }
    $bytes = file_get_contents((string)$f['tmp_name']);
    if ($bytes === false) return 'The upload could not be read. Try again.';
    if ($bytes === '')    return 'That file is empty.';

    $mime = 'application/octet-stream';
    if (class_exists('finfo')) {
        $probe = (new finfo(FILEINFO_MIME_TYPE))->file((string)$f['tmp_name']);
        if (is_string($probe) && $probe !== '') $mime = $probe;
    }
    return [
        'name'  => share_safe_filename((string)$f['name']),
        'size'  => strlen($bytes),
        'mime'  => $mime,
        'bytes' => $bytes,
    ];
}

/**
 * Mint an outbound link. Caller must have validated the fields already.
 *
 * @param array{name:string,size:int,mime:string,bytes:string}|null $file
 * @return array{id:int,url:string,expires_at:int,token:string}
 */
function mint_share(string $staff, string $ticket, string $message, string $view, int $ttl,
                    ?string $passphrase, ?array $file, string $base): array {
    $token = new_token();
    $now   = time();
    $exp   = $now + $ttl;

    [$nonce, $ct] = seal((string)json_encode(
        ['message' => $message],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    ));

    // Blob before row, and unlink if the row fails: a row promising an attachment
    // whose bytes were never written renders a download button that 500s, and by
    // then the link is already in the customer's inbox.
    if ($file !== null) blob_put($token, seal_raw($file['bytes']));

    try {
        db()->prepare(
            "INSERT INTO requests
                (token,ticket_id,need,failed_path,bug_ref,requested_by,created_at,expires_at,
                 status,share,direction,nonce,ciphertext,pass_hash,file_name,file_size,file_mime)
             VALUES (?,?,'message','','',?,?,?,'pending',?,'out',?,?,?,?,?,?)"
        )->execute([
            $token, $ticket, $staff, $now, $exp, $view, $nonce, $ct,
            ($passphrase === null || $passphrase === '') ? null : password_hash($passphrase, PASSWORD_DEFAULT),
            $file['name'] ?? null, $file['size'] ?? null, $file['mime'] ?? null,
        ]);
    } catch (Throwable $e) {
        blob_delete($token);
        throw $e;
    }

    $id  = (int)db()->lastInsertId();
    $url = rtrim($base, '/') . '/v/' . $token;
    audit($staff, 'share.created', $id, $ticket,
        'view=' . $view . ' ttl=' . $ttl . 's'
        . ' pass=' . ($passphrase === null || $passphrase === '' ? 'no' : 'yes')
        . ' file=' . ($file === null ? 'no' : 'yes'));

    $lines = [
        'Automated note — secure credential handoff.',
        '',
        "$staff sent the customer a secure message through the handoff app.",
        'The content is NOT in this note, and is not stored in FreeScout.',
        '',
        $file !== null ? 'It carries an attachment: ' . $file['name'] : 'It carries no attachment.',
        ($passphrase === null || $passphrase === '')
            ? 'It is not passphrase-protected — the link alone opens it.'
            : 'It is passphrase-protected. The passphrase must reach the customer some other way.',
        view_is_once(['share' => $view])
            ? 'It can be opened ONCE, then it is destroyed.'
            : 'It can be re-opened until it expires.',
        '',
        'Expires ' . gmdate('Y-m-d H:i', $exp) . ' UTC.',
    ];
    defer(fn() => freescout_note($ticket, implode("\n", $lines)));

    return ['id' => $id, 'url' => $url, 'expires_at' => $exp, 'token' => $token];
}

/** True while this share still has content the customer could open. */
function share_openable(array $r): bool {
    if ((int)$r['expires_at'] < time()) return false;
    if ($r['ciphertext'] === null) return false;
    return $r['status'] === 'pending' || ($r['status'] === 'read' && !view_is_once($r));
}

/**
 * Claim the single view of a view-once share. Returns true for the ONE caller
 * that wins. Same compare-and-set contract as claim_credential_read() — the
 * caller's status check above is an optimisation, not the guarantee.
 */
function claim_share_view(int $id): bool {
    $st = db()->prepare("UPDATE requests SET status='read', read_at=?, read_by='customer',
                         nonce=NULL, ciphertext=NULL WHERE id=? AND status='pending'");
    $st->execute([time(), $id]);
    return $st->rowCount() === 1;
}

/**
 * Open a share on the customer's behalf: decrypt, then burn if it is view-once.
 *
 * Decrypt FIRST. Burning a share we then fail to decrypt would destroy the only
 * copy and show the customer an error, with nothing left to retry.
 *
 * @param array<string,mixed> $r
 * @return array{ok:true,message:string,file:?array{name:string,size:int,url:string}}|array{ok:false,error:string}
 */
function open_share(array $r, string $base): array {
    if (!share_openable($r)) {
        return ['ok' => false, 'error' => 'This message has already been opened, or it has expired.'];
    }
    try {
        $plain = unseal((string)$r['nonce'], (string)$r['ciphertext']);
    } catch (Throwable $e) {
        audit('customer', 'share.view.failed', (int)$r['id'], (string)$r['ticket_id'], $e->getMessage());
        return ['ok' => false, 'error' => 'This message could not be opened. Reply on your ticket and we will resend it.'];
    }

    $id     = (int)$r['id'];
    $ticket = (string)$r['ticket_id'];

    if (view_is_once($r)) {
        if (!claim_share_view($id)) {
            audit('customer', 'share.view.lost_race', $id, $ticket);
            sodium_memzero($plain);
            return ['ok' => false, 'error' => 'This message has already been opened.'];
        }
    } else {
        db()->prepare("UPDATE requests SET status='read', read_at=COALESCE(read_at,?), read_by='customer'
                       WHERE id=? AND status IN ('pending','read')")->execute([time(), $id]);
    }
    audit('customer', 'share.viewed', $id, $ticket);

    // The attachment cannot be handed over in this response — it is a second
    // request — so opening the message mints a short grant to fetch it with. The
    // message is gone either way; the grant is what keeps "view once" honest
    // without making a dropped download unrecoverable.
    $file = null;
    if ($r['file_name'] !== null && blob_exists((string)$r['token'])) {
        $grant = new_token();
        $until = min(time() + SHARE_DOWNLOAD_GRANT, (int)$r['expires_at']);
        db()->prepare("UPDATE requests SET dl_token=?, dl_expires=? WHERE id=?")->execute([$grant, $until, $id]);
        $file = [
            'name' => (string)$r['file_name'],
            'size' => (int)$r['file_size'],
            'url'  => rtrim($base, '/') . '/v/' . $r['token'] . '/f/' . $grant,
        ];
    }

    $data    = json_decode($plain, true);
    $message = is_array($data) ? (string)($data['message'] ?? '') : $plain;

    defer(fn() => freescout_note($ticket,
        "Automated note — secure credential handoff.\n\n" .
        "The customer opened the secure message sent to them, on " . gmdate('Y-m-d H:i', time()) . " UTC.\n" .
        (view_is_once($r)
            ? "The stored copy has been destroyed. It cannot be opened again."
            : "It stays openable until " . gmdate('Y-m-d H:i', (int)$r['expires_at']) . " UTC.")));

    return ['ok' => true, 'message' => $message, 'file' => $file];
}

/** Constant-time check of a download grant. */
function share_grant_ok(array $r, string $grant): bool {
    return $r['dl_token'] !== null
        && $r['dl_expires'] !== null
        && (int)$r['dl_expires'] > time()
        && hash_equals((string)$r['dl_token'], $grant);
}

/**
 * Record a failed passphrase attempt, destroying the content at the limit.
 *
 * Throttling alone only slows an attacker down; the link is public and the
 * passphrase is usually short enough to be worth grinding. Destroying at five
 * means a guessing attempt costs the customer a resend rather than the secret.
 */
function share_pass_failed(array $r): bool {
    $id = (int)$r['id'];
    db()->prepare("UPDATE requests SET pass_fails = pass_fails + 1 WHERE id=?")->execute([$id]);
    $st = db()->prepare("SELECT pass_fails FROM requests WHERE id=?");
    $st->execute([$id]);
    $fails = (int)($st->fetch()['pass_fails'] ?? 0);
    audit('customer', 'share.unlock.failed', $id, (string)$r['ticket_id'], "attempt=$fails");

    if ($fails < SHARE_MAX_PASS_FAILS) return false;

    db()->prepare("UPDATE requests SET status='expired', purged_at=?, nonce=NULL, ciphertext=NULL,
                   dl_token=NULL, dl_expires=NULL WHERE id=?")->execute([time(), $id]);
    blob_delete((string)$r['token']);
    audit('system', 'share.destroyed.attempts', $id, (string)$r['ticket_id'], "fails=$fails");
    $ticket = (string)$r['ticket_id'];
    defer(fn() => freescout_note($ticket,
        "Automated note — secure credential handoff.\n\n" .
        "A secure message sent to this customer was destroyed after " . SHARE_MAX_PASS_FAILS .
        " wrong passphrase attempts.\n" .
        "That may simply be the customer mistyping it — but treat the link as having been\n" .
        "seen by someone else until you have confirmed otherwise, and send a fresh one."));
    return true;
}

/**
 * Drop attachment bytes whose download grant has run out.
 *
 * A view-once share keeps its blob past the read that destroyed its message, so
 * that the grant can still serve it. Without this the file would outlive the
 * message by the whole TTL, quietly defeating the point.
 */
function purge_share_blobs(string $actor = 'system'): int {
    $st = db()->prepare("SELECT id, token, ticket_id FROM requests
                         WHERE direction='out' AND file_name IS NOT NULL
                           AND dl_expires IS NOT NULL AND dl_expires < ?
                           AND status='read' AND share != 'keep'");
    $st->execute([time()]);
    $n = 0;
    foreach ($st->fetchAll() as $r) {
        if (!blob_exists((string)$r['token'])) continue;
        blob_delete((string)$r['token']);
        db()->prepare("UPDATE requests SET dl_token=NULL, dl_expires=NULL WHERE id=?")->execute([(int)$r['id']]);
        audit($actor, 'share.file.purged', (int)$r['id'], (string)$r['ticket_id']);
        $n++;
    }
    return $n;
}

/** Human-readable attachment size. */
function share_size_label(int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return round($bytes / 1024) . ' KB';
    return rtrim(rtrim(number_format($bytes / 1048576, 1), '0'), '.') . ' MB';
}

/**
 * Serialize an outbound share for the API.
 *
 * Never includes the message, the ciphertext, or the attachment bytes. There is no
 * read-back endpoint for a share at all: the content is the customer's to open once,
 * and an API that could replay it would make "view once" false for every share ever
 * sent, silently and for the whole TTL.
 *
 * @param array<string,mixed> $r
 * @return array<string,mixed>
 */
function share_to_api(array $r, string $base, bool $includeUrl = true): array {
    $out = [
        'id'            => (int)$r['id'],
        'ticket_id'     => (string)$r['ticket_id'],
        'direction'     => 'out',
        'status'        => (string)$r['status'],
        'sent_by'       => (string)$r['requested_by'],
        'created_at'    => (int)$r['created_at'],
        'expires_at'    => (int)$r['expires_at'],
        'opened_at'     => $r['read_at'] !== null ? (int)$r['read_at'] : null,
        'view'          => (string)($r['share'] ?? 'once'),
        'view_label'    => view_label($r),
        'passphrase'    => $r['pass_hash'] !== null,
        'pass_fails'    => (int)($r['pass_fails'] ?? 0),
        'attachment'    => $r['file_name'] === null ? null : [
            'name'      => (string)$r['file_name'],
            'size'      => (int)$r['file_size'],
            'mime'      => (string)$r['file_mime'],
            'available' => blob_exists((string)$r['token']),
        ],
    ];
    if ($includeUrl && share_openable($r)) {
        $out['url'] = rtrim($base, '/') . '/v/' . $r['token'];
    }
    return $out;
}

/**
 * Decode an API attachment: {"name": "...", "content_b64": "..."}.
 *
 * @return array{name:string,size:int,mime:string,bytes:string}|string|null
 */
function share_file_from_api(mixed $spec): array|string|null {
    if ($spec === null) return null;
    if (!is_array($spec)) return 'attachment must be an object with name and content_b64.';
    $name = share_safe_filename((string)($spec['name'] ?? ''));
    $b64  = (string)($spec['content_b64'] ?? '');
    if ($b64 === '') return 'attachment.content_b64 is required.';
    $bytes = base64_decode($b64, true);
    if ($bytes === false) return 'attachment.content_b64 is not valid base64.';
    if ($bytes === '')    return 'attachment.content_b64 decoded to nothing.';
    if (strlen($bytes) > max_upload_bytes()) {
        return 'attachment is larger than the ' . share_size_label(max_upload_bytes()) . ' limit.';
    }
    $mime = 'application/octet-stream';
    if (class_exists('finfo')) {
        $probe = (new finfo(FILEINFO_MIME_TYPE))->buffer($bytes);
        if (is_string($probe) && $probe !== '') $mime = $probe;
    }
    return ['name' => $name, 'size' => strlen($bytes), 'mime' => $mime, 'bytes' => $bytes];
}
