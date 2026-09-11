<?php
declare(strict_types=1);

function request_fields_valid(string $ticket, string $need, string $failed, string $bug, int $ttl): bool {
    return $ticket !== '' && isset(needs()[$need]) && $failed !== '' && $bug !== '' && isset(ttl_choices()[$ttl]);
}

/**
 * Mint a single-use customer link. Caller must have already validated the fields.
 *
 * @return array{id:int,url:string,expires_at:int,token:string}
 */
function mint_request(string $staff, string $ticket, string $need, string $failed, string $bug, int $ttl, string $base): array {
    $token = new_token();
    $now   = time();
    $exp   = $now + $ttl;
    db()->prepare("INSERT INTO requests (token,ticket_id,need,failed_path,bug_ref,requested_by,created_at,expires_at)
                   VALUES (?,?,?,?,?,?,?,?)")
        ->execute([$token, $ticket, $need, $failed, $bug, $staff, $now, $exp]);
    $id = (int)db()->lastInsertId();
    audit($staff, 'request.created', $id, $ticket, "need=$need ttl={$ttl}s bug=$bug");
    $url = rtrim($base, '/') . '/s/' . $token;
    freescout_note($ticket,
        "Automated note — secure credential handoff.\n\n" .
        "$staff raised a credential request (" . needs()[$need] . ").\n" .
        "Product path that failed: $failed\nBug reference: $bug\n\n" .
        "Send the customer this single-use link:\n$url\n\nIt expires " . gmdate('Y-m-d H:i', $exp) . " UTC.");
    return ['id' => $id, 'url' => $url, 'expires_at' => $exp, 'token' => $token];
}

/**
 * Serialize a request row for the API. Never includes nonce or ciphertext.
 *
 * @param array<string,mixed> $r
 * @return array<string,mixed>
 */
function request_to_api(array $r, string $base, bool $includeUrl = true): array {
    $out = [
        'id'                  => (int)$r['id'],
        'ticket_id'           => (string)$r['ticket_id'],
        'need'                => (string)$r['need'],
        'need_label'          => needs()[$r['need']] ?? (string)$r['need'],
        'failed_path'         => (string)$r['failed_path'],
        'bug_ref'             => (string)$r['bug_ref'],
        'requested_by'        => (string)$r['requested_by'],
        'status'              => (string)$r['status'],
        'created_at'          => (int)$r['created_at'],
        'expires_at'          => (int)$r['expires_at'],
        'submitted_at'        => $r['submitted_at'] !== null ? (int)$r['submitted_at'] : null,
        'read_at'             => $r['read_at'] !== null ? (int)$r['read_at'] : null,
        'read_by'             => $r['read_by'],
        'rotation_flagged_at' => $r['rotation_flagged_at'] !== null ? (int)$r['rotation_flagged_at'] : null,
        'share'               => (string)($r['share'] ?? 'once'),
        'share_label'         => share_label($r),
    ];
    if ($includeUrl && $r['status'] === 'pending') {
        $out['url'] = rtrim($base, '/') . '/s/' . $r['token'];
    }
    return $out;
}

/**
 * Burn-on-read. Decrypts first, then compare-and-set. Same guarantee as the web UI.
 *
 * @param array<string,mixed> $r
 * @return array{ok:true,fields:array<string,string>,plain:string}|array{ok:false,error:string,lost_race?:bool,decrypt_failed?:bool}
 */
function reveal_request(array $r, string $staff): array {
    if ($r['status'] !== 'submitted') {
        return ['ok' => false, 'error' => 'Nothing to read — this request is ' . (string)$r['status'] . '.'];
    }
    if ((int)$r['expires_at'] < time()) {
        return ['ok' => false, 'error' => 'Nothing to read — this request has expired.'];
    }
    try {
        $plain = unseal((string)$r['nonce'], (string)$r['ciphertext']);
        $ticket = (string)$r['ticket_id'];

        if (share_is_once($r)) {
            $won = claim_credential_read((int)$r['id'], $staff);
            if (!$won) {
                sodium_memzero($plain);
                audit($staff, 'credential.read.lost_race', (int)$r['id'], $ticket);
                return ['ok' => false, 'lost_race' => true, 'error' => 'Nothing to read — someone else opened this first.'];
            }
            audit($staff, 'credential.read', (int)$r['id'], $ticket);
            defer(fn() => freescout_note($ticket,
                "Automated note — secure credential handoff.\n\n" .
                "$staff opened the credential for this ticket on " . gmdate('Y-m-d H:i', time()) . " UTC.\n" .
                "The stored copy has been destroyed. It cannot be opened again.\n\n" .
                "When the work is done, ask the customer to change the password AND delete the application\n" .
                "password created for us — a password change does not revoke one."));
            flag_rotation((int)$r['id']);
        } else {
            $first = db()->prepare("UPDATE requests SET read_at=?, read_by=? WHERE id=? AND status='submitted' AND read_at IS NULL");
            $first->execute([time(), $staff, (int)$r['id']]);
            if ($first->rowCount() === 1) {
                audit($staff, 'credential.read', (int)$r['id'], $ticket);
                $until = gmdate('Y-m-d H:i', (int)$r['expires_at']);
                defer(fn() => freescout_note($ticket,
                    "Automated note — secure credential handoff.\n\n" .
                    "$staff opened the credential for this ticket on " . gmdate('Y-m-d H:i', time()) . " UTC.\n" .
                    "The customer asked us to keep it until $until UTC. It can be opened again until then.\n\n" .
                    "When the work is done, ask the customer to change the password AND delete the application\n" .
                    "password created for us — a password change does not revoke one."));
                flag_rotation((int)$r['id']);
            } else {
                audit($staff, 'credential.reread', (int)$r['id'], $ticket);
            }
        }

        $fields = json_decode($plain, true);
        if (!is_array($fields)) $fields = ['_raw' => $plain];
        /** @var array<string,string> $clean */
        $clean = [];
        foreach ($fields as $k => $v) {
            if (trim((string)$v) === '') continue;
            $clean[(string)$k] = (string)$v;
        }
        return ['ok' => true, 'fields' => $clean, 'plain' => $plain];
    } catch (Throwable $e) {
        try { audit($staff, 'credential.read.failed', (int)$r['id'], (string)$r['ticket_id'], $e->getMessage()); }
        catch (Throwable $ignored) { /* nothing further we can do from here */ }
        return ['ok' => false, 'decrypt_failed' => true, 'error' => $e->getMessage()];
    }
}

/**
 * Destroy stored ciphertext, then remove the row. Rotation is flagged when the
 * customer had already submitted and we had not yet nagged.
 */
function delete_request(int $id, string $staff): bool {
    if ($id < 1) return false;
    $st = db()->prepare("SELECT * FROM requests WHERE id = ?");
    $st->execute([$id]);
    $r = $st->fetch();
    if (!$r) return false;

    db()->prepare("UPDATE requests SET nonce=NULL, ciphertext=NULL, purged_at=? WHERE id=?")
        ->execute([time(), $id]);
    // An outbound share's attachment lives on disk, so NULLing the row is not enough.
    blob_delete((string)$r['token']);
    if ($r['submitted_at'] !== null && $r['rotation_flagged_at'] === null) {
        flag_rotation($id);
    }
    db()->prepare("DELETE FROM requests WHERE id = ?")->execute([$id]);
    audit($staff, 'request.deleted', $id, (string)$r['ticket_id'], 'status=' . $r['status']);
    return true;
}

/** Mark a row expired now: wipe ciphertext, keep the row, nag if they had submitted. */
function expire_request(int $id, string $staff): bool {
    if ($id < 1) return false;
    $st = db()->prepare("SELECT * FROM requests WHERE id = ?");
    $st->execute([$id]);
    $r = $st->fetch();
    if (!$r || $r['status'] === 'expired') return false;

    $upd = db()->prepare("UPDATE requests SET status='expired', purged_at=?, nonce=NULL, ciphertext=NULL,
                          dl_token=NULL, dl_expires=NULL WHERE id=? AND status!='expired'");
    $upd->execute([time(), $id]);
    if ($upd->rowCount() !== 1) return false;
    blob_delete((string)$r['token']);
    audit($staff, 'request.expired', $id, (string)$r['ticket_id'], 'status=' . $r['status']);
    if ($r['submitted_at'] !== null) flag_rotation($id);
    return true;
}
