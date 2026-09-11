<?php
declare(strict_types=1);

function api_send(int $code, array $body): never {
    http_response_code($code);
    if (!headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function api_error(int $code, string $err, string $message): never {
    api_send($code, ['ok' => false, 'error' => ['code' => $err, 'message' => $message]]);
}

function api_json_body(): array {
    $raw = file_get_contents('php://input') ?: '';
    if ($raw === '') return [];
    $data = json_decode($raw, true);
    if (!is_array($data)) api_error(400, 'invalid_json', 'Body must be a JSON object.');
    return $data;
}

function api_bearer_token(): ?string {
    $hdr = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (preg_match('/^Bearer\s+(iwp_[a-f0-9]{64})$/i', $hdr, $m)) return strtolower($m[1]);
    return null;
}

function require_api_staff(): string {
    $token = api_bearer_token();
    if ($token === null) api_error(401, 'unauthorized', 'Send Authorization: Bearer iwp_<token>. Mint one with: php bin/staff.php token <email>');
    if (!throttle_ok('api:' . client_ip(), 120, 60)) {
        api_error(429, 'rate_limited', 'Too many requests. Wait a minute.');
    }
    $hash = hash('sha256', $token);
    $st   = db()->prepare("SELECT email, active FROM staff WHERE api_token_hash = ?");
    $st->execute([$hash]);
    $row  = $st->fetch();
    if (!$row || !(int)$row['active']) {
        api_error(401, 'unauthorized', 'Invalid or revoked token.');
    }
    return (string)$row['email'];
}

/**
 * @param 'in'|'out'|null $direction Refuse a row of the other kind, so /requests/{id}
 *        can never reveal (or try to reveal) an outbound share and vice versa.
 */
function api_fetch_request(int $id, ?string $direction = 'in'): array {
    $st = db()->prepare("SELECT * FROM requests WHERE id = ?");
    $st->execute([$id]);
    $r = $st->fetch();
    if (!$r) api_error(404, 'not_found', 'No such request.');
    if ($direction !== null && (string)($r['direction'] ?? 'in') !== $direction) {
        api_error(404, 'not_found', $direction === 'in'
            ? 'No such request. That id is an outbound share — use /api/v1/shares.'
            : 'No such share. That id is an inbound request — use /api/v1/requests.');
    }
    return $r;
}

function api_dispatch(string $path, string $method, string $base): void {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if ($path === '/api/v1/health' && $method === 'GET') {
        try {
            db();
            master_key();
            api_send(200, ['ok' => true]);
        } catch (Throwable $e) {
            api_send(500, ['ok' => false, 'error' => ['code' => 'unhealthy', 'message' => $e->getMessage()]]);
        }
    }

    if (!str_starts_with($path, '/api/v1/')) {
        api_error(404, 'not_found', 'No such endpoint. Staff API lives under /api/v1/.');
    }

    $staff = require_api_staff();

    if ($path === '/api/v1/me' && $method === 'GET') {
        $acct = staff_account($staff);
        api_send(200, ['ok' => true, 'data' => [
            'email'          => $staff,
            'name'           => trim((string)($acct['name'] ?? '')),
            'infra_enabled'  => infra_enabled(),
        ]]);
    }

    if ($path === '/api/v1/meta' && $method === 'GET') {
        $needs = [];
        foreach (needs() as $k => $label) $needs[] = ['id' => $k, 'label' => $label];
        $ttls = [];
        foreach (ttl_choices() as $sec => $label) $ttls[] = ['seconds' => $sec, 'label' => $label];
        $views = [];
        foreach (view_choices() as $k => $label) $views[] = ['id' => $k, 'label' => $label];
        api_send(200, ['ok' => true, 'data' => [
            'needs'          => $needs,
            'ttl'            => $ttls,
            'share_views'    => $views,
            'max_attachment' => max_upload_bytes(),
        ]]);
    }

    if ($path === '/api/v1/requests' && $method === 'GET') {
        $statusFilter = (string)($_GET['status'] ?? '');
        $ticketFilter = trim((string)($_GET['ticket_id'] ?? ''));
        $allowed = ['pending', 'submitted', 'read', 'expired'];
        $sql = "SELECT * FROM requests WHERE direction = 'in'";
        $params = [];
        if (in_array($statusFilter, $allowed, true)) {
            $sql .= " AND status = ?";
            $params[] = $statusFilter;
        }
        if ($ticketFilter !== '') {
            $sql .= " AND ticket_id = ?";
            $params[] = $ticketFilter;
        }
        $sql .= requests_list_order_sql();
        $st = db()->prepare($sql);
        $st->execute($params);
        $rows = [];
        foreach ($st->fetchAll() as $r) $rows[] = request_to_api($r, $base);
        api_send(200, ['ok' => true, 'data' => $rows]);
    }

    if ($path === '/api/v1/requests' && $method === 'POST') {
        $body   = api_json_body();
        $ticket = trim((string)($body['ticket_id'] ?? ''));
        $need   = (string)($body['need'] ?? '');
        $failed = trim((string)($body['failed_path'] ?? ''));
        $bug    = trim((string)($body['bug_ref'] ?? ''));
        $ttl    = (int)($body['ttl'] ?? 172800);
        if (!request_fields_valid($ticket, $need, $failed, $bug, $ttl)) {
            api_error(400, 'validation', 'ticket_id, need, failed_path, bug_ref and a listed ttl are all required.');
        }
        $minted = mint_request($staff, $ticket, $need, $failed, $bug, $ttl, $base);
        $row    = api_fetch_request($minted['id']);
        api_send(201, ['ok' => true, 'data' => request_to_api($row, $base)]);
    }

    if (preg_match('#^/api/v1/requests/(\d+)$#', $path, $m) && $method === 'GET') {
        api_send(200, ['ok' => true, 'data' => request_to_api(api_fetch_request((int)$m[1]), $base)]);
    }

    if (preg_match('#^/api/v1/requests/(\d+)/reveal$#', $path, $m) && $method === 'POST') {
        $r = api_fetch_request((int)$m[1]);
        $out = reveal_request($r, $staff);
        if (!$out['ok']) {
            $code = !empty($out['lost_race']) || str_starts_with($out['error'], 'Nothing to read') ? 409 : 400;
            if (!empty($out['decrypt_failed'])) $code = 500;
            api_error($code, !empty($out['lost_race']) ? 'already_read' : (!empty($out['decrypt_failed']) ? 'decrypt_failed' : 'not_ready'), $out['error']);
        }
        $fresh = api_fetch_request((int)$m[1]);
        $payload = request_to_api($fresh, $base, false);
        $payload['fields'] = $out['fields'];
        $payload['rotation_owed'] = $fresh['rotation_flagged_at'] !== null;
        sodium_memzero($out['plain']);
        api_send(200, ['ok' => true, 'data' => $payload]);
    }

    if ($path === '/api/v1/shares' && $method === 'GET') {
        $statusFilter = (string)($_GET['status'] ?? '');
        $ticketFilter = trim((string)($_GET['ticket_id'] ?? ''));
        $sql = "SELECT * FROM requests WHERE direction = 'out'";
        $params = [];
        if (in_array($statusFilter, ['pending', 'read', 'expired'], true)) {
            $sql .= " AND status = ?";
            $params[] = $statusFilter;
        }
        if ($ticketFilter !== '') {
            $sql .= " AND ticket_id = ?";
            $params[] = $ticketFilter;
        }
        $sql .= requests_list_order_sql();
        $st = db()->prepare($sql);
        $st->execute($params);
        $rows = [];
        foreach ($st->fetchAll() as $r) $rows[] = share_to_api($r, $base);
        api_send(200, ['ok' => true, 'data' => $rows]);
    }

    if ($path === '/api/v1/shares' && $method === 'POST') {
        $body    = api_json_body();
        $ticket  = trim((string)($body['ticket_id'] ?? ''));
        $message = trim((string)($body['message'] ?? ''));
        $view    = (string)($body['view'] ?? 'once');
        $ttl     = (int)($body['ttl'] ?? 86400);
        $pass    = (string)($body['passphrase'] ?? '');

        $file = share_file_from_api($body['attachment'] ?? null);
        if (is_string($file)) api_error(400, 'validation', $file);

        if (!share_fields_valid($ticket, $message, $view, $ttl, $file !== null)) {
            api_error(400, 'validation', 'ticket_id, a listed ttl and a listed view are required, plus a message or an attachment.');
        }
        if ($pass !== '' && strlen($pass) < 6) {
            api_error(400, 'validation', 'passphrase must be at least 6 characters, or omitted.');
        }
        $minted = mint_share($staff, $ticket, $message, $view, $ttl, $pass === '' ? null : $pass, $file, $base);
        api_send(201, ['ok' => true, 'data' => share_to_api(api_fetch_request($minted['id'], 'out'), $base)]);
    }

    if (preg_match('#^/api/v1/shares/(\d+)$#', $path, $m) && $method === 'GET') {
        api_send(200, ['ok' => true, 'data' => share_to_api(api_fetch_request((int)$m[1], 'out'), $base)]);
    }

    if (preg_match('#^/api/v1/shares/(\d+)$#', $path, $m) && $method === 'DELETE') {
        $r = api_fetch_request((int)$m[1], 'out');
        expire_request((int)$r['id'], $staff);
        api_send(200, ['ok' => true, 'data' => share_to_api(api_fetch_request((int)$r['id'], 'out'), $base)]);
    }

    if ($path === '/api/v1/audit' && $method === 'GET') {
        $rows = [];
        foreach (db()->query("SELECT id,at,actor,action,request_id,ticket_id,ip,detail FROM audit ORDER BY id DESC LIMIT 300")->fetchAll() as $a) {
            $rows[] = [
                'id'         => (int)$a['id'],
                'at'         => (int)$a['at'],
                'actor'      => $a['actor'],
                'action'     => $a['action'],
                'request_id' => $a['request_id'] !== null ? (int)$a['request_id'] : null,
                'ticket_id'  => $a['ticket_id'],
                'ip'         => $a['ip'],
                'detail'     => $a['detail'],
            ];
        }
        api_send(200, ['ok' => true, 'data' => $rows]);
    }

    api_error(404, 'not_found', 'No such endpoint.');
}
