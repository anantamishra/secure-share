<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';
env_load(getenv('APP_ENV_FILE') ?: '/home/instapod/handoff.env');
require __DIR__ . '/../src/crypto.php';
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/views.php';
require __DIR__ . '/../src/freescout.php';
require __DIR__ . '/../src/rotation.php';
require __DIR__ . '/../src/requests.php';
require __DIR__ . '/../src/api.php';

// Without this an uncaught throwable renders a blank page (or, if the pod ever has
// zend.exception_ignore_args=Off, a stack trace whose frames include the plaintext
// credential and the master key). Neither is acceptable on this app.
set_exception_handler(function (Throwable $e): void {
    $api = str_starts_with(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/', '/api/');
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: ' . ($api ? 'application/json; charset=utf-8' : 'text/plain'));
    }
    try { audit('system', 'unhandled.exception', null, null, get_class($e) . ': ' . $e->getMessage()); }
    catch (Throwable $ignored) { /* the DB is the thing that failed; do not mask it */ }
    if ($api) {
        echo json_encode(['ok' => false, 'error' => ['code' => 'internal', 'message' => 'Something went wrong and has been logged.']]);
        return;
    }
    echo "Something went wrong and has been logged.\n"
       . "If you were opening a credential, check the request page before asking the customer again:\n"
       . "it may already have been marked read.\n";
});
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" . csp_nonce() . "'; form-action 'self'; frame-ancestors 'none'");

$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$base   = rtrim(cfg('APP_URL', 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')), '/');

/** Expire and purge anything past its deadline. Cheap, so run it on every request. */
function sweep(): void {
    purge_expired('system');
}

if ($path === '/healthz') {
    header('Content-Type: application/json');
    try { db(); master_key(); echo json_encode(['ok' => true]); }
    catch (Throwable $e) { http_response_code(500); echo json_encode(['ok' => false, 'error' => $e->getMessage()]); }
    exit;
}

sweep();

if (str_starts_with($path, '/api/')) {
    api_dispatch($path, $method, $base);
}

// ---------------------------------------------------------------- customer side

if (preg_match('#^/s/([a-f0-9]{48})$#', $path, $m)) {
    $st = db()->prepare("SELECT * FROM requests WHERE token = ?");
    $st->execute([$m[1]]);
    $r = $st->fetch();

    $gone = fn(string $why) => print(layout('Link unavailable',
        '<div class="box danger"><strong>This link is no longer usable.</strong><p>' . h($why) . '</p></div>
         <p class="mut">If you still need to send us access, reply on your support ticket and we will issue a new link.</p>',
        null, ['audience' => 'customer']));

    if (!$r)                        { http_response_code(404); $gone('The link is not valid.'); exit; }
    if ($r['status'] !== 'pending') { http_response_code(410); $gone('It has already been used.'); exit; }
    if ($r['expires_at'] < time())  { http_response_code(410); $gone('It has expired.'); exit; }

    if ($method === 'POST') {
        if (!throttle_ok('submit:' . $r['token'], 5, 900)) {
            http_response_code(429); exit('Too many attempts. Wait 15 minutes.');
        }
        $fields   = fields_for($r['need']);
        $optional = optional_fields($r['need']);

        $payload = [];
        $missing = false;
        foreach ($fields as $k => $lbl) {
            $v = trim((string)($_POST[$k] ?? ''));
            if ($v === '' && !in_array($k, $optional, true)) $missing = true;
            $payload[$lbl] = $v;
        }
        $payload['Notes'] = trim((string)($_POST['notes'] ?? ''));
        $share = share_from_post();

        if ($missing) {
            $err = '<div class="box danger">Every field except Notes' . ($optional ? ' and Port' : '') . ' is required.</div>';
        } else {
            // JSON_INVALID_UTF8_SUBSTITUTE: json_encode() returns false on invalid UTF-8,
            // and seal(false) then fatals under strict_types -- the customer's submission
            // was silently lost and the row stayed pending, so they retried into the same
            // failure. Substituting keeps the field readable rather than dropping it.
            $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            [$nonce, $ct] = seal((string)$json);
            $secs    = share_seconds($share);
            $keepExp = $secs === null ? (int)$r['expires_at'] : time() + $secs;
            // Guarded on status: a submit racing the expiry sweep would otherwise write
            // ciphertext back onto a row that had just been purged, and a double-submit
            // would overwrite the first payload.
            $upd = db()->prepare("UPDATE requests SET status='submitted', submitted_at=?, nonce=?, ciphertext=?, site_url=?, share=?, expires_at=? WHERE id=? AND status='pending'");
            $upd->execute([time(), $nonce, $ct, $payload[$fields[array_key_first($fields)]], $share, $keepExp, $r['id']]);
            if ($upd->rowCount() !== 1) {
                http_response_code(410); $gone('It has already been used.'); exit;
            }
            audit('customer', 'credential.submitted', (int)$r['id'], $r['ticket_id'], "share=$share");
            $until = gmdate('Y-m-d H:i', $keepExp);
            $noteKeep = $share === 'once'
                ? "They are readable ONCE, then destroyed. Expires $until UTC."
                : "The customer asked us to keep them until $until UTC. They can be opened again until then.";
            $thanks = $share === 'once'
                ? 'Your details are encrypted and can be opened once by the engineer working your ticket, then destroyed automatically.'
                : 'Your details are encrypted and will be available to the engineer until ' . local_time($keepExp) . ', then destroyed automatically.';
            defer(fn() => freescout_note($r['ticket_id'],
                "Automated note — secure credential handoff.\n\n" .
                "The customer has submitted credentials through the secure form.\n" .
                "Read them at: {$GLOBALS['base']}/r/{$r['id']}\n\n" .
                $noteKeep));
            echo layout('Received',
                '<div class="box ok"><strong>Thank you — received.</strong>
                 <p>' . $thanks . '</p></div>
                 <p class="mut">You can close this page. Once we are finished we will ask you to change the password and remove the access you created.</p>',
                null, ['audience' => 'customer']);
            exit;
        }
    }

    $intro = match ($r['need']) {
        'wp_admin' => '<p class="lede">Create a temporary WordPress administrator account and enter it below.</p>',
        'wp_app_password' => '<p class="lede">Enter a WordPress application password created for us (Users &rarr; Profile).</p>',
        'ssh' => '<p class="lede">Enter SSH/SFTP details for a separate account if your host allows one.</p>',
        default => '',
    };

    // An SSH credential cannot be narrowed or revoked the way a WordPress one can,
    // so the customer is told plainly what to do afterwards, on the form itself.
    $extra = $r['need'] === 'ssh'
        ? '<div class="box danger"><strong>Please change this password once we are done.</strong>
            Server credentials usually unlock more than one site, so treat anything you send here as disclosed.
            We will remind you on the ticket as well.</div>'
        : '';

    $inputs = '';
    $optional = optional_fields($r['need']);
    foreach (fields_for($r['need']) as $k => $lbl) {
        $type = $k === 'password' ? 'password' : ($k === 'login_url' ? 'url' : 'text');
        $req  = in_array($k, $optional, true) ? '' : ' required';
        $ph   = $k === 'login_url' ? ' placeholder="https://example.com/wp-login.php"'
              : ($k === 'port' ? ' placeholder="22"' : '');
        $auto = $k === 'password' ? 'new-password' : 'off';
        $id   = 'f-' . $k;
        $keep = $k === 'password' ? '' : ' value="' . posted_value($k) . '"';
        if ($k === 'password' && $r['need'] === 'ssh') {
            $inputs .= '<div class="field"><label for="' . $id . '">' . h($lbl) . '</label>'
                    . '<textarea id="' . $id . '" name="' . h($k) . '" rows="6" autocomplete="off" spellcheck="false" autocapitalize="off" required></textarea>'
                    . '<p class="hint">Paste a password or a private key. Prefer a separate account created for this ticket.</p></div>';
            continue;
        }
        $inputs .= '<div class="field"><label for="' . $id . '">' . h($lbl) . ($req ? '' : ' (optional)') . '</label>'
                . '<input id="' . $id . '" name="' . h($k) . '" type="' . $type . '" autocomplete="' . $auto . '" spellcheck="false" autocapitalize="off"' . $ph . $keep . $req . '></div>';
    }

    $sharePicked = share_from_post();
    $shareRadios = '';
    foreach (share_choices() as $val => $lbl) {
        $chk = $sharePicked === $val ? ' checked' : '';
        $shareRadios .= '<label><input type="radio" name="share" value="' . h($val) . '" required' . $chk . '> '
                      . h($lbl) . "</label>\n";
    }

    echo layout('Send credentials securely',
        ($err ?? '') . '
        <h2>Ticket #' . h($r['ticket_id']) . '</h2>
        <p class="lede">This link is single-use. Details are encrypted. Choose below how long the engineer can keep them.</p>
        ' . $intro . '
        <p class="mut">This form expires ' . local_time((int)$r['expires_at']) . '</p>
        ' . $extra . '
        <form method="post" autocomplete="off" class="card">
          ' . $inputs . '
          <div class="field">
            <label for="f-notes">Notes (optional)</label>
            <textarea id="f-notes" name="notes" rows="2">' . posted_value('notes') . '</textarea>
          </div>
          <fieldset class="share">
            <legend>How long should we keep this?</legend>
            ' . $shareRadios . '
            <p class="hint">View once is destroyed when the engineer opens it. 1 day and 2 days can be opened again until they expire.</p>
          </fieldset>
          <p class="btn-row"><button class="btn-block" type="submit">Send securely</button></p>
        </form>',
        null, ['audience' => 'customer']);
    exit;
}

// ------------------------------------------------------------------- staff side

if ($path === '/login') {
    if ($method === 'POST') {
        csrf_check();
        $email = (string)($_POST['email'] ?? '');
        // Two independent buckets. The per-IP one stops one host grinding away; the
        // per-account one stops a distributed attempt at a single known staff address,
        // which the IP bucket alone cannot see.
        if (!throttle_ok('login:' . client_ip(), 10, 900)
            || !throttle_ok('login-acct:' . strtolower(trim($email)), 10, 900)) {
            http_response_code(429); exit('Too many attempts. Wait 15 minutes.');
        }
        if (staff_login($email, (string)($_POST['password'] ?? ''))) {
            audit($email, 'staff.login.ok');
            redirect('/');
        }
        audit($email, 'staff.login.failed');
        $err = '<div class="box danger">Wrong email or password.</div>';
    }
    echo layout('Sign in', ($err ?? '') . '
        <div class="card">
          <h2>Sign in</h2>
          <p class="lede">Staff only. Customer links do not use this page.</p>
          <form method="post">
            <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
            <div class="field">
              <label for="email">Email</label>
              <input id="email" name="email" type="email" required autofocus autocomplete="username" value="' . posted_value('email') . '">
            </div>
            <div class="field">
              <label for="password">Password</label>
              <input id="password" name="password" type="password" required autocomplete="current-password">
            </div>
            <p class="btn-row"><button class="btn-block" type="submit">Sign in</button></p>
          </form>
        </div>',
        null, ['audience' => 'guest']);
    exit;
}

if ($path === '/logout' && $method === 'POST') {
    csrf_check();
    audit((string)current_staff(), 'staff.logout');
    staff_logout();
    redirect('/login');
}

$staff = require_staff();

if ($path === '/') {
    if ($method === 'POST' && (isset($_POST['delete_one']) || isset($_POST['expire_one']))) {
        csrf_check();
        if (isset($_POST['delete_one'])) {
            delete_request((int)$_POST['delete_one'], $staff);
        } else {
            expire_request((int)$_POST['expire_one'], $staff);
        }
        $back = (string)($_POST['status'] ?? 'all');
        if ($back !== 'all' && !isset(['pending' => 1, 'submitted' => 1, 'read' => 1, 'expired' => 1][$back])) {
            $back = 'all';
        }
        redirect('/?status=' . $back);
    }

    $allowed = ['pending' => 'Awaiting', 'submitted' => 'Ready', 'read' => 'Read', 'expired' => 'Expired'];
    $counts = ['pending' => 0, 'submitted' => 0, 'read' => 0, 'expired' => 0];
    foreach (db()->query("SELECT status, COUNT(*) c FROM requests GROUP BY status")->fetchAll() as $c) {
        $counts[$c['status']] = (int)$c['c'];
    }
    $total = array_sum($counts);
    $fallback = $counts['read'] > 0 ? 'read' : '';
    if (!isset($_GET['status'])) {
        $statusFilter = $fallback;
    } else {
        $raw = (string)$_GET['status'];
        $statusFilter = $raw === 'all' ? '' : (isset($allowed[$raw]) ? $raw : $fallback);
    }

    $sql = "SELECT * FROM requests";
    $params = [];
    if (isset($allowed[$statusFilter])) {
        $sql .= " WHERE status = ?";
        $params[] = $statusFilter;
    }
    $sql .= requests_list_order_sql();
    $st = db()->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll();

    $ready = $counts['submitted'];
    $banner = $ready > 0 && $statusFilter === ''
        ? '<div class="box warn"><strong>' . $ready . ' request' . ($ready === 1 ? '' : 's') . ' ready to read.</strong> Open ' . ($ready === 1 ? 'it' : 'one') . ' only when you are ready to use the credential — reading destroys the stored copy.</div>'
        : '';

    $filters = '<div class="filters" role="navigation" aria-label="Filter by status">';
    $allOn = $statusFilter === '' ? ' class="on"' : '';
    $filters .= '<a href="/?status=all"' . $allOn . '>All (' . $total . ')</a>';
    foreach ($allowed as $k => $label) {
        $on = $statusFilter === $k ? ' class="on"' : '';
        $filters .= '<a href="/?status=' . $k . '"' . $on . '>' . $label . ' (' . $counts[$k] . ')</a>';
    }
    $filters .= '</div>';

    $statusQs = $statusFilter === '' ? 'all' : $statusFilter;
    $body = '<div class="pagehead"><h2>Requests</h2><a class="btn" href="/new">New request</a></div>'
          . $banner . $filters;
    if (!$rows) {
        $body .= '<div class="box"><div class="empty"><strong>Nothing yet.</strong>'
              . ($statusFilter !== ''
                  ? '<p>No requests in this status.</p>'
                  : '<p>Raise a request to mint a single-use customer link.</p><p><a class="btn" href="/new">New request</a></p>')
              . '</div></div>';
    } else {
        $body .= '<form method="post" data-confirm>'
              . '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'
              . '<input type="hidden" name="status" value="' . h($statusQs) . '">'
              . '<div class="scroll"><table><thead><tr>'
              . '<th scope="col">Ticket</th><th scope="col">Needed</th><th scope="col">Status</th>'
              . '<th scope="col">Expires</th><th scope="col">Raised by</th>'
              . '<th scope="col">Actions</th>'
              . '</tr></thead><tbody>';
        foreach ($rows as $r) {
            $id = (int)$r['id'];
            $rowCls = $r['status'] === 'submitted' ? ' class="row-ready"' : '';
            $needFull = needs()[$r['need']] ?? $r['need'];
            $expireBtn = $r['status'] !== 'expired'
                ? '<button class="ico-btn expire" type="submit" name="expire_one" value="' . $id . '" data-kind="expire" aria-label="Expire">'
                  . icon_expire_svg() . '<span class="ico-name">Expire</span></button>'
                : '<button class="ico-btn expire" type="button" disabled aria-label="Already expired">'
                  . icon_expire_svg() . '<span class="ico-name">Already expired</span></button>';
            $body .= '<tr' . $rowCls . '>'
                  . '<td><a class="rowlink" href="/r/' . $id . '">#' . h($r['ticket_id']) . '</a></td>'
                  . '<td class="need-short" title="' . h($needFull) . '">' . h(need_short((string)$r['need'])) . '</td>'
                  . '<td>' . status_pill($r['status']) . '</td>'
                  . '<td>' . local_time((int)$r['expires_at'], 'short') . '</td>'
                  . '<td class="mut">' . h($r['requested_by']) . '</td>'
                  . '<td class="row-act">' . $expireBtn
                  . '<button class="ico-btn del" type="submit" name="delete_one" value="' . $id . '" aria-label="Delete">'
                  . icon_delete_svg() . '<span class="ico-name">Delete</span></button></td></tr>';
        }
        $body .= '</tbody></table></div></form>';
    }
    echo layout('Requests', $body, $staff);
    exit;
}

if ($path === '/new') {
    if ($method === 'POST') {
        csrf_check();
        $ticket = trim((string)($_POST['ticket_id'] ?? ''));
        $need   = (string)($_POST['need'] ?? '');
        $failed = trim((string)($_POST['failed_path'] ?? ''));
        $bug    = trim((string)($_POST['bug_ref'] ?? ''));
        $ttl    = (int)($_POST['ttl'] ?? 172800);

        if (!request_fields_valid($ticket, $need, $failed, $bug, $ttl)) {
            $err = '<div class="box danger">Every field is required, including the two below the line.</div>';
        } else {
            $minted = mint_request($staff, $ticket, $need, $failed, $bug, $ttl, $base);
            $link   = $minted['url'];
            $ttlExp = $minted['expires_at'];
            echo layout('Link ready',
                '<div class="box ok"><strong>Send this to the customer.</strong>
                 <p class="hint" style="margin-bottom:10px">Copy the link and paste it into the ticket — never ask for the credential in the reply itself.</p>
                 ' . copyable_link($link) . '
                 <p class="mut" style="margin-top:12px">Single use, expires ' . local_time($ttlExp) . '.</p></div>
                 <p class="btn-row"><a class="btn" href="/">Back to requests</a><a class="btn btn-ghost" href="/new">Raise another</a></p>', $staff);
            exit;
        }
    }
    $opts = '<optgroup label="WordPress">';
    foreach (['wp_admin', 'wp_app_password'] as $k) {
        if (!isset(needs()[$k])) continue;
        $opts .= '<option value="' . h($k) . '"' . option_selected('need', $k) . '>' . h(needs()[$k]) . '</option>';
    }
    $opts .= '</optgroup>';
    if (isset(needs()['ssh'])) {
        $opts .= '<optgroup label="Server"><option value="ssh"' . option_selected('need', 'ssh') . '>'
              . h(needs()['ssh']) . '</option></optgroup>';
    }
    $ttls = '';
    foreach (ttl_choices() as $k => $v) $ttls .= '<option value="' . $k . '"' . option_selected('ttl', (string)$k, '172800') . '>' . h($v) . '</option>';

    echo layout('New request', ($err ?? '') . '
      <div class="pagehead"><h2>Raise a credential request</h2></div>
      <div class="split">
      <form method="post" class="card">
        <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
        <div class="pair">
          <div class="field">
            <label for="ticket_id">FreeScout ticket number</label>
            <input id="ticket_id" name="ticket_id" required autofocus inputmode="numeric" value="' . posted_value('ticket_id') . '">
          </div>
          <div class="field">
            <label for="ttl">Link expires after</label>
            <select id="ttl" name="ttl">' . $ttls . '</select>
          </div>
        </div>
        <div class="field">
          <label for="need">What is needed</label>
          <select id="need" name="need">' . $opts . '</select>
          ' . (infra_enabled()
              ? '<p class="hint">Prefer a temporary WordPress account. Use SSH / SFTP only when there is no WordPress-level route.</p>'
              : '') . '
        </div>

        <div class="box warn" style="margin-top:8px">
          <strong>Before you raise this.</strong>
          <p>Asking for a credential is a last resort, not a shortcut. On a site we host, use Support Access
          and Magic Login. On a source site, the customer installs <code>instawp-connect</code> and we need
          no credential at all.</p>
          <p>If that path is broken, <strong>that is a bug report</strong>. File it first — a credential
          request that replaces an investigation buries a defect that will hit the next customer.</p>
        </div>

        <div class="field">
          <label for="failed_path">Which product path failed, and how?</label>
          <input id="failed_path" name="failed_path" required placeholder="e.g. migration tool connect popup never opens on their source site" value="' . posted_value('failed_path') . '">
        </div>
        <div class="field">
          <label for="bug_ref">Bug reference</label>
          <input id="bug_ref" name="bug_ref" required placeholder="task id, GitHub issue, or ClickUp link" value="' . posted_value('bug_ref') . '">
        </div>

        <p class="btn-row"><button type="submit">Generate link</button></p>
      </form>
      <aside class="rail">
        <div class="box">
          <strong>What happens next</strong>
          <ol class="steps">
            <li>Customer opens the single-use link</li>
            <li>They submit and choose view once, 1 day, or 2 days</li>
            <li>You open it — view-once is destroyed, timed stays until expiry</li>
            <li>You ask them to rotate access</li>
          </ol>
        </div>
        ' . (infra_enabled()
            ? '<div class="box danger"><strong>SSH / SFTP is a last resort.</strong>
               An SSH credential is broad, reusable, and cannot be revoked without collateral damage — and on an
               agency ticket it is usually their client\'s server. Use it only when there is genuinely no
               WordPress-level route, and raise the rotation with the customer yourself as well.
               cPanel and FTP are still not options.</div>'
            : '<p class="mut">The form offers WordPress admin and application passwords only. SSH, cPanel and FTP
               are deliberately not options.</p>') . '
      </aside>
      </div>', $staff);
    exit;
}

if (preg_match('#^/r/(\d+)$#', $path, $m)) {
    $st = db()->prepare("SELECT * FROM requests WHERE id = ?");
    $st->execute([(int)$m[1]]);
    $r = $st->fetch();
    if (!$r) { http_response_code(404); echo layout('Not found', '<div class="box danger">No such request.</div>', $staff); exit; }

    $reveal = '';
    if ($method === 'POST' && ($_POST['action'] ?? '') === 'reveal') {
        csrf_check();
        $out = reveal_request($r, $staff);
        if (!$out['ok']) {
            if (!empty($out['lost_race'])) {
                $reveal = '<div class="box danger"><strong>Nothing to read — someone else opened this first.</strong>
                      <p>It can only be opened once. Check the audit log to see who has it.</p></div>';
            } elseif (!empty($out['decrypt_failed'])) {
                $reveal = '<div class="box danger"><strong>Could not decrypt.</strong><p>' . h($out['error']) . '</p></div>';
            } else {
                $reveal = '<div class="box danger">' . h($out['error']) . '</div>';
            }
        } elseif (share_is_once($r)) {
            $reveal = '<div class="box warn"><strong>Read once — now destroyed.</strong>
                      <p>This will not be shown again. Copy what you need now, and do not paste it into the ticket.</p>'
                      . render_credential($out['plain']) . '</div>';
            sodium_memzero($out['plain']);
        } else {
            $reveal = '<div class="box warn"><strong>Still available until ' . local_time((int)$r['expires_at']) . '.</strong>
                      <p>Copy what you need now, and do not paste it into the ticket. You can open this again until it expires.</p>'
                      . render_credential($out['plain']) . '</div>';
            sodium_memzero($out['plain']);
        }
        $st->execute([(int)$m[1]]);
        $r = $st->fetch();
    }

    $link   = $base . '/s/' . $r['token'];
    $until  = local_time((int)$r['expires_at']);
    $action = match ($r['status']) {
        'pending'   => '<div class="box"><strong>Waiting on the customer.</strong>
                        <p class="hint" style="margin-bottom:10px">Copy the link, then send it to the customer.</p>
                        ' . copyable_link($link) . '
                        <p class="mut" style="margin-top:12px">Single-use form link. Expires ' . $until . '. The customer chooses view once, 1 day, or 2 days when they submit.</p></div>',
        'submitted' => share_is_once($r)
            ? '<form method="post"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
               <input type="hidden" name="action" value="reveal">
               <div class="box warn"><strong>Ready to read.</strong>
               <p>Opening this destroys the stored copy immediately and records you as the reader. Only
               do it when you are ready to use it.</p>
               <p class="btn-row"><button class="danger" type="submit">Open once and destroy</button></p></div></form>'
            : '<form method="post"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
               <input type="hidden" name="action" value="reveal">
               <div class="box warn"><strong>Ready to read.</strong>
               <p>The customer asked us to keep this until ' . $until . '. You can open it again until then.</p>
               <p class="btn-row"><button type="submit">Open</button></p></div></form>',
        'read'      => '<div class="box"><strong>Read and destroyed.</strong><p class="mut">Opened by '
                        . h($r['read_by']) . ' on ' . local_time((int)$r['read_at']) . '.</p></div>',
        default     => '<div class="box"><strong>Expired and purged.</strong>
                        <p class="mut">No credential is stored for this request any more.</p></div>',
    };

    $rot = $r['rotation_flagged_at'] === null ? ''
        : ($r['need'] === 'ssh'
            ? '<div class="box danger"><strong>Rotation owed on this ticket.</strong>
               <p>Ask the customer to change the server password (or remove the key), and delete the account
               if it was created for us. Server credentials usually unlock every site on the box, and there is
               no scoped-revocation option — which is why this route is a last resort.</p></div>'
            : '<div class="box danger"><strong>Rotation owed on this ticket.</strong>
               <p>Ask the customer to change the password <em>and</em> delete the application password created
               for us. Application passwords live in <code>usermeta</code> and survive a password change, so a
               password change alone leaves our access live on their site.</p></div>');

    echo layout('Request #' . $r['id'],
        '<div class="pagehead"><h2>Ticket #' . h($r['ticket_id']) . '</h2>' . status_pill($r['status']) . '</div>
         ' . $reveal . $action . $rot . '
         <div class="section">
         <h2>Why this was raised</h2>
         <dl class="meta">
           <div><dt>Needed</dt><dd>' . h(needs()[$r['need']] ?? $r['need']) . '</dd></div>
           <div><dt>Raised by</dt><dd>' . h($r['requested_by']) . '</dd></div>
           <div><dt>Raised</dt><dd>' . local_time((int)$r['created_at']) . '</dd></div>
           <div><dt>Product path that failed</dt><dd>' . h($r['failed_path']) . '</dd></div>
           <div><dt>Bug reference</dt><dd>' . h($r['bug_ref']) . '</dd></div>
           <div><dt>Customer asked</dt><dd>' . h(share_label($r))
            . ($r['status'] === 'pending'
                ? ' (they choose on the form)'
                : (share_is_once($r) ? ' · destroyed on first open' : ' · until ' . local_time((int)$r['expires_at'])))
            . '</dd></div>
         </dl>
         </div>
         <p class="btn-row"><a class="btn btn-ghost" href="/">Back to requests</a></p>', $staff);
    exit;
}

if ($path === '/password') {
    redirect('/settings');
}

if ($path === '/settings') {
    $acct = staff_account($staff) ?? ['email' => $staff, 'name' => ''];
    $nameVal = posted_value('name') !== '' ? posted_value('name') : h(trim((string)($acct['name'] ?? '')));
    $emailVal = posted_value('email') !== '' ? posted_value('email') : h((string)$acct['email']);
    $flash = '';

    if ($method === 'POST') {
        csrf_check();
        $intent = (string)($_POST['intent'] ?? '');
        $cur = (string)($_POST['current'] ?? '');

        if ($intent === 'profile') {
            $name = trim((string)($_POST['name'] ?? ''));
            $email = strtolower(trim((string)($_POST['email'] ?? '')));
            $nameVal = h($name);
            $emailVal = h($email);
            if ($name === '' || strlen($name) > 80) {
                $flash = '<div class="box danger">Name is required and must be 80 characters or fewer.</div>';
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $flash = '<div class="box danger">Enter a valid email address.</div>';
            } elseif (!staff_verify_password($staff, $cur)) {
                $flash = '<div class="box danger">Your current password is wrong.</div>';
            } else {
                $dup = db()->prepare("SELECT 1 FROM staff WHERE email = ? AND email != ?");
                $dup->execute([$email, $staff]);
                if ($dup->fetchColumn()) {
                    $flash = '<div class="box danger">That email is already in use.</div>';
                } else {
                    try {
                        db()->prepare("UPDATE staff SET name = ?, email = ? WHERE email = ?")
                            ->execute([$name, $email, $staff]);
                    } catch (PDOException $e) {
                        $flash = '<div class="box danger">That email is already in use.</div>';
                    }
                    if ($flash === '') {
                        $detail = $email !== $staff ? "email $staff → $email" : null;
                        audit($email, 'staff.profile.updated', null, null, $detail);
                        if ($email !== $staff) {
                            session_start_secure();
                            $_SESSION['staff_email'] = $email;
                            $staff = $email;
                        }
                        $acct = staff_account($staff) ?? $acct;
                        $nameVal = h(trim((string)($acct['name'] ?? '')));
                        $emailVal = h((string)$acct['email']);
                        $flash = '<div class="box ok"><strong>Profile saved.</strong></div>';
                    }
                }
            }
        } elseif ($intent === 'password') {
            $new  = (string)($_POST['new'] ?? '');
            $conf = (string)($_POST['confirm'] ?? '');
            if (!staff_verify_password($staff, $cur)) {
                $flash = '<div class="box danger">Your current password is wrong.</div>';
            } elseif (strlen($new) < 12) {
                $flash = '<div class="box danger">Use at least 12 characters.</div>';
            } elseif (!hash_equals($new, $conf)) {
                $flash = '<div class="box danger">The two new passwords do not match.</div>';
            } else {
                db()->prepare("UPDATE staff SET pass_hash = ? WHERE email = ?")
                    ->execute([password_hash($new, PASSWORD_BCRYPT, ['cost' => 12]), $staff]);
                audit($staff, 'staff.password.changed');
                $flash = '<div class="box ok"><strong>Password changed.</strong></div>';
            }
        } else {
            $flash = '<div class="box danger">Unknown action.</div>';
        }
    }

    echo layout('Settings', $flash . '
      <div class="pagehead"><h2>Settings</h2></div>
      <p class="lede">Your name is shown to other staff. Email is how you sign in. Changing either needs your current password.</p>
      <div class="settings">
        <form method="post" class="card" autocomplete="off">
          <h2>Profile</h2>
          <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
          <input type="hidden" name="intent" value="profile">
          <div class="field">
            <label for="name">Name</label>
            <input id="name" name="name" type="text" required maxlength="80" autocomplete="name" value="' . $nameVal . '">
          </div>
          <div class="field">
            <label for="email">Email</label>
            <input id="email" name="email" type="email" required autocomplete="username" value="' . $emailVal . '">
          </div>
          <div class="field">
            <label for="profile-current">Current password</label>
            <input id="profile-current" name="current" type="password" required autocomplete="current-password">
            <p class="hint">Required to save name or email.</p>
          </div>
          <p class="btn-row"><button type="submit">Save profile</button></p>
        </form>
        <form method="post" class="card">
          <h2>Password</h2>
          <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
          <input type="hidden" name="intent" value="password">
          <div class="field">
            <label for="current">Current password</label>
            <input id="current" name="current" type="password" required autocomplete="current-password">
          </div>
          <div class="field">
            <label for="new">New password (12+ characters)</label>
            <input id="new" name="new" type="password" required minlength="12" autocomplete="new-password">
          </div>
          <div class="field">
            <label for="confirm">Confirm new password</label>
            <input id="confirm" name="confirm" type="password" required minlength="12" autocomplete="new-password">
          </div>
          <p class="btn-row"><button type="submit">Update password</button></p>
        </form>
      </div>', $staff);
    exit;
}

if ($path === '/audit') {
    $per   = 15;
    $total = (int)db()->query("SELECT COUNT(*) FROM audit")->fetchColumn();
    $pages = max(1, (int)ceil($total / $per));
    $page  = (int)($_GET['page'] ?? 1);
    if ($page < 1) $page = 1;
    if ($page > $pages) $page = $pages;
    $off = ($page - 1) * $per;
    $rows = db()->query("SELECT * FROM audit ORDER BY id DESC LIMIT {$per} OFFSET {$off}")->fetchAll();

    $from = $total === 0 ? 0 : $off + 1;
    $to   = $off + count($rows);
    $prev = $page > 1
        ? '<a class="btn btn-ghost" href="/audit?page=' . ($page - 1) . '">Previous</a>'
        : '<span class="btn btn-ghost off" aria-disabled="true">Previous</span>';
    $next = $page < $pages
        ? '<a class="btn btn-ghost" href="/audit?page=' . ($page + 1) . '">Next</a>'
        : '<span class="btn btn-ghost off" aria-disabled="true">Next</span>';
    $pager = $total === 0 ? ''
        : '<div class="pager"><p class="mut">Showing ' . $from . '–' . $to . ' of ' . $total
          . ' · page ' . $page . ' of ' . $pages . '</p>'
          . '<p class="btn-row">' . $prev . $next . '</p></div>';

    $body = '<div class="pagehead"><h2>Audit</h2></div>
             <p class="lede">Every read is recorded here and cannot be edited from the UI. Newest first, 15 per page.</p>
             <div class="scroll"><table>
             <thead><tr><th scope="col">When</th><th scope="col">Who</th><th scope="col">Action</th><th scope="col">Ticket</th><th scope="col">IP</th><th scope="col">Detail</th></tr></thead><tbody>';
    foreach ($rows as $a) {
        $hot = $a['action'] === 'credential.read' ? ' class="row-ready"' : '';
        $body .= '<tr' . $hot . '><td>' . local_time((int)$a['at'], 'short') . '</td><td>' . h($a['actor'])
              . '</td><td title="' . h($a['action']) . '">' . h(audit_label((string)$a['action'])) . '</td><td>' . h($a['ticket_id'])
              . '</td><td class="mut">' . h($a['ip']) . '</td><td class="mut" title="' . h((string)$a['detail']) . '">'
              . h(audit_detail_label((string)$a['action'], $a['detail'] !== null ? (string)$a['detail'] : null)) . '</td></tr>';
    }
    if (!$rows) $body .= '<tr><td colspan="6"><div class="empty"><strong>No audit rows yet.</strong></div></td></tr>';
    echo layout('Audit', $body . '</tbody></table></div>' . $pager, $staff);
    exit;
}

http_response_code(404);
echo layout('Not found', '<div class="box">No such page.</div><p class="btn-row"><a class="btn btn-ghost" href="/">Back to requests</a></p>', $staff);
