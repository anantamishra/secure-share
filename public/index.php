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
require __DIR__ . '/../src/shares.php';
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
    // Attachment bytes outlive the message they came with, by exactly the length of
    // the download grant. This is what closes that window.
    purge_share_blobs('system');
}

if ($path === '/healthz') {
    header('Content-Type: application/json');
    try { db(); master_key(); echo json_encode(['ok' => true]); }
    catch (Throwable $e) { http_response_code(500); echo json_encode(['ok' => false, 'error' => $e->getMessage()]); }
    exit;
}

// Before anything reads $_POST: see post_exceeded_limit().
if (post_exceeded_limit()) {
    $limit = share_size_label(ini_bytes('post_max_size'));
    if (!headers_sent()) {
        http_response_code(413);
        header('Content-Type: ' . (str_starts_with($path, '/api/') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8'));
    }
    if (str_starts_with($path, '/api/')) {
        echo json_encode(['ok' => false, 'error' => [
            'code'    => 'too_large',
            'message' => 'Request body exceeds the server limit of ' . $limit . '.',
        ]]);
    } else {
        echo "That upload is larger than this server accepts (limit $limit).\n"
           . "Send the file a different way, or ask an admin to raise post_max_size.\n";
    }
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
    // Tokens are unique across both directions, so an outbound token would otherwise
    // match here and render a credential form for a message we are trying to deliver.
    if (is_outbound($r))            { redirect('/v/' . $r['token']); }
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
        $input = '<input id="' . $id . '" name="' . h($k) . '" type="' . $type . '" autocomplete="' . $auto . '" spellcheck="false" autocapitalize="off"' . $ph . $keep . $req . '>';
        if ($k === 'password') {
            $input = '<div class="password-control">' . $input . password_toggle_button() . '</div>';
        }
        $inputs .= '<div class="field"><label for="' . $id . '">' . h($lbl) . ($req ? '' : ' (optional)') . '</label>'
                . $input . '</div>';
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

// ------------------------------------------------- customer side: outbound share

/** Stream a share attachment against a live download grant. */
if (preg_match('#^/v/([a-f0-9]{48})/f/([a-f0-9]{48})$#', $path, $m)) {
    $st = db()->prepare("SELECT * FROM requests WHERE token = ? AND direction = 'out'");
    $st->execute([$m[1]]);
    $r = $st->fetch();
    if (!$r || !share_grant_ok($r, $m[2]) || (int)$r['expires_at'] < time()) {
        http_response_code(410);
        echo layout('Download unavailable',
            '<div class="box danger"><strong>This download link has expired.</strong>
             <p>An attachment stays available for a short time after the message is opened, then it is destroyed.</p></div>
             <p class="mut">Reply on your support ticket and we will send a fresh link.</p>',
            null, ['audience' => 'customer']);
        exit;
    }
    $blob = blob_get((string)$r['token']);
    if ($blob === null) { http_response_code(410); exit('This attachment has been destroyed.'); }
    try {
        $bytes = unseal_raw($blob);
    } catch (Throwable $e) {
        audit('customer', 'share.view.failed', (int)$r['id'], (string)$r['ticket_id'], $e->getMessage());
        http_response_code(500);
        exit('This attachment could not be decrypted.');
    }

    audit('customer', 'share.file.downloaded', (int)$r['id'], (string)$r['ticket_id'], 'bytes=' . strlen($bytes));

    $name  = (string)$r['file_name'];
    $ascii = str_replace('"', '', (string)preg_replace('/[^\x20-\x7E]/', '_', $name));
    // ALWAYS octet-stream, never the detected type: serving a customer-supplied SVG
    // or HTML back as itself would run script on this origin, and this origin is the
    // one holding everyone else's secrets. The stored mime is for display only.
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('Content-Length: ' . strlen($bytes));
    header('Cache-Control: no-store, max-age=0');
    header('X-Content-Type-Options: nosniff');
    echo $bytes;
    exit;
}

if (preg_match('#^/v/([a-f0-9]{48})$#', $path, $m)) {
    $st = db()->prepare("SELECT * FROM requests WHERE token = ?");
    $st->execute([$m[1]]);
    $r = $st->fetch();

    $gone = fn(string $why) => print(layout('Message unavailable',
        '<div class="box danger"><strong>This message is no longer available.</strong><p>' . h($why) . '</p></div>
         <p class="mut">Reply on your support ticket and we will send you a new one.</p>',
        null, ['audience' => 'customer']));

    if (!$r)              { http_response_code(404); $gone('The link is not valid.'); exit; }
    if (!is_outbound($r)) { redirect('/s/' . $r['token']); }
    if ((int)$r['expires_at'] < time()) { http_response_code(410); $gone('It has expired.'); exit; }
    if (!share_openable($r)) {
        http_response_code(410);
        $gone($r['status'] === 'expired'
            ? 'It has expired, or it was destroyed after too many wrong passphrase attempts.'
            : 'It has already been opened. A view-once message is destroyed as soon as it is read.');
        exit;
    }

    $locked  = $r['pass_hash'] !== null;
    $hasFile = $r['file_name'] !== null;
    $err     = '';

    if ($method === 'POST') {
        // The link is the only credential here, so it is also the only thing worth
        // rate-limiting on. Wrong passphrases are counted separately and destructively
        // by share_pass_failed().
        if (!throttle_ok('share-open:' . $r['token'], 20, 900)) {
            http_response_code(429); exit('Too many attempts. Wait 15 minutes.');
        }
        $unlocked = true;
        if ($locked) {
            $given = (string)($_POST['pass'] ?? '');
            if ($given === '' || !password_verify($given, (string)$r['pass_hash'])) {
                $unlocked = false;
                if (share_pass_failed($r)) {
                    http_response_code(410);
                    $gone('It was destroyed after ' . SHARE_MAX_PASS_FAILS . ' wrong passphrase attempts.');
                    exit;
                }
                $st->execute([$m[1]]);
                $r = $st->fetch();
                $left = SHARE_MAX_PASS_FAILS - (int)$r['pass_fails'];
                $err  = '<div class="box danger"><strong>That passphrase is not right.</strong>
                         <p>' . $left . ' attempt' . ($left === 1 ? '' : 's') . ' left. After that the message is
                         destroyed and we will have to send a new one.</p></div>';
            }
        }

        if ($unlocked) {
            $opened = open_share($r, $base);
            if (!$opened['ok']) { http_response_code(410); $gone($opened['error']); exit; }

            $body = '<div class="box ok"><strong>Here it is.</strong><p>'
                  . (view_is_once($r)
                      ? 'This message has now been destroyed on our side. Copy anything you need before you close the page.'
                      : 'You can re-open this link until ' . local_time((int)$r['expires_at']) . '.')
                  . '</p></div>';
            if ($opened['message'] !== '') {
                $body .= '<div class="cred"><div class="cred-row">'
                      . '<div class="cred-k">Message</div>'
                      . '<div class="linkrow">'
                      . '<pre id="share-msg" class="verbatim cred-v">' . h($opened['message']) . '</pre>'
                      . copy_button('share-msg')
                      . '</div></div></div>';
            }
            if ($opened['file'] !== null) {
                $body .= '<div class="box"><strong>Attachment</strong>
                          <p class="mut">' . h($opened['file']['name']) . ' — ' . h(share_size_label($opened['file']['size'])) . '</p>
                          <p class="btn-row"><a class="btn" href="' . h($opened['file']['url']) . '">Download</a></p>
                          <p class="hint">This download stays available for '
                          . (int)round(SHARE_DOWNLOAD_GRANT / 60) . ' minutes, then the file is destroyed too.</p></div>';
            } elseif ($hasFile) {
                $body .= '<div class="box warn"><strong>The attachment is no longer available.</strong>
                          <p>The message reached you but the file had already been purged. Ask us to resend it.</p></div>';
            }
            $body .= '<p class="mut">Ticket #' . h((string)$r['ticket_id']) . '. If you did not expect this message, tell us on the ticket.</p>';
            echo layout('Your secure message', $body, null, ['audience' => 'customer']);
            exit;
        }
    }

    // GET never opens the message.
    //
    // Mail gateways, link scanners and chat previewers fetch every URL in an email
    // before a human sees it. If GET burned the message, a customer on a scanned
    // mailbox would open the link to find it already destroyed -- by their own
    // employer's security software -- and the secret would have been read by a
    // machine we cannot ask about it. The click below is what separates a human
    // from a prefetch.
    $lede = view_is_once($r)
        ? 'Someone at InstaWP support sent you this. <strong>It can be opened once.</strong> When you open it, our copy is destroyed.'
        : 'Someone at InstaWP support sent you this. You can open it until ' . local_time((int)$r['expires_at']) . '.';

    $form = '<form method="post" class="card">';
    if ($locked) {
        $form .= '<div class="field">
                    <label for="f-pass">Passphrase</label>
                    <div class="password-control">
                      <input id="f-pass" name="pass" type="password" required autocomplete="off"
                             spellcheck="false" autocapitalize="off" autofocus>'
              . password_toggle_button() . '
                    </div>
                    <p class="hint">Support gave you this separately — on the phone, or by text. It is not in the email.</p>
                  </div>';
    }
    $form .= '<p class="btn-row"><button class="btn-block" type="submit">'
          . ($locked ? 'Unlock and open' : 'Open the message') . '</button></p></form>';

    echo layout('A secure message for you',
        $err . '
        <h2>Ticket #' . h((string)$r['ticket_id']) . '</h2>
        <p class="lede">' . $lede . '</p>
        ' . ($hasFile ? '<p class="mut">It includes an attachment: ' . h((string)$r['file_name'])
                      . ' (' . h(share_size_label((int)$r['file_size'])) . ').</p>' : '') . '
        <p class="mut">This link expires ' . local_time((int)$r['expires_at']) . '</p>
        ' . ($locked ? '' : '<div class="box warn"><strong>Open it when you are ready to use it.</strong>
             <p>' . (view_is_once($r) ? 'Opening destroys our copy, so do not open it just to check it works.'
                                      : 'You can come back to this link until it expires.') . '</p></div>') . '
        ' . $form,
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
          <p class="lede">Use your staff email and password.</p>
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
        $backDir = (string)($_POST['dir'] ?? '');
        $backDir = in_array($backDir, ['in', 'out'], true) ? '&dir=' . $backDir : '';
        redirect('/?status=' . $back . $backDir);
    }

    $allowed    = ['pending' => 'Awaiting', 'submitted' => 'Ready', 'read' => 'Read', 'expired' => 'Expired'];
    $dirAllowed = ['in' => 'From customer', 'out' => 'Sent to customer'];

    $dirFilter = (string)($_GET['dir'] ?? '');
    $dirFilter = isset($dirAllowed[$dirFilter]) ? $dirFilter : '';

    // Each filter's counts are scoped by the OTHER one. Counted globally they
    // describe a list you cannot reach: "Awaiting (4)" sitting next to an active
    // direction that holds one row sends you to an empty table and looks broken.
    $counts = ['pending' => 0, 'submitted' => 0, 'read' => 0, 'expired' => 0];
    $cs = db()->prepare("SELECT status, COUNT(*) c FROM requests"
        . ($dirFilter === '' ? '' : " WHERE direction = ?") . " GROUP BY status");
    $cs->execute($dirFilter === '' ? [] : [$dirFilter]);
    foreach ($cs->fetchAll() as $c) $counts[$c['status']] = (int)$c['c'];
    $total = array_sum($counts);

    $fallback = $counts['read'] > 0 ? 'read' : '';
    if (!isset($_GET['status'])) {
        $statusFilter = $fallback;
    } else {
        $raw = (string)$_GET['status'];
        $statusFilter = $raw === 'all' ? '' : (isset($allowed[$raw]) ? $raw : $fallback);
    }

    $dirCounts = ['in' => 0, 'out' => 0];
    $dc = db()->prepare("SELECT direction, COUNT(*) c FROM requests"
        . ($statusFilter === '' ? '' : " WHERE status = ?") . " GROUP BY direction");
    $dc->execute($statusFilter === '' ? [] : [$statusFilter]);
    foreach ($dc->fetchAll() as $c) {
        $dirCounts[(string)$c['direction'] === 'out' ? 'out' : 'in'] += (int)$c['c'];
    }

    $sql = "SELECT * FROM requests";
    $params = [];
    $where  = [];
    if (isset($allowed[$statusFilter])) { $where[] = "status = ?";    $params[] = $statusFilter; }
    if ($dirFilter !== '')              { $where[] = "direction = ?"; $params[] = $dirFilter; }
    if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
    $sql .= requests_list_order_sql();
    $st = db()->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll();

    $ready = $counts['submitted'];
    $banner = $ready > 0 && $statusFilter === ''
        ? '<div class="box warn"><strong>' . $ready . ' request' . ($ready === 1 ? '' : 's') . ' ready to read.</strong> Open ' . ($ready === 1 ? 'it' : 'one') . ' only when you are ready to use the credential — reading destroys the stored copy.</div>'
        : '';

    // Every link carries BOTH parameters. Dropping one meant picking a status
    // silently cleared the direction you were looking at.
    $fLink = fn(string $st, string $dir) => '/?status=' . ($st === '' ? 'all' : $st)
                                          . ($dir === '' ? '' : '&dir=' . $dir);

    $filters = '<div class="filters" role="navigation" aria-label="Filter requests">'
             . '<a href="' . $fLink('', $dirFilter) . '"' . ($statusFilter === '' ? ' class="on"' : '')
             . '>All (' . $total . ')</a>';
    foreach ($allowed as $k => $label) {
        // A chip whose only destination is an empty table is furniture, not a filter.
        if ($counts[$k] === 0 && $statusFilter !== $k) continue;
        $filters .= '<a href="' . $fLink($k, $dirFilter) . '"' . ($statusFilter === $k ? ' class="on"' : '')
                 . '>' . $label . ' (' . $counts[$k] . ')</a>';
    }
    // One segmented control rather than a second row of pills. The arrows are the
    // same ones the table uses, so the vocabulary is learned once.
    if ($dirCounts['out'] > 0 || $dirFilter !== '') {
        $filters .= '<span class="seg" role="group" aria-label="Direction">'
                 . '<a href="' . $fLink($statusFilter, '') . '"' . ($dirFilter === '' ? ' class="on"' : '') . '>Both</a>'
                 . '<a href="' . $fLink($statusFilter, 'in') . '"' . ($dirFilter === 'in' ? ' class="on"' : '')
                 . ' title="Credentials the customer sends us">&larr; In (' . $dirCounts['in'] . ')</a>'
                 . '<a href="' . $fLink($statusFilter, 'out') . '"' . ($dirFilter === 'out' ? ' class="on"' : '')
                 . ' title="Secure messages we send the customer">&rarr; Out (' . $dirCounts['out'] . ')</a>'
                 . '</span>';
    }
    $filters .= '</div>';

    $statusQs = $statusFilter === '' ? 'all' : $statusFilter;
    $body = '<div class="pagehead"><h2>Requests</h2>'
          . '<span class="btn-row"><a class="btn btn-ghost" href="/new-share">Send a message</a>'
          . '<a class="btn" href="/new">New request</a></span></div>'
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
              . '<input type="hidden" name="dir" value="' . h($dirFilter) . '">'
              . '<div class="scroll"><table><thead><tr>'
              . '<th scope="col">Ticket</th><th scope="col">Needed</th><th scope="col">Status</th>'
              . '<th scope="col">Expires</th><th scope="col">Raised by</th>'
              . '<th scope="col">Actions</th>'
              . '</tr></thead><tbody>';
        foreach ($rows as $r) {
            $id = (int)$r['id'];
            $out = is_outbound($r);
            $href = ($out ? '/o/' : '/r/') . $id;
            // 'submitted' cannot occur on an outbound row, but the highlight means
            // "a credential is sitting here waiting to be read" and that is never
            // true of something we sent.
            $rowCls = (!$out && $r['status'] === 'submitted') ? ' class="row-ready"' : '';
            $needFull = $out
                ? 'Secure message sent to the customer'
                : (needs()[$r['need']] ?? $r['need']);
            $expireBtn = $r['status'] !== 'expired'
                ? '<button class="ico-btn expire" type="submit" name="expire_one" value="' . $id . '" data-kind="expire" aria-label="Expire">'
                  . icon_expire_svg() . '<span class="ico-name">Expire</span></button>'
                : '<button class="ico-btn expire" type="button" disabled aria-label="Already expired">'
                  . icon_expire_svg() . '<span class="ico-name">Already expired</span></button>';
            $body .= '<tr' . $rowCls . ' data-href="' . $href . '">'
                  . '<td><a class="rowlink" href="' . $href . '">#' . h($r['ticket_id']) . '</a></td>'
                  . '<td class="need-short" title="' . h($needFull) . '">'
                  . ($out ? '&rarr; ' : '&larr; ') . h(need_short((string)$r['need'])) . '</td>'
                  . '<td>' . status_pill($r['status'], $out) . '</td>'
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

if ($path === '/new-share') {
    if ($method === 'POST') {
        // A multipart body over post_max_size arrives with $_POST and $_FILES both
        // EMPTY and no PHP-level error -- csrf_check() would then reject it as a
        // forgery and the agent would be told their session was bad, not their file
        // was too big.
        if (!$_POST && !$_FILES && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
            http_response_code(413);
            echo layout('Too large',
                '<div class="box danger"><strong>That upload was larger than the server accepts.</strong>
                 <p>The limit is ' . h(share_size_label(max_upload_bytes())) . ' per attachment, and the server may
                 enforce a smaller one of its own.</p></div>
                 <p class="btn-row"><a class="btn" href="/new-share">Start again</a></p>', $staff);
            exit;
        }
        csrf_check();
        $ticket  = trim((string)($_POST['ticket_id'] ?? ''));
        $message = trim((string)($_POST['message'] ?? ''));
        $view    = view_from_post();
        $ttl     = (int)($_POST['ttl'] ?? 86400);
        $pass    = (string)($_POST['passphrase'] ?? '');

        $file    = share_file_from_upload('attachment');
        $fileErr = is_string($file) ? $file : null;
        if (is_string($file)) $file = null;

        if ($fileErr !== null) {
            $err = '<div class="box danger">' . h($fileErr) . '</div>';
        } elseif (!share_fields_valid($ticket, $message, $view, $ttl, $file !== null)) {
            $err = '<div class="box danger">A ticket number is required, and so is a message or an attachment.</div>';
        } elseif ($pass !== '' && strlen($pass) < 6) {
            $err = '<div class="box danger">A passphrase must be at least 6 characters, or leave it blank.</div>';
        } else {
            $minted = mint_share($staff, $ticket, $message, $view, $ttl, $pass === '' ? null : $pass, $file, $base);
            echo layout('Message ready',
                '<div class="box ok"><strong>Send this link to the customer.</strong>
                 <p class="hint" style="margin-bottom:10px">Paste the link into the ticket. Do not paste the message itself —
                 that is the whole point of the link.</p>
                 ' . copyable_link($minted['url']) . '
                 <p class="mut" style="margin-top:12px">' . h(view_label($view)) . ', expires ' . local_time($minted['expires_at']) . '.</p></div>'
                 . ($pass !== ''
                     ? '<div class="box warn"><strong>The passphrase is not in that link.</strong>
                        <p>Give it to the customer some other way — say it on the call, or text it. Putting it in the same
                        ticket reply as the link removes the only protection it was adding.</p></div>'
                     : '') . '
                 <p class="btn-row"><a class="btn" href="/">Back to requests</a><a class="btn btn-ghost" href="/new-share">Send another</a></p>', $staff);
            exit;
        }
    }

    $ttls = '';
    foreach (ttl_choices() as $k => $v) {
        $ttls .= '<option value="' . $k . '"' . option_selected('ttl', (string)$k, '86400') . '>' . h($v) . '</option>';
    }
    $views = '';
    foreach (view_choices() as $k => $v) {
        $views .= '<option value="' . h($k) . '"' . option_selected('view', $k, 'once') . '>' . h($v) . '</option>';
    }

    echo layout('Send a secure message', ($err ?? '') . '
      <div class="pagehead"><h2>Send something to the customer</h2></div>
      <div class="split">
      <form method="post" class="card" enctype="multipart/form-data" autocomplete="off">
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
          <label for="f-message">Message</label>
          <textarea id="f-message" name="message" rows="8" spellcheck="false">' . posted_value('message') . '</textarea>
          <p class="hint">Shown to the customer exactly as typed. A message, an attachment, or both.</p>
        </div>
        <div class="field">
          <label for="f-file">Attachment (optional)</label>
          <input id="f-file" name="attachment" type="file">
          <p class="hint">Up to ' . h(share_size_label(max_upload_bytes())) . '. Encrypted at rest and destroyed with the message.</p>
        </div>
        <div class="pair">
          <div class="field">
            <label for="f-view">How long it stays openable</label>
            <select id="f-view" name="view">' . $views . '</select>
          </div>
          <div class="field">
            <label for="f-passphrase">Passphrase (optional)</label>
            <div class="password-control">
              <input id="f-passphrase" name="passphrase" type="password" autocomplete="new-password" spellcheck="false">'
              . password_toggle_button() . '
            </div>
            <p class="hint">6 characters or more. Give it to the customer some other way.</p>
          </div>
        </div>
        <p class="btn-row"><button type="submit">Generate link</button></p>
      </form>
      <aside class="rail">
        <div class="box">
          <strong>What happens next</strong>
          <ol class="steps">
            <li>You paste the link into the ticket</li>
            <li>The customer clicks through and opens it</li>
            <li>View-once is destroyed as they read it</li>
            <li>Any attachment is purged ' . (int)round(SHARE_DOWNLOAD_GRANT / 60) . ' minutes later</li>
          </ol>
        </div>
        <div class="box warn">
          <strong>Use a passphrase for anything that matters.</strong>
          <p>This link <em>is</em> the secret — anyone who can read the customer\'s mailbox can open it. A passphrase
          said on a call or sent by text means an intercepted link on its own is worth nothing.</p>
        </div>
        <div class="box">
          <strong>This is not the route for their credentials.</strong>
          <p>To collect something <em>from</em> a customer, raise a <a href="/new">credential request</a> instead.
          That path is gated on a bug reference on purpose.</p>
        </div>
      </aside>
      </div>', $staff);
    exit;
}

/**
 * Staff view of an outbound share.
 *
 * Deliberately has no reveal action. The content was written by the sender and is
 * addressed to the customer; letting any signed-in agent read it back would turn a
 * one-time link into a copy retained on our side for its whole TTL, which is the
 * exact property the customer is being promised it does not have.
 */
if (preg_match('#^/o/(\d+)$#', $path, $m)) {
    $st = db()->prepare("SELECT * FROM requests WHERE id = ?");
    $st->execute([(int)$m[1]]);
    $r = $st->fetch();
    if (!$r) { http_response_code(404); echo layout('Not found', '<div class="box danger">No such message.</div>', $staff); exit; }
    if (!is_outbound($r)) { redirect('/r/' . (int)$r['id']); }

    if ($method === 'POST') {
        csrf_check();
        if (isset($_POST['delete_one'])) { delete_request((int)$r['id'], $staff); redirect('/'); }
        if (isset($_POST['expire_one'])) { expire_request((int)$r['id'], $staff); redirect('/o/' . (int)$r['id']); }
    }

    $live  = share_openable($r);
    $link  = $base . '/v/' . $r['token'];
    $until = local_time((int)$r['expires_at']);

    $action = match (true) {
        $r['status'] === 'expired' => '<div class="box"><strong>Expired and purged.</strong>
            <p>The message and any attachment are gone. Send a new one if it is still needed.</p></div>',
        $r['status'] === 'read' && view_is_once($r) => '<div class="box ok"><strong>Opened by the customer.</strong>
            <p>Our copy was destroyed as they read it, on ' . local_time((int)$r['read_at']) . '.</p></div>',
        $r['status'] === 'read' => '<div class="box ok"><strong>Opened by the customer</strong> on '
            . local_time((int)$r['read_at']) . '. <p>It stays openable until ' . $until . '.</p></div>',
        default => '<div class="box warn"><strong>Not opened yet.</strong>
            <p>The link is live until ' . $until . '. Nobody has read it.</p></div>',
    };

    $rows = '<table class="kv"><tbody>'
          . '<tr><th scope="row">Ticket</th><td>#' . h((string)$r['ticket_id']) . '</td></tr>'
          . '<tr><th scope="row">Status</th><td>' . status_pill((string)$r['status'], true) . '</td></tr>'
          . '<tr><th scope="row">Sent by</th><td>' . h((string)$r['requested_by']) . '</td></tr>'
          . '<tr><th scope="row">Created</th><td>' . local_time((int)$r['created_at']) . '</td></tr>'
          . '<tr><th scope="row">Expires</th><td>' . $until . '</td></tr>'
          . '<tr><th scope="row">Opening</th><td>' . h(view_label($r)) . '</td></tr>'
          . '<tr><th scope="row">Passphrase</th><td>'
          . ($r['pass_hash'] !== null
                ? 'Set' . ((int)$r['pass_fails'] > 0
                    ? ' — ' . (int)$r['pass_fails'] . ' wrong attempt' . ((int)$r['pass_fails'] === 1 ? '' : 's')
                    : '')
                : 'None — the link alone opens it')
          . '</td></tr>';
    if ($r['file_name'] !== null) {
        $rows .= '<tr><th scope="row">Attachment</th><td>' . h((string)$r['file_name'])
              . ' <span class="mut">(' . h(share_size_label((int)$r['file_size'])) . ', ' . h((string)$r['file_mime']) . ')</span>'
              . (blob_exists((string)$r['token']) ? '' : ' <span class="mut">— destroyed</span>')
              . '</td></tr>';
    }
    $rows .= '</tbody></table>';

    $linkBox = $live
        ? '<div class="box"><strong>The customer link</strong>
           <p class="hint" style="margin-bottom:10px">Paste this into the ticket. Never paste the message itself.</p>'
           . copyable_link($link) . '</div>'
        : '';

    echo layout('Secure message',
        '<div class="pagehead"><h2>Secure message to the customer</h2><a class="btn btn-ghost" href="/">Back</a></div>'
        . $action . $linkBox . $rows
        . '<div class="box"><strong>The content is not shown here.</strong>
           <p class="mut">It was written for the customer and is not readable from this page — that is what makes
           "view once" true rather than merely advertised. If it needs saying again, send a new message.</p></div>'
        . '<form method="post" data-confirm class="btn-row">
             <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'
        . ($r['status'] !== 'expired'
            ? '<button class="btn btn-ghost" type="submit" name="expire_one" value="' . (int)$r['id'] . '">'
              . icon_expire_svg() . ' Destroy now</button>'
            : '')
        . '<button class="btn btn-ghost" type="submit" name="delete_one" value="' . (int)$r['id'] . '">'
        . icon_delete_svg() . ' Delete record</button>
           </form>', $staff);
    exit;
}

if (preg_match('#^/r/(\d+)$#', $path, $m)) {
    $st = db()->prepare("SELECT * FROM requests WHERE id = ?");
    $st->execute([(int)$m[1]]);
    $r = $st->fetch();
    if (!$r) { http_response_code(404); echo layout('Not found', '<div class="box danger">No such request.</div>', $staff); exit; }
    if (is_outbound($r)) { redirect('/o/' . (int)$r['id']); }

    $reveal = '';
    $revealed = false;
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
            $revealed = true;
            $reveal = '<div class="box warn"><strong>Read once — now destroyed.</strong>
                      <p>This will not be shown again. Copy what you need now, and do not paste it into the ticket.</p>'
                      . render_credential($out['plain']) . '</div>';
            sodium_memzero($out['plain']);
        } else {
            $revealed = true;
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

    // Suppressed below when the credential is already on the page. A multi-day share stays
    // 'submitted' after a read -- only read_at/read_by are set -- so without this the "Ready
    // to read" prompt renders again directly under the secret it just handed over, inviting a
    // second pointless open. The reveal box already says how long it stays available.
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
         ' . $reveal . ($revealed ? '' : $action) . $rot . '
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
