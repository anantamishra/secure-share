<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';
env_load(getenv('APP_ENV_FILE') ?: '/home/instapod/handoff.env');
require __DIR__ . '/../src/crypto.php';
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/views.php';
require __DIR__ . '/../src/freescout.php';
require __DIR__ . '/../src/rotation.php';

// Without this an uncaught throwable renders a blank page (or, if the pod ever has
// zend.exception_ignore_args=Off, a stack trace whose frames include the plaintext
// credential and the master key). Neither is acceptable on this app.
set_exception_handler(function (Throwable $e): void {
    if (!headers_sent()) { http_response_code(500); header('Content-Type: text/plain'); }
    try { audit('system', 'unhandled.exception', null, null, get_class($e) . ': ' . $e->getMessage()); }
    catch (Throwable $ignored) { /* the DB is the thing that failed; do not mask it */ }
    echo "Something went wrong and has been logged.\n"
       . "If you were opening a credential, check the request page before asking the customer again:\n"
       . "it may already have been marked read.\n";
});
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");

$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$base   = rtrim(cfg('APP_URL', 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')), '/');

function ttl_choices(): array {
    return [3600 => '1 hour', 21600 => '6 hours', 86400 => '24 hours', 172800 => '48 hours'];
}

/** Expire and purge anything past its deadline. Cheap, so run it on every request. */
function sweep(): void {
    $pdo = db();
    $st  = $pdo->prepare("SELECT * FROM requests WHERE expires_at < ? AND status IN ('pending','submitted','read')");
    $st->execute([time()]);
    foreach ($st->fetchAll() as $r) {
        $pdo->prepare("UPDATE requests SET status='expired', purged_at=?, nonce=NULL, ciphertext=NULL WHERE id=?")
            ->execute([time(), $r['id']]);
        audit('system', 'request.expired.purged', (int)$r['id'], $r['ticket_id']);
        // flag_rotation() marks locally and defers its own FreeScout call, so this is
        // safe to run inline even though the sweep fires on every request.
        if ($r['submitted_at'] !== null) flag_rotation((int)$r['id']);
    }
}

if ($path === '/healthz') {
    header('Content-Type: application/json');
    try { db(); master_key(); echo json_encode(['ok' => true]); }
    catch (Throwable $e) { http_response_code(500); echo json_encode(['ok' => false, 'error' => $e->getMessage()]); }
    exit;
}

sweep();

// ---------------------------------------------------------------- customer side

if (preg_match('#^/s/([a-f0-9]{48})$#', $path, $m)) {
    $st = db()->prepare("SELECT * FROM requests WHERE token = ?");
    $st->execute([$m[1]]);
    $r = $st->fetch();

    $gone = fn(string $why) => print(layout('Link unavailable',
        '<div class="box danger"><strong>This link is no longer usable.</strong><p>' . h($why) . '</p></div>
         <p class="mut">If you still need to send us access, reply on your support ticket and we will issue a new link.</p>'));

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

        if ($missing) {
            $err = '<div class="box danger">Every field except Notes' . ($optional ? ' and Port' : '') . ' is required.</div>';
        } else {
            // JSON_INVALID_UTF8_SUBSTITUTE: json_encode() returns false on invalid UTF-8,
            // and seal(false) then fatals under strict_types -- the customer's submission
            // was silently lost and the row stayed pending, so they retried into the same
            // failure. Substituting keeps the field readable rather than dropping it.
            $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            [$nonce, $ct] = seal((string)$json);
            // Guarded on status: a submit racing the expiry sweep would otherwise write
            // ciphertext back onto a row that had just been purged, and a double-submit
            // would overwrite the first payload.
            $upd = db()->prepare("UPDATE requests SET status='submitted', submitted_at=?, nonce=?, ciphertext=?, site_url=? WHERE id=? AND status='pending'");
            $upd->execute([time(), $nonce, $ct, $payload[$fields[array_key_first($fields)]], $r['id']]);
            if ($upd->rowCount() !== 1) {
                http_response_code(410); $gone('It has already been used.'); exit;
            }
            audit('customer', 'credential.submitted', (int)$r['id'], $r['ticket_id']);
            defer(fn() => freescout_note($r['ticket_id'],
                "Automated note — secure credential handoff.\n\n" .
                "The customer has submitted credentials through the secure form.\n" .
                "Read them at: {$GLOBALS['base']}/r/{$r['id']}\n\n" .
                "They are readable ONCE, then destroyed. Expires " . gmdate('Y-m-d H:i', (int)$r['expires_at']) . " UTC."));
            echo layout('Received',
                '<div class="box"><strong>Thank you — received.</strong>
                 <p>Your details are encrypted and can be opened once by the engineer working your ticket, then destroyed automatically.</p></div>
                 <p class="mut">You can close this page. Once we are finished we will ask you to change the password and remove the access you created.</p>');
            exit;
        }
    }

    $intro = match ($r['need']) {
        'wp_admin' => '<p>Please create a <strong>temporary WordPress administrator account</strong> for us and
            enter its details below — rather than sending your own login. You can delete it as soon as we are done.</p>',
        'wp_app_password' => '<p>Please enter a <strong>WordPress application password</strong> created for us
            (Users &rarr; Profile &rarr; Application Passwords). It can be revoked on its own, without changing
            your password.</p>',
        'ssh' => '<p>Please enter <strong>SSH/SFTP details</strong> for the server. Where your host allows it,
            create a separate account for us rather than sharing your own, and remove it when we are finished.</p>',
        default => '',
    };

    // An SSH credential cannot be narrowed or revoked the way a WordPress one can,
    // so the customer is told plainly what to do afterwards, on the form itself.
    // The closing line doubles as an anti-phishing signal, so it must stay true:
    // it may only name what this instance genuinely never asks for.
    $extra = match (true) {
        $r['need'] === 'ssh' => '<div class="box danger"><strong>Please change this password once we are done.</strong>
            Server credentials usually unlock more than one site, so treat anything you send here as disclosed.
            We will remind you on the ticket as well.</div>',
        // Given its own box rather than muted small print: this single line is the whole
        // anti-phishing affordance, and it was previously the least prominent text on the
        // page. Wording is unchanged and still flag-aware -- it may only name what this
        // instance genuinely never asks for.
        infra_enabled() => '<div class="box"><strong>We will never ask you for cPanel or FTP credentials.</strong>
            If anyone claiming to be from InstaWP asks for those, please tell us.</div>',
        default => '<div class="box"><strong>We will never ask you for SSH, cPanel or FTP credentials.</strong>
            If anyone claiming to be from InstaWP asks for those, please tell us.</div>',
    };

    $inputs = '';
    $optional = optional_fields($r['need']);
    foreach (fields_for($r['need']) as $k => $lbl) {
        $type = $k === 'password' ? 'password' : ($k === 'login_url' ? 'url' : 'text');
        $req  = in_array($k, $optional, true) ? '' : ' required';
        $ph   = $k === 'login_url' ? ' placeholder="https://example.com/wp-login.php"'
              : ($k === 'port' ? ' placeholder="22"' : '');
        $inputs .= '<label>' . h($lbl) . ($req ? '' : ' (optional)') . '</label>'
                .  '<input name="' . h($k) . '" type="' . $type . '" autocomplete="off"' . $ph . $req . '>';
    }

    echo layout('Send credentials securely',
        ($err ?? '') . '
        <h2>Ticket #' . h($r['ticket_id']) . '</h2>
        ' . $intro . '
        <div class="box"><strong>Why this form.</strong> Anything typed into an email or a support ticket stays in
        both mailboxes permanently. This link is single-use, the details are encrypted, and they are destroyed
        automatically on ' . h(gmdate('j M Y H:i', (int)$r['expires_at'])) . ' UTC.</div>
        <form method="post">
          ' . $inputs . '
          <label>Anything we should know (optional)</label>
          <textarea name="notes" rows="3"></textarea>
          <p style="margin-top:18px"><button>Send securely</button></p>
        </form>
        ' . $extra);
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
        <form method="post" style="max-width:360px">
          <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
          <label>Email</label><input name="email" type="email" required autofocus>
          <label>Password</label><input name="password" type="password" required>
          <p style="margin-top:18px"><button>Sign in</button></p>
        </form>');
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
    $rows = db()->query("SELECT * FROM requests ORDER BY created_at DESC LIMIT 100")->fetchAll();
    $body = '<h2>Requests</h2><div class="scroll"><table><tr><th>Ticket</th><th>Needed</th><th>Status</th><th>Expires</th><th>Raised by</th><th></th></tr>';
    foreach ($rows as $r) {
        $pill = ['pending' => 'awaiting customer', 'submitted' => 'ready to read',
                 'read' => 'read &amp; destroyed', 'expired' => 'expired &amp; purged'][$r['status']] ?? $r['status'];
        $body .= '<tr><td>#' . h($r['ticket_id']) . '</td><td>' . h(needs()[$r['need']] ?? $r['need'])
              . '</td><td><span class="pill">' . $pill . '</span></td><td>' . h(gmdate('j M H:i', (int)$r['expires_at']))
              . '</td><td class="mut">' . h($r['requested_by']) . '</td><td><a href="/r/' . (int)$r['id'] . '">open</a></td></tr>';
    }
    if (!$rows) $body .= '<tr><td colspan="6" class="mut">Nothing yet. <a href="/new">Raise a request</a>.</td></tr>';
    echo layout('Requests', $body . '</table></div>', $staff);
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

        if ($ticket === '' || !isset(needs()[$need]) || $failed === '' || $bug === '' || !isset(ttl_choices()[$ttl])) {
            $err = '<div class="box danger">Every field is required, including the two below the line.</div>';
        } else {
            $token = new_token();
            db()->prepare("INSERT INTO requests (token,ticket_id,need,failed_path,bug_ref,requested_by,created_at,expires_at)
                           VALUES (?,?,?,?,?,?,?,?)")
                ->execute([$token, $ticket, $need, $failed, $bug, $staff, time(), time() + $ttl]);
            $id = (int)db()->lastInsertId();
            audit($staff, 'request.created', $id, $ticket, "need=$need ttl={$ttl}s bug=$bug");
            $link = $base . '/s/' . $token;
            freescout_note($ticket,
                "Automated note — secure credential handoff.\n\n" .
                "$staff raised a credential request (" . needs()[$need] . ").\n" .
                "Product path that failed: $failed\nBug reference: $bug\n\n" .
                "Send the customer this single-use link:\n$link\n\nIt expires " . gmdate('Y-m-d H:i', time() + $ttl) . " UTC.");
            echo layout('Link ready',
                '<div class="box"><strong>Send this to the customer.</strong>
                 <pre>' . h($link) . '</pre>
                 <p class="mut">Single use, expires ' . h(gmdate('j M Y H:i', time() + $ttl)) . ' UTC. Paste the link into the ticket — never ask for the credential in the reply itself.</p></div>
                 <p><a href="/">Back to requests</a></p>', $staff);
            exit;
        }
    }
    $opts = '';
    foreach (needs() as $k => $v) $opts .= '<option value="' . h($k) . '">' . h($v) . '</option>';
    $ttls = '';
    foreach (ttl_choices() as $k => $v) $ttls .= '<option value="' . $k . '"' . ($k === 172800 ? ' selected' : '') . '>' . h($v) . '</option>';

    echo layout('New request', ($err ?? '') . '
      <h2>Raise a credential request</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
        <label>FreeScout ticket number</label><input name="ticket_id" required autofocus>
        <label>What is needed</label><select name="need">' . $opts . '</select>
        <label>Link expires after</label><select name="ttl">' . $ttls . '</select>

        <div class="box warn" style="margin-top:26px">
          <strong>Before you raise this.</strong>
          <p>Asking for a credential is a last resort, not a shortcut. On a site we host, use Support Access
          and Magic Login. On a source site, the customer installs <code>instawp-connect</code> and we need
          no credential at all.</p>
          <p>If that path is broken, <strong>that is a bug report</strong>. File it first — a credential
          request that replaces an investigation buries a defect that will hit the next customer.</p>
        </div>

        <label>Which product path failed, and how?</label>
        <input name="failed_path" required placeholder="e.g. migration tool connect popup never opens on their source site">
        <label>Bug reference</label>
        <input name="bug_ref" required placeholder="task id, GitHub issue, or ClickUp link">

        <p style="margin-top:20px"><button>Generate link</button></p>
      </form>
      ' . (infra_enabled()
          ? '<div class="box danger"><strong>SSH collection is switched ON for this instance.</strong>
             An SSH credential is broad, reusable, and cannot be revoked without collateral damage — and on an
             agency ticket it is usually their client\'s server. Use it only when there is genuinely no
             WordPress-level route, and raise the rotation with the customer yourself as well.</div>'
          : '<p class="mut">The form offers WordPress admin and application passwords only. SSH, cPanel and FTP
             are deliberately not options.</p>'), $staff);
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
        if ($r['status'] !== 'submitted') {
            $reveal = '<div class="box danger">Nothing to read — this request is ' . h($r['status']) . '.</div>';
        } else {
            try {
                // Order matters, in both directions.
                //
                // Decrypt FIRST, from the row we already fetched: if decryption fails we
                // must not have destroyed anything, or a bad key would eat the credential.
                $plain = unseal($r['nonce'], $r['ciphertext']);

                // Then claim the read with a compare-and-set. The previous version read the
                // status, checked it, and then wrote unconditionally -- so two engineers
                // clicking at the same time both passed the check and both got the plaintext.
                // "Read once" is a policy behaviour, so the guarantee has to hold under
                // concurrency, not just in a sequential test. Only the request that actually
                // flips the row is allowed to see the credential.
                $won = claim_credential_read((int)$r['id'], $staff);

                if (!$won) {
                    sodium_memzero($plain);
                    audit($staff, 'credential.read.lost_race', (int)$r['id'], $r['ticket_id']);
                    $reveal = '<div class="box danger"><strong>Nothing to read — someone else opened this first.</strong>
                      <p>It can only be opened once. Check the audit log to see who has it.</p></div>';
                } else {
                    audit($staff, 'credential.read', (int)$r['id'], $r['ticket_id']);

                    $reveal = '<div class="box warn"><strong>Read once — now destroyed.</strong>
                      <p>This will not be shown again. Copy what you need now, and do not paste it into the ticket.</p>'
                      . render_credential($plain) . '</div>';

                    // Deferred until after the response is sent. These are two blocking 15s
                    // HTTP calls, and they used to run BETWEEN destroying the ciphertext and
                    // echoing it -- so a slow FreeScout meant the engineer's request timed out
                    // having received nothing at all, with the only copy already gone.
                    $ticket = $r['ticket_id'];
                    defer(fn() => freescout_note($ticket,
                        "Automated note — secure credential handoff.\n\n" .
                        "$staff opened the credential for this ticket on " . gmdate('Y-m-d H:i', time()) . " UTC.\n" .
                        "The stored copy has been destroyed. It cannot be opened again.\n\n" .
                        "When the work is done, ask the customer to change the password AND delete the application\n" .
                        "password created for us — a password change does not revoke one."));

                    // Inline: this sets rotation_flagged_at, which the re-fetch below turns
                    // into the on-page rotation reminder. Its FreeScout call defers itself.
                    flag_rotation((int)$r['id']);
                }

                $st->execute([(int)$m[1]]);
                $r = $st->fetch();
            } catch (Throwable $e) {
                // The audit write is itself a database write, and the most likely reason we
                // are in here is that the database is unhappy -- so this used to throw again
                // from inside the catch and lose the very row that records the failure.
                try { audit($staff, 'credential.read.failed', (int)$r['id'], $r['ticket_id'], $e->getMessage()); }
                catch (Throwable $ignored) { /* nothing further we can do from here */ }
                $reveal = '<div class="box danger"><strong>Could not decrypt.</strong><p>' . h($e->getMessage()) . '</p></div>';
            }
        }
    }

    $link   = $base . '/s/' . $r['token'];
    $action = match ($r['status']) {
        'pending'   => '<div class="box"><strong>Waiting on the customer.</strong><pre>' . h($link) . '</pre>
                        <p class="mut">Single-use link. Expires ' . h(gmdate('j M Y H:i', (int)$r['expires_at'])) . ' UTC.</p></div>',
        'submitted' => '<form method="post"><input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
                        <input type="hidden" name="action" value="reveal">
                        <div class="box warn"><strong>Ready to read.</strong>
                        <p>Opening this destroys the stored copy immediately and records you as the reader. Only
                        do it when you are ready to use it.</p>
                        <p><button class="danger">Open once and destroy</button></p></div></form>',
        'read'      => '<div class="box"><strong>Read and destroyed.</strong><p class="mut">Opened by '
                        . h($r['read_by']) . ' on ' . h(gmdate('j M Y H:i', (int)$r['read_at'])) . ' UTC.</p></div>',
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
        '<h2>Ticket #' . h($r['ticket_id']) . '</h2>
         <p class="mut">' . h(needs()[$r['need']] ?? $r['need']) . ' &middot; raised by ' . h($r['requested_by'])
         . ' on ' . h(gmdate('j M Y H:i', (int)$r['created_at'])) . ' UTC</p>
         ' . $reveal . $action . $rot . '
         <h2>Why this was raised</h2>
         <table><tr><th>Product path that failed</th><td>' . h($r['failed_path']) . '</td></tr>
         <tr><th>Bug reference</th><td>' . h($r['bug_ref']) . '</td></tr></table>
         <p style="margin-top:24px"><a href="/">Back to requests</a></p>', $staff);
    exit;
}

if ($path === '/password') {
    if ($method === 'POST') {
        csrf_check();
        $cur  = (string)($_POST['current'] ?? '');
        $new  = (string)($_POST['new'] ?? '');
        $conf = (string)($_POST['confirm'] ?? '');
        $st = db()->prepare("SELECT pass_hash FROM staff WHERE email = ?");
        $st->execute([$staff]);
        $row = $st->fetch();
        if (!$row || !password_verify($cur, $row['pass_hash'])) {
            $err = '<div class="box danger">Your current password is wrong.</div>';
        } elseif (strlen($new) < 12) {
            $err = '<div class="box danger">Use at least 12 characters.</div>';
        } elseif (!hash_equals($new, $conf)) {
            $err = '<div class="box danger">The two new passwords do not match.</div>';
        } else {
            db()->prepare("UPDATE staff SET pass_hash = ? WHERE email = ?")
                ->execute([password_hash($new, PASSWORD_BCRYPT, ['cost' => 12]), $staff]);
            audit($staff, 'staff.password.changed');
            $err = '<div class="box"><strong>Password changed.</strong></div>';
        }
    }
    echo layout('Change password', ($err ?? '') . '
      <h2>Change your password</h2>
      <form method="post" style="max-width:380px">
        <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
        <label>Current password</label><input name="current" type="password" required>
        <label>New password (12+ characters)</label><input name="new" type="password" required>
        <label>Confirm new password</label><input name="confirm" type="password" required>
        <p style="margin-top:18px"><button>Change password</button></p>
      </form>', $staff);
    exit;
}

if ($path === '/audit') {
    $rows = db()->query("SELECT * FROM audit ORDER BY id DESC LIMIT 300")->fetchAll();
    $body = '<h2>Audit</h2><p class="mut">Every read is recorded here and cannot be edited from the UI.</p><div class="scroll"><table>
             <tr><th>When (UTC)</th><th>Who</th><th>Action</th><th>Ticket</th><th>IP</th><th>Detail</th></tr>';
    foreach ($rows as $a) {
        $body .= '<tr><td>' . h(gmdate('j M H:i', (int)$a['at'])) . '</td><td>' . h($a['actor'])
              . '</td><td><code>' . h($a['action']) . '</code></td><td>' . h($a['ticket_id'])
              . '</td><td class="mut">' . h($a['ip']) . '</td><td class="mut">' . h($a['detail']) . '</td></tr>';
    }
    echo layout('Audit', $body . '</table></div>', $staff);
    exit;
}

http_response_code(404);
echo layout('Not found', '<div class="box">No such page.</div>', $staff);
