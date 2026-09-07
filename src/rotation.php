<?php
declare(strict_types=1);

/**
 * The rotation nag. A credential that reached us has to be rotated, and a
 * WordPress password change does NOT revoke an application password — those live
 * in usermeta and survive it. Say both, every time, or our own access stays live
 * on the customer's site after the ticket closes.
 */
function flag_rotation(int $id): void {
    $pdo = db();
    $st  = $pdo->prepare("SELECT * FROM requests WHERE id = ?");
    $st->execute([$id]);
    $r = $st->fetch();
    if (!$r || $r['rotation_flagged_at'] !== null) return;

    $what = $r['need'] === 'ssh'
        ? [
            'Rotation is required. Ask the customer to do BOTH:',
            '  1. Change the password on the server account they shared (or remove the key we were given).',
            '  2. Delete the account entirely if it was created for us.',
            '',
            'Server credentials are usually reusable across every site on the box, so this one matters more',
            'than a WordPress rotation, not less. There is no scoped-revocation option here — that is exactly',
            'why this route is meant to be the last resort.',
          ]
        : [
            'Rotation is required. Ask the customer to do BOTH:',
            '  1. Change the WordPress password for the account they shared.',
            '  2. Delete the application password created for us (Users -> Profile -> Application Passwords).',
            '',
            'Step 2 is not optional: application passwords live in usermeta and SURVIVE a password change,',
            'so "please change your password" on its own leaves our credential live on their site.',
          ];

    $lines = [
        'Automated note — secure credential handoff.',
        '',
        'A credential supplied for this ticket has now expired and its stored copy has been purged.',
        '',
        ...$what,
        '',
        $r['read_at'] ? 'The credential was read by ' . $r['read_by'] . ' on ' . gmdate('Y-m-d H:i', (int)$r['read_at']) . ' UTC.'
                      : 'The credential was submitted but never read by us.',
        '',
        'If it came from an agency, the end client should be told it was disclosed. They are the data',
        'subject and they are not in this thread.',
    ];
    freescout_note($r['ticket_id'], implode("\n", $lines));
    $pdo->prepare("UPDATE requests SET rotation_flagged_at=? WHERE id=?")->execute([time(), $id]);
    audit('system', 'rotation.flagged', $id, $r['ticket_id']);
}
