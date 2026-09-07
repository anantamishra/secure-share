<?php
declare(strict_types=1);

function layout(string $title, string $body, ?string $staff = null): string {
    $nav = $staff === null ? '' : '
      <nav>
        <a href="/">Requests</a>
        <a href="/new">New request</a>
        <a href="/audit">Audit</a>
        <a href="/password">Password</a>
        <form method="post" action="/logout" style="display:inline">
          <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
          <button class="link">Sign out (' . h($staff) . ')</button>
        </form>
      </nav>';
    return '<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>' . h($title) . ' — InstaWP secure handoff</title>
<style>
  :root{--bg:#fff;--fg:#16181d;--mut:#5b6472;--line:#e3e6ea;--acc:#2c6fdb;--warn:#8a5a00;--warnbg:#fff8e6;--dang:#a1231f;--dangbg:#fdeceb}
  @media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8eaed;--mut:#9aa3b0;--line:#2a2e35;--acc:#79a8f5;--warn:#e0b25c;--warnbg:#2a2314;--dang:#f0908b;--dangbg:#2c1817}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  .wrap{max-width:900px;margin:0 auto;padding:24px 20px 64px}
  header{border-bottom:1px solid var(--line);margin-bottom:28px;padding-bottom:14px}
  h1{font-size:19px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 10px}
  nav{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-top:10px;font-size:14px}
  a{color:var(--acc)} .mut{color:var(--mut);font-size:13px}
  label{display:block;margin:14px 0 4px;font-weight:600;font-size:14px}
  input,select,textarea{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
  button{padding:9px 15px;border:0;border-radius:6px;background:var(--acc);color:#fff;font:inherit;font-weight:600;cursor:pointer}
  button.link{background:none;color:var(--acc);padding:0;font-weight:400;text-decoration:underline}
  button.danger{background:var(--dang)}
  table{width:100%;border-collapse:collapse;font-size:14px;margin-top:8px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
  .box{border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:16px 0}
  .warn{background:var(--warnbg);border-color:var(--warn);color:var(--warn)}
  .danger{background:var(--dangbg);border-color:var(--dang);color:var(--dang)}
  code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  pre{background:var(--line);padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
  .pill{display:inline-block;font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--mut)}
  .scroll{overflow-x:auto}
</style></head><body><div class="wrap">
<header><h1>InstaWP — secure credential handoff</h1>
<div class="mut">Internal tool. Credentials are encrypted at rest, readable once, and purged on expiry.</div>
' . $nav . '</header>' . $body . '</div></body></html>';
}

/**
 * Render a revealed credential one field at a time, each value verbatim.
 *
 * Deliberately NOT a JSON dump: a password containing a quote or a backslash comes
 * back JSON-escaped ("p@ss\\"w\\\\ord"), and an engineer copying that out of a code
 * block pastes the escaped form and gets a failed login they then blame on the
 * customer. Each value gets its own box so a copy is unambiguous.
 */
function render_credential(string $json): string {
    $data = json_decode($json, true);
    if (!is_array($data)) return '<pre>' . h($json) . '</pre>';
    $out = '<table>';
    foreach ($data as $label => $value) {
        if (trim((string)$value) === '') continue;
        $out .= '<tr><th style="width:150px">' . h((string)$label) . '</th>'
             .  '<td><pre style="margin:0">' . h((string)$value) . '</pre></td></tr>';
    }
    return $out . '</table>';
}
