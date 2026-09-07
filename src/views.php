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
  /* InstaWP brand tokens. Source of truth: client-app resources/css/extra.css
     (--primary #005E54, --secondary #15B881) and tailwind.config.cjs.
     Fonts are a LOCAL-ONLY stack on purpose: this page collects customer
     credentials, so it makes zero third-party requests. Do not swap in a
     webfont CDN — that hands a request-time beacon to a third party on the
     one page where that matters most. */
  :root{
    --brand:#005E54; --brand-600:#0A7350; --brand-900:#022C22;
    --mint:#15B881; --mint-soft:#E2EFEB; --mint-tint:#F8FDFB;
    --bg:#fff; --panel:#fff; --fg:#16211f; --mut:#5b6b67;
    --line:#DDE9E5; --acc:#005E54;
    --warn:#8a5a00; --warnbg:#fff8e6;
    --dang:#a1231f; --dangbg:#fdeceb;
    --ring:rgba(21,184,129,.35);
    --shadow:0 1px 2px rgba(2,44,34,.06),0 8px 24px -12px rgba(2,44,34,.18);
  }
  @media (prefers-color-scheme:dark){:root{
    --brand:#45C491; --brand-600:#70D9B6; --brand-900:#CFF2E7;
    --mint:#15B881; --mint-soft:#12302a; --mint-tint:#0f231f;
    --bg:#0B1614; --panel:#111f1c; --fg:#E6F2EE; --mut:#93a8a2;
    --line:#1E3A33; --acc:#70D9B6;
    --warn:#e0b25c; --warnbg:#2a2314;
    --dang:#f0908b; --dangbg:#2c1817;
    --ring:rgba(21,184,129,.45);
    --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px -12px rgba(0,0,0,.6);
  }}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:15px/1.6 "Inter var",Inter,"Plus Jakarta Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       -webkit-font-smoothing:antialiased}
  .wrap{max-width:900px;margin:0 auto;padding:28px 20px 72px}
  header{border-bottom:1px solid var(--line);margin-bottom:28px;padding-bottom:16px}
  .brand{display:flex;align-items:center;gap:11px}
  .mark{flex:0 0 auto;width:34px;height:34px;border-radius:9px;
        background:linear-gradient(145deg,var(--brand) 0%,var(--mint) 100%);
        display:flex;align-items:center;justify-content:center;
        box-shadow:0 2px 8px -2px rgba(0,94,84,.45)}
  .mark svg{display:block}
  h1{font-size:19px;line-height:1.25;margin:0;letter-spacing:-.011em;font-weight:700;color:var(--brand-900)}
  h1 .sub{font-weight:500;color:var(--brand)}
  h2{font-size:16px;margin:28px 0 10px;letter-spacing:-.008em;color:var(--brand-900)}
  nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:14px;font-size:14px}
  nav a{padding:5px 11px;border-radius:7px;text-decoration:none;color:var(--fg);font-weight:500}
  nav a:hover{background:var(--mint-soft);color:var(--brand)}
  a{color:var(--acc)}
  .mut{color:var(--mut);font-size:13px}
  header .mut{margin-top:7px}
  label{display:block;margin:14px 0 5px;font-weight:600;font-size:14px;color:var(--brand-900)}
  input,select,textarea{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;
        background:var(--panel);color:var(--fg);font:inherit;transition:border-color .12s,box-shadow .12s}
  input:focus,select:focus,textarea:focus{outline:0;border-color:var(--mint);box-shadow:0 0 0 3px var(--ring)}
  button{padding:10px 17px;border:0;border-radius:8px;background:var(--brand);color:#fff;font:inherit;
        font-weight:600;cursor:pointer;transition:background .12s,box-shadow .12s}
  button:hover{background:var(--brand-600)}
  button:focus-visible{outline:0;box-shadow:0 0 0 3px var(--ring)}
  button.link{background:none;color:var(--acc);padding:0;font-weight:500;text-decoration:underline}
  button.link:hover{background:none;color:var(--brand-600)}
  button.danger{background:var(--dang)}
  button.danger:hover{background:var(--dang);filter:brightness(.92)}
  table{width:100%;border-collapse:collapse;font-size:14px;margin-top:8px}
  th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}
  th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);font-weight:600}
  tbody tr:hover{background:var(--mint-tint)}
  .box{border:1px solid var(--line);border-radius:11px;padding:15px 17px;margin:16px 0;
       background:var(--panel);box-shadow:var(--shadow)}
  .warn{background:var(--warnbg);border-color:var(--warn);color:var(--warn)}
  .danger{background:var(--dangbg);border-color:var(--dang);color:var(--dang)}
  code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  pre{background:var(--mint-tint);border:1px solid var(--line);padding:12px;border-radius:8px;
      overflow-x:auto;white-space:pre-wrap;word-break:break-all}
  .pill{display:inline-block;font-size:12px;padding:3px 9px;border-radius:99px;
        border:1px solid var(--line);background:var(--mint-tint);color:var(--mut);font-weight:500}
  .scroll{overflow-x:auto}
</style></head><body><div class="wrap">
<header>
  <div class="brand">
    <span class="mark" aria-hidden="true">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2"
           stroke-linecap="round" stroke-linejoin="round">
        <rect x="3.5" y="10.5" width="17" height="11" rx="2.5"></rect>
        <path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5"></path>
      </svg>
    </span>
    <h1>InstaWP <span class="sub">— secure credential handoff</span></h1>
  </div>
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
