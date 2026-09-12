<?php
declare(strict_types=1);

/**
 * @param array{audience?:string} $opt  audience: staff | customer | guest
 */
function layout(string $title, string $body, ?string $staff = null, array $opt = []): string {
    $audience = $opt['audience'] ?? ($staff !== null ? 'staff' : 'guest');
    $here = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    $on = function (string $href) use ($here): string {
        $active = $here === $href || ($href === '/' && (bool)preg_match('#^/[ro]/\d+$#', $here));
        return $active ? ' class="on" aria-current="page"' : '';
    };

    $whoName = $staff ?? '';
    $initial = $staff === null ? '' : strtoupper(substr($staff, 0, 1));
    if ($staff !== null) {
        $acct = staff_account($staff);
        $whoName = staff_display_name($acct, $staff);
        $initial = strtoupper(substr($whoName, 0, 1));
    }
    $settingsOn = $here === '/settings' || $here === '/password' ? ' class="on" aria-current="page"' : '';
    $nav = $staff === null ? '' : '
      <nav aria-label="Staff">
        <a href="/"' . $on('/') . '>Requests</a>
        <a href="/new"' . $on('/new') . '>New request</a>
        <a href="/new-share"' . $on('/new-share') . '>Send message</a>
        <a href="/audit"' . $on('/audit') . '>Audit</a>
        <a href="/settings"' . $settingsOn . '>Settings</a>
      </nav>
      <div class="whochip">
        <span class="who-av" aria-hidden="true">' . h($initial) . '</span>
        <span class="who" title="' . h($staff) . '">' . h($whoName) . '</span>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf" value="' . h(csrf_token()) . '">
          <button class="nav-quit" type="submit">Sign out</button>
        </form>
      </div>';

    $tagline = match ($audience) {
        'customer' => '',
        'guest'    => '',
        default    => 'Internal tool. Encrypted at rest, kept as the customer asked, purged on expiry.',
    };

    $h1 = match ($audience) {
        'customer' => 'InstaWP <span class="sub">send credentials securely</span>',
        'guest'    => 'InstaWP <span class="sub">secure credential handoff</span>',
        default    => 'InstaWP <span class="sub">secure credential handoff</span>',
    };
    $brandInner = '
        <span class="mark" aria-hidden="true">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2"
               stroke-linecap="round" stroke-linejoin="round">
            <rect x="3.5" y="10.5" width="17" height="11" rx="2.5"></rect>
            <path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5"></path>
          </svg>
        </span>
        <div><h1>' . $h1 . '</h1></div>';
    $brand = $staff !== null
        ? '<a class="brand" href="/">' . $brandInner . '</a>'
        : '<div class="brand">' . $brandInner . '</div>';

    $foot = match ($audience) {
        'customer' => '<footer class="foot">Encrypted in transit and at rest · You choose how long we keep them</footer>',
        'guest'    => '<footer class="foot">Staff only · Customer links do not use this page</footer>',
        default    => '<footer class="foot">Internal tool · v' . APP_VERSION . '</footer>',
    };

    return '<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#005E54">
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
    --bg:#F3F7F5; --panel:#fff; --fg:#14201d; --mut:#5d6e6a;
    --line:#D5E4DF; --acc:#005E54;
    --warn:#8a5a00; --warnbg:#fff7e4; --warnline:#edc56a;
    --dang:#a1231f; --dangbg:#fdeceb; --dangline:#e8a09c;
    --ok:#0A7350; --okbg:#E6F7F0; --okline:#8fd4b8;
    --btn:#005E54; --btn-fg:#fff;
    --ring:rgba(21,184,129,.38);
    --shadow:0 1px 2px rgba(2,44,34,.05),0 18px 40px -24px rgba(2,44,34,.28);
    --radius:14px;
    --ease:160ms ease;
  }
  @media (prefers-color-scheme:dark){:root{
    --brand:#45C491; --brand-600:#70D9B6; --brand-900:#E8F8F2;
    --mint:#15B881; --mint-soft:#14352e; --mint-tint:#10241f;
    --bg:#0A1412; --panel:#12201d; --fg:#E8F4F0; --mut:#93a8a2;
    --line:#234038; --acc:#70D9B6;
    --warn:#e0b25c; --warnbg:#2a2314; --warnline:#6a5420;
    --dang:#f0908b; --dangbg:#2c1817; --dangline:#6a3030;
    --ok:#70D9B6; --okbg:#12302a; --okline:#1e4a40;
    --btn:#15B881; --btn-fg:#06241c;
    --ring:rgba(21,184,129,.42);
    --shadow:0 1px 2px rgba(0,0,0,.45),0 18px 40px -20px rgba(0,0,0,.7);
  }}
  *{box-sizing:border-box}
  html{scroll-behavior:smooth;color-scheme:light dark}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       -webkit-font-smoothing:antialiased;min-height:100vh}
  body.aud-customer,body.aud-guest{
    background:
      radial-gradient(720px 280px at 50% -40px, color-mix(in srgb, var(--mint) 16%, transparent), transparent 70%),
      var(--bg);
  }
  body.aud-guest{
    display:flex;flex-direction:column;justify-content:center;min-height:100vh;
    background:
      radial-gradient(900px 420px at 50% -120px, color-mix(in srgb, var(--mint) 22%, transparent), transparent 68%),
      radial-gradient(520px 280px at 100% 100%, color-mix(in srgb, var(--brand) 10%, transparent), transparent 70%),
      var(--bg);
  }
  .skip{position:absolute;left:-999px;top:8px;z-index:9;padding:8px 12px;background:var(--brand);color:#fff;border-radius:8px}
  .skip:focus{left:12px}
  .chrome,.wrap{max-width:1040px;margin:0 auto;padding:0 20px}
  .wrap{padding-top:24px;padding-bottom:72px}
  body.aud-customer .chrome,body.aud-customer .wrap{max-width:840px}
  body.aud-guest .chrome,body.aud-guest .wrap{max-width:400px;width:100%}
  body.aud-guest .wrap{padding:20px 20px 32px;flex:0 0 auto}
  body.aud-guest header.top{padding:0;border:0;margin:0;background:transparent;flex:0 0 auto}
  body.aud-guest header.top .chrome{padding:24px 20px 0}
  body.aud-guest .brandrow{justify-content:center}
  body.aud-guest .brand{flex-direction:column;align-items:center;text-align:center;gap:14px}
  body.aud-guest .mark{width:48px;height:48px;border-radius:14px}
  body.aud-guest .mark svg{width:20px;height:20px}
  body.aud-guest h1{font-size:22px;letter-spacing:-.03em}
  body.aud-guest h1 .sub{font-size:13.5px;margin-top:4px}
  body.aud-guest .card{margin:0;padding:26px 24px 22px}
  body.aud-guest .card h2{font-size:18px;margin:0 0 4px;text-align:center}
  body.aud-guest .card .lede{text-align:center;margin:0 0 18px}
  body.aud-guest .field{margin:0 0 12px}
  body.aud-guest .btn-row{margin-top:16px}
  body.aud-guest .foot{margin:18px 0 0;padding-top:0;border:0}
  body.aud-guest main > .box{margin:0 0 12px}
  body.aud-customer header.top{padding-top:20px}
  body.aud-customer .tagline{margin-top:8px}
  body.aud-customer h2{font-size:18px;margin-bottom:6px}
  body.aud-customer .lede{margin-bottom:4px}
  body.aud-customer .box{margin:10px 0;padding:12px 14px}
  body.aud-customer .card{margin-top:14px;padding:18px}
  header.top{padding:16px 0 0;border-bottom:1px solid var(--line);margin-bottom:0}
  header.top .chrome{padding-bottom:16px}
  body.aud-staff header.top{position:sticky;top:0;z-index:4;padding:0;
    background:var(--panel);box-shadow:0 1px 0 var(--line)}
  @supports (background:color-mix(in srgb, white 80%, transparent)){
    body.aud-staff header.top{background:color-mix(in srgb, var(--panel) 88%, transparent);
      backdrop-filter:saturate(1.2) blur(14px)}
  }
  body.aud-staff header.top .chrome{padding-top:12px;padding-bottom:12px}
  .brandrow{display:flex;align-items:center;justify-content:space-between;gap:14px 20px;flex-wrap:wrap}
  .top-end{display:flex;align-items:center;gap:12px;flex-wrap:wrap;min-width:0}
  .brand{display:flex;align-items:center;gap:11px;min-width:0;text-decoration:none;color:inherit}
  .mark{flex:0 0 auto;width:38px;height:38px;border-radius:11px;
        background:linear-gradient(160deg,var(--brand) 0%,var(--mint) 100%);
        display:flex;align-items:center;justify-content:center;
        box-shadow:0 4px 14px -4px rgba(0,94,84,.55)}
  .mark svg{display:block}
  h1{font-size:16px;line-height:1.2;margin:0;letter-spacing:-.02em;font-weight:700;color:var(--brand-900)}
  h1 .sub{display:block;font-weight:500;font-size:12.5px;letter-spacing:0;color:var(--mut);margin-top:2px}
  h2{font-size:20px;margin:0 0 10px;letter-spacing:-.025em;color:var(--brand-900);font-weight:700}
  .tagline{margin:12px 0 0;color:var(--mut);font-size:13px;max-width:46em;line-height:1.5}
  body.aud-staff .tagline{display:none}
  .whochip{display:flex;align-items:center;gap:8px;min-width:0}
  .who-av{width:28px;height:28px;border-radius:99px;background:var(--mint-soft);color:var(--brand);
          display:grid;place-items:center;font-size:12px;font-weight:700;flex:0 0 auto}
  .who{font-size:12.5px;color:var(--mut);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}
  nav{display:flex;gap:2px;align-items:center;flex-wrap:wrap;padding:3px;background:var(--mint-tint);
      border:1px solid var(--line);border-radius:11px}
  nav a{padding:6px 12px;border-radius:8px;text-decoration:none;color:var(--mut);font-weight:600;
        border:0;background:transparent;font:inherit;font-size:13px;cursor:pointer}
  nav a:hover{background:var(--panel);color:var(--brand)}
  nav a.on{background:var(--panel);color:var(--brand-900);box-shadow:0 1px 2px rgba(2,44,34,.06)}
  .nav-quit{color:var(--mut);font-weight:600;font-size:13px;padding:6px 8px;border:0;background:transparent;
        box-shadow:none;cursor:pointer;font:inherit}
  .nav-quit:hover,.nav-quit:active,.nav-quit:focus-visible{
        background:transparent;color:var(--brand-900);box-shadow:none;transform:none;filter:none}
  .nav-quit:focus-visible{outline:2px solid var(--mint);outline-offset:2px}
  a{color:var(--acc)}
  a:focus-visible{outline:2px solid var(--mint);outline-offset:2px;border-radius:4px}
  .mut{color:var(--mut);font-size:13px}
  .field{margin:0 0 14px}
  .field:last-child{margin-bottom:0}
  label{display:block;margin:0 0 6px;font-weight:600;font-size:13px;color:var(--brand-900);letter-spacing:-.01em}
  .hint{margin:6px 0 0;font-size:12.5px;color:var(--mut);line-height:1.45}
  input,select,textarea{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;
        background:var(--panel);color:var(--fg);font:inherit;transition:border-color var(--ease),box-shadow var(--ease)}
  select{appearance:none;background-image:url("data:image/svg+xml;utf8,<svg xmlns=\'http://www.w3.org/2000/svg\' width=\'12\' height=\'8\' viewBox=\'0 0 12 8\'><path fill=\'%235d6e6a\' d=\'M1 1.5l5 5 5-5\'/></svg>");
        background-repeat:no-repeat;background-position:right 12px center;padding-right:32px}
  input:hover,select:hover,textarea:hover{border-color:color-mix(in srgb,var(--mint) 45%, var(--line))}
  input:focus,select:focus,textarea:focus{outline:0;border-color:var(--mint);box-shadow:0 0 0 4px var(--ring)}
  .password-control{position:relative}
  .password-control input{padding-right:48px}
  .password-toggle{position:absolute;right:6px;top:50%;width:36px;height:36px;min-width:0;padding:0;
        transform:translateY(-50%);background:transparent;color:var(--mut);border:0;box-shadow:none}
  .password-toggle:hover,.password-toggle:active{background:var(--mint-soft);color:var(--brand);transform:translateY(-50%)}
  .password-toggle:focus-visible{box-shadow:0 0 0 3px var(--ring);outline:0}
  .password-toggle svg{display:block}
  .password-toggle .password-eye-off{display:none}
  .password-toggle[aria-pressed="true"] .password-eye{display:none}
  .password-toggle[aria-pressed="true"] .password-eye-off{display:block}
  .share{border:1px solid var(--line);border-radius:10px;padding:10px 14px 12px;margin:4px 0 16px}
  .share legend{font-weight:700;font-size:13px;padding:0 4px;color:var(--brand-900)}
  .share label{display:flex;align-items:center;gap:10px;font-weight:500;margin:8px 0;cursor:pointer}
  .share input[type=radio]{width:auto;margin:0;accent-color:var(--brand);box-shadow:none}
  input.copyable{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;
        user-select:all;cursor:text;letter-spacing:-.015em}
  .linkrow{display:flex;align-items:center;gap:2px;background:var(--mint-tint);
        border:1px solid var(--line);border-radius:10px}
  .linkrow:focus-within{border-color:var(--mint);box-shadow:0 0 0 4px var(--ring)}
  .linkrow .copyable,.linkrow .cred-v{flex:1;min-width:0;width:auto;border:0;background:transparent;
        box-shadow:none;border-radius:0;padding:11px 8px 11px 14px}
  .linkrow .copyable:hover,.linkrow .copyable:focus{border:0;box-shadow:none}
  button.copy-btn{flex:0 0 auto;align-self:center;width:34px;height:34px;min-width:0;margin:0 4px 0 0;
        padding:0;background:transparent;color:var(--mut);border:0;box-shadow:none}
  button.copy-btn:hover,button.copy-btn:active{background:transparent;color:var(--brand);transform:none}
  button.copy-btn.copied,button.copy-btn.copied:hover{background:transparent;color:var(--ok)}
  button.copy-btn svg{display:block}
  button.copy-btn .copy-ok{display:none}
  button.copy-btn.copied .copy-ico{display:none}
  button.copy-btn.copied .copy-ok{display:block}
  button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 16px;border:0;border-radius:10px;
        background:var(--btn);color:var(--btn-fg);font:inherit;font-weight:600;cursor:pointer;text-decoration:none;
        transition:background var(--ease),box-shadow var(--ease),filter var(--ease),transform var(--ease)}
  button:hover,.btn:hover{background:var(--brand-600);color:var(--btn-fg)}
  button:active,.btn:active{transform:translateY(1px)}
  button:focus-visible,.btn:focus-visible{outline:0;box-shadow:0 0 0 4px var(--ring)}
  .btn-ghost{background:transparent;color:var(--brand);border:1px solid var(--line)}
  .btn-ghost:hover{background:var(--mint-soft);color:var(--brand);border-color:transparent}
  button.danger{background:var(--dang);color:#fff}
  button.danger:hover{background:var(--dang);color:#fff;filter:brightness(.92)}
  button.ico-btn{position:relative;width:32px;height:32px;min-width:0;padding:0;background:transparent;color:var(--mut);border:0;box-shadow:none}
  button.ico-btn:hover,button.ico-btn:active{background:var(--mint-soft);color:var(--brand);transform:none}
  button.ico-btn.expire:hover{color:var(--warn);background:var(--warnbg)}
  button.ico-btn.del:hover{color:var(--dang);background:var(--dangbg)}
  button.ico-btn:disabled{opacity:.45}
  button.ico-btn .ico-name{position:absolute;left:50%;bottom:calc(100% + 8px);transform:translateX(-50%);
        background:var(--fg);color:var(--bg);font-size:11px;font-weight:700;letter-spacing:.01em;
        padding:5px 8px;border-radius:6px;white-space:nowrap;opacity:0;pointer-events:none;z-index:20;
        box-shadow:0 4px 14px rgba(0,0,0,.28);transition:opacity .12s ease}
  button.ico-btn .ico-name::after{content:"";position:absolute;left:50%;top:100%;transform:translateX(-50%);
        border:5px solid transparent;border-top-color:var(--fg)}
  button.ico-btn:hover .ico-name,button.ico-btn:focus-visible .ico-name{opacity:1}
  td.row-act{width:76px;text-align:right;white-space:nowrap;overflow:visible}
  td.row-act .ico-btn{vertical-align:middle}
  tbody td{overflow:visible}
  .btn-row{margin-top:18px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  .btn-block{width:100%}
  .settings{display:grid;grid-template-columns:1fr 1fr;gap:22px;align-items:start}
  @media (max-width:800px){.settings{grid-template-columns:1fr}}
  .pair{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media (max-width:640px){.pair{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
        box-shadow:var(--shadow);padding:22px 22px 20px}
  .card > :first-child{margin-top:0}
  .card h2{font-size:17px}
  .card > :last-child{margin-bottom:0}
  .split{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:22px;align-items:start}
  .rail .box{margin:0 0 14px}
  .rail .box:last-child{margin-bottom:0}
  .steps{margin:8px 0 0;padding:0 0 0 18px}
  .steps li{margin:6px 0;color:var(--mut);font-size:13px}
  table{width:100%;border-collapse:collapse;font-size:14px;margin-top:4px}
  th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:middle}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);font-weight:700}
  tbody tr:last-child td{border-bottom:0}
  tbody tr:hover{background:var(--mint-tint)}
  tbody tr[data-href]{cursor:pointer}
  tbody tr[data-href] td.row-act{cursor:default}
  tbody tr.row-ready{background:color-mix(in srgb, var(--okbg) 70%, var(--panel))}
  tbody tr.row-ready:hover{background:var(--okbg)}
  a.rowlink{font-weight:700;color:var(--brand-900);text-decoration:none;letter-spacing:-.01em}
  a.rowlink:hover{color:var(--brand);text-decoration:underline}
  .need-short{color:var(--fg)}
  .box{border:1px solid var(--line);border-radius:var(--radius);padding:15px 17px;margin:16px 0;
       background:var(--panel);box-shadow:var(--shadow);border-left:3px solid var(--line)}
  .box > :first-child{margin-top:0}
  .box > :last-child{margin-bottom:0}
  .box p{margin:8px 0}
  .box.warn{background:var(--warnbg);border-color:var(--warnline);border-left-color:var(--warn);color:var(--warn);box-shadow:none}
  .box.danger{background:var(--dangbg);border-color:var(--dangline);border-left-color:var(--dang);color:var(--dang);box-shadow:none}
  .box.ok{background:var(--okbg);border-color:var(--okline);border-left-color:var(--ok);color:var(--ok);box-shadow:none}
  code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  code{font-size:12.5px}
  pre{background:var(--mint-tint);border:1px solid var(--line);padding:12px;border-radius:8px;
      overflow-x:auto;white-space:pre-wrap;word-break:break-all}
  .verbatim{user-select:all;cursor:text;margin:0}
  .cred{display:grid;gap:10px;margin:14px 0 4px}
  .cred-row{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
  .cred-k{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);font-weight:700;margin-bottom:6px}
  .cred-v{background:var(--mint-tint);border:0;padding:8px 10px;border-radius:8px;font-size:14px;color:var(--fg)}
  .linkrow .cred-v{background:transparent;border:0;padding:11px 8px 11px 14px;border-radius:0}
  .pill{display:inline-flex;align-items:center;font-size:12px;padding:3px 9px;border-radius:99px;
        border:1px solid var(--line);background:var(--mint-tint);color:var(--mut);font-weight:700;white-space:nowrap}
  .pill.ready{background:var(--okbg);border-color:var(--okline);color:var(--ok)}
  .pill.pending{background:var(--warnbg);border-color:var(--warnline);color:var(--warn)}
  .pill.done,.pill.dead{opacity:.92}
  .scroll{overflow-x:auto;overflow-y:visible;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow)}
  .scroll table{margin:0}
  .pagehead{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px}
  .pagehead h2{margin:0}
  .filters{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 16px}
  .filters a{padding:6px 12px;border-radius:99px;text-decoration:none;color:var(--mut);font-size:13px;font-weight:600;
        border:1px solid var(--line);background:var(--panel)}
  .filters a:hover{background:var(--mint-soft);color:var(--brand);border-color:transparent}
  .filters a.on{background:var(--btn);color:var(--btn-fg);border-color:var(--btn)}
  /* Direction lives in the same row as status: a second row of pills was more
     chrome than the table it was filtering. margin-left:auto parks it on the right;
     it wraps underneath on narrow screens rather than squeezing the status chips. */
  .filters .seg{display:inline-flex;margin-left:auto;border:1px solid var(--line);
        border-radius:99px;background:var(--panel);overflow:hidden}
  .filters .seg a{border:0;border-radius:0;background:transparent;padding:6px 11px}
  .filters .seg a + a{border-left:1px solid var(--line)}
  .filters .seg a:hover{background:var(--mint-soft);color:var(--brand)}
  .filters .seg a.on{background:var(--btn);color:var(--btn-fg)}
  .pager{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:16px 0 0}
  .pager .btn-row{margin:0}
  .pager .off{opacity:.4;pointer-events:none}
  .empty{text-align:center;padding:56px 24px;color:var(--mut)}
  .empty strong{display:block;color:var(--brand-900);font-size:17px;margin-bottom:6px;letter-spacing:-.02em}
  .empty .btn{margin-top:10px}
  .meta{display:grid;grid-template-columns:minmax(150px,190px) 1fr;gap:0;border:1px solid var(--line);
        border-radius:var(--radius);background:var(--panel);overflow:hidden;margin:12px 0 20px;box-shadow:var(--shadow)}
  .meta div{display:contents}
  .meta dt,.meta dd{margin:0;padding:11px 16px;border-bottom:1px solid var(--line);font-size:14px}
  .meta dt{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;background:var(--mint-tint);display:flex;align-items:center}
  .meta dd{background:var(--panel)}
  .meta div:last-child dt,.meta div:last-child dd{border-bottom:0}
  .lede{color:var(--mut);margin:0 0 14px;font-size:14px}
  .section{margin:28px 0 0}
  .section h2{font-size:15px;letter-spacing:.01em;text-transform:uppercase;color:var(--mut);font-weight:700}
  .foot{margin:36px 0 0;padding-top:16px;border-top:1px solid var(--line);color:var(--mut);font-size:12px;text-align:center}
  @media (max-width:800px){
    .split{grid-template-columns:1fr}
    .who{display:none}
  }
  @media (max-width:640px){
    .filters .seg{margin-left:0}
    .meta{grid-template-columns:1fr}
    .meta dt{border-bottom:0;padding-bottom:0}
    nav{width:100%}
    .top-end{width:100%}
    .whochip{width:100%;justify-content:space-between}
    body.aud-staff header.top{position:static}
    .card{padding:18px}
  }
  @media (prefers-reduced-motion:reduce){
    html{scroll-behavior:auto}
    *{transition:none!important}
  }
</style></head><body class="aud-' . h($audience) . '">
<a class="skip" href="#main">Skip to content</a>
<header class="top">
  <div class="chrome">
    <div class="brandrow">
      ' . $brand . '
      <div class="top-end">' . $nav . '</div>
    </div>
    ' . ($tagline === '' ? '' : '<p class="tagline">' . $tagline . '</p>') . '
  </div>
</header>
<div class="wrap">
<main id="main">' . $body . '</main>
' . $foot . '
</div>
<script nonce="' . h(csp_nonce()) . '">
document.querySelectorAll("time.localtime").forEach(function(el){
  var d=new Date(el.getAttribute("datetime")||"");
  if(isNaN(d.getTime()))return;
  var fmt=el.getAttribute("data-fmt")||"long";
  var opts={day:"numeric",month:"short",hour:"2-digit",minute:"2-digit",timeZoneName:"short"};
  if(fmt!=="short")opts.year="numeric";
  try{el.textContent=d.toLocaleString(undefined,opts)}catch(e){}
});
document.querySelectorAll(".password-toggle").forEach(function(btn){
  btn.addEventListener("click",function(){
    var input=btn.parentElement.querySelector("input");
    var shown=btn.getAttribute("aria-pressed")==="true";
    if(!input)return;
    input.type=shown?"password":"text";
    btn.setAttribute("aria-pressed",shown?"false":"true");
    btn.setAttribute("aria-label",shown?"Show password":"Hide password");
  });
});
// Ungated on purpose: copy_button() is rendered on the CUSTOMER share page too.
// Gating this with the staff-only handlers left that button inert — it told a
// customer their view-once message was copied and copied nothing, on the one
// page whose content cannot be fetched again.
document.querySelectorAll("[data-copy]").forEach(function(btn){
  btn.addEventListener("click",function(){
    var el=document.querySelector(btn.getAttribute("data-copy"));
    if(!el)return;
    var text=el.value||el.textContent||"";
    function done(){
      btn.classList.add("copied");
      btn.setAttribute("aria-label","Copied");
      setTimeout(function(){btn.classList.remove("copied");btn.setAttribute("aria-label","Copy")},1600);
    }
    function fallback(){if(el.select){el.focus();el.select()}try{document.execCommand("copy");done()}catch(e){}}
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done).catch(fallback)}
    else fallback();
  });
});
' . ($staff === null ? '' : '
document.querySelectorAll("form[data-confirm]").forEach(function(f){
  f.addEventListener("submit",function(e){
    var sub=e.submitter;
    var kind=sub&&sub.getAttribute("data-kind")==="expire"?"expire":"delete";
    var msg=kind==="expire"
      ?"Expire this request now? Any stored credential is destroyed. The row stays as expired."
      :"Delete this request? Any stored credential is destroyed.";
    if(!confirm(msg))e.preventDefault();
  });
});
document.querySelectorAll("tr[data-href]").forEach(function(tr){
  tr.addEventListener("click",function(e){
    if(e.defaultPrevented||e.button!==0)return;
    // The Actions cell submits the surrounding form (expire/delete), and the ticket
    // cell already holds a real link -- leave both to their own handlers.
    var t=e.target;
    if(t&&t.closest&&t.closest(".row-act,a,button,input,select,textarea,label"))return;
    // Engineers copy ticket ids and emails straight out of these cells; a drag that
    // ends in a selection is not a click on the row.
    var sel=window.getSelection();
    if(sel&&sel.toString().length)return;
    var url=tr.getAttribute("data-href");
    if(e.metaKey||e.ctrlKey||e.shiftKey){window.open(url,"_blank","noopener");return}
    location.href=url;
  });
});
') . '</script></body></html>';
}

/** Visible clock. UTC in the HTML, rewritten to the browser timezone by layout(). */
function local_time(int $unix, string $fmt = 'long'): string {
    $iso = gmdate('Y-m-d\TH:i:s\Z', $unix);
    $fallback = ($fmt === 'short' ? gmdate('j M H:i', $unix) : gmdate('j M Y H:i', $unix)) . ' UTC';
    return '<time class="localtime" datetime="' . h($iso) . '" data-fmt="' . h($fmt) . '">' . h($fallback) . '</time>';
}

function audit_label(string $action): string {
    $map = [
        'credential.submitted'      => 'Customer submitted credentials',
        'credential.read'           => 'Credential opened',
        'credential.reread'         => 'Credential opened again',
        'credential.read.lost_race' => 'Someone else opened it first',
        'credential.read.failed'    => 'Could not decrypt',
        'share.created'             => 'Secure message sent',
        'share.viewed'              => 'Customer opened the message',
        'share.view.lost_race'      => 'Message was already opened',
        'share.view.failed'         => 'Message could not be decrypted',
        'share.unlock.failed'       => 'Wrong passphrase',
        'share.destroyed.attempts'  => 'Destroyed after wrong passphrases',
        'share.file.downloaded'     => 'Attachment downloaded',
        'share.file.purged'         => 'Attachment purged',
        'request.created'           => 'Request created',
        'request.deleted'           => 'Request deleted',
        'request.expired'           => 'Request expired',
        'request.expired.purged'    => 'Expired and purged',
        'rotation.flagged'          => 'Rotation flagged',
        'staff.login.ok'            => 'Signed in',
        'staff.login.failed'        => 'Sign-in failed',
        'staff.logout'              => 'Signed out',
        'staff.profile.updated'     => 'Profile updated',
        'staff.password.changed'    => 'Password changed',
        'staff.session.revoked'     => 'Session revoked',
        'staff.added'               => 'Staff account added',
        'staff.disabled'            => 'Staff account disabled',
        'staff.api_token.issued'    => 'API token issued',
        'staff.api_token.revoked'   => 'API token revoked',
        'freescout.note.posted'     => 'Note posted to FreeScout',
        'freescout.note.failed'     => 'FreeScout note failed',
        'unhandled.exception'       => 'Something went wrong',
    ];
    return $map[$action] ?? ucfirst(str_replace('.', ' ', $action));
}

function audit_detail_label(string $action, ?string $detail): string {
    $detail = trim((string)$detail);
    if ($detail === '') return '';

    if ($action === 'credential.submitted' && preg_match('/^share=(.+)$/', $detail, $m)) {
        return 'Customer asked: ' . share_label($m[1]);
    }
    if (($action === 'request.deleted' || $action === 'request.expired') && preg_match('/^status=(.+)$/', $detail, $m)) {
        $was = [
            'pending'   => 'Was awaiting customer',
            'submitted' => 'Was ready to read',
            'read'      => 'Was already read',
            'expired'   => 'Was expired',
        ];
        return $was[$m[1]] ?? ('Was ' . $m[1]);
    }
    if ($action === 'share.created' && preg_match('/^view=(\S+) ttl=(\d+)s pass=(\S+) file=(\S+)$/', $detail, $m)) {
        return view_label($m[1])
            . ' · link lasts ' . (ttl_choices()[(int)$m[2]] ?? ($m[2] . ' seconds'))
            . ' · ' . ($m[3] === 'yes' ? 'passphrase set' : 'no passphrase')
            . ' · ' . ($m[4] === 'yes' ? 'with attachment' : 'no attachment');
    }
    if ($action === 'request.created' && preg_match('/^need=(\S+) ttl=(\d+)s bug=(.*)$/s', $detail, $m)) {
        $need = needs()[$m[1]] ?? $m[1];
        $ttl  = ttl_choices()[(int)$m[2]] ?? ($m[2] . ' seconds');
        return $need . ' · link lasts ' . $ttl . ' · bug ' . $m[3];
    }
    if ($action === 'staff.profile.updated' && preg_match('/^email (.+) → (.+)$/u', $detail, $m)) {
        return 'Email changed from ' . $m[1] . ' to ' . $m[2];
    }
    if ($action === 'freescout.note.failed' && preg_match('/^HTTP (\d+)/', $detail, $m)) {
        return 'FreeScout returned HTTP ' . $m[1];
    }
    if (preg_match('/^\S+=\S+(?:\s+\S+=\S+)*$/', $detail)) {
        $parts = [];
        foreach (preg_split('/\s+/', $detail) as $tok) {
            [$k, $v] = explode('=', $tok, 2);
            if ($k === 'share') $v = share_label($v);
            if ($k === 'need')  $v = needs()[$v] ?? $v;
            if ($k === 'ttl' && preg_match('/^(\d+)s$/', $v, $tm)) {
                $v = ttl_choices()[(int)$tm[1]] ?? $v;
            }
            $parts[] = ucfirst(str_replace('_', ' ', $k)) . ' ' . $v;
        }
        return implode(' · ', $parts);
    }
    return $detail;
}

/**
 * The same four statuses mean opposite things in each direction: 'pending' on an
 * inbound request is us waiting on the customer, on an outbound share it is the
 * customer not having opened it yet. One vocabulary for both read as nonsense on
 * half the dashboard.
 */
function status_pill(string $status, bool $outbound = false): string {
    $map = $outbound
        ? [
            'pending'   => ['not opened yet', 'pending'],
            'submitted' => ['not opened yet', 'pending'],
            'read'      => ['opened by customer', 'done'],
            'expired'   => ['expired &amp; purged', 'dead'],
        ]
        : [
            'pending'   => ['awaiting customer', 'pending'],
            'submitted' => ['ready to read', 'ready'],
            'read'      => ['read &amp; destroyed', 'done'],
            'expired'   => ['expired &amp; purged', 'dead'],
        ];
    [$label, $cls] = $map[$status] ?? [h($status), 'dead'];
    return '<span class="pill ' . $cls . '">' . $label . '</span>';
}

function copy_button(string $targetId): string {
    return '<button type="button" class="copy-btn" data-copy="#' . h($targetId) . '" aria-label="Copy" title="Copy">'
         . '<svg class="copy-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
         . '<rect x="9" y="9" width="13" height="13" rx="2"></rect>'
         . '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>'
         . '</svg>'
         . '<svg class="copy-ok" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
         . '<path d="M20 6L9 17l-5-5"></path>'
         . '</svg>'
         . '</button>';
}

/**
 * Reveal control for a password input. The customer is transcribing a credential
 * they created moments ago on another site, and a typo is only discoverable here --
 * once submitted the value is encrypted and nobody can read it back to them.
 */
function password_toggle_button(): string {
    return '<button type="button" class="password-toggle" aria-label="Show password" aria-pressed="false">'
         . '<svg class="password-eye" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
         . '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"></path>'
         . '<circle cx="12" cy="12" r="3"></circle>'
         . '</svg>'
         . '<svg class="password-eye-off" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
         . '<path d="m3 3 18 18"></path>'
         . '<path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"></path>'
         . '<path d="M9.9 4.2A10.6 10.6 0 0 1 12 4c6.5 0 10 8 10 8a18.4 18.4 0 0 1-3.1 4.3M6.6 6.6C3.7 8.6 2 12 2 12s3.5 8 10 8c1.5 0 2.9-.4 4.1-1"></path>'
         . '</svg>'
         . '</button>';
}

function icon_expire_svg(): string {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
         . '<circle cx="12" cy="12" r="9"></circle>'
         . '<path d="M12 7v5l3 2"></path>'
         . '</svg>';
}

function icon_delete_svg(): string {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
         . '<path d="M3 6h18"></path>'
         . '<path d="M8 6V4h8v2"></path>'
         . '<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path>'
         . '<path d="M10 11v6"></path>'
         . '<path d="M14 11v6"></path>'
         . '</svg>';
}

function copyable_link(string $url): string {
    static $n = 0;
    $n++;
    $id = 'cust-link-' . $n;
    return '<div class="linkrow">'
         . '<input id="' . $id . '" class="copyable" readonly value="' . h($url) . '" aria-label="Single-use customer link">'
         . copy_button($id)
         . '</div>';
}

function posted_value(string $name): string {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') return '';
    return h(trim((string)($_POST[$name] ?? '')));
}

function option_selected(string $name, string $value, string $default = ''): string {
    $cur = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
        ? (string)($_POST[$name] ?? '')
        : $default;
    return $cur === $value ? ' selected' : '';
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
    $out = '<div class="cred">';
    $n = 0;
    foreach ($data as $label => $value) {
        if (trim((string)$value) === '') continue;
        $n++;
        $id = 'cred-field-' . $n;
        $out .= '<div class="cred-row"><div class="cred-k">' . h((string)$label) . '</div>'
             . '<div class="linkrow">'
             . '<pre id="' . $id . '" class="verbatim cred-v">' . h((string)$value) . '</pre>'
             . copy_button($id)
             . '</div></div>';
    }
    return $out . '</div>';
}

function need_short(string $need): string {
    return match ($need) {
        'wp_admin'        => 'WP admin',
        'wp_app_password' => 'App password',
        'ssh'             => 'SSH / SFTP',
        'message'         => 'Secure message',
        default           => $need,
    };
}
