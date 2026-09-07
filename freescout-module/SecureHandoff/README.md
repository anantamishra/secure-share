# InstaWP secure credential handoff — FreeScout module

Drop-in module. Agents mint a customer link from the conversation sidebar.
Credentials are **never** shown in FreeScout. Reading a submitted secret still
happens in the handoff app (once, then destroyed).

## Install

1. Copy this folder to FreeScout:

       cp -R SecureHandoff /path/to/freescout/Modules/SecureHandoff

2. In FreeScout: **Manage → Modules → Activate** “Secure Handoff”.
   If the sidebar CSS/JS is missing after activate, run:

       php artisan freescout:clear-cache
       php artisan freescout:module-install SecureHandoff

3. On the **handoff** host, mint a staff API token:

       php bin/staff.php token you@instawp.com

4. In FreeScout: **Settings → Secure Handoff**
   - Handoff URL = `APP_URL` (no `/api` suffix)
   - API token = the `iwp_…` value
   - Test connection

## Ticket id

The module sends FreeScout’s conversation **id** (the number in
`/conversation/123`), not the visible `#number`. That is what the handoff
app’s `FREESCOUT_API_*` write-back expects for `POST /api/conversations/{id}/threads`.

Optional, on the handoff host, so minting also posts an internal note:

    FREESCOUT_API_URL=https://help.example.com/api
    FREESCOUT_API_KEY=…
    FREESCOUT_USER_ID=1

`FREESCOUT_API_URL` already includes `/api`. Do not append another `/api`.

## What it does not do

- It does not reveal credentials in the ticket. That would put them in
  FreeScout’s database, the mail store, and notification copies — the
  thing this tool exists to stop.
- It does not bypass the Tier-1 gate. Failed product path and bug
  reference are required in the sidebar, same as the web UI.
