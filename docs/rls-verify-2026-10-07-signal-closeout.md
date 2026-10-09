# Fresh RLS fixed-table verification

Collected 2026-10-07T18:12:42.222Z using scripts/rls-verify.mjs on proxmox-worker with Keychain-injected access.

109 fixed tables: **109 pass, 0 fail**. Every target had at least one anon-role key probe. All 109 server HEAD paths returned HTTP 200/206. Anonymous responses were denied or zero-count under RLS; server metadata establishes the collection path remains available. No GTS row data was returned.

Raw evidence: [JSON](rls-verify-2026-10-07-signal-closeout.json). This proves anonymous table lockout, not every application workflow or RPC.
