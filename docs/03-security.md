# 03 — Security

## Boundary and threat model

The forwarded port is a publicly reachable remote-control endpoint even when the underlying process is bound to `127.0.0.1`. A dedicated browser profile limits damage relative to the owner's everyday browser, **not** within the chosen websites: signed-in tabs in that profile can still hold sensitive information. Agents read untrusted page content and may be led by prompt injection. Tool allowlists, per-client tab grants, local approvals, origin restrictions, and a kill switch are defenses, not a guarantee against every unsafe agent decision.

| Threat | Required defense |
|---|---|
| Anyone discovers a Public forwarded URL | OAuth for every HTTP MCP request; rate limits; HTTPS tunnel; no secret-in-URL or `--no-auth` mode, even on loopback |
| OAuth client or token is compromised | Per-client scopes and grants, short-lived audience-bound tokens, rotated refresh tokens, owner revocation and immediate kill switch |
| Agent reaches an unshared tab, popup, or cross-origin iframe | Central policy enforced for every read and action; grant is per client/tab/origin; `listTabs` excludes ungranted tabs and cannot reveal their titles or URLs |
| Navigation crosses into an unapproved site | Check destination and redirect policies; deny local/private/file/internal URLs by default; pause/revoke grants on unexpected top-level or frame origins and block further reads/actions |
| A page attempts prompt injection or unsafe submission | Treat page output as untrusted; limit tool capabilities and domains; require local approval for high-impact or ambiguous effects |
| A browser page attacks a localhost service or a public tunnel proxies admin | Separate public MCP and local-only admin ports; validate Host/Origin; admin owner auth, CSRF tokens, and no admin routes on the public listener |
| Sensitive content leaks via logs | Log only structured metadata, never snapshots, screenshots, text input, raw arguments/results, tokens, URL query strings, or page titles |
| Raw execution bypasses policy | No `runPlaywrightCode`, arbitrary JavaScript, CDP, or browser-object passthrough exposed to MCP clients in v1 |

## Authorization and public URL

- The **HTTP MCP resource always requires OAuth**, even before a tunnel is configured. Local MCP testing must use proper auth; only a distinct optional stdio transport can rely on local process trust. Start HTTP protected but fail closed for remote client discovery until the HTTPS public URL is configured.
- Re-read the latest MCP auth and transport specifications during implementation. As of 2026-10-24 the latest MCP revision is 2026-07-28, whose Streamable HTTP shape differs from 2025-11-25. Serve tested older clients' revisions as needed rather than assuming cloud chats already implement the newest revision.
- Implement protected-resource metadata (RFC 9728), authorization server metadata, OAuth 2.1 authorization code + PKCE S256, resource indicators and audience validation, token refresh/revocation, and explicit owner-approved per-client scopes. Prefer Client ID Metadata Documents if supported by the client and support Dynamic Client Registration if needed for compatibility; strictly validate client metadata, redirect URIs, and OAuth return flow to prevent SSRF/open redirects.
- An owner sets the actual HTTPS base URL from the local admin panel after creating the forward or passes `--public-url` when known. Never infer trusted issuer/resource URLs from arbitrary `Host` or `X-Forwarded-*` request headers. Changing the public identity revokes or invalidates tokens and pending authorization requests; require clients to reconnect.
- A one-time setup code bootstraps owner access to the **local** admin panel — printed to the local terminal and carried only in the URL fragment of the panel the CLI opens (a fragment is never transmitted in HTTP requests or `Referer`), never to a publicly writable endpoint or a request URL. Subsequent owner sessions require durable local authentication; the OAuth consent request shows client identity, exact redirect URI, scopes, and currently approved tabs before it can be approved from the local panel. Failed or timed-out consent is denied.

## Policy and sensitive actions

**Default posture (owner decision):** new clients are auto-approved with all requested scopes, the whole dedicated browser is shared, and agent actions run without approval prompts. The panel's advanced security settings (and `--approve`) can restore strict mode: manual client approval, per-tab/origin/tool grants, and `sensitive`/`all` action approvals. A client the owner revokes is blocked and is never silently re-approved. Global domain restrictions still apply to grants and navigation; deny rules win. Deny privileged schemes, internal-network destinations, localhost destinations, and file URLs unless a specific safe local development workflow explicitly authorizes fixture origins.

The action-approval policy is configurable (`never`, `sensitive`, `all`; default `never`). In `sensitive` mode, local approval is required for password/OTP entry, form submission or ambiguous submit-like clicks, file downloads/uploads, first-time navigation to an origin, new tabs/popups, closing tabs, and any action the classifier cannot safely distinguish. For actions that may cause effects before a redirect is checked, intercept/hold or deny before triggering them; if safe classification/interception is not feasible, require approval instead of promising perfect prevention. Every approval is tied to the client, tab, action, and target and expires quickly. Changing grants while a call is pending must cancel or deny actions **not yet dispatched**. Already completed browser effects cannot be rolled back; revocation immediately prevents further reads and actions.

## Admin and browser isolation

The public listener at `127.0.0.1:8931` has only MCP and OAuth/discovery routes. The admin listener at `127.0.0.1:8932` requires an owner session, strict Origin and CSRF controls, and local setup; a loopback peer alone does not prove the caller is local because a tunnel may terminate on loopback. Bind both listeners to IPv4 loopback and reject rebinding Hosts. Document that the admin port must never be forwarded. Keep private keys, browser data, and metadata logs outside the npm package directory with owner-only filesystem permissions. Do not place agent-controlled pages in the admin origin or allow the agent to grant itself access.

## Required security tests

- Requests without valid OAuth, with wrong scopes/audience, expired or revoked tokens, or disabled tools fail before browser access; test both transport versions supported.
- A forwarded request cannot reach admin paths; Host/Origin/CSRF and localhost rebinding tests fail closed.
- Agents cannot list, read, screenshot, select, interact with, or close tabs not granted to their specific client, including popups and tabs after reuse/navigation.
- A cross-origin frame, new origin, restricted scheme, redirect, local/private network destination, or stale element ref never bypasses policy.
- Password/OTP typing, form submission, upload/download, close/open tab, and ambiguous clicks require valid human approval; expiry or revocation before dispatch denies the action, and revocation afterward prevents subsequent reads and actions.
- Audit files contain no page content, typed values, screenshot bytes, raw arguments/results, URLs with queries, tokens, or secret setup codes.
