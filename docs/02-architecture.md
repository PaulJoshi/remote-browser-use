# 02 — Architecture

```
 Cloud chat ──HTTPS──► public VS Code port / tunnel ──► 127.0.0.1:8931
                                                        │
                          public HTTP listener: /mcp + OAuth/discovery ONLY
                                       │ verified identity and scopes
                                       ▼
                     policy/ (client, tool, tab, origin, approval)
                              │                         │
                        tools/ (MCP)               audit/ (metadata only)
                              │
                    browser/ (granted page manager)
                              │
                 Playwright ──► dedicated Chromium profile

 Local human ──► 127.0.0.1:8932 (separate, never forwarded)
                      admin/ (owner session, tab picker, approvals,
                              revocation, public URL setup, kill switch)
```

## Components

- **cli/** — executable `bin`, flags/config precedence, first-run Chromium acquisition and local setup, progress/error output, signals and graceful shutdown. Keep data in a user-only local directory, never in `node_modules`.
- **server/** — official MCP SDK server and Streamable HTTP handler on `127.0.0.1:8931`; separately route OAuth metadata and authorization endpoints. Enforce protocol-version compatibility, body/output limits, timeouts, Host/Origin checks, and rate limits. There must be no admin route on this listener.
- **auth/** — single-owner OAuth authorization server and resource-token validation. Correct public URL and issuer/resource metadata are mandatory for remote connector setup; support the newest available spec and verified legacy client behavior. Grant `browser:read`, `browser:navigate`, `browser:interact`, and `browser:manage` independently, rather than exposing all tools to every client.
- **admin/** — *new component*: separate `127.0.0.1:8932` listener and local owner session, CSRF defense, public URL configuration, tool/origin/tab picker, per-action approval queue, client revocation, and kill switch. The request's loopback peer address is not sufficient protection; a tunnel can connect from loopback.
- **policy/** — centralized `authorize(call, ctx)` checking valid token and audience, scopes ∩ enabled tools, client-specific tab grants, current top-level/frame origin and target destination, then sensitive-action approval. Re-evaluate immediately before effect and invalidate on revocation/navigation.
- **browser/** — one Playwright-managed persistent Chromium profile, stable per-session tab IDs, grant-aware browser/page/frame adapters, tracked dialogs and downloads, and a ref map invalidated on navigation, frame detach, or new snapshot. Pages created by clicks/popups are ungranted until approved. Never connect to existing Chrome or expose the underlying browser to remote code.
- **tools/** — short, accurately described MCP tools with input validation and bounded, compact outputs. Tools only call browser operations after policy authorization.
- **audit/** — append-only structured metadata about tool decisions, duration, and failures; never page content, screenshots, raw arguments/results, typed text, full URLs, or token values.

## Element targeting

`readPage` returns a bounded, frame-aware accessibility-oriented snapshot and readable text with short refs such as `e12`. Action tools accept a `ref` (preferred) or a validated selector/role-and-text target. A ref stores the granted tab, frame identity, document/snapshot version, and locator identity; never resolve it against a different page or frame. Ref invalidation gives an actionable "call readPage again" error.

## Output size

Snapshots and text are truncated with continuation cursors tied to tab/document/snapshot state. Screenshots are image content downscaled to a maximum size; none of these outputs are written to audit logs. Cross-origin frames are processed only with a separate origin grant. A browser indicator should identify when remote control is active, with a local UI fallback for pages on which injecting a banner is unavailable.

## Forwarding and lifecycle

The forwarded port carries `/mcp`, OAuth discovery, and authorization endpoints only. The owner chooses the HTTPS base URL after forwarding; reject invalid/HTTP public URLs, apply it consistently as issuer and resource location, and fail closed until configured. Changing it invalidates stale auth state and requires clients to reconnect. The admin listener remains inaccessible through that forwarding. On process exit close both listeners and browser control cleanly, but leave the persisted profile intact.
