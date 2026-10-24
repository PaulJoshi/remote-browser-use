# remote-browser-use

Let an MCP-capable AI chat use **selected tabs of a separate, persistent Chromium browser** on your computer — behind OAuth, per-tab grants, and local approvals you control.

```sh
npx remote-browser-use
```

One command opens a dedicated browser (not your everyday Chrome profile), a local control panel, and an OAuth-protected MCP endpoint on `127.0.0.1`. You decide which tabs, origins, and tools a chat client can use; everything else stays invisible to it.

No browser extension, no ZIP install, no hosted relay, and no access to your existing Chrome profile.

## Why it exists

**KILL THE BUSYWORK.** This project was born from a very ordinary annoyance: mandatory training portals that make you click "Next" through twenty slides, answer the same quiz questions, drag pretend emails into a "phishing" folder, and wait for a certificate nobody reads. Not hard work — just an hour of mechanical clicking between you and a checkbox on someone's compliance spreadsheet.

remote-browser-use takes that whole annoying, repetitive job off your hands. Give an MCP-capable chat access to the dedicated browser and it *does* the work — navigates the gated slides, answers the quizzes, sorts the phish inbox, generates the certificate — instead of just telling you what to click. The bundled fictional course (`npx remote-browser-use demo`) demonstrates the complete workflow end to end, no external site required.

And training portals are just the demo. The same tools apply to the other click-farms in your life: expense submissions, HR onboarding forms, admin dashboards, status-page updates, CRM data entry. If it's a real workflow inside a browser tab, an agent can run it to completion while you watch — or walk away.

The security model exists *because* the workflow is real: the agent drives an isolated browser profile (your everyday logins are never touched), everything it does is visible live in a window you own, OAuth gates every connection, and the control panel can require per-tab sharing and per-action approval when real accounts are involved.

## How it works

1. **Run it.** `npx remote-browser-use` downloads a matching Chromium build on first use (requires network; can take a few minutes), launches it with an isolated persistent profile, and opens the control panel.
2. **Use the dedicated browser.** Sign in to sites normally, in that window. The agent never sees your default-profile tabs, cookies, or logins.
3. **Connect your chat.** By default the whole dedicated browser is shared with connected clients and actions run without prompts. Want tighter control? The panel's **advanced security settings** can require approval for new connections, explicit per-tab/site sharing, and per-action approvals.
4. **Forward only the MCP port.** Use VS Code's Ports view or another HTTPS tunnel to expose port `8931`. Set it to **Public** so a cloud chat can reach it. Public means *reachable* — OAuth is still mandatory. **Never forward port `8932`** (the control panel).
5. **Authorize the chat.** Paste the forwarded `https://…` base URL into the control panel (or pass `--public-url`), then add the displayed `/mcp` URL as a custom MCP connector. OAuth approval happens automatically by default; enable manual approval in advanced settings to review each client first.

Stopping the CLI ends all remote access; the browser profile is kept so your logins survive restarts.

## Try it without a real account

```sh
npx remote-browser-use demo
```

Launches a bundled fictional security-awareness course (gated slides, quizzes, a spot-the-phish inbox, a cross-origin player frame, and a simulated certificate) so you can watch an agent complete a real multi-step browsing task through the grants and approvals flow — no external site or login needed.

## Security model

- **OAuth on every MCP request**, including loopback, because a local port may later be forwarded. Authorization code + PKCE (S256), resource indicators/audience binding, client discovery via CIMD and Dynamic Client Registration, short-lived tokens, refresh rotation, revocation, and explicit owner consent.
- **Two listeners, two jobs.** MCP + OAuth on one port (default `8931`); owner panel, tab sharing, approvals, and kill switch on a separate local-only port (default `8932`). No admin route exists on the MCP listener.
- **Grants and isolation.** Connected clients can be limited to specific tabs, origins, and tools (off by default — enable in advanced settings). Policy is re-evaluated on every read and action, and domain allow/deny rules always apply.
- **Optional action approvals.** With `sensitive` or `all` enabled in advanced settings, password/OTP entry, form submission, first-time origins, opening/closing tabs, and uploads/downloads wait for a local human. Default is automatic approval — every action is still audited.
- **Privacy by construction.** Typed values are never echoed, password/OTP values never appear in snapshots, screenshots mask pixels from ungranted frames, and the audit log records metadata only — never page content, URLs with query strings, typed text, or secrets.
- **Honest limits.** Revoking access blocks future reads and actions; it cannot undo browser effects that already completed.

Full details: [docs/03-security.md](docs/03-security.md).

## Requirements

- Node.js **22.12+** (LTS), macOS or Linux desktop, ~300 MB disk for the Chromium build. Windows is expected to work but is not yet verified on a real device.
- A way to forward a local port over HTTPS for cloud chats (VS Code port forwarding, devtunnel, cloudflared, etc.).
- An MCP-capable chat client that supports remote MCP servers with OAuth.

## CLI

```text
remote-browser-use [--port 8931] [--admin-port 8932] [--public-url <https-url>]
                   [--tools <list>] [--allow-domains <list>] [--deny-domains <list>]
                   [--approve sensitive|all] [--config <path>]
remote-browser-use demo      # bundled fictional training course
remote-browser-use --help    # full option reference
```

## Status

Working implementation, verified on macOS with MCP Inspector and local end-to-end tests; Windows support is implemented but not yet verified. Not yet published to npm — see [docs/06-publishing.md](docs/06-publishing.md). Known limitations and verified-client matrix live in [docs/open-questions.md](docs/open-questions.md) and the release notes.

## Development

```sh
npm install        # use npm ≥ 11
npm run build      # TypeScript → dist/
npm run lint && npm run typecheck
npm test           # unit tests
npm run test:e2e   # browser-backed security + training-flow tests
npm run verify     # all of the above + npm pack content audit
```

Design contract: [docs/01-product.md](docs/01-product.md) → [docs/06-publishing.md](docs/06-publishing.md). Maintainer notes: [CLAUDE.md](CLAUDE.md).

## License

[Apache-2.0](LICENSE)
