# remote-browser-use

Let an MCP-capable AI chat use **selected tabs of a separate, persistent Chromium browser** on your computer — behind OAuth, per-tab grants, and local approvals you control.

```sh
npx remote-browser-use
```

One command opens a dedicated browser (not your everyday Chrome profile), a local control panel, and an OAuth-protected MCP endpoint on `127.0.0.1`. You decide which tabs, origins, and tools a chat client can use; everything else stays invisible to it.

No browser extension, no ZIP install, no hosted relay, and no access to your existing Chrome profile.

## How it works

1. **Run it.** `npx remote-browser-use` downloads a matching Chromium build on first use (requires network; can take a few minutes), launches it with an isolated persistent profile, and opens the control panel.
2. **Use the dedicated browser.** Sign in to sites normally, in that window. The agent never sees your default-profile tabs, cookies, or logins.
3. **Share deliberately.** In the local control panel you grant a chat client specific tabs, allowed origins, and tool capabilities — default is nothing shared.
4. **Forward only the MCP port.** Use VS Code's Ports view or another HTTPS tunnel to expose port `8931`. Set it to **Public** so a cloud chat can reach it. Public means *reachable* — OAuth is still mandatory. **Never forward port `8932`** (the control panel).
5. **Connect your chat.** Paste the forwarded `https://…` base URL into the control panel (or pass `--public-url`), then add the displayed `/mcp` URL as a custom MCP connector and approve the OAuth request in the panel.

Stopping the CLI ends all remote access; the browser profile is kept so your logins survive restarts.

## Try it without a real account

```sh
npx remote-browser-use demo
```

Launches a bundled fictional security-awareness course (gated slides, quizzes, a spot-the-phish inbox, a cross-origin player frame, and a simulated certificate) so you can watch an agent complete a real multi-step browsing task through the grants and approvals flow — no external site or login needed.

## Security model

- **OAuth on every MCP request**, including loopback, because a local port may later be forwarded. Authorization code + PKCE (S256), resource indicators/audience binding, client discovery via CIMD and Dynamic Client Registration, short-lived tokens, refresh rotation, revocation, and explicit owner consent.
- **Two listeners, two jobs.** MCP + OAuth on one port (default `8931`); owner panel, tab sharing, approvals, and kill switch on a separate local-only port (default `8932`). No admin route exists on the MCP listener.
- **Grants, not trust.** Per-client tab/origin/tool grants; new tabs, popups, redirects, and cross-origin frames are never automatically shared. Policy is re-evaluated on every read and action.
- **Sensitive actions need approval.** Password/OTP entry, form submission, first-time origins, opening/closing tabs, uploads/downloads — a local human approves each one. Timeouts deny.
- **Privacy by construction.** Typed values are never echoed, password/OTP values never appear in snapshots, screenshots mask pixels from ungranted frames, and the audit log records metadata only — never page content, URLs with query strings, typed text, or secrets.
- **Honest limits.** Revoking access blocks future reads and actions; it cannot undo browser effects that already completed.

Full details: [docs/03-security.md](docs/03-security.md).

## Requirements

- Node.js **22.12+** (LTS), macOS or Linux desktop, ~300 MB disk for the Chromium build.
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

Working implementation, verified on macOS with MCP Inspector and local end-to-end tests. Not yet published to npm — see [docs/06-publishing.md](docs/06-publishing.md). Known limitations and verified-client matrix live in [docs/open-questions.md](docs/open-questions.md) and the release notes.

## Development

```sh
npm install        # use npm ≥ 11
npm run build      # TypeScript → dist/
npm run lint && npm run typecheck
npm test           # unit tests
npm run test:e2e   # browser-backed security + training-flow tests
```

Design contract: [docs/01-product.md](docs/01-product.md) → [docs/06-publishing.md](docs/06-publishing.md). Maintainer notes: [CLAUDE.md](CLAUDE.md).

## License

[Apache-2.0](LICENSE)
