# 01 — Product

## What users get

`remote-browser-use` is a **free, public unscoped npm package**, not a hosted browser service. It launches Playwright-managed Chromium with a persistent isolated profile on the user's computer and an MCP endpoint on a local port. The browser starts without access to everyday Chrome logins, tabs, extensions, or cookies. A user may log into a site in this dedicated browser; the package keeps that session between runs unless the user explicitly removes its profile.

The user grants individual tabs, origins, and capabilities in a local panel. Only granted tabs appear in the remote MCP tools. Access to a browser process is not a browser-enforced sandbox for each tab: the package's policy layer must enforce that contract. No Chrome extension, ZIP installation, existing-profile CDP attachment, cloud relay, or account with this product is required in v1.

## First-run journey

1. Install a supported Node.js LTS and run `npx remote-browser-use`. First run downloads the npm package and, if missing, the **Playwright-matched Chromium binary**; report size/progress/errors and never run the browser as the user's default Chrome profile.
2. The CLI creates a private `~/.remote-browser-use/` directory for config, owner keys, the dedicated browser profile, and metadata-only audit records. Start a protected MCP/OAuth server on `127.0.0.1:8931` and a **separate admin server** on `127.0.0.1:8932` (pick free ports or fail clearly on collision). Open the controlled browser and local admin panel, delivering the one-time local owner-setup code to the panel in the opened URL's fragment (fragments are never sent in HTTP requests) and also printing it for signing in from other browsers.
3. The user opens or signs into sites in the controlled browser. By default every connected client can use the whole dedicated browser; the panel's advanced settings can instead require explicit per-tab/origin/tool grants. The panel offers an explicit read-only preset and an explicit interactive preset for tool selection.
4. To connect a **web chat**, forward **only port 8931** over HTTPS. In VS Code, sign into port forwarding if prompted, change that forwarded port's visibility from its default **Private** to **Public**, and copy the public HTTPS base URL. Other HTTPS tunnels are acceptable if they preserve MCP/OAuth requests correctly. A public forwarded URL may change between runs.
5. Set that HTTPS base URL in the local panel (or start with `--public-url` when known in advance). Only advertise working OAuth metadata once a correct public URL is configured. Display the exact `/mcp` connector URL. Add it to the chat app and complete its OAuth flow; clients are auto-approved with all requested scopes unless the owner enables manual approval in advanced settings. OAuth must be required even when the HTTP service appears to be loopback-only.
6. Stop sharing a tab, revoke tokens, approve/deny sensitive actions, or kill all access from the local panel. Stopping the CLI shuts down browser control and HTTP listeners. No permanent service is installed automatically.

One `npx` command launches the **local** software. Public forwarding, chat connector setup, site login, and human authorization cannot be performed invisibly. If the public base URL changes, require reauthorization and connector update rather than silently keeping an invalid OAuth issuer. The local browser can be used without a tunnel, but remote connector authorization must fail closed until public URL metadata is valid.

## CLI/config contract

```
--port <n>                 MCP/OAuth port; default 8931
--admin-port <n>           local-only control-panel port; default 8932
--public-url <https-url>   exact externally reachable base URL for OAuth/MCP discovery
--tools <list>             maximum enabled tool allowlist; default none
--allow-domains <list>     additional domain restriction on local grants
--deny-domains <list>      prohibited domains (deny wins)
--approve never|sensitive|all   local approval policy; overrides the saved setting (default never)
--config <path>            explicit local configuration file
--help / --version
```

Both HTTP listeners bind only to `127.0.0.1`. Do not implement `--host 0.0.0.0`, `--no-auth`, `--browser attach`, `--cdp-url`, `--allow-code`, or `--headless` in v1. Config has the same safe fields as the CLI; flags override config. Reject unknown or invalid flags and unsafe public URLs. Documentation for resetting the browser profile must require deliberate confirmation because it deletes saved site sessions.

## Local control panel

The admin panel exists on the **second, non-forwarded port**, not at `/admin` on the forwarded listener. It has local owner authentication, an explicit setup and approval UI, client/token revocation, tab/tool/origin grants, a pending-requests queue, safe audit metadata, and an immediate kill switch. Connecting from a tunnel that terminates locally must not satisfy an admin authorization check. See `docs/03-security.md`.

## Demo

Bundle a fictional no-login security-awareness course in `tests/fixtures/` and optionally ship a demo launcher. Include gated slides, short training content, single- and multi-answer quizzes, a spot-the-phish inbox, a simulated certificate, and a cross-origin iframe representing an LMS/SCORM player. Host the frame on a different loopback origin in tests to exercise frame grants. The fixture, not a live third-party website, is the deterministic end-to-end test target. Optional real-world no-login examples: HookMinute and Jigsaw's Phishing Quiz; no claim that these sites are equivalent to a real training assignment.
