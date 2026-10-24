# remote-browser-use — project brief

## Product

`remote-browser-use` is an unscoped public npm package for controlling an **isolated, persistent browser launched by the package** from an MCP-capable AI chat. The user runs `npx remote-browser-use`, signs in to sites in that separate browser if needed, grants specific tabs and tools in a local control panel, forwards the MCP port over public HTTPS (for example with VS Code), and adds the forwarded `/mcp` URL as a connector. The package does not need a browser extension, hosted relay, or downloaded extension ZIP.

The package must **not** claim to read the user's existing Chrome tabs, cookies, or signed-in default profile. Playwright cannot safely automate that profile. Chrome 144+ can consent to a browser-wide debugging connection, but that is not a per-tab browser-enforced permission; attaching to existing Chrome and extension-based sharing are outside v1.

The repository now contains a working implementation (`src/`, `tests/`, `dist/` after build), but the package is **not yet published to npm**. Do not claim that `npx remote-browser-use` works from the registry until publication is verified. The working folder name is not part of the runtime contract.

## Actual user journey

1. Run `npx remote-browser-use` with a supported LTS Node.js release. On first run, the CLI obtains its matching Chromium binary, creates an isolated persistent profile and owner credentials, starts an OAuth-protected Streamable HTTP MCP endpoint bound to `127.0.0.1`, and opens the controlled browser plus a separate local-only control panel. Browser installation may take time and requires network access.
2. Sign in manually to any sites the agent should work with **in the controlled browser**. Grant only selected tabs, allowed origins, and tool capabilities through the local panel; all other tabs in this dedicated browser stay invisible to MCP clients.
3. Forward the MCP port through VS Code or another HTTPS tunnel. VS Code ports default to Private; a cloud chat cannot sign into VS Code's private forwarding gate, so set the forwarded port to Public. Public refers only to reachability: OAuth is still required, and the **admin port must never be forwarded**.
4. Enter the forwarded HTTPS base URL in the local panel (or pass `--public-url` for a known stable tunnel), copy its `/mcp` URL into the chat connector, and locally approve the OAuth client and requested scopes. A new forwarded URL requires reconnecting the connector; changes to issuer/resource identity invalidate old grants and tokens.
5. Stop sharing a tab, revoke a client, or kill the session at any time from the local panel. Stopping the CLI ends remote access. Later sessions require the CLI/tunnel to be running; no background service is installed without user approval.

One `npx` command starts the local software, **not** the public port forward, chat connector, or site login. Compatibility depends on each chat app's plan and remote MCP support. Prioritize Claude custom connectors and MCP Inspector; test ChatGPT where a suitable account is available.

## v1 tools

`requestTabAccess`, `listTabs`, `selectTab`, `closeTab`, `openBrowserPage`, `navigatePage`, `readPage`, `clickElement`, `hoverElement`, `dragElement`, `typeInPage`, `handleDialog`, `screenshotPage`. Every page tool uses only a granted `tabId` (or the selected granted tab). A newly opened tab, popup, or cross-origin frame is not automatically granted. Tool descriptions and bounded outputs are part of the product.

`runPlaywrightCode` is **not** a v1 tool. Running arbitrary code in the server is not safely constrained by passing only a `page` object; keep it deferred pending a separate security design. Do not expose raw Playwright, CDP, browser contexts, or browser-wide enumeration to remote clients.

## Non-negotiable security

- Require OAuth for **all HTTP MCP access**, including loopback, because a loopback service may later be forwarded publicly. No `--no-auth`, URL-secret authentication, or unauthenticated bind on `0.0.0.0`.
- Follow the current MCP authorization and Streamable HTTP specifications, and support the older protocol revisions actually used by tested clients. Implement protected-resource and authorization-server metadata, authorization code + PKCE, resource indicators/audience binding, client registration compatibility, refresh/revocation, and consent tied to local owner approval.
- Run the dedicated browser with its own user-data directory; never point Playwright at the ordinary Chrome profile. Tool allowlists, per-client tab grants, frame/origin policy, human approvals for sensitive actions, and an immediate revoke-all switch must apply from the first usable tool.
- The public MCP/OAuth listener and local-only admin listener use **different ports**. Validate host/origin as appropriate, reject local rebinding/CSRF, rate-limit authentication, and require an owner session and local approval for admin actions. Forwarding the MCP port must never expose `/admin`.
- Audit only metadata (tool, client, tab identifier, decision, duration); do not log page text, screenshots, raw tool inputs/outputs, typed values, URL query strings, or secrets. Treat web page text as untrusted.
- Provide a visible browser-control indicator and safe fallback where injection is impossible. Default to deny; approvals time out to deny. Protect password/OTP fields, form submissions, uploads/downloads, and first-time origins.

## Tech and workflow

- TypeScript ESM on a currently supported Node.js LTS (Node 22+ as of 2026-10-24; use a Node/npm combination supported by the chosen SDK and npm trusted publishing). Use the official MCP SDK, Playwright-managed Chromium, Vitest, and a local fake security-awareness course fixture with a cross-origin iframe.
- Read `docs/01-product.md` through `docs/05-roadmap.md`, `docs/06-publishing.md`, then `docs/open-questions.md` before coding. Build policy and auth with the first working tool, not after browser automation.
- Check package-name availability again before publishing. npm returned 404 for `remote-browser-use` on 2026-10-24, which is **not** a reservation. Source repository: github.com/PaulJoshi/remote-browser-use (public).
- Test on macOS and another desktop OS before making cross-platform claims. Test against MCP Inspector and at least one real cloud chat connector; report unavailable accounts/client limitations accurately.
- Publishing is a separate owner-approved action. Follow `docs/06-publishing.md`; do not publish a placeholder package, invent credentials or repository URLs, or include local profiles, secrets, audit logs, or fixture test artifacts in the npm tarball.
