# Open Questions for Paul

## Decided

- Unscoped npm name: **`remote-browser-use`**. npm returned 404 on 2026-10-24, but that is not a reservation.
- V1 browser: a separately launched, persistent Playwright Chromium; **no extension or ZIP**, default-profile CDP attach, hosted relay, or automatic access to the user's everyday browser.
- First-class remote path: public HTTPS port forwarding, with VS Code instructions. `npx` only launches local software; the chat and forwarding still require setup.
- Public HTTP MCP always uses OAuth; admin is on a distinct non-forwarded local port. Tools and tab grants are denied by default. Approval mode defaults to `sensitive`, and `runPlaywrightCode` is deferred.
- The tool is spelled `typeInPage`. A bundled fictional, no-login training fixture is the reliable demo/test target.

## Owner decisions required before publication

1. What license should the publicly installed package use, and will its source live in a public Git repository? npm provenance requires a matching public repository URL. This folder currently is **not** a Git repository; do not fabricate its URL or license.
2. Which npm account owns the unscoped name, and what repository/CI workflow will publish it? The owner must approve the first actual `npm publish`; do not publish a specification-only package.
3. Which real web chat accounts are available for end-to-end testing? Prioritize Claude custom connectors and MCP Inspector. ChatGPT support must be tested on an account/plan with custom remote MCP enabled before claiming it works.
4. Which desktop OSes are required for the first release? A clean macOS test is mandatory; test at least one other desktop OS before claiming cross-platform support.

## Implementation choices to validate with prototypes

5. Which persistent local owner-login method follows one-time terminal-code setup? It must not rely on a localhost peer IP alone or expose a reusable public owner credential.
6. Does the chosen Playwright capture strategy safely exclude disallowed cross-origin iframe pixels from screenshots? If not, deny affected screenshots and document the limitation.
7. Can sensitive-effect detection safely identify submit-like clicks and downloads before they occur? If not, prompt locally for ambiguous actions rather than silently allowing them.
