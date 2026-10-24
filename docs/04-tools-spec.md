# 04 — Tools Spec

All remote tools require OAuth and per-client tool permission. Every page tool accepts optional `tabId`, defaulting only to the client's selected **granted** tab; if none exists, return a compact error instructing the agent to request a tab grant. Return only granted tab/frame metadata. Outputs include a short state-change hint where safe, are size-limited, and never enter audit logs as raw payloads. Describe every tool clearly to the LLM and mark side-effecting tools as writes.

Target (`Target`): `{ ref }` | `{ selector }` | `{ text, role?, exact? }`, optionally qualified by an allowed `frameId`. Refs from `readPage` bind to tab, frame, and document version. Invalid or ambiguous targets return a specific error; never fall back to another tab or frame.

| Tool | Main input | Output | Scope / constraints |
|---|---|---|---|
| `requestTabAccess` | optional short `reason` | pending request ID or denial, never ungranted tab metadata | `browser:read`; local owner chooses a tab and origin; rate-limit and sanitize agent-supplied reason |
| `listTabs` | none | granted tab IDs, titles, approved URLs, active marker | `browser:read`; do not enumerate any other tab or frame |
| `selectTab` | `tabId` | selected ID | `browser:read`; must already be granted to this client |
| `closeTab` | `tabId` | closed ID | `browser:manage` + local approval; only granted tab |
| `openBrowserPage` | `url` | pending or approved new `tabId`; only reveal URL/title after grant | `browser:manage`; check target scheme/origin and get local approval before opening; new page remains ungranted until owner grants it |
| `navigatePage` | `action: goto\|back\|forward\|reload`, `url?`, `waitUntil?`, `tabId?` | approved URL/title/status | `browser:navigate`; check current and destination origins, redirects, and resulting frames |
| `readPage` | `mode: snapshot\|text\|both`, `frameId?`, `cursor?`, `maxChars?`, `tabId?` | bounded, frame-aware accessibility-oriented refs/text, next cursor | `browser:read`; exclude ungranted cross-origin frame contents and secret field values |
| `clickElement` | `Target`, `button?`, `clickCount?`, `modifiers?`, `tabId?` | ok, safe URL/dialog hint | `browser:interact`; approval for submit-like or ambiguous effects; popups ungranted |
| `hoverElement` | `Target`, `tabId?` | ok | `browser:interact`; re-check origin and target before effect |
| `dragElement` | `source: Target`, `target: Target`, `tabId?` | ok | `browser:interact`; both targets must be permitted, approve ambiguous effects |
| `typeInPage` | `Target?`, `text?`, `keys?`, `clear?`, `submit?`, `tabId?` | ok, no typed text echoed | `browser:interact`; approve secret fields and submissions; never log content |
| `handleDialog` | `accept: boolean`, `promptText?`, `tabId?` | type and safe outcome | `browser:interact`; captured pending dialog only; handle timeout/limitations, redact prompt text |
| `screenshotPage` | `fullPage?`, `target?: Target`, `maxWidth?`, `tabId?` | bounded image content | `browser:read`; deny or mask disallowed frames and restricted content rather than leaking pixels |

`readPage` cursors are tied to one document/snapshot and expire on navigation or grant change. Before returning URLs or page titles, apply tab/origin policy and omit unnecessary query/fragment data. If a feature cannot enforce the declared policy (especially cross-origin frame screenshots or navigation interception), fail closed with a documented limitation. A tab closing, losing its grant, or changing origin invalidates refs, cancels undispatched operations, and blocks subsequent reads/actions; already completed browser effects cannot be undone.

`runPlaywrightCode` is intentionally **not** available over MCP in v1; there is no remote arbitrary code evaluation, raw CDP command tool, or browser-wide tab enumeration.
