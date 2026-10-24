# 06 — Publishing `remote-browser-use` to npm

These are release instructions for the **future working package**, not a claim that this repository is ready to publish. This folder currently has no Git repository, `package.json`, executable, tests, or built distribution. Publishing is an irreversible public action: **an agent must obtain specific owner approval immediately before each real publish**, and the owner may prefer to execute the command personally. Never publish the specification-only repository.

## Prerequisites and name

1. Recheck `https://registry.npmjs.org/remote-browser-use` and `npm view remote-browser-use` immediately before creating a release. It returned 404 on 2026-10-24, which does not reserve it. Do not substitute another name without asking the owner.
2. The owner chooses a license and source-repository visibility/URL; record the real matching `repository` and `license` in `package.json` and README. An unscoped npm package is public even if its source is private; **npm build provenance requires a public source repository**. Do not invent a GitHub repository or license.
3. The owner creates/controls the npm account and package name, with two-factor authentication enabled; authentication, tokens, repository creation, and billing (if any) are owner-controlled steps. Never store npm credentials in the repository or logs.
4. Complete all roadmap release gates, including at least one real remote chat connector, MCP Inspector, Chromium first-run install, fixture training E2E, negative security tests, and a clean-install check on macOS plus another claimed OS.

## Package and clean-install checks

- Add a real `bin` entry for `remote-browser-use`, correct executable/shebang and executable permissions, `engines` for supported Node versions, `type: module`, a deterministic build, and a narrow `files` allowlist. Ship compiled code, README, license, and essential static assets only; Chromium is acquired on first run, not bundled into the npm tarball.
- Exclude local profile data, audit logs, owner keys, `.env`, test screenshots, CI artifacts, secrets, and `.devin/config.local.json`. Check `.gitignore` **and** the package `files` list; `.gitignore` alone is not a release security policy.
- Run package-specific lint, typecheck, build, tests, and end-to-end checks. Examine the full `npm pack --dry-run --json` file list and `npm publish --dry-run` output for size, contents, executable entry, and secrets. Also install the packed tarball in a fresh temporary project and exercise the CLI and first-run Chromium install; a local workspace can hide missing runtime files/dependencies.
- Re-run a security/privacy review of the forwarded HTTP listener: OAuth on every MCP call, no public admin route, correct HTTPS discovery URLs, tab grant enforcement, metadata-only audit, and no default Chrome profile access.

## First public release

The owner confirms package name, version, license, actual npm identity, public/private repository choice, release notes, and the inspected tarball. Ask for explicit approval **before** calling any `npm publish` command. If the name is free and all checks pass, an authenticated owner can publish the initial unscoped public package with `npm publish --access public`, following npm's then-current 2FA/login requirements. Record the version and verify `npm view remote-browser-use version`, the published file list, and a fresh `npx remote-browser-use@<version> --version` and browser-start smoke test. Never run this publish command merely because it appears in a prompt.

## Repeatable releases with provenance

For later CI releases, prefer npm **trusted publishing** rather than a long-lived npm token. After the package and real public source repository exist, configure the matching repository and workflow in npm package settings. Use a supported cloud-hosted CI runner, least-privilege release workflow with `id-token: write`, verification gates before publish, and protected release approval. As of 2026-10-24, npm trusted publishing requires **Node >=22.14.0 and npm CLI >=11.5.1**; recheck its documentation when implementing. Configure provenance according to the current npm guidance and verify it on the published package. Do not claim provenance for a local manual release or weaken security settings to force a failing release.

Before each later publish, review all changes since the preceding release, update version/changelog, inspect the tarball, confirm CI tests and client smoke tests, and request owner authorization for the **specific** release. Publish immutable versions; never force-overwrite or republish a released version. Document rollback using a new fixed version or dist-tag adjustment only with separate approval.

## References

- npm: https://docs.npmjs.com/creating-and-publishing-unscoped-public-packages/
- npm: https://docs.npmjs.com/trusted-publishers/
- npm: https://docs.npmjs.com/generating-provenance-statements/
