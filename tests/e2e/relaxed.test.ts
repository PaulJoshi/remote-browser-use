import { describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../../src/util/crypto.js';
import { call, mcpClient, startHarness, type Harness } from './harness.js';

/** The OAuth dance for relaxed mode: /authorize redirects straight back with a code. */
async function authorizeAuto(h: Harness) {
  const prm = (await (await fetch(`${h.base}/.well-known/oauth-protected-resource/mcp`)).json()) as { resource: string; authorization_servers: string[] };
  const asm = (await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json()) as Record<string, string>;
  const redirectUri = 'http://127.0.0.1:9/callback';
  const reg = await fetch(asm.registration_endpoint!, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Relaxed client', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' }),
  });
  const { client_id: clientId } = (await reg.json()) as { client_id: string };
  const verifier = randomToken(48);
  const auth = new URL(asm.authorization_endpoint!);
  auth.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource: prm.resource,
    scope: 'browser:read browser:navigate browser:interact browser:manage',
  }).toString();
  const res = await fetch(auth, { redirect: 'manual' });
  expect(res.status).toBe(302);
  const code = new URL(res.headers.get('location')!).searchParams.get('code');
  expect(code).toBeTruthy();
  const tokens = (await (
    await fetch(asm.token_endpoint!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: code!, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier, resource: prm.resource }),
    })
  ).json()) as { access_token: string };
  expect(tokens.access_token).toBeTruthy();
  return { clientId, accessToken: tokens.access_token };
}

describe('relaxed defaults (advanced settings off)', () => {
  it('auto-approves the client and exposes the whole browser without prompts', async () => {
    const h = await startHarness({ relaxed: true });
    try {
      await h.app.browser.openTab(`${h.fixtures.courseOrigin}/`);
      const { accessToken } = await authorizeAuto(h);
      const client = await mcpClient(h, accessToken);

      // All scopes/tools granted without an owner approval step.
      const tabs = await call(client, 'listTabs');
      expect(tabs.isError).toBe(false);
      expect(tabs.text).toContain('tab-');

      // The fixture course tab is readable without any per-tab grant.
      const read = await call(client, 'readPage', { format: 'text' });
      expect(read.isError).toBe(false);
      expect(read.text).toContain('Northwind');

      // Navigating to a new origin needs no owner approval or grant.
      const nav = await call(client, 'navigatePage', { url: `${h.fixtures.courseOrigin}/quiz.html`, waitUntil: 'load' });
      expect(nav.isError).toBe(false);

      // No approvals ever showed up in the panel.
      const state = await h.admin.state();
      expect(state.approvals).toHaveLength(0);
      expect(state.pendingAuthorizations).toHaveLength(0);
    } finally {
      await h.stop();
    }
  });

  it('strict settings can be re-enabled through /api/settings', async () => {
    const h = await startHarness({ relaxed: true });
    try {
      const r = await h.admin.ok('/api/settings', { autoApproveClients: false, shareEntireBrowser: false, actionApprovals: 'sensitive' });
      expect(r.settings).toMatchObject({ autoApproveClients: false, shareEntireBrowser: false, actionApprovals: 'sensitive' });
      const state = await h.admin.state();
      expect(state.settings.shareEntireBrowser).toBe(false);
    } finally {
      await h.stop();
    }
  });
});
