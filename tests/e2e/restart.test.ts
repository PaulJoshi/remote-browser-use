import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { startFixtureServers, type FixtureServers } from '../../src/demo/fixtureServer.js';
import { AdminClient, authorizeClient, call, freePort, mcpClient, refFor, startHarness } from './harness.js';

describe('browser profile, owner session and OAuth state survive a restart', () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'rbu-restart-'));
  let fixtures: FixtureServers;
  afterAll(async () => {
    await fixtures?.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('keeps site storage, the owner device cookie and refresh tokens; tab grants are per session', async () => {
    fixtures = await startFixtureServers();
    const port = await freePort();
    const adminPort = await freePort();
    const config = { port, adminPort };
    const publicUrl = `http://127.0.0.1:${port}`;

    // --- first run
    const h1 = await startHarness({ dataDir, fixtures, config, publicUrl });
    await h1.app.browser.openTab(`${fixtures.courseOrigin}/slide-1.html`);
    const oauth = await authorizeClient(h1, { name: 'Persistent client' });
    const c1 = await mcpClient(h1, oauth.accessToken);
    const tab1 = await h1.admin.tabIdFor(`${fixtures.courseOrigin}/slide-1.html`);
    await h1.admin.ok('/api/grant', { action: 'share', clientId: oauth.clientId, tabId: tab1 });
    let s = (await call(c1, 'readPage', {})).text;
    await call(c1, 'clickElement', { ref: refFor(s, /checkbox "I have read this slide"/) });
    s = (await call(c1, 'readPage', {})).text;
    await call(c1, 'clickElement', { ref: refFor(s, /button "Next slide"/) });
    const cookie = h1.admin.cookie;
    await c1.close();
    await h1.stop({ keepData: true });

    const mode = (p: string) => statSync(p).mode & 0o777;
    if (process.platform !== 'win32') {
      expect(mode(dataDir)).toBe(0o700);
      expect(mode(join(dataDir, 'profile'))).toBe(0o700);
      expect(mode(join(dataDir, 'state.json'))).toBe(0o600);
      expect(mode(join(dataDir, 'audit.log'))).toBe(0o600);
    }
    expect(existsSync(join(dataDir, 'profile', 'Default'))).toBe(true);

    // --- second run with the same profile
    const h2 = await startHarness({ dataDir, fixtures, config, publicUrl });
    try {
      // The owner's device cookie still works without a new setup code.
      const owner = new AdminClient(`http://127.0.0.1:${adminPort}`);
      owner.cookie = cookie;
      const session = (await (await fetch(`${owner.base}/api/session`, { headers: { Cookie: cookie } })).json()) as { authenticated: boolean };
      expect(session.authenticated).toBe(true);
      // The refresh token from the first run still works (same public URL), and rotates.
      const res = await fetch(`${h2.base}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: oauth.refreshToken, client_id: oauth.clientId }),
      });
      const tokens = (await res.json()) as { access_token: string };
      expect(res.status).toBe(200);
      const c2 = await mcpClient(h2, tokens.access_token);
      // Grants do not survive a restart.
      expect((await call(c2, 'listTabs')).text).toMatch(/No tabs are shared/);
      await h2.app.browser.openTab(`${fixtures.courseOrigin}/`);
      const tab = await h2.admin.tabIdFor(`${fixtures.courseOrigin}/`);
      await h2.admin.ok('/api/grant', { action: 'share', clientId: oauth.clientId, tabId: tab });
      const home = await call(c2, 'readPage', { mode: 'text', tabId: tab });
      // localStorage progress from the first run is still in the persistent profile.
      expect(home.text).toContain('Slide 1: done');
      expect(home.text).toContain('Slide 2: not done');
      await c2.close();
    } finally {
      await h2.stop({ keepData: true });
    }
  });
});
