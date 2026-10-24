import { request } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AdminClient, authorizeClient, startHarness, type Harness } from './harness.js';

function rawGet(port: number, path: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', headers }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode!, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

describe('local admin listener isolation and CSRF defenses', () => {
  let h: Harness;
  let adminBase: string;
  let adminPort: number;
  beforeAll(async () => {
    h = await startHarness();
    adminPort = h.app.config.adminPort;
    adminBase = `http://127.0.0.1:${adminPort}`;
  });
  afterAll(async () => h?.stop());

  it('is a different port from MCP, and no admin route exists on the forwarded MCP port', async () => {
    expect(adminPort).not.toBe(h.app.config.port);
    for (const path of ['/', '/api/state', '/api/session', '/api/kill', '/panel.js', '/admin']) {
      const res = await fetch(`${h.base}${path}`);
      expect(await res.text(), path).not.toMatch(/control panel|csrf|"tabs"/i);
      if (path !== '/') expect(res.status, path).toBe(404);
    }
  });

  it('rejects rebinding/tunnel Host headers and serves the panel only with strict CSP', async () => {
    expect((await rawGet(adminPort, '/', { Host: 'evil.example' })).status).toBe(421);
    expect((await rawGet(adminPort, '/', { Host: `attacker.example:${adminPort}` })).status).toBe(421);
    expect((await rawGet(adminPort, '/api/session', { Host: 'abc-8932.devtunnels.ms' })).status).toBe(421);
    const ok = await fetch(`${adminBase}/`);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('content-security-policy')).toContain("script-src 'self'");
    expect(ok.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(ok.headers.get('x-frame-options')).toBe('DENY');
  });

  it('a loopback peer is not enough: every API call needs the owner cookie', async () => {
    expect((await fetch(`${adminBase}/api/state`)).status).toBe(401);
    expect(await (await fetch(`${adminBase}/api/session`)).json()).toEqual({ authenticated: false });
    const kill = await fetch(`${adminBase}/api/kill`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: adminBase }, body: '{}' });
    expect(kill.status).toBe(401);
  });

  it('requires same-origin Origin, Sec-Fetch-Site and a CSRF token on state changes', async () => {
    const { cookie, csrf } = h.admin;
    const post = (headers: Record<string, string>) =>
      fetch(`${adminBase}/api/public-url`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, ...headers }, body: JSON.stringify({ url: 'not a url' }) });
    expect((await post({ 'X-CSRF-Token': csrf })).status).toBe(403); // no Origin
    expect((await post({ Origin: 'https://evil.example', 'X-CSRF-Token': csrf })).status).toBe(403);
    expect((await post({ Origin: 'http://localhost:1', 'X-CSRF-Token': csrf })).status).toBe(403);
    expect((await post({ Origin: adminBase })).status).toBe(403); // no CSRF token
    expect((await post({ Origin: adminBase, 'X-CSRF-Token': 'forged' })).status).toBe(403);
    expect((await post({ Origin: adminBase, 'X-CSRF-Token': csrf, 'Sec-Fetch-Site': 'cross-site' })).status).toBe(403);
    // Passing all checks reaches the handler (which then rejects the invalid URL).
    const passed = await post({ Origin: adminBase, 'X-CSRF-Token': csrf, 'Sec-Fetch-Site': 'same-origin' });
    expect(passed.status).toBe(400);
    expect(await passed.text()).toMatch(/not a valid URL/);
    const form = await fetch(`${adminBase}/api/kill`, { method: 'POST', headers: { 'Content-Type': 'text/plain', Origin: adminBase, Cookie: cookie, 'X-CSRF-Token': csrf }, body: '{}' });
    expect(form.status).toBe(415);
  });

  it('setup codes are single-use and login attempts are rate-limited', async () => {
    const used = new AdminClient(adminBase);
    await expect(used.login('AAAA-BBBB-CCCC')).rejects.toThrow(/403/);
    const fresh = new AdminClient(adminBase);
    await fresh.login(h.app.setupCode);
    const code = h.app.setupCode;
    await fresh.post('/api/logout', {});
    const again = new AdminClient(adminBase);
    await again.login(code);
    await expect(new AdminClient(adminBase).login(code)).rejects.toThrow(/403/);
    let limited = false;
    for (let i = 0; i < 8; i++) {
      const res = await fetch(`${adminBase}/api/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: adminBase }, body: JSON.stringify({ code: 'WRONG-CODE-1234' }) });
      if ((await res.text()).includes('Too many attempts')) limited = true;
    }
    expect(limited).toBe(true);
  });

  it('the control panel cannot be opened in the agent browser', async () => {
    const res = await h.admin.post('/api/tab', { action: 'open', url: `http://localhost:${adminPort}/` });
    expect(res.status).toBe(400);
    expect(String(res.json.error)).toMatch(/cannot be opened/);
  });

  it('changing the public URL in the panel disconnects existing clients', async () => {
    const oauth = await authorizeClient(h, { name: 'Before change' });
    const ok = await fetch(`${h.base}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${oauth.accessToken}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } }) });
    expect(ok.status).toBe(200);
    await h.admin.ok('/api/public-url', { url: 'https://changed-tunnel.example' });
    const after = await rawGet(h.app.config.port, '/.well-known/oauth-protected-resource/mcp', { Host: 'changed-tunnel.example' });
    expect(JSON.parse(after.body).resource).toBe('https://changed-tunnel.example/mcp');
    const denied = await fetch(`${h.base}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${oauth.accessToken}` }, body: '{}' });
    expect(denied.status).toBe(401);
    const st = await h.admin.state();
    expect(st.clients).toEqual([]);
  });
});
