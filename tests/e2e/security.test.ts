import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Client } from '@modelcontextprotocol/client';
import { PNG } from 'pngjs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authorizeClient, call, mcpClient, refFor, startHarness, type Harness, type OAuthResult } from './harness.js';

/** Count pixels close to the player's distinctive green (#00a86b). */
function greenPixels(base64: string): number {
  const png = PNG.sync.read(Buffer.from(base64, 'base64'));
  let n = 0;
  for (let i = 0; i < png.data.length; i += 4) {
    if (Math.abs(png.data[i]! - 0) < 30 && Math.abs(png.data[i + 1]! - 168) < 30 && Math.abs(png.data[i + 2]! - 107) < 30) n++;
  }
  return n;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const imageOf = (raw: any) => (raw.content as any[]).find((c) => c.type === 'image')?.data as string;

describe('security: grants, isolation, frames, popups, navigation, refs, approvals, redaction', () => {
  let h: Harness;
  let a: OAuthResult;
  let b: OAuthResult;
  let ca: Client;
  let cb: Client;
  let practiceTab: string;
  let practiceUrl: string;

  async function approve(kind: string, client = a, body: Record<string, unknown> = {}) {
    const x = await h.admin.waitForApproval((r) => r.kind === kind && r.clientId === client.clientId);
    await h.admin.ok('/api/approval', { id: x.id, decision: 'approve', ...body });
    return x;
  }
  async function deny(kind: string, client = a) {
    const x = await h.admin.waitForApproval((r) => r.kind === kind && r.clientId === client.clientId);
    await h.admin.ok('/api/approval', { id: x.id, decision: 'deny' });
    return x;
  }
  async function resetPracticeTab() {
    const r = await call(ca, 'navigatePage', { action: 'goto', url: practiceUrl, tabId: practiceTab });
    expect(r.isError, r.text).toBe(false);
  }

  beforeAll(async () => {
    h = await startHarness({ approvalTimeoutSeconds: 10, lookup: async (host) => (host === 'rebind.example' ? ['127.0.0.1'] : ['93.184.216.34']) });
    practiceUrl = `${h.fixtures.courseOrigin}/practice.html`;
    await h.app.browser.openTab(practiceUrl);
    await h.app.browser.openTab(`${h.fixtures.courseOrigin}/popup-target.html`);
    a = await authorizeClient(h, { name: 'Agent A' });
    b = await authorizeClient(h, { name: 'Agent B' });
    ca = await mcpClient(h, a.accessToken);
    cb = await mcpClient(h, b.accessToken, 'legacy');
    practiceTab = await h.admin.tabIdFor(practiceUrl);
    await h.admin.ok('/api/grant', { action: 'share', clientId: a.clientId, tabId: practiceTab });
  });
  afterAll(async () => {
    await ca?.close().catch(() => undefined);
    await cb?.close().catch(() => undefined);
    await h?.stop();
  });

  it('never reveals unshared tabs to a client, and isolates clients from each other', async () => {
    const listA = await call(ca, 'listTabs');
    expect(listA.text).toContain(practiceTab);
    expect(listA.text).not.toContain('Course help');
    const listB = await call(cb, 'listTabs');
    expect(listB.text).toMatch(/No tabs are shared/);
    const helpTab = await h.admin.tabIdFor(`${h.fixtures.courseOrigin}/popup-target.html`);
    for (const [tool, args] of [
      ['readPage', { tabId: practiceTab }],
      ['screenshotPage', { tabId: practiceTab }],
      ['selectTab', { tabId: practiceTab }],
      ['clickElement', { tabId: practiceTab, selector: 'button' }],
      ['typeInPage', { tabId: practiceTab, text: 'x' }],
      ['navigatePage', { tabId: practiceTab, action: 'reload' }],
      ['readPage', { tabId: helpTab }],
      ['readPage', { tabId: 'tab-999' }],
    ] as const) {
      const r = await call(cb, tool, args);
      expect(r.isError, `${tool} ${JSON.stringify(args)}`).toBe(true);
      expect(r.text).not.toContain('Practice sign-in');
      expect(r.text).not.toContain('Course help');
    }
    // Same message for "exists but unshared" and "does not exist": no enumeration.
    const x = await call(cb, 'readPage', { tabId: helpTab });
    const y = await call(cb, 'readPage', { tabId: 'tab-999' });
    expect(x.text.replace(helpTab, 'T')).toBe(y.text.replace('tab-999', 'T'));
    // B's closeTab needs manage scope + a grant; neither leaks or closes anything.
    expect((await call(cb, 'closeTab', { tabId: practiceTab })).isError).toBe(true);
    expect(h.app.browser.tab(practiceTab)).toBeDefined();
  });

  it('excludes unshared cross-origin frame content from snapshots, text, and screenshot pixels until the frame is granted', async () => {
    await resetPracticeTab();
    const snap = await call(ca, 'readPage', { mode: 'both', maxChars: 40000 });
    expect(snap.text).toContain('Practice sign-in');
    expect(snap.text).not.toContain('Secret player-origin content');
    const frameId = /iframe \[frame=(frame-\d+)\] \(contents not shared/.exec(snap.text)?.[1];
    expect(frameId).toBeTruthy();
    expect((await call(ca, 'readPage', { frameId })).text).toMatch(/not shared/);
    expect((await call(ca, 'clickElement', { frameId, text: 'Player site landing page' })).text).toMatch(/frame_not_shared/);

    await h.app.browser.tab(practiceTab)!.page.locator('iframe').scrollIntoViewIfNeeded();
    const masked = await call(ca, 'screenshotPage', {});
    expect(masked.isError, masked.text).toBe(false);
    expect(masked.text).toMatch(/1 frame\(s\) not shared with you are covered/);
    expect(greenPixels(imageOf(masked.raw))).toBe(0);
    const full = await call(ca, 'screenshotPage', { fullPage: true });
    expect(full.isError).toBe(true);
    expect(full.text).toMatch(/Full-page screenshots are unavailable/);

    const req = call(ca, 'requestTabAccess', { frameId, reason: 'need the player' });
    await approve('frame_access');
    expect((await req).isError).toBe(false);
    const after = await call(ca, 'readPage', { mode: 'text' });
    expect(after.text).toContain('Secret player-origin content');
    const visible = await call(ca, 'screenshotPage', {});
    expect(greenPixels(imageOf(visible.raw))).toBeGreaterThan(1000);
    // B still sees nothing.
    expect((await call(cb, 'readPage', { tabId: practiceTab })).isError).toBe(true);
    // Owner removes the frame grant: content disappears again.
    await h.admin.ok('/api/grant', { action: 'set', clientId: a.clientId, tabId: practiceTab, origins: [h.fixtures.courseOrigin], frameOrigins: [] });
    expect((await call(ca, 'readPage', { mode: 'text' })).text).not.toContain('Secret player-origin content');
  });

  it('opens popups and script-opened tabs only as unshared tabs', async () => {
    await resetPracticeTab();
    const snap = (await call(ca, 'readPage', {})).text;
    const click = call(ca, 'clickElement', { ref: refFor(snap, /link "Open help in a new tab"/) });
    const ap = await approve('popup');
    expect(ap.summary).toMatch(/opens a new tab/);
    const r = await click;
    const newTab = /opened a new tab \((tab-\d+)\)\. It is NOT shared/.exec(r.text)?.[1];
    expect(newTab, r.text).toBeTruthy();
    expect((await call(ca, 'readPage', { tabId: newTab })).isError).toBe(true);
    expect((await call(ca, 'listTabs')).text).not.toContain(newTab!);

    const r2 = await call(ca, 'clickElement', { text: 'Open help with a script', role: 'button' });
    expect(r2.text).toMatch(/opened a new tab \(tab-\d+\)\. It is NOT shared/);
    expect((await call(ca, 'listTabs')).text.match(/tab-\d+/g)).toEqual([practiceTab]);
  });

  it('blocks restricted schemes, local/private destinations and DNS-rebinding names', async () => {
    for (const url of ['file:///etc/passwd', 'chrome://settings', 'http://localhost:8932/', 'http://127.0.0.1:1/', 'http://10.0.0.1/', 'http://169.254.169.254/latest/meta-data', 'http://rebind.example/']) {
      const nav = await call(ca, 'navigatePage', { action: 'goto', url });
      expect(nav.isError, url).toBe(true);
      expect(nav.text, url).toMatch(/restricted|not allowed|blocked/i);
      const open = await call(ca, 'openBrowserPage', { url });
      expect(open.isError, url).toBe(true);
    }
    expect(h.app.browser.tab(practiceTab)!.page.url()).toContain('/practice.html');
  });

  it('holds navigation to unshared sites for approval, and pauses access after redirects/scripted navigation', async () => {
    await resetPracticeTab();
    // Direct goto to an unshared site needs approval; denial keeps the tab where it is.
    const goto = call(ca, 'navigatePage', { action: 'goto', url: `${h.fixtures.playerOrigin}/landing.html` });
    await deny('navigate_new_origin');
    expect((await goto).text).toMatch(/approval_denied/);
    expect(h.app.browser.tab(practiceTab)!.page.url()).toContain('/practice.html');

    // Scripted navigation to another site is intercepted and held for approval.
    const scripted = call(ca, 'clickElement', { text: 'Scripted navigation to the player site', role: 'button' });
    await deny('navigate_new_origin');
    const sr = await scripted;
    expect(sr.text).toMatch(/blocked/);
    expect((await call(ca, 'readPage', { mode: 'text' })).text).not.toContain('Secret player-origin content');

    // A same-origin link that 302-redirects to another site never exposes the destination.
    const snap = (await call(ca, 'readPage', {})).text;
    const redirect = call(ca, 'clickElement', { ref: refFor(snap, /link "Go to the player site via redirect"/) });
    const held = await Promise.race([
      h.admin.waitForApproval((r) => r.kind === 'navigate_new_origin' && r.clientId === a.clientId, 4000).then((x) => x, () => null),
      redirect.then(() => null),
    ]);
    if (held) await h.admin.ok('/api/approval', { id: held.id, decision: 'deny' });
    await redirect;
    const read = await call(ca, 'readPage', { mode: 'text' });
    expect(read.text).not.toContain('Secret player-origin content');
    if (read.isError) expect(read.text).toMatch(/origin_not_shared/);
    // listTabs does not reveal the new site either.
    expect((await call(ca, 'listTabs')).text).not.toContain('Player site landing page');

    // Redirect to a private address is blocked or paused, never read.
    await resetPracticeTab();
    const priv = await call(ca, 'clickElement', { text: 'Redirect to a private network address', role: 'link' });
    expect(priv.text).not.toContain('10.255.255.1');
  });

  it('rejects stale refs after navigation and refs from another client\'s snapshot', async () => {
    await resetPracticeTab();
    const snap = (await call(ca, 'readPage', {})).text;
    const ref = refFor(snap, /button "Show alert"/);
    await call(ca, 'navigatePage', { action: 'reload' });
    const stale = await call(ca, 'clickElement', { ref });
    expect(stale.isError).toBe(true);
    expect(stale.text).toMatch(/stale_ref.*readPage again/);
    expect((await call(ca, 'clickElement', { ref: 'e99999' })).text).toMatch(/stale_ref/);
    expect((await call(ca, 'clickElement', { selector: 'iframe >> internal:control=enter-frame >> h1' })).text).toMatch(/invalid_target/);
    expect((await call(ca, 'clickElement', { selector: 'xpath=//button' })).text).toMatch(/invalid_target/);
    // Cursor pagination is bounded and expires on navigation.
    const small = await call(ca, 'readPage', { mode: 'both', maxChars: 1000 });
    const cursor = /cursor "([^"]+)"/.exec(small.text)?.[1];
    expect(cursor).toBeTruthy();
    expect(small.text.length).toBeLessThan(1300);
    expect((await call(ca, 'readPage', { cursor })).isError).toBe(false);
    await call(ca, 'navigatePage', { action: 'reload' });
    expect((await call(ca, 'readPage', { cursor })).text).toMatch(/stale_cursor/);
  });

  it('requires approval for password/OTP typing and submission, redacts secrets, and never logs them', async () => {
    await resetPracticeTab();
    const secret = 'Hunter2-Sup3r-Secret';
    let snap = (await call(ca, 'readPage', {})).text;
    const pw = refFor(snap, /textbox "Password"/);
    const typing = call(ca, 'typeInPage', { ref: pw, text: secret });
    const ap = await approve('type_secret');
    expect(ap.summary).not.toContain(secret);
    expect(ap.summary).toMatch(/protected field/);
    const typed = await typing;
    expect(typed.isError, typed.text).toBe(false);
    expect(typed.text).not.toContain(secret);
    snap = (await call(ca, 'readPage', { mode: 'both' })).text;
    expect(snap).not.toContain(secret);
    expect(snap).toMatch(/textbox "Password" \[ref=\w+\]: \[redacted\]/);
    const otp = call(ca, 'typeInPage', { ref: refFor(snap, /textbox "One-time code"/), text: '123456' });
    await deny('type_secret');
    expect((await otp).text).toMatch(/approval_denied/);
    expect(await h.app.browser.tab(practiceTab)!.page.inputValue('#otp')).toBe('');
    // Enter in a single-line field is a submission.
    const enter = call(ca, 'typeInPage', { ref: refFor(snap, /textbox "Username"/), text: 'alex', keys: ['Enter'] });
    await deny('submit');
    expect((await enter).text).toMatch(/approval_denied/);
    expect(await h.app.browser.tab(practiceTab)!.page.textContent('#login-result')).toBe('');
    // Browser-level shortcuts are refused.
    expect((await call(ca, 'typeInPage', { keys: ['Meta+W'] })).text).toMatch(/not allowed/);
    // Prompt dialog text is not echoed.
    const prompt = await call(ca, 'clickElement', { text: 'Ask my name', role: 'button' });
    expect(prompt.text).toMatch(/prompt dialog is open/);
    const handled = await call(ca, 'handleDialog', { accept: true, promptText: 'Prompt-Secret-Name' });
    expect(handled.text).not.toContain('Prompt-Secret-Name');

    const audit = readFileSync(join(h.dataDir, 'audit.log'), 'utf8');
    for (const bad of [secret, '123456', 'Prompt-Secret-Name', 'alex', 'practice.html', 'Practice sign-in', 'rbu_at_', 'rbu_rt_', h.app.setupCode]) {
      expect(audit, bad).not.toContain(bad);
    }
    expect(audit).toContain('"tool":"typeInPage"');
  });

  it('times out unanswered approvals to deny, and cancels undispatched actions when access is revoked', async () => {
    await resetPracticeTab();
    const snap = (await call(ca, 'readPage', {})).text;
    const signIn = refFor(snap, /button "Sign in"/);
    const started = Date.now();
    const timedOut = await call(ca, 'clickElement', { ref: signIn });
    expect(timedOut.text).toMatch(/approval_timeout/);
    expect(Date.now() - started).toBeGreaterThanOrEqual(9000);
    expect(await h.app.browser.tab(practiceTab)!.page.textContent('#login-result')).toBe('');

    const snap2 = (await call(ca, 'readPage', {})).text;
    const pending = call(ca, 'clickElement', { ref: refFor(snap2, /button "Sign in"/) });
    await h.admin.waitForApproval((r) => r.kind === 'submit' && r.clientId === a.clientId);
    await h.admin.ok('/api/grant', { action: 'revoke', clientId: a.clientId, tabId: practiceTab });
    const res = await pending;
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/approval_denied|revoked/);
    expect(await h.app.browser.tab(practiceTab)!.page.textContent('#login-result')).toBe('');
    expect((await call(ca, 'readPage', { tabId: practiceTab })).isError).toBe(true);
    await h.admin.ok('/api/grant', { action: 'share', clientId: a.clientId, tabId: practiceTab });
  });

  it('requires approval for downloads and only saves approved files', async () => {
    await resetPracticeTab();
    const click = call(ca, 'clickElement', { text: 'Download the handbook', role: 'link' });
    await approve('download');
    expect((await click).isError).toBe(false);
    const dir = join(h.dataDir, 'downloads');
    for (let i = 0; i < 50 && !(existsSync(dir) && readdirSync(dir).length); i++) await new Promise((r) => setTimeout(r, 100));
    expect(readdirSync(dir)).toContain('northwind-handbook.txt');
  });

  it('closing a tab and opening a page require approval; opened tabs are shared only if the owner chooses', async () => {
    const open = call(ca, 'openBrowserPage', { url: `${h.fixtures.courseOrigin}/` });
    await approve('open_tab', a, { share: false });
    const r = await open;
    expect(r.text).toMatch(/chose not to share/);
    const tabId = /Opened (tab-\d+)/.exec(r.text)![1]!;
    expect((await call(ca, 'readPage', { tabId })).isError).toBe(true);
    const open2 = call(ca, 'openBrowserPage', { url: `${h.fixtures.courseOrigin}/` });
    await approve('open_tab', a, { share: true });
    const r2 = await open2;
    expect(r2.text).toMatch(/Opened and shared/);
    const tab2 = /Opened and shared (tab-\d+)/.exec(r2.text)![1]!;
    expect((await call(ca, 'readPage', { tabId: tab2 })).text).toContain('Security awareness course 2026');
    const close = call(ca, 'closeTab', { tabId: tab2 });
    await approve('close_tab');
    expect((await close).text).toContain(`Closed ${tab2}`);
    expect(h.app.browser.tab(tab2)).toBeUndefined();
  });

  it('kill switch revokes every token and grant immediately', async () => {
    expect((await call(ca, 'listTabs')).text).toContain(practiceTab);
    await h.admin.ok('/api/kill', {});
    await expect(ca.callTool({ name: 'listTabs', arguments: {} })).rejects.toThrow();
    await expect(cb.callTool({ name: 'listTabs', arguments: {} })).rejects.toThrow();
    const st = await h.admin.state();
    expect(st.grants).toEqual([]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(st.clients.every((c: any) => !c.approved)).toBe(true);
  });
});
