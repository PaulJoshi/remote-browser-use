import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from '@modelcontextprotocol/client';
import { authorizeClient, call, mcpClient, refFor, startHarness, type Harness, type OAuthResult } from './harness.js';

/**
 * The complete bundled fictional training flow, driven only through MCP tools
 * (as a remote agent would), with the owner's grants and approvals given
 * through the local admin API (as the owner would in the control panel).
 */
describe('complete fictional security-awareness course via MCP tools', () => {
  let h: Harness;
  let oauth: OAuthResult;
  let client: Client;

  async function approveNext(kind: string, body: Record<string, unknown> = {}) {
    const a = await h.admin.waitForApproval((x) => x.kind === kind && x.clientId === oauth.clientId);
    await h.admin.ok('/api/approval', { id: a.id, decision: 'approve', ...body });
    return a;
  }

  async function snap(args: Record<string, unknown> = {}) {
    const r = await call(client, 'readPage', { maxChars: 40000, ...args });
    expect(r.isError, r.text).toBe(false);
    return r.text;
  }

  async function click(ref: string) {
    const r = await call(client, 'clickElement', { ref });
    expect(r.isError, r.text).toBe(false);
    return r.text;
  }

  beforeAll(async () => {
    h = await startHarness();
    await h.app.browser.openTab(`${h.fixtures.courseOrigin}/`);
    oauth = await authorizeClient(h, { name: 'Course agent' });
    client = await mcpClient(h, oauth.accessToken);
  });
  afterAll(async () => {
    await client?.close();
    await h?.stop();
  });

  it('runs every step: tab request, slides, quiz, inbox, cross-origin player, dialog, certificate', async () => {
    // 1. No tab is visible until the owner shares one.
    expect((await call(client, 'listTabs')).text).toMatch(/No tabs are shared/);
    const courseTab = await h.admin.tabIdFor(h.fixtures.courseOrigin);
    const request = call(client, 'requestTabAccess', { reason: 'Complete the Northwind security course' });
    const tabReq = await h.admin.waitForApproval((x) => x.kind === 'tab_access');
    expect(tabReq.details.reason).toBe('Complete the Northwind security course');
    await h.admin.ok('/api/approval', { id: tabReq.id, decision: 'approve', tabId: courseTab });
    const granted = await request;
    expect(granted.isError, granted.text).toBe(false);
    expect(granted.text).toContain(courseTab);

    // 2. Slides with gates.
    let s = await snap();
    await click(refFor(s, /link "Start course"/));
    s = await snap();
    expect(s).toContain('Why phishing works');
    expect(s).toMatch(/button "Next slide".*\[disabled\]/);
    await click(refFor(s, /checkbox "I have read this slide"/));
    s = await snap();
    await click(refFor(s, /button "Next slide"/));

    s = await snap();
    expect(s).toContain('Red flags');
    for (const term of ['Spoofing', 'Pretexting']) {
      const r = await call(client, 'hoverElement', { text: term, exact: true });
      expect(r.isError, r.text).toBe(false);
    }
    s = await snap();
    expect(s).toContain('Revealed 2 of 2 terms');
    await click(refFor(s, /button "Next slide"/));

    s = await snap();
    await click(refFor(s, /button "I understand how to report"/));
    s = await snap();
    await click(refFor(s, /button "Go to the knowledge check"/));

    // 3. Quiz: single + multi answer; submitting the form needs owner approval.
    s = await snap();
    await click(refFor(s, /radio "Report it with the Report phishing button"/));
    await click(refFor(s, /checkbox "A demand to act within one hour"/));
    await click(refFor(s, /checkbox "The sender domain is northwind-traders.co/));
    await click(refFor(s, /checkbox "A request to confirm your password"/));
    const submit = call(client, 'clickElement', { ref: refFor(s, /button "Submit answers"/) });
    const sub = await approveNext('submit');
    expect(sub.summary).toMatch(/submits a form/);
    expect((await submit).isError).toBe(false);
    s = await snap();
    expect(s).toContain('Passed: 2 of 2 correct');
    await click(refFor(s, /link "Continue to the inbox exercise"/));

    // 4. Spot-the-phish inbox: drag phish into the bin, mark the rest safe.
    s = await snap();
    const bin = refFor(s, /region "Report phishing bin"/);
    for (const subject of [/Password expires today/, /Urgent: buy gift cards/]) {
      const r = await call(client, 'dragElement', { source: { ref: refFor(s, new RegExp(`Drag handle for .*${subject.source}`)) }, target: { ref: bin } });
      expect(r.isError, r.text).toBe(false);
    }
    s = await snap();
    await click(refFor(s, /button "Mark .*Your October payslip is available.* as safe"/));
    await click(refFor(s, /button "Mark .*Office closed Friday for maintenance.* as safe"/));
    await click(refFor(s, /button "Open .*Urgent: buy gift cards for a client/));
    s = await snap();
    expect(s).toContain('Buy five gift cards');
    await click(refFor(s, /button "Check my answers"/));
    s = await snap();
    expect(s).toContain('All messages sorted correctly');

    // 5. Cross-origin LMS player: invisible until the owner shares that frame.
    const nav = await call(client, 'navigatePage', { action: 'goto', url: `${h.fixtures.courseOrigin}/module.html` });
    expect(nav.isError, nav.text).toBe(false);
    s = await snap();
    expect(s).not.toContain('Launch module');
    const frameId = /iframe \[frame=(frame-\d+)\] \(contents not shared/.exec(s)?.[1];
    expect(frameId).toBeTruthy();
    const frameReq = call(client, 'requestTabAccess', { frameId, reason: 'The course module runs in this player' });
    const fr = await approveNext('frame_access');
    expect(fr.details.origin).toBe(h.fixtures.playerOrigin);
    expect((await frameReq).isError).toBe(false);
    s = await snap();
    expect(s).toContain('Launch module');
    await click(refFor(s, /button "Launch module"/));
    s = await snap();
    await click(refFor(s, /radio "https:\/\/northwind.example\/benefits"/));
    await click(refFor(s, /button "Check answer"/));
    s = await snap();
    expect(s).toContain('Correct: that link uses the real company domain');
    const completed = await click(refFor(s, /button "Complete module"/));
    expect(completed).toMatch(/confirm dialog is open/);
    const dlg = await call(client, 'handleDialog', { accept: true });
    expect(dlg.isError, dlg.text).toBe(false);
    s = await snap({ mode: 'text' });
    expect(s).toContain('Module status: completed (score 100)');

    // 6. Certificate: type the name and generate (form submission → approval).
    await call(client, 'navigatePage', { action: 'goto', url: `${h.fixtures.courseOrigin}/certificate.html` });
    s = await snap();
    const typed = await call(client, 'typeInPage', { ref: refFor(s, /textbox "Full name for the certificate"/), text: 'Alex Example' });
    expect(typed.isError, typed.text).toBe(false);
    expect(typed.text).not.toContain('Alex Example');
    const gen = call(client, 'clickElement', { ref: refFor(s, /button "Generate certificate"/) });
    await approveNext('submit');
    expect((await gen).isError).toBe(false);
    s = await snap({ mode: 'text' });
    expect(s).toContain('Certificate of Completion');
    expect(s).toContain('Alex Example');
    expect(s).toMatch(/Certificate ID: NW-2026-\d{7}/);

    // 7. Visual check: the shared player frame is visible in a screenshot.
    await call(client, 'navigatePage', { action: 'goto', url: `${h.fixtures.courseOrigin}/module.html` });
    const shot = await call(client, 'screenshotPage', {});
    expect(shot.isError, shot.text).toBe(false);
    expect(shot.text).not.toMatch(/covered by a gray striped mask/);
  });
});
