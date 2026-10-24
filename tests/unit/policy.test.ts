import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit/audit.js';
import { ApprovalQueue } from '../../src/policy/approvals.js';
import { GrantStore } from '../../src/policy/grants.js';
import { checkDestination, documentOrigin, DomainRules, isRestrictedHostname, isRestrictedIp, resolvesToRestricted } from '../../src/policy/urlPolicy.js';
import { humanCode, normalizeHumanCode } from '../../src/util/crypto.js';
import { displayUrl, sanitizeText } from '../../src/util/sanitize.js';

const opts = (allow: string[] = [], deny: string[] = [], exceptions: string[] = []) => ({ rules: new DomainRules(allow, deny), localExceptions: new Set(exceptions) });

describe('destination policy', () => {
  it('blocks loopback, private, link-local, CGNAT, metadata and reserved addresses', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '224.0.0.1']) {
      expect(isRestrictedIp(ip), ip).toBe(true);
    }
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) expect(isRestrictedIp(ip), ip).toBe(false);
  });

  it('blocks local and internal hostnames, including WHATWG-normalised numeric forms', () => {
    for (const host of ['localhost', 'app.localhost', 'printer.local', 'db.internal', 'router.home.arpa', 'intranet', '[::1]']) expect(isRestrictedHostname(host), host).toBe(true);
    expect(isRestrictedHostname('example.com')).toBe(false);
    for (const url of ['http://0x7f.1/', 'http://2130706433/', 'http://127.1/', 'http://[::ffff:127.0.0.1]/']) {
      expect(checkDestination(url, opts()).ok, url).toBe(false);
    }
  });

  it('only allows http(s), applies allow/deny domain rules (deny wins), and honours exact local exceptions', () => {
    for (const url of ['file:///etc/passwd', 'chrome://settings', 'javascript:alert(1)', 'data:text/html,hi', 'about:blank', 'view-source:https://example.com']) {
      const v = checkDestination(url, opts());
      expect(v.ok, url).toBe(false);
    }
    expect(checkDestination('https://user:pw@example.com/', opts()).ok).toBe(false);
    expect(checkDestination('https://shop.example.com/x', opts(['example.com'])).ok).toBe(true);
    expect(checkDestination('https://example.org/', opts(['example.com'])).ok).toBe(false);
    expect(checkDestination('https://bank.example.com/', opts(['example.com'], ['bank.example.com'])).ok).toBe(false);
    expect(checkDestination('http://127.0.0.1:5555/x', opts([], [], ['http://127.0.0.1:5555'])).ok).toBe(true);
    expect(checkDestination('http://127.0.0.1:5556/x', opts([], [], ['http://127.0.0.1:5555'])).ok).toBe(false);
  });

  it('treats public names that resolve to private addresses as restricted (DNS rebinding)', async () => {
    expect(await resolvesToRestricted('rebind.example', async () => ['93.184.216.34', '127.0.0.1'])).toBe(true);
    expect(await resolvesToRestricted('ok.example', async () => ['93.184.216.34'])).toBe(false);
  });

  it('computes effective document origins for about:blank, srcdoc, blob and opaque URLs', () => {
    expect(documentOrigin('about:blank', 'https://a.example')).toBe('https://a.example');
    expect(documentOrigin('about:srcdoc', 'https://a.example')).toBe('https://a.example');
    expect(documentOrigin('blob:https://a.example/uuid')).toBe('https://a.example');
    expect(documentOrigin('data:text/html,x', 'https://a.example')).toBe('null');
    expect(documentOrigin('https://b.example:8443/p?q=1')).toBe('https://b.example:8443');
  });
});

describe('grants', () => {
  it('are per client, default-deny, and separate top-level and frame origins', () => {
    const g = new GrantStore(opts());
    expect(g.tabsFor('A')).toEqual([]);
    const grant = g.grant('A', 'tab-1', ['https://course.example']);
    expect(g.get('B', 'tab-1')).toBeUndefined();
    expect(g.originAllowed(grant, 'https://course.example')).toBe(true);
    expect(g.originAllowed(grant, 'https://other.example')).toBe(false);
    expect(g.frameAllowed(grant, 'https://course.example', 'https://course.example')).toBe(true);
    expect(g.frameAllowed(grant, 'https://player.example', 'https://course.example')).toBe(false);
    g.addFrameOrigin('A', 'tab-1', 'https://player.example');
    expect(g.frameAllowed(grant, 'https://player.example', 'https://course.example')).toBe(true);
    // Frame access never survives the top-level site leaving the grant.
    expect(g.frameAllowed(grant, 'https://player.example', 'https://evil.example')).toBe(false);
    expect(() => g.grant('A', 'tab-2', ['http://192.168.1.1'])).toThrow();
    expect(() => g.grant('A', 'tab-2', ['null'])).toThrow();
  });

  it('bump the generation on revocation but not on additive changes', () => {
    const g = new GrantStore(opts());
    g.grant('A', 'tab-1', ['https://a.example']);
    const gen = g.generation('A');
    g.addOrigin('A', 'tab-1', 'https://b.example');
    expect(g.generation('A')).toBe(gen);
    g.revokeTab('A', 'tab-1');
    expect(g.generation('A')).not.toBe(gen);
    const gen2 = g.generation('B');
    g.revokeAll();
    expect(g.generation('B')).not.toBe(gen2);
    g.grant('A', 'tab-3', ['https://a.example']);
    g.forgetTab('tab-3');
    expect(g.tabsFor('A')).toEqual([]);
  });
});

describe('approvals', () => {
  const audit = new AuditLog(undefined);
  it('time out to deny', async () => {
    const q = new ApprovalQueue(audit);
    const d = await q.request({ clientId: 'A', clientName: 'A', tool: 'clickElement', kind: 'submit', summary: 's' }, 50);
    expect(d).toEqual({ approved: false, reason: 'timeout' });
    expect(q.list()).toEqual([]);
  });
  it('resolve on owner decision and can be cancelled per client', async () => {
    const q = new ApprovalQueue(audit);
    const p1 = q.request({ clientId: 'A', clientName: 'A', tool: 't', kind: 'submit', summary: 's' }, 5000);
    const p2 = q.request({ clientId: 'B', clientName: 'B', tool: 't', kind: 'submit', summary: 's' }, 5000);
    q.decide(q.list().find((r) => r.clientId === 'A')!.id, true);
    expect((await p1).approved).toBe(true);
    q.cancelWhere((r) => r.clientId === 'B');
    expect(await p2).toEqual({ approved: false, reason: 'cancelled' });
    expect(() => q.decide('missing', true)).toThrow();
  });
  it('are cancelled when the requesting call is aborted', async () => {
    const q = new ApprovalQueue(audit);
    const ac = new AbortController();
    const p = q.request({ clientId: 'A', clientName: 'A', tool: 't', kind: 'submit', summary: 's' }, 5000, ac.signal);
    ac.abort();
    expect((await p).reason).toBe('cancelled');
  });
});

describe('audit log and sanitisers', () => {
  it('writes only whitelisted metadata and redacts anything that looks like content, queries or tokens', () => {
    const dir = mkdtempSync(join(tmpdir(), 'rbu-audit-'));
    const log = new AuditLog(join(dir, 'audit.log'));
    log.record({ event: 'tool', tool: 'typeInPage', client: 'dcr_abc', tab: 'tab-1', decision: 'allowed', ms: 12.7 });
    log.record({ event: 'tool', tool: 'readPage', client: 'https://chatgpt.com/oauth/client.json', tab: 'https://bank.example/?acct=1', decision: 'my password is hunter2', reason: 'rbu_at_secret' });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    log.record({ event: 'tool', tool: 'x', text: 'hunter2', url: 'https://x.example/?q=1' } as any);
    const text = readFileSync(join(dir, 'audit.log'), 'utf8');
    expect(text).toContain('"ms":13');
    expect(text).toContain('https://chatgpt.com/oauth/client.json');
    for (const bad of ['hunter2', 'acct=1', 'rbu_at_secret', 'q=1', '"text"', '"url"']) expect(text).not.toContain(bad);
  });

  it('strips queries from displayed URLs and control/bidi characters from text', () => {
    expect(displayUrl('https://a.example/p/q?token=1#frag')).toBe('https://a.example/p/q');
    expect(sanitizeText('a\u202Eb\u0000c   d', 10)).toBe('abc d');
    const code = humanCode(12, 4);
    expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(normalizeHumanCode(code.toLowerCase())).toBe(code.replace(/-/g, ''));
  });
});
