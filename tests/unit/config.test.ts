import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { normalizePublicUrl } from '../../src/auth/publicUrl.js';
import { ConfigError, loadConfigFile, parseArgs, resolveConfig } from '../../src/config.js';
import { TOOL_NAMES } from '../../src/policy/scopes.js';

describe('CLI arguments and configuration', () => {
  it('uses safe defaults: loopback ports 8931/8932, no public URL, sensitive approvals, full ceiling but nothing enabled', () => {
    const c = resolveConfig({}, parseArgs([]).cli);
    expect(c).toMatchObject({ port: 8931, adminPort: 8932, approve: 'sensitive', approvalTimeoutSeconds: 60, openPanel: true, allowDomains: [], denyDomains: [] });
    expect(c.publicUrl).toBeUndefined();
    expect(c.toolCeiling).toEqual(TOOL_NAMES);
  });

  it('parses every documented flag', () => {
    const p = parseArgs([
      '--port', '9001', '--admin-port=9002', '--public-url', 'https://abc-9001.example.devtunnels.ms/', '--tools', 'readPage,listTabs',
      '--allow-domains', 'Example.com,*.course.example', '--deny-domains', 'bank.example', '--approve', 'all', '--approval-timeout', '30', '--no-open',
    ]);
    const c = resolveConfig({}, p.cli);
    expect(c.port).toBe(9001);
    expect(c.adminPort).toBe(9002);
    expect(c.publicUrl).toBe('https://abc-9001.example.devtunnels.ms');
    expect(c.toolCeiling).toEqual(['readPage', 'listTabs']);
    expect(c.allowDomains).toEqual(['example.com', 'course.example']);
    expect(c.denyDomains).toEqual(['bank.example']);
    expect(c.approve).toBe('all');
    expect(c.approvalTimeoutSeconds).toBe(30);
    expect(c.openPanel).toBe(false);
    expect(parseArgs(['demo', '--port', '9100']).command).toBe('demo');
    expect(parseArgs(['--help']).command).toBe('help');
    expect(parseArgs(['-v']).command).toBe('version');
  });

  it('rejects unknown and unsafe flags (no --host, --no-auth, --cdp-url, --headless, --allow-code)', () => {
    for (const flag of ['--host', '--no-auth', '--cdp-url', '--browser', '--headless', '--allow-code', '--bogus']) {
      expect(() => parseArgs([flag, 'x']), flag).toThrow(ConfigError);
    }
    expect(() => parseArgs(['--port'])).toThrow(/requires a value/);
    expect(() => parseArgs(['--approve', 'none'])).toThrow(ConfigError);
    expect(() => parseArgs(['--port', '80'])).toThrow(ConfigError);
    expect(() => parseArgs(['--approval-timeout', '5'])).toThrow(ConfigError);
    expect(() => resolveConfig({}, { port: 9000, adminPort: 9000 })).toThrow(/different/);
    expect(() => resolveConfig({}, { tools: 'readPage,runPlaywrightCode' })).toThrow(/Unknown tool/);
    expect(() => resolveConfig({}, { allowDomains: 'http://example.com' })).toThrow(/Invalid domain/);
  });

  it('validates public URLs: https base only, plain http only for this machine\'s MCP port', () => {
    expect(normalizePublicUrl('https://x.example', 8931)).toBe('https://x.example');
    expect(normalizePublicUrl('HTTPS://X.Example:8443/', 8931)).toBe('https://x.example:8443');
    expect(normalizePublicUrl('http://127.0.0.1:8931', 8931)).toBe('http://127.0.0.1:8931');
    for (const bad of ['http://x.example', 'http://127.0.0.1:8932', 'https://u:p@x.example', 'https://x.example/mcp', 'https://x.example/?a=1', 'https://x.example/#f', 'ftp://x.example', 'not a url']) {
      expect(() => normalizePublicUrl(bad, 8931), bad).toThrow();
    }
  });

  it('loads a strict JSON config file and lets flags override it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'rbu-cfg-'));
    const file = join(dir, 'config.json');
    writeFileSync(file, JSON.stringify({ port: 9200, approve: 'all', tools: ['readPage'] }));
    const p = parseArgs(['--config', file, '--port', '9300']);
    const c = resolveConfig(loadConfigFile(p.configPath!), p.cli);
    expect(c.port).toBe(9300);
    expect(c.approve).toBe('all');
    expect(c.toolCeiling).toEqual(['readPage']);
    writeFileSync(file, JSON.stringify({ port: 9200, noAuth: true }));
    expect(() => loadConfigFile(file)).toThrow(/noAuth|Unrecognized/);
    writeFileSync(file, '{not json');
    expect(() => loadConfigFile(file)).toThrow(/not valid JSON/);
  });
});
