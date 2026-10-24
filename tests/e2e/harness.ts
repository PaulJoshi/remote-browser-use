import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { App } from '../../src/app.js';
import { resolveConfig, type FileConfig } from '../../src/config.js';
import { startFixtureServers, type FixtureServers } from '../../src/demo/fixtureServer.js';
import { pkceChallenge, randomToken } from '../../src/util/crypto.js';

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

export interface Harness {
  app: App;
  fixtures: FixtureServers;
  dataDir: string;
  admin: AdminClient;
  base: string;
  stop(opts?: { keepData?: boolean }): Promise<void>;
}

export interface HarnessOptions {
  config?: FileConfig;
  dataDir?: string;
  /** When true, use the shipped relaxed defaults instead of strict test settings. */
  relaxed?: boolean;
  fixtures?: FixtureServers;
  approvalTimeoutSeconds?: number;
  accessTokenTtlSeconds?: number;
  publicUrl?: string | null;
  lookup?: (host: string) => Promise<string[]>;
}

export async function startHarness(opts: HarnessOptions = {}): Promise<Harness> {
  const dataDir = opts.dataDir ?? mkdtempSync(join(tmpdir(), 'rbu-e2e-'));
  const fixtures = opts.fixtures ?? (await startFixtureServers());
  const port = opts.config?.port ?? (await freePort());
  const adminPort = opts.config?.adminPort ?? (await freePort());
  const publicUrl = opts.publicUrl === null ? undefined : (opts.publicUrl ?? `http://127.0.0.1:${port}`);
  const config = resolveConfig({}, { port, adminPort, publicUrl, approvalTimeoutSeconds: opts.approvalTimeoutSeconds ?? 15, openPanel: false, ...opts.config });
  if (!opts.relaxed) {
    // E2E tests exercise the strict grant/approval paths; enable relaxed mode explicitly per test.
    const stateFile = join(dataDir, 'state.json');
    const state = existsSync(stateFile) ? (JSON.parse(readFileSync(stateFile, 'utf8')) as Record<string, unknown>) : { version: 1 };
    state.settings = { autoApproveClients: false, shareEntireBrowser: false, actionApprovals: 'sensitive' };
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });
  }
  const app = await App.start({
    config,
    dataDir,
    headless: true,
    localOriginExceptions: [fixtures.courseOrigin, fixtures.playerOrigin],
    downloadsDir: join(dataDir, 'downloads'),
    accessTokenTtlSeconds: opts.accessTokenTtlSeconds,
    lookup: opts.lookup,
  });
  const admin = new AdminClient(`http://127.0.0.1:${adminPort}`);
  await admin.login(app.setupCode);
  return {
    app,
    fixtures,
    dataDir,
    admin,
    base: `http://127.0.0.1:${port}`,
    async stop(o = {}) {
      await app.stop();
      if (!opts.fixtures) await fixtures.close();
      if (!o.keepData && !opts.dataDir) rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/** Simulates the owner using the local control panel. */
export class AdminClient {
  cookie = '';
  csrf = '';
  constructor(readonly base: string) {}

  async login(code: string): Promise<void> {
    const res = await fetch(`${this.base}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: this.base },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) throw new Error(`admin login failed: ${res.status} ${await res.text()}`);
    this.cookie = (res.headers.get('set-cookie') ?? '').split(';')[0]!;
    const session = (await (await fetch(`${this.base}/api/session`, { headers: { Cookie: this.cookie } })).json()) as { csrf: string };
    this.csrf = session.csrf;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async state(): Promise<any> {
    const res = await fetch(`${this.base}/api/state`, { headers: { Cookie: this.cookie } });
    if (!res.ok) throw new Error(`state failed: ${res.status}`);
    return res.json();
  }

  async post(path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
    const res = await fetch(`${this.base}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: this.base, Cookie: this.cookie, 'X-CSRF-Token': this.csrf },
      body: JSON.stringify(body),
    });
    return { status: res.status, json: (await res.json().catch(() => ({}))) as Record<string, unknown> };
  }

  async ok(path: string, body: unknown): Promise<Record<string, unknown>> {
    const r = await this.post(path, body);
    if (r.status !== 200) throw new Error(`${path} failed: ${r.status} ${JSON.stringify(r.json)}`);
    return r.json;
  }

  /** Wait for a pending approval matching the predicate (polls like the panel does). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async waitForApproval(pred: (a: any) => boolean, timeoutMs = 10_000): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const s = await this.state();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const found = s.approvals.find((a: any) => pred(a));
      if (found) return found;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error('approval did not appear');
  }

  async tabIdFor(urlPrefix: string): Promise<string> {
    const s = await this.state();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tab = s.tabs.find((t: any) => t.url.startsWith(urlPrefix));
    if (!tab) throw new Error(`no tab at ${urlPrefix}`);
    return tab.tabId;
  }
}

export interface OAuthResult {
  clientId: string;
  accessToken: string;
  refreshToken: string;
  redirectUri: string;
}

/** Run the full OAuth dance as an MCP client would (DCR + PKCE + resource), approving locally via the admin API. */
export async function authorizeClient(
  h: Harness,
  opts: { name?: string; scopes?: string[]; grantScopes?: string[]; tools?: string[]; deny?: boolean } = {},
): Promise<OAuthResult> {
  const prm = (await (await fetch(`${h.base}/.well-known/oauth-protected-resource/mcp`)).json()) as { resource: string; authorization_servers: string[] };
  const asm = (await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json()) as Record<string, string>;
  const redirectUri = 'http://127.0.0.1:9/callback';
  const reg = await fetch(asm.registration_endpoint!, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: opts.name ?? 'Test client', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'] }),
  });
  const { client_id: clientId } = (await reg.json()) as { client_id: string };
  const verifier = randomToken(48);
  const state = randomToken(8);
  const auth = new URL(asm.authorization_endpoint!);
  auth.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: 'S256',
    state,
    resource: prm.resource,
    scope: (opts.scopes ?? ['browser:read', 'browser:navigate', 'browser:interact', 'browser:manage']).join(' '),
  }).toString();
  const page = await (await fetch(auth, { redirect: 'manual' })).text();
  const handle = /authorize\/wait\?h=([A-Za-z0-9_-]+)/.exec(page)?.[1];
  if (!handle) throw new Error(`no waiting page: ${page.slice(0, 300)}`);
  const st = await h.admin.state();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const pending = st.pendingAuthorizations.find((p: any) => p.clientId === clientId);
  if (!pending) throw new Error('pending authorization not visible in admin');
  if (opts.deny) {
    await h.admin.ok('/api/authorization', { id: pending.id, decision: 'deny' });
  } else {
    await h.admin.ok('/api/authorization', {
      id: pending.id,
      decision: 'approve',
      scopes: opts.grantScopes ?? pending.requestedScopes,
      tools: opts.tools ?? pending.allowedTools,
    });
  }
  const done = await fetch(`${h.base}/authorize/wait?h=${handle}`, { redirect: 'manual' });
  const location = new URL(done.headers.get('location')!);
  if (location.searchParams.get('state') !== state) throw new Error('state mismatch');
  if (location.searchParams.get('iss') !== prm.authorization_servers[0]) throw new Error('iss mismatch');
  const code = location.searchParams.get('code');
  if (!code) throw new Error(`authorization failed: ${location.searchParams.get('error')}`);
  const tokenRes = await fetch(asm.token_endpoint!, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier, resource: prm.resource }),
  });
  const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string };
  if (!tokens.access_token) throw new Error(`token failed: ${JSON.stringify(tokens)}`);
  return { clientId, accessToken: tokens.access_token, refreshToken: tokens.refresh_token, redirectUri };
}

export async function mcpClient(h: Harness, token: string, era: 'modern' | 'legacy' = 'modern'): Promise<Client> {
  const client = new Client(
    { name: 'rbu-e2e', version: '1.0.0' },
    era === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {},
  );
  const transport = new StreamableHTTPClientTransport(new URL(`${h.base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
  await client.connect(transport);
  return client;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function textOf(result: any): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (result.content as any[]).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
}

export async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<{ text: string; isError: boolean; raw: unknown }> {
  const started = Date.now();
  if (process.env.RBU_TRACE) console.error(`-> ${name} ${JSON.stringify(args).slice(0, 120)}`);
  const raw = await client.callTool({ name, arguments: args });
  if (process.env.RBU_TRACE) console.error(`<- ${name} ${Date.now() - started}ms`);
  return { text: textOf(raw), isError: Boolean((raw as { isError?: boolean }).isError), raw };
}

/** Find a ref in a readPage snapshot line matching the pattern. */
export function refFor(snapshot: string, pattern: RegExp): string {
  for (const line of snapshot.split('\n')) {
    if (pattern.test(line)) {
      const m = /\[ref=([a-z0-9]+)\]/.exec(line);
      if (m) return m[1]!;
    }
  }
  throw new Error(`no ref for ${pattern} in:\n${snapshot.slice(0, 3000)}`);
}
