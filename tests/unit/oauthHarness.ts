import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { AuditLog } from '../../src/audit/audit.js';
import { AuthorizationServer } from '../../src/auth/oauth.js';
import { normalizePublicUrl } from '../../src/auth/publicUrl.js';
import { TOOL_NAMES, TOOL_SCOPES } from '../../src/policy/scopes.js';
import { McpListener } from '../../src/server/mcpServer.js';
import { StateStore } from '../../src/store.js';
import { pkceChallenge, randomToken } from '../../src/util/crypto.js';
import { createServer } from 'node:net';

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

export interface FakeClock {
  t: number;
  now(): number;
}

export interface OAuthEnv {
  dir: string;
  port: number;
  base: string;
  clock: FakeClock;
  store: StateStore;
  audit: AuditLog;
  auth: AuthorizationServer;
  listener: McpListener;
  cimdDocs: Map<string, unknown>;
  jwksDocs: Map<string, unknown>;
  auditText(): string;
  close(): Promise<void>;
}

export async function startOAuthEnv(opts: { publicUrl?: boolean } = {}): Promise<OAuthEnv> {
  const dir = mkdtempSync(join(tmpdir(), 'rbu-unit-'));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const clock: FakeClock = { t: Date.now(), now() { return this.t; } };
  const store = new StateStore(join(dir, 'state.json'));
  // Unit tests exercise the strict/manual approval paths by default.
  store.state.settings = { autoApproveClients: false, shareEntireBrowser: false, actionApprovals: 'sensitive' };
  if (opts.publicUrl !== false) store.state.publicUrl = normalizePublicUrl(base, port);
  const audit = new AuditLog(join(dir, 'audit.log'));
  const cimdDocs = new Map<string, unknown>();
  const jwksDocs = new Map<string, unknown>();
  const auth = new AuthorizationServer({
    store,
    audit,
    clock,
    toolCeiling: TOOL_NAMES,
    fetchClientMetadata: async (url) => {
      if (!cimdDocs.has(url)) throw new Error('not found');
      return cimdDocs.get(url);
    },
    fetchJwks: async (url) => {
      if (!jwksDocs.has(url)) throw new Error('not found');
      return jwksDocs.get(url);
    },
    settings: () => store.state.settings,
  });
  const listener = new McpListener({
    port,
    auth,
    audit,
    buildServer: (info) => {
      const server = new McpServer({ name: 'stub', version: '0' });
      for (const name of ['readPage', 'clickElement']) {
        server.registerTool(name, { description: name, inputSchema: z.object({}) }, async () => ({ content: [{ type: 'text', text: `${name} ok for ${info.clientId}` }] }));
      }
      return server;
    },
  });
  await listener.listen();
  return {
    dir,
    port,
    base,
    clock,
    store,
    audit,
    auth,
    listener,
    cimdDocs,
    jwksDocs,
    auditText: () => {
      try {
        return readFileSync(join(dir, 'audit.log'), 'utf8');
      } catch {
        return '';
      }
    },
    async close() {
      await listener.close();
      auth.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

export const REDIRECT = 'http://127.0.0.1:9/cb';

export async function register(env: OAuthEnv, body: Record<string, unknown> = {}): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${env.base}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Unit client', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none', ...body }),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

export interface AuthorizeParams {
  clientId: string;
  redirectUri?: string;
  verifier?: string;
  scope?: string;
  resource?: string | null;
  method?: string;
}

export function authorizeUrl(env: OAuthEnv, p: AuthorizeParams): { url: string; verifier: string; state: string } {
  const verifier = p.verifier ?? randomToken(48);
  const state = randomToken(8);
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: p.clientId,
    redirect_uri: p.redirectUri ?? REDIRECT,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: p.method ?? 'S256',
    state,
  });
  if (p.scope) q.set('scope', p.scope);
  if (p.resource !== null) q.set('resource', p.resource ?? `${env.base}/mcp`);
  return { url: `${env.base}/authorize?${q}`, verifier, state };
}

/** Start authorization, approve it as the owner, and return the code. */
export async function obtainCode(env: OAuthEnv, p: AuthorizeParams & { grantScopes?: string[]; tools?: string[] }): Promise<{ code: string; verifier: string }> {
  const { url, verifier } = authorizeUrl(env, p);
  const page = await (await fetch(url, { redirect: 'manual' })).text();
  const handle = /authorize\/wait\?h=([A-Za-z0-9_-]+)/.exec(page)?.[1];
  if (!handle) throw new Error(`no handle: ${page.slice(0, 200)}`);
  const pending = env.auth.pendingAuthorizations().find((x) => x.clientId === p.clientId)!;
  const scopes = p.grantScopes ?? pending.requestedScopes;
  const tools = p.tools ?? pending.allowedTools.filter((t) => scopes.includes(TOOL_SCOPES[t]));
  env.auth.approveAuthorization(pending.id, scopes, tools);
  const res = await fetch(`${env.base}/authorize/wait?h=${handle}`, { redirect: 'manual' });
  const loc = new URL(res.headers.get('location')!);
  return { code: loc.searchParams.get('code')!, verifier };
}

export async function token(env: OAuthEnv, params: Record<string, string>, headers: Record<string, string> = {}): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${env.base}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(params) });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

export async function fullTokens(env: OAuthEnv, opts: { grantScopes?: string[]; scope?: string } = {}) {
  const reg = await register(env);
  const clientId = reg.json.client_id as string;
  const { code, verifier } = await obtainCode(env, { clientId, grantScopes: opts.grantScopes, scope: opts.scope });
  const t = await token(env, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier, resource: `${env.base}/mcp` });
  return { clientId, accessToken: t.json.access_token as string, refreshToken: t.json.refresh_token as string, raw: t };
}

export async function mcpPost(env: OAuthEnv, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(`${env.base}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify(body),
  });
}

export const INIT = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'unit', version: '0' } },
};

export function toolCall(name: string, id = 2) {
  return { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: {} } };
}
