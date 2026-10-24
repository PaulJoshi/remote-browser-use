import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AuditLog } from '../audit/audit.js';
import { isScope, SCOPES, toolsAllowedByScopes, type ToolName } from '../policy/scopes.js';
import type { StateStore, StoredClient, StoredRefreshToken } from '../store.js';
import type { Clock } from '../util/clock.js';
import { humanCode, pkceChallenge, randomToken, safeEqual, sha256 } from '../util/crypto.js';
import { HttpError, readForm, readJson, send, sendHtml, sendJson } from '../util/http.js';
import { RateLimiter } from '../util/rateLimit.js';
import { escapeHtml, sanitizeText } from '../util/sanitize.js';
import { type CimdFetcher, isCimdClientId, validateClientMetadata } from './cimd.js';
import { type Identity, identityFor } from './publicUrl.js';

export interface AuthInfo {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource?: URL;
  extra?: Record<string, unknown>;
}

interface AccessTokenRecord {
  clientId: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
  familyId: string;
}

interface AuthCodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
  used: boolean;
  familyId: string;
}

export type PendingStatus = 'pending' | 'approved' | 'denied' | 'expired';

interface PendingAuthorization {
  id: string;
  handle: string;
  clientId: string;
  redirectUri: string;
  requestedScopes: string[];
  state?: string;
  codeChallenge: string;
  resource: string;
  createdAt: number;
  expiresAt: number;
  matchCode: string;
  status: PendingStatus;
  redirectTo?: string;
}

export interface PendingAuthorizationView {
  id: string;
  clientId: string;
  clientName: string;
  clientKind: 'dcr' | 'cimd';
  verifiedHost?: string;
  redirectUri: string;
  requestedScopes: string[];
  matchCode: string;
  createdAt: number;
  expiresAt: number;
  previouslyApproved: boolean;
  allowedTools: ToolName[];
}

export interface ClientView {
  clientId: string;
  name: string;
  kind: 'dcr' | 'cimd';
  verifiedHost?: string;
  redirectUris: string[];
  approved: boolean;
  scopes: string[];
  tools: string[];
  allowedTools: ToolName[];
  activeTokens: number;
  lastUsed?: number;
}

export interface AuthServerOptions {
  store: StateStore;
  audit: AuditLog;
  clock: Clock;
  fetchClientMetadata: CimdFetcher;
  toolCeiling: readonly ToolName[];
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  pendingTtlSeconds?: number;
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, MCP-Protocol-Version',
  'Access-Control-Max-Age': '600',
};
const TOKEN_HEADERS = { ...CORS_HEADERS, Pragma: 'no-cache' };

const MAX_CLIENTS = 100;
const MAX_PENDING = 20;
const CODE_TTL_MS = 60_000;
const BANNED_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'about:', 'blob:', 'filesystem:', 'ftp:', 'ws:', 'wss:']);

class OAuthError extends Error {
  constructor(
    readonly code: string,
    readonly description: string,
    readonly status = 400,
  ) {
    super(description);
  }
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '[::1]';
}

export function validateRedirectUri(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new OAuthError('invalid_redirect_uri', 'redirect_uri must be an absolute URL');
  }
  if (url.hash || raw.includes('#')) throw new OAuthError('invalid_redirect_uri', 'redirect_uri must not contain a fragment');
  if (url.username || url.password) throw new OAuthError('invalid_redirect_uri', 'redirect_uri must not contain credentials');
  if (url.protocol === 'https:') return raw;
  if (url.protocol === 'http:' && isLoopbackHost(url.hostname)) return raw;
  if (url.protocol === 'http:') throw new OAuthError('invalid_redirect_uri', 'http redirect URIs are only allowed on loopback');
  if (BANNED_SCHEMES.has(url.protocol) || !/^[a-z][a-z0-9+.-]{2,}:$/.test(url.protocol)) {
    throw new OAuthError('invalid_redirect_uri', `redirect_uri scheme ${url.protocol} is not allowed`);
  }
  return raw; // private-use URI scheme for native apps (RFC 8252)
}

function parseScopes(raw: string | null): string[] {
  if (!raw || !raw.trim()) return [...SCOPES];
  const requested = [...new Set(raw.split(/\s+/).filter(Boolean))].filter((s) => s !== 'offline_access');
  const unknown = requested.filter((s) => !isScope(s));
  if (unknown.length) throw new OAuthError('invalid_scope', `Unsupported scope: ${unknown.slice(0, 3).join(' ')}`);
  return requested.length ? requested : [...SCOPES];
}

function verifiedHost(client: StoredClient): string | undefined {
  return client.kind === 'cimd' ? new URL(client.clientId).host : undefined;
}

/**
 * Single-owner OAuth 2.1 authorization server co-hosted with the MCP resource.
 * Authorization requests are approved by the owner in the local control panel;
 * the public listener only shows a waiting page.
 */
export class AuthorizationServer extends EventEmitter {
  private readonly accessTokens = new Map<string, AccessTokenRecord>();
  private readonly codes = new Map<string, AuthCodeRecord>();
  private readonly pending = new Map<string, PendingAuthorization>();
  private readonly limits = {
    register: new RateLimiter(10, 20),
    authorize: new RateLimiter(20, 30),
    token: new RateLimiter(60, 120),
    wait: new RateLimiter(120, 600),
    revoke: new RateLimiter(30, 60),
  };
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly pendingTtl: number;
  private readonly sweeper: NodeJS.Timeout;

  constructor(private readonly opts: AuthServerOptions) {
    super();
    this.accessTtl = (opts.accessTokenTtlSeconds ?? 900) * 1000;
    this.refreshTtl = (opts.refreshTokenTtlSeconds ?? 30 * 24 * 3600) * 1000;
    this.pendingTtl = (opts.pendingTtlSeconds ?? 600) * 1000;
    const identity = this.identity();
    if (opts.store.state.oauth.issuer !== identity?.issuer) this.clearOAuthState(identity?.issuer);
    this.sweeper = setInterval(() => this.sweep(), 15_000);
    this.sweeper.unref();
  }

  private get state() {
    return this.opts.store.state;
  }

  private now(): number {
    return this.opts.clock.now();
  }

  identity(): Identity | undefined {
    return this.state.publicUrl ? identityFor(this.state.publicUrl) : undefined;
  }

  close(): void {
    clearInterval(this.sweeper);
  }

  // ---------------------------------------------------------------- identity

  /** Set (or change) the public base URL. A change invalidates every grant, token, registration and pending request. */
  setPublicUrl(baseUrl: string): boolean {
    if (this.state.publicUrl === baseUrl) return false;
    const hadIdentity = Boolean(this.state.publicUrl);
    this.state.publicUrl = baseUrl;
    this.clearOAuthState(identityFor(baseUrl).issuer);
    this.opts.audit.record({ event: 'identity_changed', decision: hadIdentity ? 'changed' : 'configured' });
    this.emit('all-revoked');
    this.emit('changed');
    return true;
  }

  private clearOAuthState(issuer: string | undefined): void {
    this.accessTokens.clear();
    this.codes.clear();
    for (const p of this.pending.values()) p.status = 'expired';
    this.pending.clear();
    this.state.oauth = { issuer, clients: [], refreshTokens: [] };
    this.opts.store.save();
  }

  // ---------------------------------------------------------------- metadata

  protectedResourceMetadata(identity: Identity) {
    return {
      resource: identity.resource,
      authorization_servers: [identity.issuer],
      scopes_supported: [...SCOPES],
      bearer_methods_supported: ['header'],
      resource_name: 'remote-browser-use (local browser)',
    };
  }

  authorizationServerMetadata(identity: Identity) {
    const base = identity.baseUrl;
    return {
      issuer: identity.issuer,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      revocation_endpoint: `${base}/revoke`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      scopes_supported: [...SCOPES],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
      service_documentation: 'https://www.npmjs.com/package/remote-browser-use',
    };
  }

  // ---------------------------------------------------------------- routing

  /** Handle OAuth/discovery routes on the public listener. Returns false if the path is not an OAuth route. */
  async handle(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
    const path = url.pathname;
    const routes = new Set([
      '/.well-known/oauth-protected-resource',
      '/.well-known/oauth-protected-resource/mcp',
      '/.well-known/oauth-authorization-server',
      '/register',
      '/authorize',
      '/authorize/wait',
      '/token',
      '/revoke',
    ]);
    if (!routes.has(path)) return false;
    const corsPath = path !== '/authorize' && path !== '/authorize/wait';
    if (req.method === 'OPTIONS' && corsPath) {
      res.writeHead(204, CORS_HEADERS);
      res.end();
      return true;
    }
    const identity = this.identity();
    if (!identity) {
      sendJson(
        res,
        503,
        { error: 'temporarily_unavailable', error_description: 'The public HTTPS URL has not been configured in the local control panel yet.' },
        corsPath ? CORS_HEADERS : {},
      );
      return true;
    }
    try {
      switch (path) {
        case '/.well-known/oauth-protected-resource':
        case '/.well-known/oauth-protected-resource/mcp':
          this.requireMethod(req, 'GET');
          sendJson(res, 200, this.protectedResourceMetadata(identity), { ...CORS_HEADERS, 'Cache-Control': 'no-cache' });
          return true;
        case '/.well-known/oauth-authorization-server':
          this.requireMethod(req, 'GET');
          sendJson(res, 200, this.authorizationServerMetadata(identity), { ...CORS_HEADERS, 'Cache-Control': 'no-cache' });
          return true;
        case '/register':
          this.requireMethod(req, 'POST');
          if (!this.limits.register.take('global')) throw new OAuthError('temporarily_unavailable', 'Too many registrations; try again later.', 429);
          sendJson(res, 201, this.register(await readJson(req, 16 * 1024)), TOKEN_HEADERS);
          return true;
        case '/authorize':
          this.requireMethod(req, 'GET');
          await this.authorize(res, url, identity);
          return true;
        case '/authorize/wait':
          this.requireMethod(req, 'GET');
          this.waitPage(res, url, identity);
          return true;
        case '/token':
          this.requireMethod(req, 'POST');
          if (!this.limits.token.take('global')) throw new OAuthError('temporarily_unavailable', 'Too many token requests; slow down.', 429);
          sendJson(res, 200, this.token(await readForm(req), req, identity), TOKEN_HEADERS);
          return true;
        case '/revoke':
          this.requireMethod(req, 'POST');
          if (!this.limits.revoke.take('global')) throw new OAuthError('temporarily_unavailable', 'Too many requests.', 429);
          this.revoke(await readForm(req), req);
          send(res, 200, '', 'text/plain', TOKEN_HEADERS);
          return true;
      }
    } catch (error) {
      if (error instanceof OAuthError) {
        const headers: Record<string, string> = { ...TOKEN_HEADERS };
        if (error.status === 401) headers['WWW-Authenticate'] = 'Basic realm="remote-browser-use"';
        sendJson(res, error.status, { error: error.code, error_description: error.description }, headers);
        return true;
      }
      if (error instanceof HttpError) {
        sendJson(res, error.status, { error: 'invalid_request', error_description: error.message }, TOKEN_HEADERS);
        return true;
      }
      throw error;
    }
    return false;
  }

  private requireMethod(req: IncomingMessage, method: string): void {
    if (req.method !== method) throw new OAuthError('invalid_request', `Use ${method}`, 405);
  }

  // ---------------------------------------------------------------- registration (RFC 7591)

  private register(body: unknown) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new OAuthError('invalid_client_metadata', 'Expected a JSON object');
    const b = body as Record<string, unknown>;
    const redirectUris = b.redirect_uris;
    if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 10 || !redirectUris.every((u) => typeof u === 'string' && u.length <= 2000)) {
      throw new OAuthError('invalid_redirect_uri', 'redirect_uris must be a non-empty array of up to 10 URLs');
    }
    redirectUris.forEach((u) => validateRedirectUri(u as string));
    const grantTypes = (b.grant_types as unknown[] | undefined) ?? ['authorization_code'];
    if (!Array.isArray(grantTypes) || !grantTypes.includes('authorization_code') || grantTypes.some((g) => g !== 'authorization_code' && g !== 'refresh_token')) {
      throw new OAuthError('invalid_client_metadata', 'grant_types must include authorization_code and may include refresh_token');
    }
    const responseTypes = (b.response_types as unknown[] | undefined) ?? ['code'];
    if (!Array.isArray(responseTypes) || responseTypes.some((r) => r !== 'code')) {
      throw new OAuthError('invalid_client_metadata', 'response_types must be ["code"]');
    }
    const method = (b.token_endpoint_auth_method as string | undefined) ?? 'client_secret_basic';
    if (method !== 'none' && method !== 'client_secret_post' && method !== 'client_secret_basic') {
      throw new OAuthError('invalid_client_metadata', `Unsupported token_endpoint_auth_method ${String(method)}`);
    }
    this.pruneClients();
    if (this.state.oauth.clients.length >= MAX_CLIENTS) throw new OAuthError('temporarily_unavailable', 'Too many registered clients; remove some in the control panel.', 503);
    const clientId = `dcr_${randomToken(16)}`;
    const secret = method === 'none' ? undefined : `rbu_cs_${randomToken(32)}`;
    const client: StoredClient = {
      clientId,
      kind: 'dcr',
      name: sanitizeText(b.client_name, 80) || 'Unnamed client',
      redirectUris: redirectUris as string[],
      tokenEndpointAuthMethod: method,
      secretHash: secret ? sha256(secret) : undefined,
      createdAt: this.now(),
      approved: false,
      scopes: [],
      tools: [],
    };
    this.state.oauth.clients.push(client);
    this.opts.store.save();
    this.opts.audit.record({ event: 'client_registered', client: clientId, decision: 'dcr' });
    this.emit('changed');
    return {
      client_id: clientId,
      client_id_issued_at: Math.floor(client.createdAt / 1000),
      client_name: client.name,
      redirect_uris: client.redirectUris,
      grant_types: grantTypes,
      response_types: ['code'],
      token_endpoint_auth_method: method,
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
    };
  }

  private pruneClients(): void {
    const cutoff = this.now() - 24 * 3600 * 1000;
    const before = this.state.oauth.clients.length;
    this.state.oauth.clients = this.state.oauth.clients.filter((c) => c.approved || c.createdAt > cutoff);
    if (this.state.oauth.clients.length !== before) this.opts.store.save();
  }

  private client(clientId: string): StoredClient | undefined {
    return this.state.oauth.clients.find((c) => c.clientId === clientId);
  }

  // ---------------------------------------------------------------- authorization endpoint

  private async resolveClient(clientId: string, redirectUri: string): Promise<StoredClient> {
    if (isCimdClientId(clientId)) {
      let doc;
      try {
        doc = validateClientMetadata(clientId, await this.opts.fetchClientMetadata(clientId));
      } catch (error) {
        throw new OAuthError('invalid_client', `Could not use client metadata document: ${(error as Error).message}`);
      }
      if (!doc.redirect_uris.includes(redirectUri)) throw new OAuthError('invalid_redirect_uri', 'redirect_uri is not listed in the client metadata document');
      validateRedirectUri(redirectUri);
      let client = this.client(clientId);
      if (!client) {
        this.pruneClients();
        if (this.state.oauth.clients.length >= MAX_CLIENTS) throw new OAuthError('temporarily_unavailable', 'Too many registered clients', 503);
        client = {
          clientId,
          kind: 'cimd',
          name: sanitizeText(doc.client_name, 80) || new URL(clientId).host,
          redirectUris: doc.redirect_uris,
          tokenEndpointAuthMethod: 'none',
          createdAt: this.now(),
          approved: false,
          scopes: [],
          tools: [],
        };
        this.state.oauth.clients.push(client);
        this.opts.audit.record({ event: 'client_registered', client: clientId, decision: 'cimd' });
      } else {
        client.name = sanitizeText(doc.client_name, 80) || client.name;
        client.redirectUris = doc.redirect_uris;
      }
      this.opts.store.save();
      return client;
    }
    const client = this.client(clientId);
    if (!client) throw new OAuthError('invalid_client', 'Unknown client_id. Register the client again (the server URL may have changed).');
    if (!client.redirectUris.includes(redirectUri)) throw new OAuthError('invalid_redirect_uri', 'redirect_uri does not exactly match a registered redirect URI');
    return client;
  }

  private async authorize(res: ServerResponse, url: URL, identity: Identity): Promise<void> {
    const q = url.searchParams;
    const clientId = q.get('client_id') ?? '';
    const redirectUri = q.get('redirect_uri') ?? '';
    let client: StoredClient;
    try {
      if (!this.limits.authorize.take('global')) throw new OAuthError('temporarily_unavailable', 'Too many authorization requests; try again shortly.', 429);
      if (!clientId || !redirectUri) throw new OAuthError('invalid_request', 'client_id and redirect_uri are required');
      client = await this.resolveClient(clientId, redirectUri);
    } catch (error) {
      // Never redirect to an unverified redirect_uri: show the error here instead.
      const e = error instanceof OAuthError ? error : new OAuthError('server_error', 'Unexpected error');
      sendHtml(res, e.status === 429 ? 429 : 400, this.page('Authorization failed', `<p>${escapeHtml(e.description)}</p>`), this.pageHeaders());
      return;
    }
    const state = q.get('state') ?? undefined;
    const fail = (code: string, description: string) => {
      res.writeHead(302, { Location: this.redirectWith(redirectUri, { error: code, error_description: description, state }, identity), 'Cache-Control': 'no-store' });
      res.end();
    };
    try {
      if (q.get('response_type') !== 'code') throw new OAuthError('unsupported_response_type', 'response_type must be code');
      const challenge = q.get('code_challenge') ?? '';
      if (q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
        throw new OAuthError('invalid_request', 'PKCE with code_challenge_method=S256 is required');
      }
      const resource = q.get('resource');
      if (q.getAll('resource').length > 1) throw new OAuthError('invalid_target', 'Only one resource may be requested');
      if (resource !== null && resource.replace(/\/$/, '') !== identity.resource && resource.replace(/\/$/, '') !== identity.baseUrl) {
        throw new OAuthError('invalid_target', 'resource does not identify this MCP server');
      }
      const scopes = parseScopes(q.get('scope'));
      const active = [...this.pending.values()].filter((p) => p.status === 'pending');
      if (active.length >= MAX_PENDING) throw new OAuthError('temporarily_unavailable', 'Too many pending authorization requests');
      const pending: PendingAuthorization = {
        id: randomToken(9),
        handle: randomToken(24),
        clientId: client.clientId,
        redirectUri,
        requestedScopes: scopes,
        state,
        codeChallenge: challenge,
        resource: identity.resource,
        createdAt: this.now(),
        expiresAt: this.now() + this.pendingTtl,
        matchCode: humanCode(6, 3),
        status: 'pending',
      };
      this.pending.set(pending.id, pending);
      this.opts.audit.record({ event: 'authorization_requested', client: client.clientId });
      this.emit('changed');
      this.renderWaiting(res, pending, client);
    } catch (error) {
      const e = error instanceof OAuthError ? error : new OAuthError('server_error', 'Unexpected error');
      fail(e.code, e.description);
    }
  }

  private redirectWith(redirectUri: string, params: Record<string, string | undefined>, identity: Identity): string {
    const target = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v !== undefined) target.searchParams.set(k, v);
    target.searchParams.set('iss', identity.issuer);
    return target.toString();
  }

  private pageHeaders(nonce?: string): Record<string, string> {
    return {
      'Content-Security-Policy': `default-src 'none'; style-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
    };
  }

  private page(title: string, body: string, nonce = randomToken(12), refresh?: string): string {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
${refresh ? `<meta http-equiv="refresh" content="2;url=${escapeHtml(refresh)}">` : ''}
<title>${escapeHtml(title)}</title><style nonce="${nonce}">body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#1d1d1f}
.code{font:600 1.6rem ui-monospace,monospace;letter-spacing:.15em;background:#f2f2f7;padding:.4rem .8rem;border-radius:.4rem;display:inline-block}
.muted{color:#555}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
  }

  private renderWaiting(res: ServerResponse, pending: PendingAuthorization, client: StoredClient): void {
    const nonce = randomToken(12);
    const host = verifiedHost(client);
    const body = `<p>Approve this connection on <strong>the computer running remote-browser-use</strong>, in its local control panel. The control panel is not reachable through this link.</p>
<p>Check that the control panel shows the same match code:</p><p class="code">${escapeHtml(pending.matchCode)}</p>
<p class="muted">Client: ${escapeHtml(client.name)}${host ? ` (${escapeHtml(host)})` : ' (name not verified)'}</p>
<p class="muted">This page refreshes automatically and continues once the owner approves or denies. Requests expire after ${Math.round(this.pendingTtl / 60000)} minutes.</p>`;
    sendHtml(res, 200, this.page('Waiting for owner approval', body, nonce, `/authorize/wait?h=${pending.handle}`), this.pageHeaders(nonce));
  }

  private waitPage(res: ServerResponse, url: URL, identity: Identity): void {
    if (!this.limits.wait.take('global')) {
      sendHtml(res, 429, this.page('Slow down', '<p>Too many requests.</p>'), this.pageHeaders());
      return;
    }
    const handle = url.searchParams.get('h') ?? '';
    const pending = [...this.pending.values()].find((p) => safeEqual(p.handle, handle));
    if (!pending) {
      sendHtml(res, 404, this.page('Request not found', '<p>This authorization request is unknown or already finished. Start the connection again from your chat app.</p>'), this.pageHeaders());
      return;
    }
    if (pending.status === 'pending' && this.now() > pending.expiresAt) pending.status = 'expired';
    if (pending.status === 'pending') {
      const client = this.client(pending.clientId);
      if (!client) pending.status = 'expired';
      else return this.renderWaiting(res, pending, client);
    }
    this.pending.delete(pending.id);
    const location =
      pending.status === 'approved' && pending.redirectTo
        ? pending.redirectTo
        : this.redirectWith(pending.redirectUri, { error: 'access_denied', error_description: pending.status === 'expired' ? 'The owner did not approve in time' : 'The owner denied access', state: pending.state }, identity);
    res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
    res.end();
  }

  // ---------------------------------------------------------------- owner decisions (local panel only)

  pendingAuthorizations(): PendingAuthorizationView[] {
    const now = this.now();
    const out: PendingAuthorizationView[] = [];
    for (const p of this.pending.values()) {
      if (p.status !== 'pending' || now > p.expiresAt) continue;
      const client = this.client(p.clientId);
      if (!client) continue;
      out.push({
        id: p.id,
        clientId: client.clientId,
        clientName: client.name,
        clientKind: client.kind,
        verifiedHost: verifiedHost(client),
        redirectUri: p.redirectUri,
        requestedScopes: p.requestedScopes,
        matchCode: p.matchCode,
        createdAt: p.createdAt,
        expiresAt: p.expiresAt,
        previouslyApproved: client.approved,
        allowedTools: toolsAllowedByScopes(p.requestedScopes, this.opts.toolCeiling),
      });
    }
    return out;
  }

  approveAuthorization(id: string, scopes: string[], tools: string[]): void {
    const pending = this.pending.get(id);
    const identity = this.identity();
    if (!pending || pending.status !== 'pending' || this.now() > pending.expiresAt || !identity) throw new Error('This authorization request is no longer pending.');
    const client = this.client(pending.clientId);
    if (!client) throw new Error('Client no longer exists.');
    const granted = scopes.filter((s) => pending.requestedScopes.includes(s));
    if (granted.length === 0) throw new Error('Grant at least one scope, or deny the request.');
    const allowedTools = toolsAllowedByScopes(granted, this.opts.toolCeiling);
    const badTool = tools.find((t) => !(allowedTools as string[]).includes(t));
    if (badTool) throw new Error(`Tool ${badTool} is not allowed by the granted scopes or the --tools ceiling.`);
    client.approved = true;
    client.scopes = granted;
    client.tools = [...new Set(tools)];
    this.opts.store.save();
    const code = `rbu_ac_${randomToken(32)}`;
    this.codes.set(sha256(code), {
      clientId: client.clientId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      scopes: granted,
      resource: pending.resource,
      expiresAt: this.now() + CODE_TTL_MS,
      used: false,
      familyId: randomToken(12),
    });
    pending.status = 'approved';
    pending.redirectTo = this.redirectWith(pending.redirectUri, { code, state: pending.state }, identity);
    this.opts.audit.record({ event: 'authorization_decided', client: client.clientId, decision: 'approved' });
    this.emit('changed');
  }

  denyAuthorization(id: string): void {
    const pending = this.pending.get(id);
    if (!pending || pending.status !== 'pending') return;
    pending.status = 'denied';
    this.opts.audit.record({ event: 'authorization_decided', client: pending.clientId, decision: 'denied' });
    this.emit('changed');
  }

  clients(): ClientView[] {
    return this.state.oauth.clients.map((c) => ({
      clientId: c.clientId,
      name: c.name,
      kind: c.kind,
      verifiedHost: verifiedHost(c),
      redirectUris: c.redirectUris,
      approved: c.approved,
      scopes: c.scopes,
      tools: c.tools,
      allowedTools: toolsAllowedByScopes(c.scopes, this.opts.toolCeiling),
      activeTokens: [...this.accessTokens.values()].filter((t) => t.clientId === c.clientId && t.expiresAt > this.now()).length,
      lastUsed: c.lastUsed,
    }));
  }

  verifyClientActive(clientId: string): boolean {
    return Boolean(this.client(clientId)?.approved);
  }

  clientName(clientId: string): string {
    return this.client(clientId)?.name ?? 'unknown client';
  }

  clientTools(clientId: string): ToolName[] {
    const c = this.client(clientId);
    if (!c?.approved) return [];
    const allowed = toolsAllowedByScopes(c.scopes, this.opts.toolCeiling);
    return allowed.filter((t) => c.tools.includes(t));
  }

  setClientTools(clientId: string, tools: string[]): void {
    const c = this.client(clientId);
    if (!c) throw new Error('Unknown client');
    const allowed = toolsAllowedByScopes(c.scopes, this.opts.toolCeiling) as string[];
    const bad = tools.find((t) => !allowed.includes(t));
    if (bad) throw new Error(`Tool ${bad} is not allowed by this client's scopes or the --tools ceiling.`);
    c.tools = [...new Set(tools)];
    this.opts.store.save();
    this.opts.audit.record({ event: 'grant_changed', client: clientId, decision: 'tools_updated' });
    this.emit('changed');
  }

  /** Revoke every token of a client; it must be re-approved before it can connect again. */
  revokeClient(clientId: string, remove = false): void {
    for (const [hash, t] of this.accessTokens) if (t.clientId === clientId) this.accessTokens.delete(hash);
    for (const [hash, c] of this.codes) if (c.clientId === clientId) this.codes.delete(hash);
    for (const p of this.pending.values()) if (p.clientId === clientId && p.status === 'pending') p.status = 'denied';
    this.state.oauth.refreshTokens = this.state.oauth.refreshTokens.filter((r) => r.clientId !== clientId);
    const client = this.client(clientId);
    if (client) client.approved = false;
    if (remove) this.state.oauth.clients = this.state.oauth.clients.filter((c) => c.clientId !== clientId);
    this.opts.store.save();
    this.opts.audit.record({ event: 'token_revoked', client: clientId, decision: remove ? 'client_removed' : 'client_revoked' });
    this.emit('client-revoked', clientId);
    this.emit('changed');
  }

  /** Kill switch: invalidate every token, code and pending request for all clients. */
  revokeAll(): void {
    this.accessTokens.clear();
    this.codes.clear();
    for (const p of this.pending.values()) if (p.status === 'pending') p.status = 'denied';
    this.state.oauth.refreshTokens = [];
    for (const c of this.state.oauth.clients) c.approved = false;
    this.opts.store.save();
    this.emit('all-revoked');
    this.emit('changed');
  }

  // ---------------------------------------------------------------- token endpoint

  private authenticateClient(params: URLSearchParams, req: IncomingMessage): StoredClient {
    let clientId = params.get('client_id') ?? undefined;
    let secret = params.get('client_secret') ?? undefined;
    const header = req.headers.authorization;
    let usedBasic = false;
    if (header?.startsWith('Basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      if (idx < 0) throw new OAuthError('invalid_client', 'Malformed Basic credentials', 401);
      const basicId = decodeURIComponent(decoded.slice(0, idx));
      if (clientId && clientId !== basicId) throw new OAuthError('invalid_client', 'client_id mismatch', 401);
      clientId = basicId;
      secret = decodeURIComponent(decoded.slice(idx + 1));
      usedBasic = true;
    }
    if (!clientId) throw new OAuthError('invalid_client', 'client_id is required', 401);
    const client = this.client(clientId);
    if (!client) throw new OAuthError('invalid_client', 'Unknown client', 401);
    if (client.secretHash) {
      if (!secret || !safeEqual(sha256(secret), client.secretHash)) throw new OAuthError('invalid_client', 'Client authentication failed', 401);
    } else if (secret || usedBasic) {
      throw new OAuthError('invalid_client', 'This is a public client; do not send a client secret', 401);
    }
    return client;
  }

  private token(params: URLSearchParams, req: IncomingMessage, identity: Identity) {
    const grantType = params.get('grant_type');
    const client = this.authenticateClient(params, req);
    const resource = params.get('resource');
    if (resource !== null && resource.replace(/\/$/, '') !== identity.resource && resource.replace(/\/$/, '') !== identity.baseUrl) {
      throw new OAuthError('invalid_target', 'resource does not identify this MCP server');
    }
    if (grantType === 'authorization_code') {
      const code = params.get('code') ?? '';
      const record = this.codes.get(sha256(code));
      if (!record) throw new OAuthError('invalid_grant', 'Unknown or expired authorization code');
      if (record.used) {
        this.revokeFamily(record.familyId);
        this.codes.delete(sha256(code));
        throw new OAuthError('invalid_grant', 'Authorization code was already used');
      }
      record.used = true;
      if (record.expiresAt < this.now()) throw new OAuthError('invalid_grant', 'Authorization code expired');
      if (record.clientId !== client.clientId) throw new OAuthError('invalid_grant', 'Code was issued to another client');
      if (params.get('redirect_uri') !== record.redirectUri) throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request');
      const verifier = params.get('code_verifier') ?? '';
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || !safeEqual(pkceChallenge(verifier), record.codeChallenge)) {
        throw new OAuthError('invalid_grant', 'PKCE verification failed');
      }
      if (!client.approved) throw new OAuthError('invalid_grant', 'Client is no longer approved');
      const scopes = record.scopes.filter((s) => client.scopes.includes(s));
      const issued = this.issueTokens(client, scopes, record.familyId, identity);
      this.opts.audit.record({ event: 'token_issued', client: client.clientId });
      return issued;
    }
    if (grantType === 'refresh_token') {
      const raw = params.get('refresh_token') ?? '';
      const hash = sha256(raw);
      const record = this.state.oauth.refreshTokens.find((r) => safeEqual(r.hash, hash));
      if (!record) throw new OAuthError('invalid_grant', 'Unknown refresh token');
      if (record.clientId !== client.clientId) throw new OAuthError('invalid_grant', 'Refresh token was issued to another client');
      if (record.used) {
        this.revokeFamily(record.familyId);
        this.opts.audit.record({ event: 'refresh_reuse_detected', client: client.clientId, decision: 'family_revoked' });
        throw new OAuthError('invalid_grant', 'Refresh token reuse detected; all tokens in this grant were revoked');
      }
      if (record.expiresAt < this.now()) throw new OAuthError('invalid_grant', 'Refresh token expired');
      if (!client.approved) throw new OAuthError('invalid_grant', 'Client is no longer approved');
      record.used = true;
      let scopes = record.scopes.filter((s) => client.scopes.includes(s));
      const requested = params.get('scope');
      if (requested) {
        const narrowed = parseScopes(requested);
        if (narrowed.some((s) => !scopes.includes(s))) throw new OAuthError('invalid_scope', 'Cannot widen scope on refresh');
        scopes = narrowed;
      }
      const issued = this.issueTokens(client, scopes, record.familyId, identity);
      this.opts.audit.record({ event: 'token_refreshed', client: client.clientId });
      return issued;
    }
    throw new OAuthError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
  }

  private issueTokens(client: StoredClient, scopes: string[], familyId: string, identity: Identity) {
    const access = `rbu_at_${randomToken(32)}`;
    const refresh = `rbu_rt_${randomToken(32)}`;
    const now = this.now();
    this.accessTokens.set(sha256(access), { clientId: client.clientId, scopes, resource: identity.resource, expiresAt: now + this.accessTtl, familyId });
    const record: StoredRefreshToken = { hash: sha256(refresh), clientId: client.clientId, scopes, familyId, expiresAt: now + this.refreshTtl, used: false };
    this.state.oauth.refreshTokens = this.state.oauth.refreshTokens.filter((r) => !(r.used && r.expiresAt < now));
    this.state.oauth.refreshTokens.push(record);
    client.lastUsed = now;
    this.opts.store.save();
    this.emit('changed');
    return { access_token: access, token_type: 'Bearer', expires_in: Math.floor(this.accessTtl / 1000), refresh_token: refresh, scope: scopes.join(' ') };
  }

  private revokeFamily(familyId: string): void {
    for (const [hash, t] of this.accessTokens) if (t.familyId === familyId) this.accessTokens.delete(hash);
    this.state.oauth.refreshTokens = this.state.oauth.refreshTokens.filter((r) => r.familyId !== familyId);
    this.opts.store.save();
  }

  private revoke(params: URLSearchParams, req: IncomingMessage): void {
    const client = this.authenticateClient(params, req);
    const hash = sha256(params.get('token') ?? '');
    const access = this.accessTokens.get(hash);
    if (access && access.clientId === client.clientId) {
      this.revokeFamily(access.familyId);
      this.opts.audit.record({ event: 'token_revoked', client: client.clientId, decision: 'client_request' });
      return;
    }
    const refresh = this.state.oauth.refreshTokens.find((r) => r.hash === hash);
    if (refresh && refresh.clientId === client.clientId) {
      this.revokeFamily(refresh.familyId);
      this.opts.audit.record({ event: 'token_revoked', client: client.clientId, decision: 'client_request' });
    }
  }

  // ---------------------------------------------------------------- resource server

  /** Validate a bearer token for the MCP resource: existence, expiry, audience, and client approval. */
  verifyAccessToken(token: string): AuthInfo | undefined {
    const identity = this.identity();
    if (!identity) return undefined;
    const record = this.accessTokens.get(sha256(token));
    if (!record) return undefined;
    if (record.expiresAt <= this.now()) {
      this.accessTokens.delete(sha256(token));
      return undefined;
    }
    if (record.resource !== identity.resource) return undefined;
    const client = this.client(record.clientId);
    if (!client?.approved) return undefined;
    const scopes = record.scopes.filter((s) => client.scopes.includes(s));
    return { token, clientId: record.clientId, scopes, expiresAt: Math.floor(record.expiresAt / 1000), resource: new URL(record.resource) };
  }

  private sweep(): void {
    const now = this.now();
    for (const [hash, t] of this.accessTokens) if (t.expiresAt <= now) this.accessTokens.delete(hash);
    for (const [hash, c] of this.codes) if (c.expiresAt <= now) this.codes.delete(hash);
    let changed = false;
    for (const p of this.pending.values()) {
      if (p.status === 'pending' && now > p.expiresAt) {
        p.status = 'expired';
        changed = true;
        this.opts.audit.record({ event: 'authorization_decided', client: p.clientId, decision: 'expired' });
      }
      if (now > p.expiresAt + 10 * 60_000) this.pending.delete(p.id);
    }
    if (changed) this.emit('changed');
  }
}
