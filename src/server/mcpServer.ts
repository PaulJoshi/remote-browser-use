import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { createMcpHandler, type McpHttpHandler, type McpServer } from '@modelcontextprotocol/server';
import type { AuditLog } from '../audit/audit.js';
import type { AuthInfo, AuthorizationServer } from '../auth/oauth.js';
import { isToolName, SCOPES, TOOL_SCOPES } from '../policy/scopes.js';
import { HttpError, hostHeader, readBody, safeJson, sendJson, BASE_SECURITY_HEADERS, send } from '../util/http.js';
import { RateLimiter } from '../util/rateLimit.js';
import { sha256 } from '../util/crypto.js';

export const MAX_MCP_BODY = 1024 * 1024;

export interface McpListenerOptions {
  port: number;
  auth: AuthorizationServer;
  audit: AuditLog;
  buildServer: (authInfo: AuthInfo) => McpServer;
  onError?: (error: Error) => void;
}

const EXPOSE_HEADERS = 'WWW-Authenticate, Mcp-Session-Id, MCP-Protocol-Version';

/**
 * The forwarded (public) listener: Streamable HTTP MCP at /mcp plus OAuth and
 * discovery routes. There are deliberately no admin routes on this listener.
 */
export class McpListener {
  readonly server: Server;
  private readonly handler: McpHttpHandler;
  private readonly globalLimit = new RateLimiter(300, 1200);
  private readonly clientLimit = new RateLimiter(120, 600);

  constructor(private readonly opts: McpListenerOptions) {
    this.handler = createMcpHandler(
      ({ authInfo }) => {
        if (!authInfo) throw new Error('unauthenticated MCP request reached the handler');
        return opts.buildServer(authInfo as AuthInfo);
      },
      { maxRequestBodySize: MAX_MCP_BODY, onerror: (e) => opts.onError?.(e) },
    );
    this.server = createServer((req, res) => {
      this.route(req, res).catch((error: unknown) => {
        if (error instanceof HttpError) {
          sendJson(res, error.status, { error: error.message });
          return;
        }
        opts.onError?.(error as Error);
        if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
        else res.end();
      });
    });
    this.server.requestTimeout = 330_000;
    this.server.headersTimeout = 20_000;
    this.server.keepAliveTimeout = 5_000;
  }

  listen(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.opts.port, '127.0.0.1', () => {
        this.server.off('error', reject);
        resolve();
      });
    });
  }

  async close(): Promise<void> {
    await this.handler.close().catch(() => undefined);
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    this.server.closeAllConnections();
  }

  private allowedHosts(): Set<string> {
    const hosts = new Set([`127.0.0.1:${this.opts.port}`, `localhost:${this.opts.port}`]);
    const identity = this.opts.auth.identity();
    if (identity) hosts.add(new URL(identity.baseUrl).host);
    return hosts;
  }

  private allowedOrigins(): Set<string> {
    const origins = new Set([`http://127.0.0.1:${this.opts.port}`, `http://localhost:${this.opts.port}`]);
    const identity = this.opts.auth.identity();
    if (identity) origins.add(new URL(identity.baseUrl).origin);
    return origins;
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const host = hostHeader(req);
    if (!host || !this.allowedHosts().has(host)) {
      send(res, 421, 'Unrecognized Host header. If you reach this server through a tunnel, enter the tunnel\'s https URL in the local control panel first.\n', 'text/plain; charset=utf-8');
      return;
    }
    if (!this.globalLimit.take('global')) {
      sendJson(res, 429, { error: 'rate_limited' }, { 'Retry-After': '10' });
      return;
    }
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${this.opts.port}`);
    if (url.pathname === '/mcp' || url.pathname === '/mcp/') return this.mcp(req, res, url);
    if (await this.opts.auth.handle(req, res, url)) return;
    if (url.pathname === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
      send(res, 200, 'remote-browser-use MCP endpoint. Add <this base URL>/mcp to an MCP-capable chat app. OAuth is required.\n', 'text/plain; charset=utf-8');
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
  }

  private corsHeaders(origin: string | undefined): Record<string, string> {
    if (!origin) return {};
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Expose-Headers': EXPOSE_HEADERS,
      Vary: 'Origin',
    };
  }

  private challenge(res: ServerResponse, status: 401 | 403, params: Record<string, string>, cors: Record<string, string>, body: unknown): void {
    const header = `Bearer ${Object.entries(params)
      .map(([k, v]) => `${k}="${v.replace(/["\\]/g, '')}"`)
      .join(', ')}`;
    sendJson(res, status, body, { ...cors, 'WWW-Authenticate': header });
  }

  private async mcp(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const origin = typeof req.headers.origin === 'string' ? req.headers.origin : undefined;
    if (origin !== undefined && !this.allowedOrigins().has(origin)) {
      sendJson(res, 403, { jsonrpc: '2.0', error: { code: -32000, message: 'Origin not allowed' }, id: null });
      return;
    }
    const cors = this.corsHeaders(origin);
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        ...BASE_SECURITY_HEADERS,
        ...cors,
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept, MCP-Protocol-Version, Mcp-Session-Id, Mcp-Method, Mcp-Name, Last-Event-ID',
        'Access-Control-Max-Age': '600',
      });
      res.end();
      return;
    }
    if (url.searchParams.has('access_token')) {
      sendJson(res, 400, { error: 'invalid_request', error_description: 'Access tokens must be sent in the Authorization header, never in the URL.' }, cors);
      return;
    }
    const identity = this.opts.auth.identity();
    if (!identity) {
      this.challenge(res, 401, { realm: 'remote-browser-use', error: 'invalid_token', error_description: 'The owner has not configured the public HTTPS URL yet' }, cors, {
        error: 'public_url_not_configured',
        error_description: 'Open the remote-browser-use control panel on the host computer and enter the forwarded https URL.',
      });
      return;
    }
    const authz = req.headers.authorization;
    const token = authz?.startsWith('Bearer ') ? authz.slice(7).trim() : undefined;
    const authInfo = token ? this.opts.auth.verifyAccessToken(token) : undefined;
    if (!authInfo) {
      if (token) this.opts.audit.record({ event: 'token_rejected', reason: 'invalid_or_expired' });
      const params: Record<string, string> = { resource_metadata: identity.resourceMetadataUrl, scope: SCOPES.join(' ') };
      if (token) {
        params.error = 'invalid_token';
        params.error_description = 'The access token is invalid, expired, revoked, or for another resource';
      }
      this.challenge(res, 401, params, cors, { error: token ? 'invalid_token' : 'unauthorized', error_description: 'OAuth access token required' });
      return;
    }
    if (!this.clientLimit.take(sha256(authInfo.clientId))) {
      sendJson(res, 429, { error: 'rate_limited' }, { ...cors, 'Retry-After': '5' });
      return;
    }

    let parsedBody: unknown;
    let rawBody: Buffer | undefined;
    if (req.method === 'POST') {
      rawBody = await readBody(req, MAX_MCP_BODY);
      parsedBody = safeJson(rawBody.toString('utf8'));
      const messages = Array.isArray(parsedBody) ? parsedBody : [parsedBody];
      for (const message of messages) {
        const m = message as { method?: unknown; params?: { name?: unknown } } | undefined;
        if (m?.method !== 'tools/call' || typeof m.params?.name !== 'string' || !isToolName(m.params.name)) continue;
        const needed = TOOL_SCOPES[m.params.name];
        if (!authInfo.scopes.includes(needed)) {
          this.opts.audit.record({ event: 'tool', tool: m.params.name, client: authInfo.clientId, decision: 'denied', reason: 'insufficient_scope' });
          this.challenge(
            res,
            403,
            { error: 'insufficient_scope', scope: [...new Set([...authInfo.scopes, needed])].join(' '), resource_metadata: identity.resourceMetadataUrl, error_description: `${m.params.name} requires ${needed}` },
            cors,
            { error: 'insufficient_scope', error_description: `${m.params.name} requires the ${needed} scope` },
          );
          return;
        }
      }
    }

    const abort = new AbortController();
    res.on('close', () => {
      if (!res.writableFinished) abort.abort();
    });
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value === undefined || key === 'host' || key === 'connection' || key === 'content-length') continue;
      headers.set(key, Array.isArray(value) ? value.join(', ') : value);
    }
    const request = new Request(`http://127.0.0.1:${this.opts.port}/mcp`, {
      method: req.method,
      headers,
      body: rawBody && rawBody.length ? new Uint8Array(rawBody) : undefined,
      signal: abort.signal,
    });
    const response = await this.handler.fetch(request, parsedBody === undefined ? { authInfo } : { authInfo, parsedBody });
    const outHeaders: Record<string, string> = { ...BASE_SECURITY_HEADERS, ...cors };
    response.headers.forEach((value, key) => {
      outHeaders[key] = value;
    });
    if (outHeaders['content-type']?.startsWith('text/event-stream')) outHeaders['X-Accel-Buffering'] = 'no';
    res.writeHead(response.status, outHeaders);
    if (!response.body) {
      res.end();
      return;
    }
    Readable.fromWeb(response.body as import('node:stream/web').ReadableStream).pipe(res);
  }
}
