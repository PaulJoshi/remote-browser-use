import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuditLog } from '../audit/audit.js';
import type { AuthorizationServer } from '../auth/oauth.js';
import type { BrowserManager } from '../browser/manager.js';
import type { ResolvedConfig } from '../config.js';
import type { ApprovalQueue } from '../policy/approvals.js';
import type { GrantStore } from '../policy/grants.js';
import { PRESETS, SCOPES, TOOL_SCOPES } from '../policy/scopes.js';
import type { StateStore, StoredDevice } from '../store.js';
import { HttpError, hostHeader, readJson, send, sendJson } from '../util/http.js';
import { LoginError, OwnerAuth } from './ownerAuth.js';

export interface AdminDeps {
  config: ResolvedConfig;
  version: string;
  store: StateStore;
  auth: AuthorizationServer;
  grants: GrantStore;
  approvals: ApprovalQueue;
  browser: BrowserManager;
  audit: AuditLog;
  owner: OwnerAuth;
  localExceptions: ReadonlySet<string>;
  setPublicUrl: (url: string) => void;
  killAll: () => void;
  openOwnerTab: (url: string) => Promise<string>;
}

const STATIC_DIR = join(dirname(fileURLToPath(import.meta.url)), 'static');
const STATIC: Record<string, string> = {
  '/': 'panel.html',
  '/panel.js': 'panel.js',
  '/panel.css': 'panel.css',
};
const TYPES: Record<string, string> = { html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8' };
const PANEL_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

function str(v: unknown, max = 2000): string {
  if (typeof v !== 'string') throw new HttpError(400, 'Invalid request');
  return v.slice(0, max);
}

function strList(v: unknown): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > 50 || !v.every((s) => typeof s === 'string')) throw new HttpError(400, 'Invalid list');
  return v as string[];
}

/**
 * Local-only control panel on a separate port that must never be forwarded.
 * Requires an exact loopback Host, a same-origin Origin on every state change,
 * an owner device cookie, and a CSRF token header.
 */
export class AdminServer {
  readonly server: Server;

  constructor(private readonly d: AdminDeps) {
    this.server = createServer((req, res) => {
      this.route(req, res).catch((error: unknown) => {
        if (error instanceof HttpError) return sendJson(res, error.status, { error: error.message });
        if (error instanceof LoginError) return sendJson(res, 403, { error: error.message });
        const message = (error as Error)?.message ?? 'error';
        sendJson(res, 400, { error: message.slice(0, 300) });
      });
    });
    this.server.requestTimeout = 30_000;
    this.server.headersTimeout = 10_000;
  }

  listen(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.d.config.adminPort, '127.0.0.1', () => {
        this.server.off('error', reject);
        resolve();
      });
    });
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    this.server.closeAllConnections();
  }

  private origins(): Set<string> {
    const p = this.d.config.adminPort;
    return new Set([`http://127.0.0.1:${p}`, `http://localhost:${p}`]);
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const port = this.d.config.adminPort;
    const host = hostHeader(req);
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
      send(res, 421, 'This control panel only answers on http://127.0.0.1:' + port + ' (it must never be forwarded or tunneled).\n', 'text/plain; charset=utf-8');
      return;
    }
    const origin = req.headers.origin;
    if (origin !== undefined && !this.origins().has(origin)) {
      sendJson(res, 403, { error: 'Cross-origin requests are not allowed' });
      return;
    }
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin' && site !== 'none') {
      sendJson(res, 403, { error: 'Cross-site requests are not allowed' });
      return;
    }
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
    const file = STATIC[url.pathname];
    if (file && req.method === 'GET') {
      const ext = file.split('.').pop()!;
      send(res, 200, readFileSync(join(STATIC_DIR, file)), TYPES[ext]!, { 'Content-Security-Policy': PANEL_CSP });
      return;
    }
    if (!url.pathname.startsWith('/api/')) {
      sendJson(res, 404, { error: 'not_found' });
      return;
    }
    if (req.method === 'POST' && origin === undefined) {
      sendJson(res, 403, { error: 'Missing Origin header' });
      return;
    }
    const cookie = OwnerAuth.readCookie(req.headers.cookie);
    const device = this.d.owner.authenticate(cookie);

    if (url.pathname === '/api/session' && req.method === 'GET') {
      sendJson(res, 200, device ? { authenticated: true, csrf: this.d.owner.csrfToken(device) } : { authenticated: false });
      return;
    }
    if (url.pathname === '/api/login' && req.method === 'POST') {
      const body = (await readJson(req, 4096)) as { code?: unknown };
      const token = this.d.owner.login(str(body.code, 64));
      sendJson(res, 200, { ok: true }, { 'Set-Cookie': OwnerAuth.cookieHeader(token) });
      return;
    }
    if (!device) {
      sendJson(res, 401, { error: 'Owner login required' });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/state') {
      sendJson(res, 200, await this.state());
      return;
    }
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }
    const csrf = req.headers['x-csrf-token'];
    if (!this.d.owner.checkCsrf(device, typeof csrf === 'string' ? csrf : undefined)) {
      sendJson(res, 403, { error: 'Invalid CSRF token. Reload the control panel.' });
      return;
    }
    const body = (await readJson(req, 32 * 1024)) as Record<string, unknown>;
    sendJson(res, 200, (await this.action(url.pathname, body, device)) ?? { ok: true });
  }

  private async action(path: string, b: Record<string, unknown>, device: StoredDevice): Promise<unknown> {
    const { auth, grants, approvals } = this.d;
    switch (path) {
      case '/api/logout':
        this.d.owner.logout(device);
        return { ok: true };
      case '/api/public-url':
        this.d.setPublicUrl(str(b.url));
        return { ok: true };
      case '/api/authorization': {
        const id = str(b.id, 64);
        if (b.decision === 'approve') auth.approveAuthorization(id, strList(b.scopes), strList(b.tools));
        else auth.denyAuthorization(id);
        return { ok: true };
      }
      case '/api/approval': {
        const id = str(b.id, 64);
        const request = approvals.get(id);
        if (!request) throw new Error('This request is no longer pending.');
        if (b.decision !== 'approve') {
          approvals.decide(id, false);
          return { ok: true };
        }
        if (request.kind === 'tab_access') {
          const tabId = str(b.tabId, 40);
          const tab = this.d.browser.tab(tabId);
          if (!tab) throw new Error('That tab no longer exists.');
          const origins = strList(b.origins);
          grants.grant(request.clientId, tabId, origins.length ? origins : [tab.topOrigin()], strList(b.frameOrigins));
          approvals.decide(id, true, { tabId });
        } else if (request.kind === 'open_tab') {
          approvals.decide(id, true, { share: b.share === true });
        } else approvals.decide(id, true);
        return { ok: true };
      }
      case '/api/client': {
        const clientId = str(b.clientId, 300);
        if (b.action === 'tools') auth.setClientTools(clientId, strList(b.tools));
        else if (b.action === 'revoke') auth.revokeClient(clientId);
        else if (b.action === 'remove') auth.revokeClient(clientId, true);
        else throw new HttpError(400, 'Unknown client action');
        return { ok: true };
      }
      case '/api/grant': {
        const clientId = str(b.clientId, 300);
        const tabId = str(b.tabId, 40);
        if (b.action === 'revoke') grants.revokeTab(clientId, tabId);
        else if (b.action === 'set') grants.setOrigins(clientId, tabId, strList(b.origins), strList(b.frameOrigins));
        else if (b.action === 'share') {
          if (!auth.verifyClientActive(clientId)) throw new Error('Approve this client before sharing tabs with it.');
          const tab = this.d.browser.tab(tabId);
          if (!tab) throw new Error('That tab no longer exists.');
          const origins = strList(b.origins);
          grants.grant(clientId, tabId, origins.length ? origins : [tab.topOrigin()], strList(b.frameOrigins));
        } else throw new HttpError(400, 'Unknown grant action');
        return { ok: true };
      }
      case '/api/tab':
        if (b.action !== 'open') throw new HttpError(400, 'Unknown tab action');
        return { ok: true, tabId: await this.d.openOwnerTab(str(b.url)) };
      case '/api/kill':
        this.d.killAll();
        return { ok: true };
      case '/api/settings': {
        const st = this.d.store.state.settings;
        if (b.autoApproveClients !== undefined) {
          if (typeof b.autoApproveClients !== 'boolean') throw new HttpError(400, 'autoApproveClients must be a boolean');
          st.autoApproveClients = b.autoApproveClients;
        }
        if (b.shareEntireBrowser !== undefined) {
          if (typeof b.shareEntireBrowser !== 'boolean') throw new HttpError(400, 'shareEntireBrowser must be a boolean');
          st.shareEntireBrowser = b.shareEntireBrowser;
        }
        if (b.actionApprovals !== undefined) {
          if (b.actionApprovals !== 'never' && b.actionApprovals !== 'sensitive' && b.actionApprovals !== 'all') throw new HttpError(400, 'actionApprovals must be never, sensitive or all');
          st.actionApprovals = b.actionApprovals;
        }
        this.d.store.save();
        this.d.audit.record({ event: 'settings_changed', decision: `${st.autoApproveClients ? 'auto' : 'manual'}_clients,${st.shareEntireBrowser ? 'all_tabs' : 'per_tab'},approvals_${st.actionApprovals}` });
        return { ok: true, settings: { ...st } };
      }
    }
    throw new HttpError(404, 'Unknown action');
  }

  private async state() {
    const { config, auth, grants, approvals, browser, audit } = this.d;
    const identity = auth.identity();
    return {
      version: this.d.version,
      publicUrl: identity?.baseUrl ?? null,
      connectorUrl: identity?.mcpUrl ?? null,
      localMcpUrl: `http://127.0.0.1:${config.port}/mcp`,
      mcpPort: config.port,
      adminPort: config.adminPort,
      settings: { ...this.d.store.state.settings },
      approvalTimeoutSeconds: config.approvalTimeoutSeconds,
      toolCeiling: config.toolCeiling,
      allowDomains: config.allowDomains,
      denyDomains: config.denyDomains,
      localExceptions: [...this.d.localExceptions],
      scopes: SCOPES,
      toolScopes: TOOL_SCOPES,
      presets: PRESETS,
      tabs: (await browser.ownerView()).map((t) => ({ ...t, shareable: grants.grantable(t.origin) })),
      grants: grants.views(),
      clients: auth.clients(),
      pendingAuthorizations: auth.pendingAuthorizations(),
      approvals: approvals.list(),
      audit: audit.recent(40),
    };
  }
}
