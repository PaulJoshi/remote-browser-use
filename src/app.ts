import { homedir } from 'node:os';
import { join } from 'node:path';
import { AdminServer } from './admin/adminServer.js';
import { OwnerAuth } from './admin/ownerAuth.js';
import { AuditLog } from './audit/audit.js';
import { type CimdFetcher, fetchClientMetadata } from './auth/cimd.js';
import { AuthorizationServer } from './auth/oauth.js';
import { normalizePublicUrl } from './auth/publicUrl.js';
import { BrowserManager } from './browser/manager.js';
import type { ResolvedConfig } from './config.js';
import { ApprovalQueue } from './policy/approvals.js';
import { GrantStore } from './policy/grants.js';
import { DomainRules, type Lookup, type UrlPolicyOptions } from './policy/urlPolicy.js';
import { McpListener } from './server/mcpServer.js';
import { ensurePrivateDir, resolveDataPaths, StateStore, type DataPaths } from './store.js';
import { buildMcpServer } from './tools/register.js';
import { ToolService } from './tools/service.js';
import { type Clock, systemClock } from './util/clock.js';
import { VERSION } from './version.js';

export interface AppOptions {
  config: ResolvedConfig;
  /** Private data directory (defaults to ~/.remote-browser-use or $REMOTE_BROWSER_USE_HOME). */
  dataDir?: string;
  /** Exact origins exempt from the local/private-destination rule (the bundled demo fixture). */
  localOriginExceptions?: string[];
  /** URLs to open (unshared) in the dedicated browser after launch. */
  initialUrls?: string[];
  /** Internal/testing only: not exposed through the CLI or config file. */
  headless?: boolean;
  fetchClientMetadata?: CimdFetcher;
  lookup?: Lookup;
  clock?: Clock;
  accessTokenTtlSeconds?: number;
  downloadsDir?: string;
  log?: (line: string) => void;
  onSetupCode?: (code: string) => void;
}

/** Wires the browser, policy, OAuth, MCP listener and local admin listener together. */
export class App {
  private stopping?: Promise<void>;
  private constructor(
    readonly paths: DataPaths,
    readonly config: ResolvedConfig,
    readonly store: StateStore,
    readonly audit: AuditLog,
    readonly auth: AuthorizationServer,
    readonly grants: GrantStore,
    readonly approvals: ApprovalQueue,
    readonly owner: OwnerAuth,
    readonly browser: BrowserManager,
    readonly tools: ToolService,
    readonly mcp: McpListener,
    readonly admin: AdminServer,
    readonly localExceptions: ReadonlySet<string>,
  ) {}

  get mcpUrl(): string {
    return `http://127.0.0.1:${this.config.port}/mcp`;
  }

  get adminUrl(): string {
    return `http://127.0.0.1:${this.config.adminPort}/`;
  }

  get setupCode(): string {
    return this.owner.currentSetupCode();
  }

  static async start(opts: AppOptions): Promise<App> {
    const log = opts.log ?? (() => undefined);
    const config = opts.config;
    const paths = resolveDataPaths(opts.dataDir);
    ensurePrivateDir(paths.root);
    ensurePrivateDir(paths.profile);
    const store = new StateStore(paths.state);
    if (config.publicUrl) store.state.publicUrl = config.publicUrl;
    store.save();
    const audit = new AuditLog(paths.audit);
    const clock = opts.clock ?? systemClock;
    const localExceptions = new Set(opts.localOriginExceptions ?? []);
    const urlOpts: UrlPolicyOptions = { rules: new DomainRules(config.allowDomains, config.denyDomains), localExceptions };
    const auth = new AuthorizationServer({
      store,
      audit,
      clock,
      fetchClientMetadata: opts.fetchClientMetadata ?? fetchClientMetadata,
      toolCeiling: config.toolCeiling,
      accessTokenTtlSeconds: opts.accessTokenTtlSeconds,
    });
    const grants = new GrantStore(urlOpts);
    const approvals = new ApprovalQueue(audit);
    const owner = new OwnerAuth(store, audit, clock, opts.onSetupCode);

    auth.on('client-revoked', (clientId: string) => {
      grants.revokeClient(clientId);
      approvals.cancelWhere((r) => r.clientId === clientId);
    });
    grants.on('revoked', (clientId: string | undefined, tabId: string | undefined) => {
      approvals.cancelWhere((r) => (!clientId || r.clientId === clientId) && (!tabId || r.tabId === tabId) && r.kind !== 'tab_access');
    });
    auth.on('all-revoked', () => {
      grants.revokeAll();
      approvals.cancelWhere(() => true);
    });

    const late: { service?: ToolService; app?: App } = {};
    const mcp = new McpListener({
      port: config.port,
      auth,
      audit,
      buildServer: (authInfo) => {
        if (!late.service) throw new Error('browser is still starting');
        return buildMcpServer(late.service, authInfo, auth.clientTools(authInfo.clientId), VERSION);
      },
      onError: (e) => log(`MCP error: ${e.message}`),
    });
    try {
      await mcp.listen();
    } catch (error) {
      auth.close();
      throw portError(error, config.port, '--port');
    }

    let browser: BrowserManager;
    try {
      browser = await BrowserManager.launch({ profileDir: paths.profile, headless: opts.headless });
    } catch (error) {
      await mcp.close();
      auth.close();
      const message = (error as Error).message;
      if (/ProcessSingleton|SingletonLock|profile.*in use|already running/i.test(message)) {
        throw new Error(`Another remote-browser-use instance is already using the browser profile at ${paths.profile}. Stop it first.`, { cause: error });
      }
      throw new Error(`Could not launch Chromium: ${message.split('\n')[0]}`, { cause: error });
    }

    const tools = new ToolService({
      browser,
      grants,
      approvals,
      auth,
      audit,
      urlOpts,
      approvalMode: config.approve,
      approvalTimeoutMs: config.approvalTimeoutSeconds * 1000,
      downloadsDir: opts.downloadsDir ?? join(homedir(), 'Downloads'),
      lookup: opts.lookup,
    });
    late.service = tools;

    const admin = new AdminServer({
      config,
      version: VERSION,
      auth,
      grants,
      approvals,
      browser,
      audit,
      owner,
      localExceptions,
      setPublicUrl: (url) => late.app!.setPublicUrl(url),
      killAll: () => late.app!.killAll(),
      openOwnerTab: async (url) => {
        const parsed = new URL(url);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('Only http and https URLs can be opened.');
        if (parsed.port === String(config.adminPort) && /^(127\.0\.0\.1|localhost|\[::1\])$/.test(parsed.hostname)) throw new Error('The control panel cannot be opened in the agent browser.');
        return (await browser.openTab(parsed.href)).id;
      },
    });
    try {
      await admin.listen();
    } catch (error) {
      await mcp.close();
      await browser.close();
      auth.close();
      throw portError(error, config.adminPort, '--admin-port');
    }

    const app = new App(paths, config, store, audit, auth, grants, approvals, owner, browser, tools, mcp, admin, localExceptions);
    late.app = app;
    await browser.showWelcome();
    for (const url of opts.initialUrls ?? []) await browser.openTab(url);
    audit.record({ event: 'startup' });
    return app;
  }

  setPublicUrl(raw: string): void {
    this.auth.setPublicUrl(normalizePublicUrl(raw, this.config.port));
  }

  killAll(): void {
    this.auth.revokeAll();
    this.grants.revokeAll();
    this.approvals.cancelWhere(() => true);
    this.audit.record({ event: 'kill_switch', decision: 'all_revoked' });
  }

  stop(): Promise<void> {
    this.stopping ??= (async () => {
      this.approvals.cancelWhere(() => true);
      await Promise.allSettled([this.mcp.close(), this.admin.close()]);
      await this.browser.close();
      this.auth.close();
      this.audit.record({ event: 'shutdown' });
    })();
    return this.stopping;
  }
}

function portError(error: unknown, port: number, flag: string): Error {
  if ((error as NodeJS.ErrnoException).code === 'EADDRINUSE') {
    return new Error(`Port ${port} on 127.0.0.1 is already in use (another remote-browser-use, or another program). Stop it or choose another port with ${flag}.`);
  }
  return error as Error;
}
