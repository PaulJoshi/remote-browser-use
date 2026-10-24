import { EventEmitter } from 'node:events';
import { chromium, type BrowserContext, type Dialog, type Download, type Frame, type Page } from 'playwright-core';
import { documentOrigin } from '../policy/urlPolicy.js';
import { displayUrl } from '../util/sanitize.js';

export interface PendingDialog {
  dialog: Dialog;
  type: string;
  message: string;
  defaultValue: string;
  at: number;
}

export interface SnapshotRef {
  frame: Frame;
  frameId: string;
  frameVersion: number;
  role: string;
  name: string;
}

export interface SnapshotRecord {
  id: number;
  clientId: string;
  docVersion: number;
  refs: Map<string, SnapshotRef>;
}

export interface CursorRecord {
  clientId: string;
  docVersion: number;
  generation: string;
  text: string;
  createdAt: number;
}

/** One browser tab with a stable per-session id and frame identities. */
export class Tab {
  docVersion = 0;
  snapshot?: SnapshotRecord;
  snapshotSeq = 0;
  readonly cursors = new Map<string, CursorRecord>();
  pendingDialog?: PendingDialog;
  agentActive = 0;
  lastAgentAction = 0;
  indicator: 'off' | 'shown' | 'unavailable' = 'off';
  closed = false;
  private readonly frameIds = new WeakMap<Frame, string>();
  private readonly frameVersions = new WeakMap<Frame, number>();
  private frameSeq = 0;

  constructor(
    readonly id: string,
    readonly page: Page,
    readonly openerTabId?: string,
  ) {}

  frameId(frame: Frame): string {
    if (frame === this.page.mainFrame()) return 'main';
    let id = this.frameIds.get(frame);
    if (!id) {
      id = `frame-${++this.frameSeq}`;
      this.frameIds.set(frame, id);
    }
    return id;
  }

  frameById(id: string): Frame | undefined {
    return this.page.frames().find((f) => !f.isDetached() && this.frameId(f) === id);
  }

  frameVersion(frame: Frame): number {
    return this.frameVersions.get(frame) ?? 0;
  }

  bumpFrame(frame: Frame): void {
    this.frameVersions.set(frame, this.frameVersion(frame) + 1);
  }

  frameOrigin(frame: Frame): string {
    const parent = frame.parentFrame();
    return documentOrigin(frame.url(), parent ? this.frameOrigin(parent) : undefined);
  }

  topOrigin(): string {
    return this.frameOrigin(this.page.mainFrame());
  }

  invalidateDocument(): void {
    this.docVersion++;
    this.snapshot = undefined;
    this.cursors.clear();
    this.pendingDialog = undefined;
  }
}

export interface OwnerTabView {
  tabId: string;
  title: string;
  url: string;
  origin: string;
  openerTabId?: string;
  indicator: Tab['indicator'];
  agentActive: boolean;
  frames: { frameId: string; origin: string; url: string }[];
}

export interface BrowserLaunchOptions {
  profileDir: string;
  headless?: boolean;
  executablePath?: string;
}

export const WELCOME_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>remote-browser-use browser</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1d1d1f}code{background:#f2f2f7;padding:.1rem .3rem;border-radius:.25rem}</style></head>
<body><h1>This is the remote-browser-use browser</h1>
<p>This window uses its own isolated profile. It does not have your everyday Chrome tabs, cookies, extensions or logins.</p>
<ol><li>Open the sites you want an AI agent to use, and sign in here if needed.</li>
<li>Share specific tabs from the local control panel (open in your normal browser, link printed in the terminal).</li>
<li>Tabs you do not share stay invisible to agents.</li></ol>
<p>Shared tabs show a purple border and a label while they are shared.</p></body></html>`;

/** Playwright-managed Chromium with a dedicated persistent profile. Never attaches to an existing Chrome. */
export class BrowserManager extends EventEmitter {
  readonly tabs = new Map<string, Tab>();
  private readonly byPage = new WeakMap<Page, Tab>();
  private seq = 0;
  private closing = false;

  private constructor(readonly context: BrowserContext) {
    super();
  }

  static async launch(opts: BrowserLaunchOptions): Promise<BrowserManager> {
    const context = await chromium.launchPersistentContext(opts.profileDir, {
      // The full Chromium build in both modes (headless is only used by automated tests), so only one browser download is needed.
      channel: 'chromium',
      headless: opts.headless ?? false,
      executablePath: opts.executablePath,
      viewport: null,
      acceptDownloads: true,
      // The CLI performs its own graceful shutdown (listeners first, then the browser).
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false,
      args: ['--no-first-run', '--no-default-browser-check'],
    });
    const manager = new BrowserManager(context);
    context.on('page', (page) => void manager.attach(page));
    context.on('close', () => {
      if (!manager.closing) manager.emit('closed');
    });
    for (const page of context.pages()) await manager.attach(page);
    return manager;
  }

  private async attach(page: Page): Promise<Tab> {
    const existing = this.byPage.get(page);
    if (existing) return existing;
    const opener = await page.opener().catch(() => null);
    const tab = new Tab(`tab-${++this.seq}`, page, opener ? this.byPage.get(opener)?.id : undefined);
    if (this.byPage.get(page)) return this.byPage.get(page)!;
    this.byPage.set(page, tab);
    this.tabs.set(tab.id, tab);
    page.on('framenavigated', (frame) => {
      tab.bumpFrame(frame);
      if (frame === page.mainFrame()) tab.invalidateDocument();
      else if (tab.snapshot) tab.snapshot = undefined;
      this.emit('navigated', tab, frame);
    });
    page.on('frameattached', () => this.emit('frames', tab));
    page.on('framedetached', () => {
      if (tab.snapshot) tab.snapshot = undefined;
      this.emit('frames', tab);
    });
    page.on('load', () => this.emit('load', tab));
    page.on('dialog', (dialog) => {
      tab.pendingDialog = { dialog, type: dialog.type(), message: dialog.message(), defaultValue: dialog.defaultValue(), at: Date.now() };
      this.emit('dialog', tab, dialog);
    });
    page.on('download', (download: Download) => this.emit('download', tab, download));
    page.on('close', () => {
      tab.closed = true;
      this.tabs.delete(tab.id);
      this.emit('tab-closed', tab);
    });
    this.emit('tab-created', tab);
    return tab;
  }

  tab(tabId: string): Tab | undefined {
    const tab = this.tabs.get(tabId);
    return tab && !tab.closed && !tab.page.isClosed() ? tab : undefined;
  }

  tabForPage(page: Page): Tab | undefined {
    return this.byPage.get(page);
  }

  async openTab(url?: string): Promise<Tab> {
    const page = await this.context.newPage();
    const tab = await this.attach(page);
    if (url) await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 }).catch(() => undefined);
    return tab;
  }

  async showWelcome(): Promise<void> {
    const page = this.context.pages()[0] ?? (await this.context.newPage());
    if (page.url() === 'about:blank') await page.setContent(WELCOME_HTML).catch(() => undefined);
  }

  /** Owner (local panel) view of every tab, including unshared ones. Never sent to MCP clients. */
  async ownerView(): Promise<OwnerTabView[]> {
    const out: OwnerTabView[] = [];
    for (const tab of this.tabs.values()) {
      if (tab.closed || tab.page.isClosed()) continue;
      const title = await tab.page.title().catch(() => '');
      out.push({
        tabId: tab.id,
        title,
        url: displayUrl(tab.page.url()),
        origin: tab.topOrigin(),
        openerTabId: tab.openerTabId,
        indicator: tab.indicator,
        agentActive: tab.agentActive > 0 || Date.now() - tab.lastAgentAction < 3000,
        frames: tab.page
          .frames()
          .filter((f) => f !== tab.page.mainFrame() && !f.isDetached())
          .map((f) => ({ frameId: tab.frameId(f), origin: tab.frameOrigin(f), url: displayUrl(f.url()) })),
      });
    }
    return out;
  }

  async close(): Promise<void> {
    this.closing = true;
    await this.context.close().catch(() => undefined);
  }
}
