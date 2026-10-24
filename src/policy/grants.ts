import { EventEmitter } from 'node:events';
import { checkDestination, type UrlPolicyOptions } from './urlPolicy.js';

export interface TabGrant {
  tabId: string;
  /** Top-level origins the client may read/act on in this tab. */
  origins: Set<string>;
  /** Additional cross-origin frame origins the client may read/act on. */
  frameOrigins: Set<string>;
  grantedAt: number;
}

interface ClientGrants {
  tabs: Map<string, TabGrant>;
  selected?: string;
  generation: number;
}

export interface GrantView {
  clientId: string;
  tabId: string;
  origins: string[];
  frameOrigins: string[];
}

/**
 * Per-client tab/origin/frame grants. Everything starts empty (default deny).
 * Every change bumps a generation counter so callers can detect revocation
 * between authorization and dispatch.
 */
export class GrantStore extends EventEmitter {
  private readonly clients = new Map<string, ClientGrants>();
  private killGeneration = 0;

  constructor(private readonly urlOpts: UrlPolicyOptions) {
    super();
  }

  private entry(clientId: string): ClientGrants {
    let e = this.clients.get(clientId);
    if (!e) {
      e = { tabs: new Map(), generation: 0 };
      this.clients.set(clientId, e);
    }
    return e;
  }

  /**
   * Additive changes keep the generation; revocations bump it and emit
   * `revoked` (clientId | undefined for all, tabId | undefined for all tabs)
   * so pending, undispatched actions are cancelled.
   */
  private bump(clientId?: string, revocation = true, tabId?: string): void {
    if (clientId && revocation) this.entry(clientId).generation++;
    if (revocation) this.emit('revoked', clientId, tabId);
    this.emit('changed', clientId);
  }

  /** Whether an origin may ever be granted under owner domain rules and destination policy. */
  grantable(origin: string): boolean {
    if (!origin || origin === 'null') return false;
    return checkDestination(`${origin}/`, this.urlOpts).ok;
  }

  grant(clientId: string, tabId: string, origins: string[], frameOrigins: string[] = []): TabGrant {
    const bad = [...origins, ...frameOrigins].find((o) => !this.grantable(o));
    if (bad) throw new Error(`Origin ${bad} cannot be shared (local/private destinations and domain rules apply).`);
    if (origins.length === 0) throw new Error('Share at least one top-level origin.');
    const e = this.entry(clientId);
    const existing = e.tabs.get(tabId);
    const grant: TabGrant = existing ?? { tabId, origins: new Set(), frameOrigins: new Set(), grantedAt: Date.now() };
    origins.forEach((o) => grant.origins.add(o));
    frameOrigins.forEach((o) => grant.frameOrigins.add(o));
    e.tabs.set(tabId, grant);
    if (!e.selected) e.selected = tabId;
    this.bump(clientId, false);
    return grant;
  }

  addOrigin(clientId: string, tabId: string, origin: string): void {
    const grant = this.get(clientId, tabId);
    if (!grant) throw new Error('Tab is not shared with this client.');
    if (!this.grantable(origin)) throw new Error(`Origin ${origin} cannot be shared.`);
    grant.origins.add(origin);
    this.bump(clientId, false);
  }

  addFrameOrigin(clientId: string, tabId: string, origin: string): void {
    const grant = this.get(clientId, tabId);
    if (!grant) throw new Error('Tab is not shared with this client.');
    if (!this.grantable(origin)) throw new Error(`Origin ${origin} cannot be shared.`);
    grant.frameOrigins.add(origin);
    this.bump(clientId, false);
  }

  /** Replace a tab grant's origin sets (owner edit). Removing anything counts as a revocation. */
  setOrigins(clientId: string, tabId: string, origins: string[], frameOrigins: string[]): void {
    const grant = this.get(clientId, tabId);
    if (!grant) throw new Error('Tab is not shared with this client.');
    if (origins.length === 0) return this.revokeTab(clientId, tabId);
    const bad = [...origins, ...frameOrigins].find((o) => !this.grantable(o));
    if (bad) throw new Error(`Origin ${bad} cannot be shared.`);
    const removed = [...grant.origins].some((o) => !origins.includes(o)) || [...grant.frameOrigins].some((o) => !frameOrigins.includes(o));
    grant.origins = new Set(origins);
    grant.frameOrigins = new Set(frameOrigins);
    this.bump(clientId, removed, tabId);
  }

  revokeTab(clientId: string, tabId: string): void {
    const e = this.clients.get(clientId);
    if (!e?.tabs.delete(tabId)) return;
    if (e.selected === tabId) e.selected = undefined;
    this.bump(clientId, true, tabId);
  }

  /** A tab closed: drop it from every client. */
  forgetTab(tabId: string): void {
    for (const [clientId, e] of this.clients) {
      if (e.tabs.delete(tabId)) {
        if (e.selected === tabId) e.selected = undefined;
        this.bump(clientId, true, tabId);
      }
    }
  }

  revokeClient(clientId: string): void {
    const e = this.entry(clientId);
    e.tabs.clear();
    e.selected = undefined;
    this.bump(clientId);
  }

  revokeAll(): void {
    this.killGeneration++;
    for (const [, e] of this.clients) {
      e.tabs.clear();
      e.selected = undefined;
      e.generation++;
    }
    this.bump();
  }

  get(clientId: string, tabId: string): TabGrant | undefined {
    return this.clients.get(clientId)?.tabs.get(tabId);
  }

  tabsFor(clientId: string): TabGrant[] {
    return [...(this.clients.get(clientId)?.tabs.values() ?? [])];
  }

  clientsForTab(tabId: string): string[] {
    return [...this.clients].filter(([, e]) => e.tabs.has(tabId)).map(([id]) => id);
  }

  isTabShared(tabId: string): boolean {
    return this.clientsForTab(tabId).length > 0;
  }

  select(clientId: string, tabId: string): void {
    if (!this.get(clientId, tabId)) throw new Error('Tab is not shared with this client.');
    this.entry(clientId).selected = tabId;
  }

  selected(clientId: string): string | undefined {
    return this.clients.get(clientId)?.selected;
  }

  /** Opaque token that changes whenever this client's grants (or the kill switch) change. */
  generation(clientId: string): string {
    return `${this.killGeneration}:${this.clients.get(clientId)?.generation ?? 0}`;
  }

  originAllowed(grant: TabGrant, origin: string): boolean {
    return grant.origins.has(origin) && this.grantable(origin);
  }

  frameAllowed(grant: TabGrant, frameOrigin: string, topOrigin: string): boolean {
    if (!this.originAllowed(grant, topOrigin)) return false;
    if (frameOrigin === topOrigin) return true;
    return grant.frameOrigins.has(frameOrigin) && this.grantable(frameOrigin);
  }

  views(): GrantView[] {
    const out: GrantView[] = [];
    for (const [clientId, e] of this.clients) {
      for (const g of e.tabs.values()) out.push({ clientId, tabId: g.tabId, origins: [...g.origins], frameOrigins: [...g.frameOrigins] });
    }
    return out;
  }
}
