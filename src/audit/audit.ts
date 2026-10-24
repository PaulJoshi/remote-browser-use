import { appendFileSync, chmodSync, existsSync, renameSync, statSync } from 'node:fs';
import { ensurePrivateDir } from '../store.js';
import { dirname } from 'node:path';

/**
 * Metadata-only audit records. Only the whitelisted fields below are written,
 * every value is a short sanitized token, and anything that looks like a URL
 * with a query, a bearer/refresh token, or free text is redacted.
 */
export interface AuditEvent {
  event:
    | 'startup'
    | 'shutdown'
    | 'tool'
    | 'client_registered'
    | 'authorization_requested'
    | 'authorization_decided'
    | 'token_issued'
    | 'token_refreshed'
    | 'token_rejected'
    | 'token_revoked'
    | 'refresh_reuse_detected'
    | 'identity_changed'
    | 'grant_changed'
    | 'approval'
    | 'tab_request'
    | 'kill_switch'
    | 'settings_changed'
    | 'owner_login'
    | 'owner_login_failed'
    | 'download';
  tool?: string;
  client?: string;
  tab?: string;
  decision?: string;
  reason?: string;
  ms?: number;
}

export interface AuditEntry extends AuditEvent {
  ts: string;
}

const SAFE_TOKEN = /^[A-Za-z0-9_.:/@-]{1,160}$/;

function clean(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (/rbu_(at|rt)_/.test(value) || value.includes('?') || value.includes('#') || !SAFE_TOKEN.test(value)) return '[redacted]';
  return value;
}

export class AuditLog {
  private readonly ring: AuditEntry[] = [];
  private listeners = new Set<(entry: AuditEntry) => void>();

  constructor(
    private readonly file: string | undefined,
    private readonly maxBytes = 5 * 1024 * 1024,
  ) {
    if (file) ensurePrivateDir(dirname(file));
  }

  record(event: AuditEvent): void {
    const entry: AuditEntry = {
      ts: new Date().toISOString(),
      event: event.event,
      tool: clean(event.tool),
      client: clean(event.client),
      tab: clean(event.tab),
      decision: clean(event.decision),
      reason: clean(event.reason),
      ms: typeof event.ms === 'number' && Number.isFinite(event.ms) ? Math.round(event.ms) : undefined,
    };
    for (const key of Object.keys(entry) as (keyof AuditEntry)[]) if (entry[key] === undefined) delete entry[key];
    this.ring.push(entry);
    if (this.ring.length > 200) this.ring.shift();
    for (const listener of this.listeners) listener(entry);
    if (!this.file) return;
    try {
      if (existsSync(this.file) && statSync(this.file).size > this.maxBytes) renameSync(this.file, `${this.file}.1`);
      appendFileSync(this.file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
      if (process.platform !== 'win32') chmodSync(this.file, 0o600);
    } catch {
      /* audit must never crash the server */
    }
  }

  recent(limit = 50): AuditEntry[] {
    return this.ring.slice(-limit).reverse();
  }

  onEntry(listener: (entry: AuditEntry) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
