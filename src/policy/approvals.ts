import { EventEmitter } from 'node:events';
import type { AuditLog } from '../audit/audit.js';
import { randomToken } from '../util/crypto.js';

export type ApprovalKind =
  | 'tab_access'
  | 'frame_access'
  | 'submit'
  | 'type_secret'
  | 'navigate_new_origin'
  | 'open_tab'
  | 'close_tab'
  | 'popup'
  | 'download'
  | 'sensitive_click'
  | 'action';

export interface ApprovalInput {
  clientId: string;
  clientName: string;
  tool: string;
  kind: ApprovalKind;
  tabId?: string;
  /** Human-readable summary for the local owner (never logged). */
  summary: string;
  /** Extra structured details for the panel (e.g. requested frame/origin). */
  details?: Record<string, string>;
}

export interface ApprovalRequest extends ApprovalInput {
  id: string;
  createdAt: number;
  expiresAt: number;
}

export interface ApprovalDecision {
  approved: boolean;
  reason: 'approved' | 'denied' | 'timeout' | 'cancelled';
  data?: Record<string, unknown>;
}

interface Waiter {
  request: ApprovalRequest;
  resolve: (d: ApprovalDecision) => void;
  timer: NodeJS.Timeout;
}

/** Local owner approval queue. Every request is tied to a client, tool, tab and summary, and times out to deny. */
export class ApprovalQueue extends EventEmitter {
  private readonly waiters = new Map<string, Waiter>();

  constructor(private readonly audit: AuditLog) {
    super();
  }

  request(input: ApprovalInput, timeoutMs: number, signal?: AbortSignal): Promise<ApprovalDecision> {
    if (signal?.aborted) return Promise.resolve({ approved: false, reason: 'cancelled' });
    const now = Date.now();
    const request: ApprovalRequest = { ...input, id: randomToken(9), createdAt: now, expiresAt: now + timeoutMs };
    return new Promise((resolve) => {
      const finish = (d: ApprovalDecision) => {
        const w = this.waiters.get(request.id);
        if (!w) return;
        clearTimeout(w.timer);
        this.waiters.delete(request.id);
        signal?.removeEventListener('abort', onAbort);
        this.audit.record({ event: input.kind === 'tab_access' || input.kind === 'frame_access' ? 'tab_request' : 'approval', tool: input.tool, client: input.clientId, tab: input.tabId, decision: d.reason, reason: input.kind });
        this.emit('changed');
        resolve(d);
      };
      const onAbort = () => finish({ approved: false, reason: 'cancelled' });
      const timer = setTimeout(() => finish({ approved: false, reason: 'timeout' }), timeoutMs);
      timer.unref();
      this.waiters.set(request.id, { request, resolve: finish, timer });
      signal?.addEventListener('abort', onAbort, { once: true });
      this.emit('changed');
    });
  }

  decide(id: string, approved: boolean, data?: Record<string, unknown>): ApprovalRequest {
    const w = this.waiters.get(id);
    if (!w) throw new Error('This request is no longer pending (it may have timed out).');
    w.resolve({ approved, reason: approved ? 'approved' : 'denied', data });
    return w.request;
  }

  get(id: string): ApprovalRequest | undefined {
    return this.waiters.get(id)?.request;
  }

  cancelWhere(predicate: (r: ApprovalRequest) => boolean): void {
    for (const w of [...this.waiters.values()]) if (predicate(w.request)) w.resolve({ approved: false, reason: 'cancelled' });
  }

  pendingCount(clientId: string, kinds: ApprovalKind[]): number {
    return [...this.waiters.values()].filter((w) => w.request.clientId === clientId && kinds.includes(w.request.kind)).length;
  }

  list(): ApprovalRequest[] {
    return [...this.waiters.values()].map((w) => w.request);
  }
}
