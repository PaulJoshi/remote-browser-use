import type { AuditLog } from '../audit/audit.js';
import type { StateStore, StoredDevice } from '../store.js';
import type { Clock } from '../util/clock.js';
import { hmac, humanCode, normalizeHumanCode, randomToken, safeEqual, sha256 } from '../util/crypto.js';
import { RateLimiter } from '../util/rateLimit.js';

export const OWNER_COOKIE = 'rbu_owner';
const DEVICE_TTL_MS = 30 * 24 * 3600 * 1000;
const MAX_FAILURES = 20;

export class LoginError extends Error {}

/**
 * Owner authentication for the local control panel. A one-time code printed in
 * the terminal and carried in the URL fragment of the panel the CLI opens
 * (fragments are never sent in HTTP requests) bootstraps a durable, HttpOnly
 * device cookie. Loopback peer address is never treated as proof of ownership.
 */
export class OwnerAuth {
  private setupCode: string;
  private failures = 0;
  private readonly limiter: RateLimiter;

  constructor(
    private readonly store: StateStore,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
    private readonly onNewCode: (code: string) => void = () => undefined,
  ) {
    this.setupCode = humanCode(12, 4);
    this.limiter = new RateLimiter(5, 5, clock);
  }

  currentSetupCode(): string {
    return this.setupCode;
  }

  /** Exchange the one-time setup code for a device token. The code is single-use and rotated afterwards. */
  login(code: string): string {
    if (this.failures >= MAX_FAILURES) throw new LoginError('Too many failed attempts. Restart remote-browser-use to get a new setup code.');
    if (!this.limiter.take('login')) throw new LoginError('Too many attempts. Wait a minute and try again.');
    if (!safeEqual(normalizeHumanCode(code), normalizeHumanCode(this.setupCode))) {
      this.failures++;
      this.audit.record({ event: 'owner_login_failed' });
      throw new LoginError('That setup code is not correct. Use the code printed in the terminal where remote-browser-use is running.');
    }
    const token = randomToken(32);
    const now = this.clock.now();
    this.store.state.ownerDevices = this.store.state.ownerDevices.filter((d) => now - d.lastSeen < DEVICE_TTL_MS).slice(-9);
    this.store.state.ownerDevices.push({ id: randomToken(6), hash: sha256(token), createdAt: now, lastSeen: now });
    this.store.save();
    this.audit.record({ event: 'owner_login', decision: 'device_added' });
    this.setupCode = humanCode(12, 4);
    this.onNewCode(this.setupCode);
    return token;
  }

  authenticate(token: string | undefined): StoredDevice | undefined {
    if (!token || token.length > 100) return undefined;
    const hash = sha256(token);
    const now = this.clock.now();
    const device = this.store.state.ownerDevices.find((d) => safeEqual(d.hash, hash));
    if (!device || now - device.lastSeen > DEVICE_TTL_MS) return undefined;
    if (now - device.lastSeen > 60_000) {
      device.lastSeen = now;
      this.store.save();
    }
    return device;
  }

  csrfToken(device: StoredDevice): string {
    return hmac(this.store.state.serverSecret, `csrf:${device.hash}`);
  }

  checkCsrf(device: StoredDevice, token: string | undefined): boolean {
    return typeof token === 'string' && safeEqual(token, this.csrfToken(device));
  }

  logout(device: StoredDevice): void {
    this.store.state.ownerDevices = this.store.state.ownerDevices.filter((d) => d.id !== device.id);
    this.store.save();
  }

  static cookieHeader(token: string, maxAgeSeconds = DEVICE_TTL_MS / 1000): string {
    return `${OWNER_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeSeconds)}`;
  }

  static readCookie(header: string | undefined): string | undefined {
    if (!header) return undefined;
    for (const part of header.split(';')) {
      const [k, ...v] = part.trim().split('=');
      if (k === OWNER_COOKIE) return v.join('=');
    }
    return undefined;
  }
}
