import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

const blocked = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['100::', 64],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv6');
}

/** Loopback, private, link-local, CGNAT, documentation, multicast or reserved address. */
export function isRestrictedIp(address: string): boolean {
  const ip = address.replace(/^\[|\]$/g, '');
  const family = isIP(ip);
  if (family === 4) return blocked.check(ip, 'ipv4');
  if (family === 6) {
    const lower = ip.toLowerCase();
    const mapped = /^(?:0{0,4}:){0,5}(?:0{0,4}:)?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower) ?? /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return blocked.check(mapped[1]!, 'ipv4');
    const hexMapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
    if (hexMapped) {
      const hi = parseInt(hexMapped[1]!, 16);
      const lo = parseInt(hexMapped[2]!, 16);
      return blocked.check(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`, 'ipv4');
    }
    if (lower.startsWith('64:ff9b::')) return true;
    return blocked.check(ip, 'ipv6');
  }
  return false;
}

const INTERNAL_SUFFIXES = ['.localhost', '.local', '.internal', '.intranet', '.lan', '.home.arpa', '.corp', '.localdomain'];

/** Hostnames that refer to this machine or a private network. */
export function isRestrictedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!host) return true;
  if (isIP(host)) return isRestrictedIp(host);
  if (host === 'localhost') return true;
  if (INTERNAL_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;
  if (!host.includes('.')) return true;
  return false;
}

export type UrlVerdict =
  | { ok: true; url: URL; origin: string }
  | { ok: false; code: 'invalid_url' | 'restricted_scheme' | 'restricted_destination' | 'domain_not_allowed'; message: string };

export class DomainRules {
  constructor(
    readonly allow: readonly string[],
    readonly deny: readonly string[],
  ) {}

  private static matches(host: string, domain: string): boolean {
    return host === domain || host.endsWith(`.${domain}`);
  }

  allows(hostname: string): boolean {
    const host = hostname.toLowerCase().replace(/\.$/, '');
    if (this.deny.some((d) => DomainRules.matches(host, d))) return false;
    if (this.allow.length > 0 && !this.allow.some((d) => DomainRules.matches(host, d))) return false;
    return true;
  }
}

export interface UrlPolicyOptions {
  rules: DomainRules;
  /** Exact origins (e.g. the bundled demo fixture) exempt from the local/private destination rule. */
  localExceptions: ReadonlySet<string>;
}

/**
 * Static checks for a destination the agent wants to reach: scheme, local/private
 * destinations, and owner domain rules. DNS-based checks are separate (async).
 */
export function checkDestination(raw: string, opts: UrlPolicyOptions): UrlVerdict {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, code: 'invalid_url', message: 'Not a valid absolute URL.' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, code: 'restricted_scheme', message: `The ${url.protocol} scheme is not allowed; only http and https pages can be opened.` };
  }
  if (url.username || url.password) {
    return { ok: false, code: 'invalid_url', message: 'URLs with embedded credentials are not allowed.' };
  }
  const origin = url.origin;
  if (opts.localExceptions.has(origin)) return { ok: true, url, origin };
  if (isRestrictedHostname(url.hostname)) {
    return { ok: false, code: 'restricted_destination', message: 'Local, private-network and internal destinations are blocked for agents.' };
  }
  if (!opts.rules.allows(url.hostname)) {
    return { ok: false, code: 'domain_not_allowed', message: 'This domain is not allowed by the owner\'s domain rules.' };
  }
  return { ok: true, url, origin };
}

export type Lookup = (hostname: string) => Promise<string[]>;

export const systemLookup: Lookup = async (hostname) => (await dnsLookup(hostname, { all: true, verbatim: true })).map((r) => r.address);

/** True if the public-looking hostname resolves to any private/loopback address (DNS rebinding defense). */
export async function resolvesToRestricted(hostname: string, lookup: Lookup = systemLookup): Promise<boolean> {
  if (isIP(hostname.replace(/^\[|\]$/g, ''))) return isRestrictedIp(hostname);
  try {
    const addresses = await lookup(hostname);
    return addresses.length === 0 || addresses.some(isRestrictedIp);
  } catch {
    return false; // unresolvable hosts simply fail to load in the browser
  }
}

/**
 * Effective security origin of a document URL. about:blank/srcdoc inherit the
 * parent's origin; blob: URLs carry their creator's origin; everything else
 * non-http(s) is opaque ("null").
 */
export function documentOrigin(url: string, parentOrigin?: string): string {
  if (url === '' || url === 'about:blank' || url === 'about:srcdoc' || url.startsWith('about:blank#') || url.startsWith('about:blank?')) {
    return parentOrigin ?? 'null';
  }
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'blob:') return new URL(parsed.pathname).origin;
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return parsed.origin;
  } catch {
    /* fallthrough */
  }
  return 'null';
}
