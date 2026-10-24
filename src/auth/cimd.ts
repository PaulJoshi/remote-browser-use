import { request } from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import type { LookupFunction } from 'node:net';
import { isRestrictedHostname, isRestrictedIp } from '../policy/urlPolicy.js';

export interface ClientMetadataDocument {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
}

export type CimdFetcher = (clientIdUrl: string) => Promise<unknown>;

/** A client_id is a Client ID Metadata Document URL if it is https with a path. */
export function isCimdClientId(clientId: string): boolean {
  try {
    const url = new URL(clientId);
    return url.protocol === 'https:' && url.pathname.length > 1 && !url.hash && !url.username && !url.password;
  } catch {
    return false;
  }
}

const MAX_BYTES = 16 * 1024;

const safeLookup: LookupFunction = (hostname, options, callback) => {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, '', 0);
    const list = addresses as unknown as { address: string; family: number }[];
    const bad = list.find((a) => isRestrictedIp(a.address));
    if (bad || list.length === 0) return callback(new Error('client metadata host resolves to a private address'), '', 0);
    if ((options as { all?: boolean }).all) return (callback as unknown as (e: null, a: typeof list) => void)(null, list);
    callback(null, list[0]!.address, list[0]!.family);
  });
};

/**
 * Fetch a Client ID Metadata Document over HTTPS only, refusing private
 * destinations (checked on the resolved IP to resist DNS rebinding), redirects,
 * large bodies, and slow servers.
 */
export const fetchClientMetadata: CimdFetcher = (clientIdUrl) =>
  new Promise((resolve, reject) => {
    const url = new URL(clientIdUrl);
    if (url.protocol !== 'https:' || isRestrictedHostname(url.hostname)) {
      reject(new Error('client metadata URL must be a public https URL'));
      return;
    }
    const req = request(
      url,
      { method: 'GET', headers: { Accept: 'application/json' }, lookup: safeLookup, timeout: 5000 },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`client metadata fetch returned HTTP ${res.statusCode}`));
          return;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_BYTES) {
            req.destroy(new Error('client metadata document too large'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            reject(new Error('client metadata document is not JSON'));
          }
        });
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error('client metadata fetch timed out')));
    req.on('error', reject);
    req.end();
  });

export function validateClientMetadata(clientId: string, doc: unknown): ClientMetadataDocument {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('client metadata must be a JSON object');
  const d = doc as Record<string, unknown>;
  if (d.client_id !== clientId) throw new Error('client metadata client_id does not match its URL');
  if (!Array.isArray(d.redirect_uris) || d.redirect_uris.length === 0 || d.redirect_uris.length > 20 || !d.redirect_uris.every((u) => typeof u === 'string')) {
    throw new Error('client metadata must list redirect_uris');
  }
  const method = d.token_endpoint_auth_method;
  if (method !== undefined && method !== 'none') {
    throw new Error(`client metadata token_endpoint_auth_method "${String(method)}" is not supported (only "none")`);
  }
  for (const key of ['client_secret', 'client_secret_expires_at'] as const) {
    if (key in d) throw new Error('client metadata documents must not contain client secrets');
  }
  return {
    client_id: clientId,
    client_name: typeof d.client_name === 'string' ? d.client_name : undefined,
    redirect_uris: d.redirect_uris as string[],
    token_endpoint_auth_method: 'none',
  };
}
