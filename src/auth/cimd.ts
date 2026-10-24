import { request } from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import type { LookupFunction } from 'node:net';
import { isRestrictedHostname, isRestrictedIp } from '../policy/urlPolicy.js';

export interface ClientMetadataDocument {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: 'none' | 'private_key_jwt';
  token_endpoint_auth_methods_supported?: string[];
  token_endpoint_auth_signing_alg?: string;
  jwks_uri?: string;
  jwks?: { keys?: unknown[] };
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
 * Fetch a JSON document over HTTPS only, refusing private destinations
 * (checked on the resolved IP to resist DNS rebinding), redirects, large
 * bodies, and slow servers. Used for Client ID Metadata Documents and JWKS.
 */
export function fetchJsonHttps(rawUrl: string, maxBytes = MAX_BYTES, label = 'document'): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:' || isRestrictedHostname(url.hostname)) {
      reject(new Error(`${label} URL must be a public https URL`));
      return;
    }
    const req = request(
      url,
      { method: 'GET', headers: { Accept: 'application/json' }, lookup: safeLookup, timeout: 5000 },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`${label} fetch returned HTTP ${res.statusCode}`));
          return;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            req.destroy(new Error(`${label} too large`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            reject(new Error(`${label} is not JSON`));
          }
        });
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error(`${label} fetch timed out`)));
    req.on('error', reject);
    req.end();
  });
}

export const fetchClientMetadata: CimdFetcher = (clientIdUrl) =>
  fetchJsonHttps(clientIdUrl, MAX_BYTES, 'client metadata document');

export function validateClientMetadata(clientId: string, doc: unknown): ClientMetadataDocument {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('client metadata must be a JSON object');
  const d = doc as Record<string, unknown>;
  if (d.client_id !== clientId) throw new Error('client metadata client_id does not match its URL');
  if (!Array.isArray(d.redirect_uris) || d.redirect_uris.length === 0 || d.redirect_uris.length > 20 || !d.redirect_uris.every((u) => typeof u === 'string')) {
    throw new Error('client metadata must list redirect_uris');
  }
  const method = d.token_endpoint_auth_method;
  if (method !== undefined && method !== 'none' && method !== 'private_key_jwt') {
    throw new Error(`client metadata token_endpoint_auth_method "${String(method)}" is not supported (only "none" and "private_key_jwt")`);
  }
  for (const key of ['client_secret', 'client_secret_expires_at'] as const) {
    if (key in d) throw new Error('client metadata documents must not contain client secrets');
  }
  const out: ClientMetadataDocument = {
    client_id: clientId,
    client_name: typeof d.client_name === 'string' ? d.client_name : undefined,
    redirect_uris: d.redirect_uris as string[],
    token_endpoint_auth_method: method ?? 'none',
  };
  if (out.token_endpoint_auth_method === 'private_key_jwt') {
    const alg = d.token_endpoint_auth_signing_alg;
    if (alg !== undefined && (typeof alg !== 'string' || !['RS256', 'ES256'].includes(alg))) {
      throw new Error(`client metadata token_endpoint_auth_signing_alg "${String(alg)}" is not supported`);
    }
    const jwks = d.jwks as { keys?: unknown[] } | undefined;
    const hasInlineJwks = jwks !== undefined && typeof jwks === 'object' && jwks !== null && Array.isArray(jwks.keys);
    let jwksUri: string | undefined;
    if (typeof d.jwks_uri === 'string') {
      const u = new URL(d.jwks_uri);
      if (u.protocol !== 'https:' || isRestrictedHostname(u.hostname)) {
        throw new Error('client metadata jwks_uri must be a public https URL');
      }
      jwksUri = d.jwks_uri;
    }
    if (!hasInlineJwks && !jwksUri) throw new Error('private_key_jwt clients must publish jwks or jwks_uri');
    if (typeof alg === 'string') out.token_endpoint_auth_signing_alg = alg;
    if (hasInlineJwks) out.jwks = jwks;
    if (jwksUri) out.jwks_uri = jwksUri;
  }
  const supported = d.token_endpoint_auth_methods_supported;
  if (Array.isArray(supported) && supported.every((m) => typeof m === 'string')) {
    out.token_endpoint_auth_methods_supported = supported as string[];
  }
  return out;
}
