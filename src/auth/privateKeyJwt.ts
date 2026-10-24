import { createPublicKey, verify as cryptoVerify, type JsonWebKey, type KeyObject } from 'node:crypto';

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const SUPPORTED_ALGS = new Set(['RS256', 'ES256']);
const MAX_ASSERTION_BYTES = 16 * 1024;
const CLOCK_LEEWAY_MS = 60 * 1000;
const MAX_EXP_AHEAD_MS = 10 * 60 * 1000;

export interface AssertionClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  jti?: string;
}

function decodePart(part: string): unknown {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

function keyObjectsFor(jwks: { keys?: unknown[] }, kid: string | undefined, alg: string): KeyObject[] {
  const wantKty = alg === 'RS256' ? 'RSA' : 'EC';
  const keys = (jwks.keys ?? []).filter((k): k is Record<string, unknown> => {
    if (!k || typeof k !== 'object') return false;
    const jwk = k as Record<string, unknown>;
    if (jwk.kty !== wantKty) return false;
    if (wantKty === 'EC' && jwk.crv !== 'P-256') return false;
    if (kid !== undefined && jwk.kid !== kid) return false;
    if (typeof jwk.use === 'string' && jwk.use !== 'sig') return false;
    const jwkAlg = jwk.alg;
    if (typeof jwkAlg === 'string' && jwkAlg !== alg) return false;
    return true;
  });
  const out: KeyObject[] = [];
  for (const jwk of keys) {
    try {
      out.push(createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' }));
    } catch {
      // Skip malformed JWKs and try the next one.
    }
  }
  return out;
}

/**
 * Verify a `private_key_jwt` client assertion (RFC 7523 §3). Returns the
 * validated claims; throws with a safe message on any failure.
 *
 * `audienceCandidates` are the values accepted in `aud` — the token endpoint
 * URL per the RFC, plus the issuer for interop.
 */
export function verifyClientAssertion(args: {
  assertionType: string | null;
  assertion: string | null;
  clientId: string;
  jwks: { keys?: unknown[] };
  allowedAlg?: string;
  audienceCandidates: string[];
  now: number;
  seenJti?: (jti: string, expMs: number) => boolean;
}): AssertionClaims {
  if (args.assertionType !== CLIENT_ASSERTION_TYPE) throw new Error('Unsupported client_assertion_type');
  const assertion = args.assertion ?? '';
  if (!assertion || assertion.length > MAX_ASSERTION_BYTES) throw new Error('Missing or oversized client_assertion');
  const parts = assertion.split('.');
  if (parts.length !== 3) throw new Error('Malformed client_assertion');

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = decodePart(parts[0]!) as Record<string, unknown>;
    payload = decodePart(parts[1]!) as Record<string, unknown>;
  } catch {
    throw new Error('Malformed client_assertion');
  }

  const alg = header.alg;
  if (typeof alg !== 'string' || !SUPPORTED_ALGS.has(alg)) throw new Error('Unsupported client assertion signing algorithm');
  if (args.allowedAlg && alg !== args.allowedAlg) throw new Error('Client assertion algorithm does not match registered token_endpoint_auth_signing_alg');

  const claims = payload as unknown as AssertionClaims;
  if (claims.iss !== args.clientId || claims.sub !== args.clientId) throw new Error('Client assertion iss/sub must equal client_id');
  const aud = Array.isArray(claims.aud) ? claims.aud : typeof claims.aud === 'string' ? [claims.aud] : [];
  if (!aud.some((a) => args.audienceCandidates.includes(a))) throw new Error('Client assertion audience does not identify this server');
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) throw new Error('Client assertion requires an exp claim');
  const expMs = claims.exp * 1000;
  if (expMs <= args.now - CLOCK_LEEWAY_MS) throw new Error('Client assertion expired');
  if (expMs > args.now + MAX_EXP_AHEAD_MS) throw new Error('Client assertion lifetime is too long');
  if (typeof claims.iat === 'number' && claims.iat * 1000 > args.now + CLOCK_LEEWAY_MS) {
    throw new Error('Client assertion issued-at is in the future');
  }

  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
  const signature = Buffer.from(parts[2]!, 'base64url');
  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  const candidates = keyObjectsFor(args.jwks, kid, alg);
  if (candidates.length === 0) throw new Error('No matching key in client JWKS');
  const ok = candidates.some((key) =>
    cryptoVerify(alg === 'RS256' ? 'RSA-SHA256' : 'SHA256', signingInput, { key, dsaEncoding: 'ieee-p1363' }, signature),
  );
  if (!ok) throw new Error('Client assertion signature verification failed');

  if (typeof claims.jti === 'string') {
    if (claims.jti.length > 200) throw new Error('Client assertion jti is too long');
    if (args.seenJti?.(claims.jti, expMs)) throw new Error('Client assertion was already used');
  }
  return claims;
}
