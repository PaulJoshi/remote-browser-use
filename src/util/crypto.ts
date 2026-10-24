import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

export function hmac(secret: string, value: string): string {
  return createHmac('sha256', secret).update(value).digest('base64url');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** RFC 7636 S256 code challenge for a verifier. */
export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';

/** Human-typable code without ambiguous characters, e.g. `K7QM-2WXR-9T`. */
export function humanCode(length = 10, groups = 4): string {
  let out = '';
  for (let i = 0; i < length; i++) {
    if (i > 0 && i % groups === 0) out += '-';
    out += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  }
  return out;
}

export function normalizeHumanCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}
