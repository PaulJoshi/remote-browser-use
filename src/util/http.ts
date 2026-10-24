import type { IncomingMessage, ServerResponse } from 'node:http';

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: unknown,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

export function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] ?? '0');
    if (declared > limit) {
      reject(new HttpError(413, 'Request body too large'));
      req.resume();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new HttpError(413, 'Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function mediaType(req: IncomingMessage): string {
  return (req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
}

export async function readForm(req: IncomingMessage, limit = 64 * 1024): Promise<URLSearchParams> {
  const type = mediaType(req);
  const body = (await readBody(req, limit)).toString('utf8');
  if (type === 'application/x-www-form-urlencoded') return new URLSearchParams(body);
  if (type === 'application/json') {
    const parsed = safeJson(body);
    const params = new URLSearchParams();
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'string') params.set(k, v);
      }
    }
    return params;
  }
  throw new HttpError(415, 'Unsupported content type');
}

export async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<unknown> {
  if (mediaType(req) !== 'application/json') throw new HttpError(415, 'Expected application/json');
  const parsed = safeJson((await readBody(req, limit)).toString('utf8'));
  if (parsed === undefined) throw new HttpError(400, 'Invalid JSON');
  return parsed;
}

export function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export const BASE_SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

export function send(
  res: ServerResponse,
  status: number,
  body: string | Buffer,
  contentType: string,
  headers: Record<string, string> = {},
): void {
  if (res.headersSent) {
    res.end();
    return;
  }
  res.writeHead(status, { ...BASE_SECURITY_HEADERS, 'Content-Type': contentType, ...headers });
  res.end(body);
}

export function sendJson(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  send(res, status, JSON.stringify(value), 'application/json; charset=utf-8', headers);
}

export function sendHtml(res: ServerResponse, status: number, html: string, headers: Record<string, string> = {}): void {
  send(res, status, html, 'text/html; charset=utf-8', headers);
}

/** Host header as `hostname:port` (lowercased), or undefined. */
export function hostHeader(req: IncomingMessage): string | undefined {
  const host = req.headers.host;
  return typeof host === 'string' ? host.toLowerCase() : undefined;
}

export function peerKey(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? 'unknown';
}
