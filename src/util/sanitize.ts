// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g;

/** Strip control/bidi characters, collapse whitespace, and truncate. */
export function sanitizeText(value: unknown, max = 200): string {
  if (typeof value !== 'string') return '';
  const cleaned = value.replace(CONTROL, '').replace(/\s+/g, ' ').trim();
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

/** Origin + path only: never return query strings, fragments, or credentials. */
export function displayUrl(raw: string, max = 300): string {
  try {
    const url = new URL(raw);
    if (url.protocol === 'about:' || url.protocol === 'data:' || url.protocol === 'blob:') return url.protocol.replace(':', '');
    const out = `${url.origin}${url.pathname}`;
    return out.length > max ? `${out.slice(0, max - 1)}…` : out;
  } catch {
    return '(invalid url)';
  }
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
