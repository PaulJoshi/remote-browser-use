/**
 * Validate the externally reachable base URL that becomes the OAuth issuer and
 * MCP resource identity. HTTPS is required for anything reachable remotely.
 * The only HTTP exception is this machine's own MCP port on loopback, which is
 * useful for local clients (e.g. MCP Inspector) and cannot be reached remotely.
 */
export function normalizePublicUrl(input: string, mcpPort: number): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error(`Public URL "${input}" is not a valid URL.`);
  }
  if (url.username || url.password) throw new Error('Public URL must not contain credentials.');
  if (url.search || url.hash || input.includes('?') || input.includes('#')) throw new Error('Public URL must not contain a query string or fragment.');
  if (url.pathname !== '/' && url.pathname !== '') {
    throw new Error('Public URL must be a base URL without a path (for example https://abc-8931.example.devtunnels.ms). The /mcp path is added automatically.');
  }
  if (url.protocol === 'https:') return url.origin;
  if (url.protocol === 'http:') {
    const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
    if (loopback && Number(url.port) === mcpPort) return url.origin;
    throw new Error('Public URL must use https:// (a cloud chat app needs an HTTPS tunnel). Plain http is only accepted for this machine\'s own MCP port on 127.0.0.1/localhost.');
  }
  throw new Error('Public URL must use https://.');
}

export interface Identity {
  baseUrl: string;
  issuer: string;
  resource: string;
  mcpUrl: string;
  resourceMetadataUrl: string;
}

export function identityFor(baseUrl: string): Identity {
  return {
    baseUrl,
    issuer: baseUrl,
    resource: `${baseUrl}/mcp`,
    mcpUrl: `${baseUrl}/mcp`,
    resourceMetadataUrl: `${baseUrl}/.well-known/oauth-protected-resource/mcp`,
  };
}
