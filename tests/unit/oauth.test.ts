import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../../src/util/crypto.js';
import { authorizeUrl, fullTokens, INIT, mcpPost, obtainCode, REDIRECT, register, startOAuthEnv, token, toolCall, type OAuthEnv } from './oauthHarness.js';

describe('OAuth discovery and MCP resource protection', () => {
  let env: OAuthEnv;
  beforeEach(async () => (env = await startOAuthEnv()));
  afterEach(async () => env.close());

  it('serves RFC 9728 protected-resource metadata and RFC 8414 authorization-server metadata for the configured identity', async () => {
    const prm = (await (await fetch(`${env.base}/.well-known/oauth-protected-resource/mcp`)).json()) as Record<string, unknown>;
    expect(prm.resource).toBe(`${env.base}/mcp`);
    expect(prm.authorization_servers).toEqual([env.base]);
    expect(prm.scopes_supported).toEqual(['browser:read', 'browser:navigate', 'browser:interact', 'browser:manage']);
    const asm = (await (await fetch(`${env.base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    expect(asm.issuer).toBe(env.base);
    expect(asm.code_challenge_methods_supported).toEqual(['S256']);
    expect(asm.authorization_response_iss_parameter_supported).toBe(true);
    expect(asm.client_id_metadata_document_supported).toBe(true);
    expect(asm.registration_endpoint).toBe(`${env.base}/register`);
    expect(asm.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
  });

  it('requires OAuth on every MCP request, including loopback, with a discovery challenge', async () => {
    const res = await mcpPost(env, INIT);
    expect(res.status).toBe(401);
    const challenge = res.headers.get('www-authenticate')!;
    expect(challenge).toContain(`resource_metadata="${env.base}/.well-known/oauth-protected-resource/mcp"`);
    expect(challenge).toContain('scope="browser:read browser:navigate browser:interact browser:manage"');
    const bad = await mcpPost(env, INIT, { Authorization: 'Bearer rbu_at_not-a-real-token' });
    expect(bad.status).toBe(401);
    expect(bad.headers.get('www-authenticate')).toContain('error="invalid_token"');
    const viaQuery = await fetch(`${env.base}/mcp?access_token=x`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(INIT) });
    expect(viaQuery.status).toBe(400);
  });

  it('fails closed before a public URL is configured', async () => {
    const e2 = await startOAuthEnv({ publicUrl: false });
    try {
      expect((await fetch(`${e2.base}/.well-known/oauth-authorization-server`)).status).toBe(503);
      expect((await fetch(`${e2.base}/.well-known/oauth-protected-resource`)).status).toBe(503);
      const res = await mcpPost(e2, INIT);
      expect(res.status).toBe(401);
      expect(await res.text()).toContain('public_url_not_configured');
      expect((await register(e2)).status).toBe(503);
    } finally {
      await e2.close();
    }
  });

  it('has no admin routes on the MCP listener and rejects unknown Host and Origin headers', async () => {
    for (const path of ['/admin', '/api/state', '/api/login', '/panel.js', '/api/kill']) {
      const res = await fetch(`${env.base}${path}`);
      expect(res.status, path).toBe(404);
    }
    const http = await import('node:http');
    const status = await new Promise<number>((resolve) => {
      http.get({ host: '127.0.0.1', port: env.port, path: '/.well-known/oauth-authorization-server', headers: { Host: 'evil.example' } }, (r) => resolve(r.statusCode!)).end();
    });
    expect(status).toBe(421);
    const { accessToken } = await fullTokens(env);
    const res = await mcpPost(env, INIT, { Authorization: `Bearer ${accessToken}`, Origin: 'https://evil.example' });
    expect(res.status).toBe(403);
  });
});

describe('authorization code + PKCE flow', () => {
  let env: OAuthEnv;
  beforeEach(async () => (env = await startOAuthEnv()));
  afterEach(async () => env.close());

  it('issues audience-bound tokens only after local owner approval, with RFC 9207 iss', async () => {
    const { json } = await register(env);
    const clientId = json.client_id as string;
    const { url, state } = authorizeUrl(env, { clientId });
    const page = await (await fetch(url, { redirect: 'manual' })).text();
    expect(page).toContain('Waiting for owner approval');
    const pending = env.auth.pendingAuthorizations();
    expect(pending).toHaveLength(1);
    expect(page).toContain(pending[0]!.matchCode);
    env.auth.approveAuthorization(pending[0]!.id, ['browser:read'], ['readPage']);
    const handle = /authorize\/wait\?h=([A-Za-z0-9_-]+)/.exec(page)![1];
    const done = await fetch(`${env.base}/authorize/wait?h=${handle}`, { redirect: 'manual' });
    expect(done.status).toBe(302);
    const loc = new URL(done.headers.get('location')!);
    expect(loc.origin + loc.pathname).toBe(REDIRECT);
    expect(loc.searchParams.get('iss')).toBe(env.base);
    expect(loc.searchParams.get('state')).toBe(state);
    expect(loc.searchParams.get('code')).toMatch(/^rbu_ac_/);
    // The handle is single-use.
    expect((await fetch(`${env.base}/authorize/wait?h=${handle}`, { redirect: 'manual' })).status).toBe(404);
  });

  it('rejects missing PKCE, plain PKCE, wrong verifier, wrong redirect_uri, and code reuse', async () => {
    const clientId = (await register(env)).json.client_id as string;
    for (const method of ['plain', '']) {
      const { url } = authorizeUrl(env, { clientId, method });
      const res = await fetch(url, { redirect: 'manual' });
      expect(res.status).toBe(302);
      expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_request');
    }
    const { code, verifier } = await obtainCode(env, { clientId });
    const wrongVerifier = await token(env, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: randomToken(48) });
    expect(wrongVerifier.json.error).toBe('invalid_grant');
    // The code was burned by the failed attempt.
    const retry = await token(env, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
    expect(retry.json.error).toBe('invalid_grant');

    const second = await obtainCode(env, { clientId });
    const wrongRedirect = await token(env, { grant_type: 'authorization_code', code: second.code, redirect_uri: 'http://127.0.0.1:9/other', client_id: clientId, code_verifier: second.verifier });
    expect(wrongRedirect.json.error).toBe('invalid_grant');

    const third = await obtainCode(env, { clientId });
    const ok = await token(env, { grant_type: 'authorization_code', code: third.code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: third.verifier });
    expect(ok.status).toBe(200);
    const reuse = await token(env, { grant_type: 'authorization_code', code: third.code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: third.verifier });
    expect(reuse.json.error).toBe('invalid_grant');
    // Reuse revokes the tokens issued from that code.
    const init = await mcpPost(env, INIT, { Authorization: `Bearer ${ok.json.access_token}` });
    expect(init.status).toBe(401);
  });

  it('validates the resource indicator (RFC 8707) at authorize and token endpoints', async () => {
    const clientId = (await register(env)).json.client_id as string;
    const { url } = authorizeUrl(env, { clientId, resource: 'https://other.example/mcp' });
    const res = await fetch(url, { redirect: 'manual' });
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_target');
    const { code, verifier } = await obtainCode(env, { clientId });
    const bad = await token(env, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier, resource: 'https://other.example/mcp' });
    expect(bad.json.error).toBe('invalid_target');
  });

  it('never redirects to an unregistered redirect_uri and shows an error page instead', async () => {
    const clientId = (await register(env)).json.client_id as string;
    const { url } = authorizeUrl(env, { clientId, redirectUri: 'https://attacker.example/steal' });
    const res = await fetch(url, { redirect: 'manual' });
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
    const unknown = await fetch(authorizeUrl(env, { clientId: 'dcr_unknown' }).url, { redirect: 'manual' });
    expect(unknown.status).toBe(400);
  });

  it('denial and expiry redirect with access_denied and no code', async () => {
    const clientId = (await register(env)).json.client_id as string;
    const { url } = authorizeUrl(env, { clientId });
    const page = await (await fetch(url, { redirect: 'manual' })).text();
    const handle = /authorize\/wait\?h=([A-Za-z0-9_-]+)/.exec(page)![1];
    env.auth.denyAuthorization(env.auth.pendingAuthorizations()[0]!.id);
    const loc = new URL((await fetch(`${env.base}/authorize/wait?h=${handle}`, { redirect: 'manual' })).headers.get('location')!);
    expect(loc.searchParams.get('error')).toBe('access_denied');
    expect(loc.searchParams.get('code')).toBeNull();
    expect(loc.searchParams.get('iss')).toBe(env.base);

    const second = authorizeUrl(env, { clientId });
    const page2 = await (await fetch(second.url, { redirect: 'manual' })).text();
    const handle2 = /authorize\/wait\?h=([A-Za-z0-9_-]+)/.exec(page2)![1];
    env.clock.t += 11 * 60_000;
    const loc2 = new URL((await fetch(`${env.base}/authorize/wait?h=${handle2}`, { redirect: 'manual' })).headers.get('location')!);
    expect(loc2.searchParams.get('error')).toBe('access_denied');
  });
});

describe('dynamic client registration and client ID metadata documents', () => {
  let env: OAuthEnv;
  beforeEach(async () => (env = await startOAuthEnv()));
  afterEach(async () => env.close());

  it('validates registration metadata strictly', async () => {
    expect((await register(env, { redirect_uris: ['javascript:alert(1)'] })).status).toBe(400);
    expect((await register(env, { redirect_uris: ['http://example.com/cb'] })).status).toBe(400);
    expect((await register(env, { redirect_uris: ['https://example.com/cb#frag'] })).status).toBe(400);
    expect((await register(env, { redirect_uris: [] })).status).toBe(400);
    expect((await register(env, { grant_types: ['client_credentials'] })).status).toBe(400);
    expect((await register(env, { token_endpoint_auth_method: 'private_key_jwt' })).status).toBe(400);
    const ok = await register(env, { redirect_uris: ['https://chat.example/cb', 'http://localhost:3333/cb', 'com.example.app:/cb'], client_name: 'A\u202Ename\u0007' });
    expect(ok.status).toBe(201);
    expect(ok.json.client_name).toBe('Aname');
  });

  it('supports confidential DCR clients with client_secret_basic', async () => {
    const reg = await register(env, { token_endpoint_auth_method: 'client_secret_basic' });
    const clientId = reg.json.client_id as string;
    const secret = reg.json.client_secret as string;
    expect(secret).toMatch(/^rbu_cs_/);
    const { code, verifier } = await obtainCode(env, { clientId });
    const noSecret = await token(env, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
    expect(noSecret.status).toBe(401);
    const again = await obtainCode(env, { clientId });
    const basic = Buffer.from(`${clientId}:${secret}`).toString('base64');
    const ok = await token(env, { grant_type: 'authorization_code', code: again.code, redirect_uri: REDIRECT, code_verifier: again.verifier }, { Authorization: `Basic ${basic}` });
    expect(ok.status).toBe(200);
  });

  it('accepts a CIMD client whose metadata lists the redirect URI, and rejects mismatches', async () => {
    const cid = 'https://chat.example/oauth/client.json';
    const redirect = 'https://chat.example/connector/oauth/cb';
    env.cimdDocs.set(cid, { client_id: cid, client_name: 'Chat Example', redirect_uris: [redirect], token_endpoint_auth_method: 'none' });
    const { url } = authorizeUrl(env, { clientId: cid, redirectUri: redirect });
    expect((await fetch(url, { redirect: 'manual' })).status).toBe(200);
    const pending = env.auth.pendingAuthorizations().find((p) => p.clientId === cid)!;
    expect(pending.clientKind).toBe('cimd');
    expect(pending.verifiedHost).toBe('chat.example');
    const bad = await fetch(authorizeUrl(env, { clientId: cid, redirectUri: 'https://evil.example/cb' }).url, { redirect: 'manual' });
    expect(bad.status).toBe(400);
    const wrongId = 'https://chat.example/oauth/other.json';
    env.cimdDocs.set(wrongId, { client_id: 'https://someone-else.example/c.json', redirect_uris: [redirect] });
    expect((await fetch(authorizeUrl(env, { clientId: wrongId, redirectUri: redirect }).url, { redirect: 'manual' })).status).toBe(400);
    const withSecret = 'https://chat.example/oauth/secret.json';
    env.cimdDocs.set(withSecret, { client_id: withSecret, redirect_uris: [redirect], token_endpoint_auth_method: 'client_secret_basic' });
    expect((await fetch(authorizeUrl(env, { clientId: withSecret, redirectUri: redirect }).url, { redirect: 'manual' })).status).toBe(400);
  });

  it('authenticates CIMD clients with a private_key_jwt assertion', async () => {
    const { generateKeyPairSync, sign } = await import('node:crypto');
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    jwk.kid = 'k1';
    const cid = 'https://chat.example/oauth/client.json';
    const jwksUri = 'https://chat.example/oauth/jwks.json';
    const redirect = 'https://chat.example/connector/oauth/cb';
    env.jwksDocs.set(jwksUri, { keys: [jwk] });
    env.cimdDocs.set(cid, {
      client_id: cid,
      client_name: 'Chat Example',
      redirect_uris: [redirect],
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'RS256',
      jwks_uri: jwksUri,
    });

    const { code, verifier } = await obtainCode(env, { clientId: cid, redirectUri: redirect });
    const assertion = (claims: Record<string, unknown>, kid = 'k1') => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url');
      const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
      const sig = sign('RSA-SHA256', Buffer.from(`${header}.${body}`), privateKey).toString('base64url');
      return `${header}.${body}.${sig}`;
    };
    const claims = {
      iss: cid,
      sub: cid,
      aud: `${env.base}/token`,
      exp: Math.floor(env.clock.t / 1000) + 120,
      iat: Math.floor(env.clock.t / 1000),
      jti: randomToken(8),
    };

    const withoutAssertion = await token(env, { grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: cid, code_verifier: verifier });
    expect(withoutAssertion.status).toBe(401);

    const second = await obtainCode(env, { clientId: cid, redirectUri: redirect });
    const ok = await token(env, {
      grant_type: 'authorization_code',
      code: second.code,
      redirect_uri: redirect,
      code_verifier: second.verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion(claims),
    });
    expect(ok.status).toBe(200);
    expect(ok.json.access_token).toMatch(/^rbu_at_/);

    const third = await obtainCode(env, { clientId: cid, redirectUri: redirect });
    const wrongAud = await token(env, {
      grant_type: 'authorization_code',
      code: third.code,
      redirect_uri: redirect,
      code_verifier: third.verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion({ ...claims, aud: 'https://other.example/token', jti: randomToken(8) }),
    });
    expect(wrongAud.status).toBe(401);

    const replayed = await token(env, {
      grant_type: 'refresh_token',
      refresh_token: ok.json.refresh_token as string,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion(claims),
    });
    expect(replayed.status).toBe(401);
  });
});

describe('token lifecycle', () => {
  let env: OAuthEnv;
  beforeEach(async () => (env = await startOAuthEnv()));
  afterEach(async () => env.close());

  it('rotates refresh tokens and revokes the whole grant on refresh-token reuse', async () => {
    const t = await fullTokens(env);
    const r1 = await token(env, { grant_type: 'refresh_token', refresh_token: t.refreshToken, client_id: t.clientId });
    expect(r1.status).toBe(200);
    expect(r1.json.refresh_token).not.toBe(t.refreshToken);
    const reuse = await token(env, { grant_type: 'refresh_token', refresh_token: t.refreshToken, client_id: t.clientId });
    expect(reuse.json.error).toBe('invalid_grant');
    expect(String(reuse.json.error_description)).toMatch(/reuse/);
    const newer = await token(env, { grant_type: 'refresh_token', refresh_token: r1.json.refresh_token as string, client_id: t.clientId });
    expect(newer.json.error).toBe('invalid_grant');
    expect((await mcpPost(env, INIT, { Authorization: `Bearer ${r1.json.access_token}` })).status).toBe(401);
    expect(env.auditText()).toContain('refresh_reuse_detected');
  });

  it('expires access tokens and cannot widen scope on refresh', async () => {
    const t = await fullTokens(env, { grantScopes: ['browser:read'] });
    expect((await mcpPost(env, INIT, { Authorization: `Bearer ${t.accessToken}` })).status).toBe(200);
    env.clock.t += 16 * 60_000;
    expect((await mcpPost(env, INIT, { Authorization: `Bearer ${t.accessToken}` })).status).toBe(401);
    const wider = await token(env, { grant_type: 'refresh_token', refresh_token: t.refreshToken, client_id: t.clientId, scope: 'browser:read browser:manage' });
    expect(wider.json.error).toBe('invalid_scope');
  });

  it('supports RFC 7009 revocation of access and refresh tokens', async () => {
    const t = await fullTokens(env);
    const res = await fetch(`${env.base}/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: t.refreshToken, client_id: t.clientId }) });
    expect(res.status).toBe(200);
    expect((await mcpPost(env, INIT, { Authorization: `Bearer ${t.accessToken}` })).status).toBe(401);
    const refresh = await token(env, { grant_type: 'refresh_token', refresh_token: t.refreshToken, client_id: t.clientId });
    expect(refresh.json.error).toBe('invalid_grant');
  });

  it('owner revocation and the kill switch invalidate tokens immediately', async () => {
    const a = await fullTokens(env);
    const b = await fullTokens(env);
    env.auth.revokeClient(a.clientId);
    expect((await mcpPost(env, INIT, { Authorization: `Bearer ${a.accessToken}` })).status).toBe(401);
    expect((await mcpPost(env, INIT, { Authorization: `Bearer ${b.accessToken}` })).status).toBe(200);
    env.auth.revokeAll();
    expect((await mcpPost(env, INIT, { Authorization: `Bearer ${b.accessToken}` })).status).toBe(401);
    expect((await token(env, { grant_type: 'refresh_token', refresh_token: b.refreshToken, client_id: b.clientId })).json.error).toBe('invalid_grant');
  });

  it('changing the public URL invalidates tokens, registrations and pending requests', async () => {
    const t = await fullTokens(env);
    const clientId = (await register(env)).json.client_id as string;
    await fetch(authorizeUrl(env, { clientId }).url, { redirect: 'manual' });
    expect(env.auth.pendingAuthorizations()).toHaveLength(1);
    env.auth.setPublicUrl('https://new-tunnel.example');
    expect(env.auth.pendingAuthorizations()).toHaveLength(0);
    expect(env.auth.clients()).toHaveLength(0);
    // The old token is unusable even on loopback (audience is the old resource).
    const res = await fetch(`${env.base}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${t.accessToken}` }, body: JSON.stringify(INIT) });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('https://new-tunnel.example/.well-known/oauth-protected-resource/mcp');
  });

  it('enforces per-tool scopes with a 403 insufficient_scope step-up challenge', async () => {
    const t = await fullTokens(env, { grantScopes: ['browser:read'] });
    const auth = { Authorization: `Bearer ${t.accessToken}` };
    expect((await mcpPost(env, INIT, auth)).status).toBe(200);
    const read = await mcpPost(env, toolCall('readPage'), { ...auth, 'MCP-Protocol-Version': '2025-06-18' });
    expect(read.status).toBe(200);
    const click = await mcpPost(env, toolCall('clickElement'), { ...auth, 'MCP-Protocol-Version': '2025-06-18' });
    expect(click.status).toBe(403);
    const challenge = click.headers.get('www-authenticate')!;
    expect(challenge).toContain('error="insufficient_scope"');
    expect(challenge).toContain('browser:interact');
  });

  it('never writes tokens, codes or secrets to the audit log', async () => {
    const reg = await register(env, { token_endpoint_auth_method: 'client_secret_post' });
    const { code, verifier } = await obtainCode(env, { clientId: reg.json.client_id as string });
    const t = await token(env, { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: reg.json.client_id as string, client_secret: reg.json.client_secret as string, code_verifier: verifier });
    await mcpPost(env, INIT, { Authorization: 'Bearer rbu_at_bogus' });
    const log = env.auditText();
    expect(log.length).toBeGreaterThan(0);
    for (const secret of [t.json.access_token, t.json.refresh_token, code, verifier, reg.json.client_secret, pkceChallenge(verifier), 'rbu_at_', 'rbu_rt_', 'rbu_ac_', 'rbu_cs_']) {
      expect(log).not.toContain(String(secret));
    }
  });
});
