// OAuth 2.0 / OpenID Connect helpers: token classification, at_hash/c_hash checks,
// and a static review of authorization request URLs. Pure functions, no network.

import { base64urlEncode, utf8Encode } from './base64url.js';

/**
 * Guess what kind of token this is from its header and claims.
 */
export function classifyToken(header = {}, payload = {}) {
  const typ = String(header.typ || '').toLowerCase();
  const p = payload && typeof payload === 'object' ? payload : {};
  if (typ === 'at+jwt' || typ === 'application/at+jwt') {
    return { kind: 'access_token', label: 'OAuth 2.0 access token (RFC 9068)', reason: `typ is "${header.typ}"` };
  }
  if (typ === 'dpop+jwt') return { kind: 'dpop', label: 'DPoP proof (RFC 9449)', reason: 'typ is "dpop+jwt"' };
  if (typ === 'logout+jwt' || (p.events && p.events['http://schemas.openid.net/event/backchannel-logout'])) {
    return { kind: 'logout_token', label: 'OIDC back-channel logout token', reason: 'logout event claim' };
  }
  if (p.nonce !== undefined || p.at_hash !== undefined || p.c_hash !== undefined || p.auth_time !== undefined) {
    return { kind: 'id_token', label: 'OpenID Connect ID token', reason: 'has nonce / at_hash / c_hash / auth_time' };
  }
  if (p.scope !== undefined || p.scp !== undefined || p.client_id !== undefined) {
    return { kind: 'access_token', label: 'OAuth 2.0 access token (likely)', reason: 'has scope / client_id' };
  }
  if (p.iss && p.sub && p.aud) {
    return { kind: 'id_token', label: 'ID token or access token', reason: 'has iss, sub and aud' };
  }
  return { kind: 'jwt', label: 'Generic JWT', reason: 'no OAuth/OIDC-specific markers' };
}

/** List the scopes in a token as an array. */
export function extractScopes(payload = {}) {
  const raw = payload.scope ?? payload.scp;
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === 'string') return raw.split(/\s+/).filter(Boolean);
  return [];
}

const HASH_FOR_ALG = {
  256: 'SHA-256', 384: 'SHA-384', 512: 'SHA-512',
};

/**
 * OIDC at_hash / c_hash: base64url of the left-most half of the hash of the ASCII value,
 * using the hash from the ID token's alg (OIDC Core §3.1.3.6).
 */
export async function computeOidcHash(value, alg) {
  let hash;
  if (alg === 'EdDSA' || alg === 'Ed25519') hash = 'SHA-512';
  else {
    const m = /^(HS|RS|PS|ES)(256|384|512)$/.exec(alg || '');
    if (!m) throw new Error(`Cannot derive hash function from alg "${alg}"`);
    hash = HASH_FOR_ALG[m[2]];
  }
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest(hash, utf8Encode(value)));
  return base64urlEncode(digest.slice(0, digest.length / 2));
}

function issue(severity, title, detail) {
  return { severity, title, detail };
}

function isLoopback(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host.endsWith('.localhost');
}

/**
 * Static review of an OAuth 2.0 / OIDC authorization request URL, following the
 * OAuth 2.0 Security Best Current Practice (RFC 9700).
 */
export function inspectAuthorizationUrl(input) {
  let url;
  try {
    url = new URL(String(input).trim());
  } catch {
    throw new Error('Not a valid absolute URL');
  }
  const q = url.searchParams;
  const params = Object.fromEntries(q.entries());
  const findings = [];
  const responseType = (q.get('response_type') || '').split(/\s+/).filter(Boolean);
  const scopes = (q.get('scope') || '').split(/\s+/).filter(Boolean);
  const isOidc = scopes.includes('openid');

  if (url.protocol !== 'https:' && !isLoopback(url.hostname)) {
    findings.push(issue('high', 'Authorization endpoint is not HTTPS', `${url.origin} will expose the request and the user's credentials to the network.`));
  }
  if (!responseType.length) {
    findings.push(issue('medium', 'Missing response_type', 'Required by RFC 6749 §3.1.1.'));
  }
  if (responseType.includes('token')) {
    findings.push(issue('high', 'Implicit flow (response_type includes "token")',
      'Access tokens in the URL fragment leak through history, referrers and logs. RFC 9700 says clients should not use the implicit grant; use the authorization code flow with PKCE.'));
  }
  if (responseType.includes('id_token') && !responseType.includes('code') && !responseType.includes('token')) {
    findings.push(issue('medium', 'Implicit ID token flow', 'Prefer the authorization code flow with PKCE.'));
  }
  if (responseType.includes('code')) {
    const challenge = q.get('code_challenge');
    const method = q.get('code_challenge_method');
    if (!challenge) {
      findings.push(issue('high', 'No PKCE code_challenge',
        'Without PKCE, an intercepted authorization code can be redeemed by an attacker. RFC 9700 requires PKCE for public clients and recommends it for all clients.'));
    } else {
      if (!method || method === 'plain') {
        findings.push(issue('medium', `PKCE method is ${method ? '"plain"' : 'unspecified (defaults to "plain")'}`,
          'The plain method sends the verifier itself. Use code_challenge_method=S256.'));
      }
      if (method === 'S256' && !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
        findings.push(issue('low', 'Unusual S256 code_challenge', 'An S256 challenge is the 43-character base64url SHA-256 of the verifier.'));
      }
    }
  }
  const state = q.get('state');
  if (!state) {
    findings.push(issue(q.get('code_challenge') ? 'low' : 'medium', 'No state parameter',
      'state (or PKCE) protects against CSRF on the redirect. Without either, login CSRF is possible.'));
  } else if (state.length < 16) {
    findings.push(issue('low', 'Short state value', `state is ${state.length} characters; use at least 128 bits of randomness.`));
  }
  if (isOidc && !q.get('nonce') && responseType.some((t) => t === 'id_token' || t === 'token')) {
    findings.push(issue('high', 'No nonce on an implicit/hybrid OIDC request', 'nonce is required here to prevent ID token replay (OIDC Core §3.2.2.1).'));
  } else if (isOidc && !q.get('nonce')) {
    findings.push(issue('low', 'No nonce', 'nonce binds the ID token to this browser session; recommended even with the code flow.'));
  }
  const redirect = q.get('redirect_uri');
  if (!redirect) {
    findings.push(issue('low', 'No redirect_uri', 'The server will use the registered default. Fine if exactly one is registered.'));
  } else {
    let ru;
    try { ru = new URL(redirect); } catch { ru = null; }
    if (!ru) {
      findings.push(issue('medium', 'redirect_uri is not an absolute URL', redirect));
    } else {
      if (ru.protocol === 'http:' && !isLoopback(ru.hostname)) {
        findings.push(issue('high', 'redirect_uri uses plain HTTP', 'Authorization codes or tokens will travel unencrypted.'));
      }
      if (ru.hash) findings.push(issue('medium', 'redirect_uri contains a fragment', 'Not allowed by RFC 6749 §3.1.2.'));
      if (/\*/.test(redirect)) findings.push(issue('high', 'Wildcard in redirect_uri', 'Servers must use exact string matching of redirect URIs (RFC 9700 §4.1).'));
      if (/[?&](url|next|redirect|return|continue|goto)=/i.test(ru.search)) {
        findings.push(issue('medium', 'redirect_uri carries its own redirect parameter',
          'Open redirectors on the client can leak codes and tokens to attackers (RFC 9700 §4.11).'));
      }
    }
  }
  if (q.get('response_mode') === 'query' && responseType.some((t) => t === 'token' || t === 'id_token')) {
    findings.push(issue('high', 'Tokens requested in the query string', 'response_mode=query with tokens puts them in server logs and Referer headers.'));
  }
  if (q.get('client_secret')) {
    findings.push(issue('critical', 'client_secret in the authorization URL', 'The client secret is exposed to the browser and anyone who sees this URL. Rotate it.'));
  }
  if (q.get('access_token') || q.get('id_token')) {
    findings.push(issue('high', 'Token in the URL', 'Bearer tokens in URLs leak via logs, history and Referer headers.'));
  }
  if (!q.get('client_id')) findings.push(issue('medium', 'Missing client_id', 'Required by RFC 6749 §4.1.1.'));
  if (scopes.length > 10) {
    findings.push(issue('low', `Requests ${scopes.length} scopes`, 'Ask for the minimum scopes the client needs.'));
  }
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return {
    endpoint: `${url.origin}${url.pathname}`, params, responseType, scopes, isOidc, findings,
  };
}
