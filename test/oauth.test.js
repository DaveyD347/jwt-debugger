import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyToken, computeOidcHash, extractScopes, inspectAuthorizationUrl } from '../src/oauth.js';

const titles = (r) => r.findings.map((f) => f.title).join(' | ');

test('classifies tokens', () => {
  assert.equal(classifyToken({ typ: 'at+jwt' }, {}).kind, 'access_token');
  assert.equal(classifyToken({}, { nonce: 'n', iss: 'i' }).kind, 'id_token');
  assert.equal(classifyToken({}, { scope: 'read write' }).kind, 'access_token');
  assert.equal(classifyToken({ typ: 'dpop+jwt' }, {}).kind, 'dpop');
  assert.equal(classifyToken({}, { foo: 1 }).kind, 'jwt');
});

test('extracts scopes from scope and scp', () => {
  assert.deepEqual(extractScopes({ scope: 'openid  profile email' }), ['openid', 'profile', 'email']);
  assert.deepEqual(extractScopes({ scp: ['a', 'b'] }), ['a', 'b']);
  assert.deepEqual(extractScopes({}), []);
});

test('at_hash matches the OIDC Core spec example', async () => {
  // OpenID Connect Core 1.0, Appendix A.4 (RS256)
  assert.equal(await computeOidcHash('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y', 'RS256'), '77QmUPtjPfzWtF2AnpK9RQ');
  await assert.rejects(computeOidcHash('x', 'none'), /Cannot derive/);
});

test('flags implicit flow, missing PKCE and state, insecure redirect', () => {
  const r = inspectAuthorizationUrl('http://idp.example/authorize?response_type=token&client_id=c&redirect_uri=http://app.example/cb&scope=openid');
  const t = titles(r);
  assert.match(t, /not HTTPS/);
  assert.match(t, /Implicit flow/);
  assert.match(t, /No state/);
  assert.match(t, /plain HTTP/);
  assert.match(t, /No nonce on an implicit/);
  assert.doesNotMatch(t, /Implicit ID token flow/);
  assert.equal(r.findings[0].severity, 'high');
});

test('code flow without PKCE, with plain PKCE, and with client_secret', () => {
  assert.match(titles(inspectAuthorizationUrl('https://idp/authorize?response_type=code&client_id=c&state=abcdefghijklmnopq')), /No PKCE/);
  assert.match(titles(inspectAuthorizationUrl('https://idp/authorize?response_type=code&client_id=c&code_challenge=abc')), /PKCE method is unspecified/);
  const r = inspectAuthorizationUrl('https://idp/authorize?response_type=code&client_id=c&client_secret=s');
  assert.equal(r.findings[0].severity, 'critical');
});

test('a best-practice request is clean', () => {
  const url = 'https://idp.example/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb'
    + '&scope=openid%20profile&state=Zx9uY2hKk3Lm8QpR&nonce=n-0S6_WzA2Mj'
    + '&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256';
  const r = inspectAuthorizationUrl(url);
  assert.deepEqual(r.findings, []);
  assert.equal(r.isOidc, true);
  assert.equal(r.endpoint, 'https://idp.example/authorize');
});

test('loopback redirect over http is allowed; wildcards are not', () => {
  const ok = inspectAuthorizationUrl('https://idp/a?response_type=code&client_id=c&redirect_uri=http://127.0.0.1:8080/cb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=0123456789abcdef');
  assert.doesNotMatch(titles(ok), /plain HTTP/);
  assert.match(titles(inspectAuthorizationUrl('https://idp/a?response_type=code&client_id=c&redirect_uri=https://*.app.example/cb')), /Wildcard/);
  assert.throws(() => inspectAuthorizationUrl('not a url'), /valid absolute URL/);
});
