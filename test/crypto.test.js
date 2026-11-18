import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { base64urlEncode, bytesToBase64 } from '../src/base64url.js';
import {
  jwkThumbprint, keyConfusionVariants, parseKeyInput, scanWeakSecrets, signJwt, spkiFromCertificate, spkiFromPkcs1, testKeyConfusion, verifyJwt,
} from '../src/crypto.js';
import { decodeJwt } from '../src/jwt.js';
import { COMMON_SECRETS } from '../src/wordlist.js';
import { keyPair } from './helpers.js';

const PAYLOAD = { sub: 'alice', iat: 1_700_000_000, exp: 1_700_000_900 };

test('verifies the jwt.io sample with "your-256-bit-secret"', async () => {
  const d = decodeJwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
  const ok = await verifyJwt(d, 'your-256-bit-secret');
  assert.equal(ok.valid, true);
  assert.equal((await verifyJwt(d, 'wrong')).valid, false);
});

for (const alg of ['HS256', 'HS384', 'HS512']) {
  test(`${alg} sign/verify with utf8, base64 and hex secrets`, async () => {
    const secret = 'a'.repeat(64);
    const t = await signJwt({ alg, typ: 'JWT' }, PAYLOAD, secret);
    assert.equal((await verifyJwt(decodeJwt(t), secret)).valid, true);
    const b64 = bytesToBase64(new TextEncoder().encode(secret));
    assert.equal((await verifyJwt(decodeJwt(t), b64, { secretEncoding: 'base64' })).valid, true);
    const hex = Buffer.from(secret).toString('hex');
    assert.equal((await verifyJwt(decodeJwt(t), hex, { secretEncoding: 'hex' })).valid, true);
  });
}

test('warns about HMAC secrets shorter than the hash output', async () => {
  const t = await signJwt({ alg: 'HS256' }, PAYLOAD, 'short');
  const r = await verifyJwt(decodeJwt(t), 'short');
  assert.equal(r.valid, true);
  assert.match(r.warnings.join(' '), /RFC 7518/);
});

for (const alg of ['RS256', 'PS256', 'ES256', 'ES384', 'ES512', 'EdDSA']) {
  test(`${alg} sign with PKCS#8 / verify with SPKI PEM, JWK and JWKS`, async () => {
    const k = await keyPair(alg);
    const token = await signJwt({ alg, kid: 'k1' }, PAYLOAD, k.privatePem);
    const d = decodeJwt(token);
    assert.equal((await verifyJwt(d, k.publicPem)).valid, true, 'PEM');
    assert.equal((await verifyJwt(d, JSON.stringify(k.publicJwk))).valid, true, 'JWK');
    assert.equal((await verifyJwt(d, k.privatePem)).valid, true, 'private PEM derives public key');
    const jwks = { keys: [{ ...k.publicJwk, kid: 'other' }, { ...k.publicJwk, kid: 'k1' }] };
    const r = await verifyJwt(d, JSON.stringify(jwks));
    assert.equal(r.valid, true, 'JWKS');
    assert.match(r.keyInfo, /kid=k1/);

    const fromJwk = await signJwt({ alg }, PAYLOAD, JSON.stringify(k.privateJwk));
    assert.equal((await verifyJwt(decodeJwt(fromJwk), k.publicPem)).valid, true, 'sign with private JWK');

    const tampered = decodeJwt(`${token.split('.')[0]}.${base64urlEncode(JSON.stringify({ ...PAYLOAD, sub: 'mallory' }))}.${token.split('.')[2]}`);
    assert.equal((await verifyJwt(tampered, k.publicPem)).valid, false, 'tampered payload');
  });
}

test('wrong key type gives a clear error', async () => {
  const k = await keyPair('RS256');
  const t = await signJwt({ alg: 'RS256' }, PAYLOAD, k.privatePem);
  await assert.rejects(verifyJwt(decodeJwt(t), 'just-a-secret'), /needs a public key/);
  const hs = await signJwt({ alg: 'HS256' }, PAYLOAD, 'secret');
  await assert.rejects(verifyJwt(decodeJwt(hs), k.publicPem), /key confusion/);
});

test('empty HMAC secrets work (kid=/dev/null attack) despite WebCrypto rejecting zero-length keys', async () => {
  const t = decodeJwt(await signJwt({ alg: 'HS256', kid: '/dev/null' }, PAYLOAD, ''));
  assert.equal((await verifyJwt(t, '')).valid, true);
  // Cross-check against Node's HMAC implementation, which accepts empty keys.
  const { createHmac } = await import('node:crypto');
  const expected = createHmac('sha256', Buffer.alloc(0)).update(t.signingInput).digest('base64url');
  assert.equal(t.parts[2], expected);
  assert.equal((await scanWeakSecrets(t, ['nope', ''])).found, '');
});

test('alg none never verifies, and algorithm pinning rejects mismatches', async () => {
  const none = await signJwt({ alg: 'none' }, PAYLOAD, '');
  assert.ok(none.endsWith('.'));
  assert.equal((await verifyJwt(decodeJwt(none), 'anything')).valid, false);
  const hs = await signJwt({ alg: 'HS256' }, PAYLOAD, 'secret');
  const r = await verifyJwt(decodeJwt(hs), 'secret', { expectedAlg: 'RS256' });
  assert.equal(r.valid, false);
  assert.match(r.warnings[0], /pinned/);
});

test('PKCS#1 "RSA PUBLIC KEY" PEM is accepted', async () => {
  const k = await keyPair('RS256');
  const { der } = parseKeyInput(k.publicPem);
  // Extract the PKCS#1 key from the SPKI BIT STRING (fixed 24-byte prefix for 2048-bit keys).
  const pkcs1 = der.slice(24);
  assert.deepEqual(spkiFromPkcs1(pkcs1), der);
  const pem = `-----BEGIN RSA PUBLIC KEY-----\n${bytesToBase64(pkcs1)}\n-----END RSA PUBLIC KEY-----`;
  const t = await signJwt({ alg: 'RS256' }, PAYLOAD, k.privatePem);
  assert.equal((await verifyJwt(decodeJwt(t), pem)).valid, true);
});

test('X.509 certificate PEM is accepted (public key extracted from the cert)', async () => {
  const cert = readFileSync(new URL('./fixtures/cert.pem', import.meta.url), 'utf8');
  const key = readFileSync(new URL('./fixtures/cert-key.pem', import.meta.url), 'utf8');
  const t = await signJwt({ alg: 'ES256' }, PAYLOAD, key);
  assert.equal((await verifyJwt(decodeJwt(t), cert)).valid, true);
  assert.equal(spkiFromCertificate(parseKeyInput(cert).der).length, 91); // P-256 SPKI
});

test('weak secret scan finds dictionary secrets and honours abort', async () => {
  const t = decodeJwt(await signJwt({ alg: 'HS256' }, PAYLOAD, 'changeme'));
  const r = await scanWeakSecrets(t, COMMON_SECRETS);
  assert.equal(r.found, 'changeme');
  const strong = decodeJwt(await signJwt({ alg: 'HS512' }, PAYLOAD, crypto.randomUUID() + crypto.randomUUID()));
  const r2 = await scanWeakSecrets(strong, COMMON_SECRETS, { batchSize: 50 });
  assert.equal(r2.found, null);
  assert.equal(r2.tried, new Set(COMMON_SECRETS).size);
  const ac = new AbortController(); ac.abort();
  assert.equal((await scanWeakSecrets(strong, COMMON_SECRETS, { signal: ac.signal })).tried, 0);
  await assert.rejects(scanWeakSecrets(decodeJwt(await signJwt({ alg: 'none' }, {}, '')), ['x']), /only applies/);
});

test('key confusion: detects HS256 tokens signed with the RSA public key', async () => {
  const k = await keyPair('RS256');
  const forged = decodeJwt(await signJwt({ alg: 'HS256' }, { sub: 'admin' }, k.publicPem));
  const r = await testKeyConfusion(forged, k.publicPem);
  assert.equal(r.vulnerable, true);
  assert.ok(keyConfusionVariants(k.publicPem).size >= 5);
  const honest = decodeJwt(await signJwt({ alg: 'HS256' }, { sub: 'admin' }, 'unrelated-secret'));
  assert.equal((await testKeyConfusion(honest, k.publicPem)).vulnerable, false);
  // Variant with trimmed PEM (no trailing newline) is also found.
  const trimmedForged = decodeJwt(await signJwt({ alg: 'HS256' }, {}, k.publicPem.trim()));
  assert.equal((await testKeyConfusion(trimmedForged, k.publicPem)).vulnerable, true);
});

test('RFC 7638 thumbprint test vector', async () => {
  const jwk = {
    kty: 'RSA',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    e: 'AQAB',
    alg: 'RS256',
    kid: '2011-04-29',
  };
  assert.equal(await jwkThumbprint(jwk), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
});
