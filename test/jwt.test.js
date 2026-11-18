import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base64urlDecode, base64urlEncode, utf8Decode } from '../src/base64url.js';
import { analyzeJwt, decodeJwt, describeTimeClaim, JwtError } from '../src/jwt.js';

const NOW = 1_700_000_000;
const ids = (findings) => findings.map((f) => f.id);

function make(header, payload, sig = 'c2ln') {
  return `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.${sig}`;
}

test('base64url round-trips unicode and binary', () => {
  const s = 'héllo 🌍 ~~~???';
  assert.equal(utf8Decode(base64urlDecode(base64urlEncode(s))), s);
  const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(base64urlDecode(base64urlEncode(bytes)), bytes);
  assert.throws(() => base64urlDecode('ab+c'), /Invalid base64url/);
  assert.throws(() => base64urlDecode('abc='), /Invalid base64url/);
});

test('decodes the jwt.io sample token', () => {
  const t = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const d = decodeJwt(`Bearer ${t}`);
  assert.equal(d.kind, 'JWS');
  assert.deepEqual(d.header, { alg: 'HS256', typ: 'JWT' });
  assert.equal(d.payload.name, 'John Doe');
  assert.equal(d.signature.length, 32);
});

test('rejects malformed tokens', () => {
  assert.throws(() => decodeJwt(''), JwtError);
  assert.throws(() => decodeJwt('a.b'), /dot-separated/);
  assert.throws(() => decodeJwt('!!!.e30.'), /Header/);
  assert.throws(() => decodeJwt(`${base64urlEncode('[1]')}.e30.`), /not a JSON object/);
});

test('recognises JWE and flags RSA1_5', () => {
  const h = base64urlEncode(JSON.stringify({ alg: 'RSA1_5', enc: 'A128GCM' }));
  const d = decodeJwt(`${h}.a.b.c.d`);
  assert.equal(d.kind, 'JWE');
  assert.ok(ids(analyzeJwt(d)).includes('jwe-rsa1_5'));
});

test('flags alg none, case variants and leftover signatures', () => {
  let f = analyzeJwt(decodeJwt(make({ alg: 'none' }, { exp: NOW + 60 }, '')), { now: NOW });
  assert.equal(f[0].severity, 'critical');
  assert.ok(ids(f).includes('alg-none'));
  assert.ok(!ids(f).includes('sig-empty'));
  f = analyzeJwt(decodeJwt(make({ alg: 'nOnE' }, {}, 'c2ln')), { now: NOW });
  assert.ok(ids(f).includes('alg-none-case'));
  assert.ok(ids(f).includes('alg-none-sig'));
});

test('flags stripped signatures and header key-injection vectors', () => {
  const f = analyzeJwt(decodeJwt(make(
    { alg: 'RS256', jku: 'https://evil.example/jwks.json', jwk: { kty: 'RSA' }, x5u: 'https://x', kid: '../../dev/null' },
    {}, '',
  )), { now: NOW });
  for (const id of ['sig-empty', 'hdr-jku', 'hdr-jwk', 'hdr-x5u', 'kid-path']) assert.ok(ids(f).includes(id), id);
  const sqli = analyzeJwt(decodeJwt(make({ alg: 'HS256', kid: "x' UNION SELECT 'key" }, {})), { now: NOW });
  assert.ok(ids(sqli).includes('kid-sqli'));
});

test('time claims: expired, not-yet-valid, future iat, milliseconds, long lifetime', () => {
  const f = analyzeJwt(decodeJwt(make({ alg: 'HS256' }, {
    exp: NOW - 120, nbf: NOW + 3600, iat: NOW + 7200,
  })), { now: NOW });
  for (const id of ['expired', 'nbf-future', 'iat-future']) assert.ok(ids(f).includes(id), id);

  const ms = analyzeJwt(decodeJwt(make({ alg: 'HS256' }, { exp: NOW * 1000 })), { now: NOW });
  assert.ok(ids(ms).includes('claim-exp-ms'));

  const long = analyzeJwt(decodeJwt(make({ alg: 'HS256' }, { iat: NOW, exp: NOW + 90 * 86400 })), { now: NOW });
  assert.ok(ids(long).includes('lifetime-long'));

  const typed = analyzeJwt(decodeJwt(make({ alg: 'HS256' }, { exp: '9999999999' })), { now: NOW });
  assert.ok(ids(typed).includes('claim-exp-type'));

  const skew = analyzeJwt(decodeJwt(make({ alg: 'HS256' }, { exp: NOW - 10 })), { now: NOW, clockSkew: 30 });
  assert.ok(!ids(skew).includes('expired'));
});

test('missing exp/iss/aud and sensitive claims', () => {
  const f = analyzeJwt(decodeJwt(make({ alg: 'HS256' }, { user: { password: 'hunter2' }, api_key: 'abc' })), { now: NOW });
  for (const id of ['exp-missing', 'iss-missing', 'aud-missing', 'sensitive-data']) assert.ok(ids(f).includes(id), id);
  const sens = f.find((x) => x.id === 'sensitive-data');
  assert.match(sens.detail, /user\.password/);
  assert.match(sens.detail, /api_key/);
});

test('signature length heuristics: weak RSA and DER-encoded ECDSA', () => {
  const rsa1024 = base64urlEncode(new Uint8Array(128));
  assert.ok(ids(analyzeJwt(decodeJwt(make({ alg: 'RS256' }, {}, rsa1024)), { now: NOW })).includes('rsa-weak'));
  const der = new Uint8Array(71); der[0] = 0x30;
  const f = analyzeJwt(decodeJwt(make({ alg: 'ES256' }, {}, base64urlEncode(der))), { now: NOW });
  const len = f.find((x) => x.id === 'sig-length');
  assert.ok(len);
  assert.match(len.detail, /DER/);
});

test('a well-formed token has no high or critical findings', () => {
  const f = analyzeJwt(decodeJwt(make(
    { alg: 'ES256', typ: 'JWT', kid: 'k1' },
    { iss: 'https://idp', aud: 'api', sub: 'u', iat: NOW, exp: NOW + 900 },
    base64urlEncode(new Uint8Array(64)),
  )), { now: NOW });
  assert.ok(f.every((x) => !['critical', 'high', 'medium'].includes(x.severity)), JSON.stringify(f));
});

test('findings are sorted by severity', () => {
  const f = analyzeJwt(decodeJwt(make({ alg: 'none', jku: 'x' }, {}, '')), { now: NOW });
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  for (let i = 1; i < f.length; i++) assert.ok(order.indexOf(f[i - 1].severity) <= order.indexOf(f[i].severity));
});

test('describeTimeClaim', () => {
  assert.equal(describeTimeClaim(NOW + 3600, NOW).relative, 'in 1h');
  assert.equal(describeTimeClaim(NOW - 172800, NOW).relative, '2d ago');
  assert.equal(describeTimeClaim('x', NOW), null);
});
