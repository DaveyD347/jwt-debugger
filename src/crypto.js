// Signature verification, signing, weak-secret scanning and key-confusion testing.
// Uses only the WebCrypto API (window.crypto.subtle / globalThis.crypto.subtle).

import {
  base64ToBytes, base64urlDecode, base64urlEncode, bytesToBase64, hexToBytes, utf8Encode,
} from './base64url.js';

const subtle = () => {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Error('WebCrypto is unavailable (a secure context such as https:// or localhost is required)');
  return s;
};

const HASH = { 256: 'SHA-256', 384: 'SHA-384', 512: 'SHA-512' };
const CURVE = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };

/** WebCrypto parameters for a JWS alg. */
export function algParams(alg) {
  if (typeof alg !== 'string') throw new Error('Missing alg');
  const bits = alg.slice(2);
  if (/^HS(256|384|512)$/.test(alg)) {
    return { family: 'HMAC', importParams: { name: 'HMAC', hash: HASH[bits] }, signParams: { name: 'HMAC' } };
  }
  if (/^RS(256|384|512)$/.test(alg)) {
    const p = { name: 'RSASSA-PKCS1-v1_5', hash: HASH[bits] };
    return { family: 'RSA', importParams: p, signParams: p };
  }
  if (/^PS(256|384|512)$/.test(alg)) {
    return {
      family: 'RSA',
      importParams: { name: 'RSA-PSS', hash: HASH[bits] },
      signParams: { name: 'RSA-PSS', saltLength: Number(bits) / 8 },
    };
  }
  if (/^ES(256|384|512)$/.test(alg)) {
    return {
      family: 'EC',
      importParams: { name: 'ECDSA', namedCurve: CURVE[alg] },
      signParams: { name: 'ECDSA', hash: HASH[bits] },
    };
  }
  if (alg === 'EdDSA' || alg === 'Ed25519') {
    return { family: 'OKP', importParams: { name: 'Ed25519' }, signParams: { name: 'Ed25519' } };
  }
  throw new Error(`Unsupported algorithm "${alg}"`);
}

// WebCrypto refuses zero-length HMAC keys. HMAC zero-pads keys to the block size, so an
// empty key is equivalent to a single 0x00 byte. This matters for kid=/dev/null style attacks.
function hmacKeyBytes(bytes) {
  return bytes.length ? bytes : new Uint8Array([0]);
}

// ---------------------------------------------------------------- DER helpers

function readTlv(bytes, offset) {
  const tag = bytes[offset];
  let len = bytes[offset + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) throw new Error('Unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = (len * 256) + bytes[offset + 2 + i];
    hdr += n;
  }
  const start = offset + hdr;
  const end = start + len;
  if (end > bytes.length) throw new Error('Truncated DER');
  return { tag, start, end, offset };
}

function children(bytes, tlv) {
  const out = [];
  let o = tlv.start;
  while (o < tlv.end) {
    const c = readTlv(bytes, o);
    out.push(c);
    o = c.end;
  }
  return out;
}

/** Extract SubjectPublicKeyInfo DER from an X.509 certificate DER. */
export function spkiFromCertificate(der) {
  const cert = readTlv(der, 0);
  const tbs = children(der, cert)[0];
  const kids = children(der, tbs);
  let i = kids[0].tag === 0xa0 ? 1 : 0; // optional [0] version
  i += 5; // serialNumber, signature, issuer, validity, subject
  const spki = kids[i];
  if (!spki || spki.tag !== 0x30) throw new Error('Could not locate SubjectPublicKeyInfo in certificate');
  return der.slice(spki.offset, spki.end);
}

function derLen(n) {
  if (n < 0x80) return [n];
  const b = [];
  while (n > 0) { b.unshift(n & 0xff); n >>= 8; }
  return [0x80 | b.length, ...b];
}

function derWrap(tag, content) {
  return Uint8Array.from([tag, ...derLen(content.length), ...content]);
}

/** Wrap a PKCS#1 RSAPublicKey in a SubjectPublicKeyInfo. */
export function spkiFromPkcs1(pkcs1) {
  const algId = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  const bitString = derWrap(0x03, Uint8Array.from([0x00, ...pkcs1]));
  return derWrap(0x30, Uint8Array.from([...algId, ...bitString]));
}

// ---------------------------------------------------------------- key parsing

export function parsePem(text) {
  const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
  if (!m) throw new Error('Malformed PEM block');
  return { label: m[1], der: base64ToBytes(m[2].replace(/[^A-Za-z0-9+/=]/g, '')) };
}

/**
 * Classify user key input. Returns one of:
 *  { type: 'pem', label, der } | { type: 'jwk', jwk } | { type: 'jwks', keys } | { type: 'secret', bytes }
 */
export function parseKeyInput(input, { secretEncoding = 'utf8' } = {}) {
  const text = String(input ?? '');
  const trimmed = text.trim();
  if (trimmed.startsWith('-----BEGIN')) {
    return { type: 'pem', ...parsePem(trimmed) };
  }
  if (trimmed.startsWith('{')) {
    let obj;
    try { obj = JSON.parse(trimmed); } catch { obj = null; }
    if (obj && Array.isArray(obj.keys)) return { type: 'jwks', keys: obj.keys };
    if (obj && typeof obj.kty === 'string') return { type: 'jwk', jwk: obj };
  }
  return { type: 'secret', bytes: decodeSecret(text, secretEncoding) };
}

export function decodeSecret(text, encoding = 'utf8') {
  switch (encoding) {
    case 'utf8': return utf8Encode(text);
    case 'base64': return base64ToBytes(text.trim());
    case 'base64url': return base64urlDecode(text.trim().replace(/=+$/, ''));
    case 'hex': return hexToBytes(text);
    default: throw new Error(`Unknown secret encoding ${encoding}`);
  }
}

const PRIVATE_JWK_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

function publicJwk(jwk) {
  const pub = { ...jwk };
  for (const f of PRIVATE_JWK_FIELDS) delete pub[f];
  delete pub.key_ops;
  delete pub.alg;
  delete pub.use;
  pub.ext = true;
  return pub;
}

function jwkMatchesFamily(jwk, family) {
  return (family === 'RSA' && jwk.kty === 'RSA')
    || (family === 'EC' && jwk.kty === 'EC')
    || (family === 'OKP' && jwk.kty === 'OKP')
    || (family === 'HMAC' && jwk.kty === 'oct');
}

async function importVerifyKey(parsed, alg) {
  const { family, importParams } = algParams(alg);
  const s = subtle();
  if (family === 'HMAC') {
    if (parsed.type === 'secret') return s.importKey('raw', hmacKeyBytes(parsed.bytes), importParams, false, ['verify']);
    if (parsed.type === 'jwk' && parsed.jwk.kty === 'oct') {
      return s.importKey('raw', base64urlDecode(parsed.jwk.k), importParams, false, ['verify']);
    }
    if (parsed.type === 'pem') {
      throw new Error('An HMAC token needs a shared secret, not a PEM key. Use "Test key confusion" to check whether the server would accept the public key as an HMAC secret.');
    }
    throw new Error('HMAC algorithms need a shared secret');
  }
  if (parsed.type === 'secret') {
    throw new Error(`${alg} needs a public key (PEM, JWK or JWKS), not a shared secret`);
  }
  if (parsed.type === 'jwk') {
    if (!jwkMatchesFamily(parsed.jwk, family)) throw new Error(`JWK kty "${parsed.jwk.kty}" does not fit ${alg}`);
    return s.importKey('jwk', publicJwk(parsed.jwk), importParams, true, ['verify']);
  }
  if (parsed.type === 'pem') {
    const { label, der } = parsed;
    if (label === 'PUBLIC KEY') return s.importKey('spki', der, importParams, true, ['verify']);
    if (label === 'CERTIFICATE') return s.importKey('spki', spkiFromCertificate(der), importParams, true, ['verify']);
    if (label === 'RSA PUBLIC KEY') return s.importKey('spki', spkiFromPkcs1(der), importParams, true, ['verify']);
    if (label === 'PRIVATE KEY') {
      const priv = await s.importKey('pkcs8', der, importParams, true, ['sign']);
      const jwk = await s.exportKey('jwk', priv);
      return s.importKey('jwk', publicJwk(jwk), importParams, true, ['verify']);
    }
    throw new Error(`PEM type "${label}" is not supported. Convert it to "PUBLIC KEY" (SPKI) or "PRIVATE KEY" (PKCS#8).`);
  }
  throw new Error('Unsupported key input');
}

/**
 * Verify a decoded JWS. keyInput is a PEM / JWK / JWKS string or a secret.
 * Returns { valid, alg, keyInfo, warnings[] }. Throws on unusable keys.
 */
export async function verifyJwt(decoded, keyInput, { secretEncoding = 'utf8', expectedAlg } = {}) {
  if (decoded.kind !== 'JWS') throw new Error('Only JWS tokens can be verified');
  const alg = decoded.header.alg;
  const warnings = [];
  if (typeof alg === 'string' && alg.toLowerCase() === 'none') {
    return {
      valid: false, alg, keyInfo: 'n/a',
      warnings: ['alg "none" carries no signature. A secure verifier rejects this token outright.'],
    };
  }
  if (expectedAlg && expectedAlg !== alg) {
    return {
      valid: false, alg, keyInfo: 'n/a',
      warnings: [`Token alg ${alg} does not match the pinned algorithm ${expectedAlg}. A verifier with an algorithm allowlist rejects it before checking the signature.`],
    };
  }
  const { family, signParams } = algParams(alg);
  const parsed = parseKeyInput(keyInput, { secretEncoding });
  const data = utf8Encode(decoded.signingInput);
  const s = subtle();

  let candidates;
  if (parsed.type === 'jwks') {
    const kid = decoded.header.kid;
    let pool = parsed.keys.filter((k) => jwkMatchesFamily(k, family));
    if (kid !== undefined) {
      const byKid = pool.filter((k) => k.kid === kid);
      if (byKid.length) pool = byKid;
      else warnings.push(`No key in the JWKS has kid "${kid}"; trying every ${family} key.`);
    }
    if (!pool.length) throw new Error(`The JWKS has no ${family} keys`);
    candidates = pool.map((jwk) => ({ parsed: { type: 'jwk', jwk }, info: `JWK kid=${jwk.kid ?? '(none)'}` }));
  } else {
    candidates = [{ parsed, info: describeKey(parsed) }];
  }

  let lastErr;
  for (const c of candidates) {
    if (c.parsed.type === 'jwk' && c.parsed.jwk.alg && c.parsed.jwk.alg !== alg) {
      warnings.push(`JWK declares alg ${c.parsed.jwk.alg} but the token uses ${alg}. A strict verifier rejects this.`);
    }
    try {
      const key = await importVerifyKey(c.parsed, alg);
      if (family === 'HMAC' && c.parsed.type === 'secret') {
        const minLen = Number(alg.slice(2)) / 8;
        if (c.parsed.bytes.length < minLen) {
          warnings.push(`Secret is ${c.parsed.bytes.length} bytes; RFC 7518 §3.2 requires at least ${minLen} bytes for ${alg}.`);
        }
      }
      const ok = await s.verify(signParams, key, decoded.signature, data);
      if (ok) return { valid: true, alg, keyInfo: c.info, warnings };
    } catch (e) {
      lastErr = e;
    }
  }
  if (lastErr && candidates.length === 1) throw lastErr;
  return { valid: false, alg, keyInfo: candidates.map((c) => c.info).join(', '), warnings };
}

function describeKey(parsed) {
  switch (parsed.type) {
    case 'pem': return `PEM ${parsed.label}`;
    case 'jwk': return `JWK kty=${parsed.jwk.kty}${parsed.jwk.kid ? ` kid=${parsed.jwk.kid}` : ''}`;
    case 'secret': return `shared secret (${parsed.bytes.length} bytes)`;
    default: return parsed.type;
  }
}

// ---------------------------------------------------------------- signing

async function importSignKey(parsed, alg) {
  const { family, importParams } = algParams(alg);
  const s = subtle();
  if (family === 'HMAC') {
    if (parsed.type === 'secret') return s.importKey('raw', hmacKeyBytes(parsed.bytes), importParams, false, ['sign']);
    if (parsed.type === 'jwk' && parsed.jwk.kty === 'oct') {
      return s.importKey('raw', base64urlDecode(parsed.jwk.k), importParams, false, ['sign']);
    }
    if (parsed.type === 'pem') {
      // Deliberately allowed for key-confusion testing: PEM text is the HMAC secret.
      return s.importKey('raw', parsed.rawText, importParams, false, ['sign']);
    }
    throw new Error('HMAC signing needs a secret');
  }
  if (parsed.type === 'jwk') {
    if (!parsed.jwk.d) throw new Error('JWK has no private part ("d")');
    const jwk = { ...parsed.jwk };
    delete jwk.key_ops; delete jwk.alg; delete jwk.use;
    return s.importKey('jwk', jwk, importParams, false, ['sign']);
  }
  if (parsed.type === 'pem' && parsed.label === 'PRIVATE KEY') {
    return s.importKey('pkcs8', parsed.der, importParams, false, ['sign']);
  }
  throw new Error(`${alg} signing needs a private key (PKCS#8 "PRIVATE KEY" PEM or private JWK)`);
}

/**
 * Create a compact JWS. header.alg selects the algorithm. alg "none" yields an empty signature.
 */
export async function signJwt(header, payload, keyInput, { secretEncoding = 'utf8' } = {}) {
  const h = base64urlEncode(JSON.stringify(header));
  const p = base64urlEncode(typeof payload === 'string' ? payload : JSON.stringify(payload));
  const input = `${h}.${p}`;
  if (typeof header.alg === 'string' && header.alg.toLowerCase() === 'none') return `${input}.`;
  const { signParams } = algParams(header.alg);
  let parsed = parseKeyInput(keyInput, { secretEncoding });
  if (parsed.type === 'pem') parsed = { ...parsed, rawText: utf8Encode(String(keyInput)) };
  const key = await importSignKey(parsed, header.alg);
  const sig = new Uint8Array(await subtle().sign(signParams, key, utf8Encode(input)));
  return `${input}.${base64urlEncode(sig)}`;
}

// ---------------------------------------------------------------- HMAC attacks

async function hmacMatches(alg, secretBytes, data, signature) {
  const s = subtle();
  const key = await s.importKey('raw', hmacKeyBytes(secretBytes), { name: 'HMAC', hash: HASH[alg.slice(2)] }, false, ['verify']);
  return s.verify({ name: 'HMAC' }, key, signature, data);
}

/**
 * Dictionary attack on an HS* token's secret, entirely in-process.
 * Returns { found: string|null, tried }.
 */
export async function scanWeakSecrets(decoded, candidates, { onProgress, signal, batchSize = 200 } = {}) {
  const alg = decoded.header.alg;
  if (!/^HS(256|384|512)$/.test(alg)) throw new Error('Weak-secret scanning only applies to HS256/HS384/HS512 tokens');
  if (!decoded.signature.length) throw new Error('Token has no signature');
  const data = utf8Encode(decoded.signingInput);
  let tried = 0;
  const seen = new Set();
  for (let i = 0; i < candidates.length; i += batchSize) {
    if (signal?.aborted) break;
    const batch = candidates.slice(i, i + batchSize).filter((c) => {
      if (seen.has(c)) return false;
      seen.add(c);
      return true;
    });
    const results = await Promise.all(batch.map((c) => hmacMatches(alg, utf8Encode(c), data, decoded.signature)));
    tried += batch.length;
    const idx = results.indexOf(true);
    if (idx !== -1) return { found: batch[idx], tried };
    if (onProgress) onProgress(tried, candidates.length);
    await new Promise((r) => setTimeout(r, 0)); // yield to the UI thread
  }
  return { found: null, tried };
}

/** Variants of a public key that misconfigured libraries have been known to use as the HMAC secret. */
export function keyConfusionVariants(publicKeyText) {
  const text = String(publicKeyText);
  const trimmed = text.trim();
  const variants = new Map();
  variants.set('PEM as entered', utf8Encode(text));
  variants.set('PEM, trimmed', utf8Encode(trimmed));
  variants.set('PEM + trailing newline', utf8Encode(`${trimmed}\n`));
  variants.set('PEM with CRLF line endings', utf8Encode(`${trimmed.replace(/\r?\n/g, '\r\n')}\r\n`));
  try {
    const { label, der } = parsePem(trimmed);
    variants.set(`DER bytes of ${label}`, der);
    if (label === 'CERTIFICATE') {
      const spki = spkiFromCertificate(der);
      variants.set('DER bytes of the certificate public key', spki);
      const b64 = bytesToBase64(spki).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
      variants.set('Certificate public key as PEM', utf8Encode(`-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`));
    }
  } catch {
    // not PEM: JSON JWK text is still tried as entered
  }
  return variants;
}

/**
 * RS/ES -> HS key-confusion check (CVE-2016-10555 class): does an HS* token verify when the
 * server's *public* key is used as the HMAC secret? Returns { vulnerable, variant|null, tried }.
 */
export async function testKeyConfusion(decoded, publicKeyText) {
  const alg = decoded.header.alg;
  if (!/^HS(256|384|512)$/.test(alg)) {
    throw new Error('Key-confusion testing needs an HS* token, e.g. one forged with "Sign with public key as HMAC secret"');
  }
  const data = utf8Encode(decoded.signingInput);
  const variants = keyConfusionVariants(publicKeyText);
  for (const [name, bytes] of variants) {
    if (await hmacMatches(alg, bytes, data, decoded.signature)) return { vulnerable: true, variant: name, tried: variants.size };
  }
  return { vulnerable: false, variant: null, tried: variants.size };
}

/** Compute a JWK thumbprint (RFC 7638) for display. */
export async function jwkThumbprint(jwk) {
  const req = {
    RSA: ['e', 'kty', 'n'], EC: ['crv', 'kty', 'x', 'y'], OKP: ['crv', 'kty', 'x'], oct: ['k', 'kty'],
  }[jwk.kty];
  if (!req) throw new Error(`Unknown kty ${jwk.kty}`);
  const canon = `{${req.map((k) => `${JSON.stringify(k)}:${JSON.stringify(jwk[k])}`).join(',')}}`;
  const digest = await subtle().digest('SHA-256', utf8Encode(canon));
  return base64urlEncode(new Uint8Array(digest));
}
