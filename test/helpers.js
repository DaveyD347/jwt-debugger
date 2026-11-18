import { bytesToBase64 } from '../src/base64url.js';

export function toPem(der, label) {
  const b64 = bytesToBase64(new Uint8Array(der)).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

const GEN = {
  RS256: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  PS256: { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  ES256: { name: 'ECDSA', namedCurve: 'P-256' },
  ES384: { name: 'ECDSA', namedCurve: 'P-384' },
  ES512: { name: 'ECDSA', namedCurve: 'P-521' },
  EdDSA: { name: 'Ed25519' },
};

const cache = new Map();

export async function keyPair(alg) {
  if (cache.has(alg)) return cache.get(alg);
  const s = globalThis.crypto.subtle;
  const kp = await s.generateKey(GEN[alg], true, ['sign', 'verify']);
  const out = {
    publicPem: toPem(await s.exportKey('spki', kp.publicKey), 'PUBLIC KEY'),
    privatePem: toPem(await s.exportKey('pkcs8', kp.privateKey), 'PRIVATE KEY'),
    publicJwk: await s.exportKey('jwk', kp.publicKey),
    privateJwk: await s.exportKey('jwk', kp.privateKey),
  };
  cache.set(alg, out);
  return out;
}
