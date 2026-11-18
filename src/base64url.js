// Base64url helpers (RFC 4648 §5) that work in browsers and Node >= 18.

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

export function utf8Encode(str) {
  return enc.encode(str);
}

export function utf8Decode(bytes) {
  return dec.decode(bytes);
}

export function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const clean = b64.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new Error('Invalid base64 characters');
  }
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64urlEncode(input) {
  const bytes = typeof input === 'string' ? utf8Encode(input) : input;
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(str) {
  if (!/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new Error('Invalid base64url characters (padding "=" and "+" "/" are not allowed in JWS)');
  }
  if (str.length % 4 === 1) throw new Error('Invalid base64url length');
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return base64ToBytes(b64);
}

export function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '').replace(/^0x/i, '');
  if (clean.length % 2 || /[^0-9a-f]/i.test(clean)) throw new Error('Invalid hex string');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
