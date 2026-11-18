// JWT parsing and static security analysis. Pure functions, no network, no DOM.

import { base64urlDecode, utf8Decode } from './base64url.js';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const KNOWN_ALGS = [
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA', 'Ed25519',
];

// Expected raw signature length in bytes, where it is fixed by the algorithm.
const FIXED_SIG_LEN = {
  HS256: 32, HS384: 48, HS512: 64,
  ES256: 64, ES384: 96, ES512: 132,
  EdDSA: 64, Ed25519: 64,
};

export const REGISTERED_CLAIMS = {
  iss: 'Issuer',
  sub: 'Subject',
  aud: 'Audience',
  exp: 'Expiration time',
  nbf: 'Not before',
  iat: 'Issued at',
  jti: 'JWT ID',
  azp: 'Authorized party (OIDC)',
  nonce: 'Nonce (OIDC)',
  auth_time: 'Authentication time (OIDC)',
  at_hash: 'Access token hash (OIDC)',
  c_hash: 'Code hash (OIDC)',
  acr: 'Authentication context class (OIDC)',
  amr: 'Authentication methods (OIDC)',
  sid: 'Session ID (OIDC)',
  scope: 'Scopes (OAuth 2.0)',
  scp: 'Scopes (non-standard)',
  client_id: 'Client ID (RFC 9068)',
  cnf: 'Confirmation / proof-of-possession key (RFC 7800)',
};

export const TIME_CLAIMS = ['exp', 'nbf', 'iat', 'auth_time'];

export const HEADER_PARAMS = {
  alg: 'Signature algorithm',
  typ: 'Media type',
  cty: 'Content type',
  kid: 'Key ID',
  jku: 'JWK Set URL',
  jwk: 'Embedded JSON Web Key',
  x5u: 'X.509 certificate URL',
  x5c: 'X.509 certificate chain',
  x5t: 'X.509 SHA-1 thumbprint',
  'x5t#S256': 'X.509 SHA-256 thumbprint',
  crit: 'Critical extensions',
  zip: 'Compression',
  b64: 'Base64url-encode payload (RFC 7797)',
  enc: 'Content encryption (JWE)',
};

const SENSITIVE_KEY_RE = /pass(word|wd)?$|^pwd$|secret|private[_-]?key|api[_-]?key|access[_-]?key|ssn|social[_-]?security|credit[_-]?card|card[_-]?number|cvv|pin$/i;

function parseJsonPart(segment, name) {
  let bytes;
  try {
    bytes = base64urlDecode(segment);
  } catch (e) {
    throw new JwtError(`${name}: ${e.message}`);
  }
  let text;
  try {
    text = utf8Decode(bytes);
  } catch {
    throw new JwtError(`${name}: not valid UTF-8`);
  }
  try {
    return { value: JSON.parse(text), text };
  } catch {
    return { value: undefined, text };
  }
}

export class JwtError extends Error {}

/**
 * Split and decode a compact JWS/JWE. Throws JwtError on structural problems.
 */
export function decodeJwt(raw) {
  const token = String(raw || '').trim().replace(/^Bearer\s+/i, '');
  if (!token) throw new JwtError('Empty token');
  if (/\s/.test(token)) throw new JwtError('Token contains whitespace');
  const parts = token.split('.');
  if (parts.length !== 3 && parts.length !== 5) {
    throw new JwtError(`Expected 3 (JWS) or 5 (JWE) dot-separated parts, got ${parts.length}`);
  }
  const header = parseJsonPart(parts[0], 'Header');
  if (header.value === undefined || typeof header.value !== 'object' || header.value === null || Array.isArray(header.value)) {
    throw new JwtError('Header is not a JSON object');
  }
  if (parts.length === 5) {
    return {
      token, parts, kind: 'JWE',
      header: header.value, headerText: header.text,
      payload: undefined, payloadText: undefined, signature: undefined,
    };
  }
  let payload;
  let payloadText;
  if (header.value.b64 === false) {
    payloadText = parts[1];
    payload = undefined;
  } else {
    const p = parseJsonPart(parts[1], 'Payload');
    payload = p.value;
    payloadText = p.text;
  }
  let signature;
  try {
    signature = base64urlDecode(parts[2]);
  } catch (e) {
    throw new JwtError(`Signature: ${e.message}`);
  }
  return {
    token, parts, kind: 'JWS',
    header: header.value, headerText: header.text,
    payload, payloadText, signature,
    signingInput: `${parts[0]}.${parts[1]}`,
  };
}

function finding(severity, id, title, detail) {
  return { severity, id, title, detail };
}

function fmtDuration(seconds) {
  const s = Math.abs(Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${(s / 3600).toFixed(1).replace(/\.0$/, '')}h`;
  return `${(s / 86400).toFixed(1).replace(/\.0$/, '')}d`;
}

export function formatDuration(seconds) {
  return fmtDuration(seconds);
}

function walkKeys(obj, cb, path = []) {
  if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      cb(k, v, [...path, k]);
      walkKeys(v, cb, [...path, k]);
    }
  }
}

/**
 * Static analysis of a decoded token. `now` is seconds since epoch.
 * Returns findings sorted by severity.
 */
export function analyzeJwt(decoded, { now = Math.floor(Date.now() / 1000), clockSkew = 0 } = {}) {
  const out = [];
  const h = decoded.header;

  if (decoded.kind === 'JWE') {
    out.push(finding('info', 'jwe', 'Encrypted token (JWE)',
      `This is a JWE (alg=${h.alg}, enc=${h.enc}). The payload is encrypted and cannot be inspected without the decryption key.`));
    if (h.alg === 'RSA1_5') {
      out.push(finding('medium', 'jwe-rsa1_5', 'JWE uses RSA1_5 key wrapping',
        'RSAES-PKCS1-v1_5 is vulnerable to Bleichenbacher padding-oracle attacks. Prefer RSA-OAEP-256 or ECDH-ES.'));
    }
    return sortFindings(out);
  }

  // ---- Header checks ----
  const alg = h.alg;
  if (alg === undefined) {
    out.push(finding('high', 'alg-missing', 'Missing "alg" header',
      'Every JWS must declare its algorithm. Libraries may fall back to insecure defaults.'));
  } else if (typeof alg !== 'string') {
    out.push(finding('high', 'alg-type', '"alg" is not a string', `Got ${JSON.stringify(alg)}.`));
  } else if (alg.toLowerCase() === 'none') {
    out.push(finding('critical', 'alg-none', 'Unsigned token: alg is "' + alg + '"',
      'Anyone can forge this token. A verifier that accepts "none" (CVE-2015-9235 class) lets attackers bypass authentication entirely. ' +
      'Servers must pin an algorithm allowlist and reject "none" in any capitalisation.'));
    if (alg !== 'none') {
      out.push(finding('high', 'alg-none-case', 'Case-variant "none" algorithm',
        `"${alg}" is a common filter-bypass trick against blocklists that only check the lowercase string.`));
    }
    if (decoded.signature.length > 0) {
      out.push(finding('medium', 'alg-none-sig', 'alg "none" but a signature is present',
        'An unsecured JWS must have an empty signature. This mismatch suggests tampering.'));
    }
  } else if (!KNOWN_ALGS.includes(alg)) {
    out.push(finding('medium', 'alg-unknown', `Unrecognised algorithm "${alg}"`,
      'Not a registered JWS signature algorithm this tool can verify.'));
  } else if (alg.startsWith('HS')) {
    out.push(finding('info', 'alg-hmac', 'Symmetric (HMAC) signature',
      'Every party that can verify this token can also mint new ones. Make sure the secret is long and random ' +
      `(at least ${parseInt(alg.slice(2), 10) / 8} bytes for ${alg}), and that the verifier never accepts HS* when it expects RS*/ES* (key-confusion).`));
  }

  if (h.jku !== undefined) {
    out.push(finding('high', 'hdr-jku', 'Header specifies a remote key set (jku)',
      `jku = ${JSON.stringify(h.jku)}. If the verifier fetches keys from this URL without a strict allowlist, an attacker can point it at their own JWKS and sign arbitrary tokens.`));
  }
  if (h.x5u !== undefined) {
    out.push(finding('high', 'hdr-x5u', 'Header specifies a remote certificate (x5u)',
      `x5u = ${JSON.stringify(h.x5u)}. Same risk as jku: the verifier must never trust a key location supplied by the token itself.`));
  }
  if (h.jwk !== undefined) {
    out.push(finding('high', 'hdr-jwk', 'Embedded public key (jwk header)',
      'A token that carries its own verification key is self-signed. Verifiers that trust it (CVE-2018-0114) accept attacker-generated tokens.'));
  }
  if (h.x5c !== undefined) {
    out.push(finding('medium', 'hdr-x5c', 'Embedded certificate chain (x5c)',
      'The verifier must validate this chain against a trusted root and must not simply use the leaf key.'));
  }
  if (h.kid !== undefined) {
    const kid = String(h.kid);
    if (/\.\.[/\\]|^\/|^[a-z]:\\|\0/i.test(kid)) {
      out.push(finding('high', 'kid-path', 'Suspicious "kid": path traversal pattern',
        `kid = ${JSON.stringify(kid)}. If the server reads key files by kid, this can load an attacker-chosen file (e.g. /dev/null as an empty HMAC secret).`));
    } else if (/['";]|--|\bunion\b|\bselect\b|\bor\s+1=1/i.test(kid)) {
      out.push(finding('high', 'kid-sqli', 'Suspicious "kid": injection pattern',
        `kid = ${JSON.stringify(kid)}. If kid is used in a database query, this can return an attacker-controlled key.`));
    } else if (/[|`$]|\$\(/.test(kid)) {
      out.push(finding('high', 'kid-cmd', 'Suspicious "kid": shell metacharacters',
        `kid = ${JSON.stringify(kid)}. Possible command-injection probe.`));
    }
  }
  if (h.crit !== undefined) {
    out.push(finding('medium', 'hdr-crit', 'Critical header extensions (crit)',
      `crit = ${JSON.stringify(h.crit)}. Verifiers must reject the token if they do not understand every listed extension.`));
  }
  if (h.b64 === false) {
    out.push(finding('medium', 'hdr-b64', 'Unencoded payload (b64: false, RFC 7797)',
      'Many libraries do not support RFC 7797 and may verify a different payload than they parse.'));
  }
  if (h.zip !== undefined) {
    out.push(finding('medium', 'hdr-zip', 'Compression header on a JWS',
      '"zip" is only defined for JWE. Compression of attacker-influenced data can also leak secrets (CRIME-style) or enable decompression bombs.'));
  }
  if (h.typ !== undefined && typeof h.typ === 'string' && !/^(jwt|at\+jwt|application\/(at\+)?jwt|jose|dpop\+jwt|logout\+jwt|secevent\+jwt)$/i.test(h.typ)) {
    out.push(finding('low', 'hdr-typ', `Unusual "typ": ${h.typ}`,
      'Explicit typing helps prevent a token of one kind being replayed as another (RFC 8725 §3.11).'));
  }

  // ---- Signature checks ----
  const sigLen = decoded.signature.length;
  const isNone = typeof alg === 'string' && alg.toLowerCase() === 'none';
  if (!isNone && sigLen === 0) {
    out.push(finding('high', 'sig-empty', 'Signature is empty',
      `alg is ${JSON.stringify(alg)} but the signature segment is empty. This is a signature-stripping attempt; a correct verifier must reject it.`));
  } else if (!isNone && FIXED_SIG_LEN[alg] && sigLen !== FIXED_SIG_LEN[alg]) {
    const derHint = alg.startsWith('ES') && decoded.signature[0] === 0x30
      ? ' It starts with 0x30 and looks DER-encoded; JWS requires the raw R||S form (RFC 7518 §3.4).' : '';
    out.push(finding('medium', 'sig-length', 'Unexpected signature length',
      `${alg} signatures are ${FIXED_SIG_LEN[alg]} bytes, this one is ${sigLen}.${derHint}`));
  } else if (typeof alg === 'string' && /^(RS|PS)/.test(alg) && sigLen > 0) {
    const bits = sigLen * 8;
    if (bits < 2048) {
      out.push(finding('high', 'rsa-weak', `RSA key is only ~${bits} bits`,
        'The signature length reveals the modulus size. RSA keys below 2048 bits are considered breakable.'));
    } else {
      out.push(finding('info', 'rsa-size', `RSA key size ~${bits} bits`, 'Inferred from the signature length.'));
    }
  }

  // ---- Payload checks ----
  const p = decoded.payload;
  if (h.b64 !== false) {
    if (p === undefined) {
      out.push(finding('medium', 'payload-json', 'Payload is not JSON',
        'JWT claims sets must be JSON objects. This may be a nested token or arbitrary JWS content.'));
    } else if (typeof p !== 'object' || p === null || Array.isArray(p)) {
      out.push(finding('medium', 'payload-object', 'Payload is not a JSON object', 'JWT claims must be a JSON object.'));
    }
  }

  if (p && typeof p === 'object' && !Array.isArray(p)) {
    for (const c of TIME_CLAIMS) {
      if (p[c] !== undefined && (typeof p[c] !== 'number' || !Number.isFinite(p[c]))) {
        out.push(finding('high', `claim-${c}-type`, `"${c}" is not a numeric date`,
          `${c} = ${JSON.stringify(p[c])}. Many libraries silently skip the check when the type is wrong.`));
      } else if (typeof p[c] === 'number' && p[c] > 1e11) {
        out.push(finding('medium', `claim-${c}-ms`, `"${c}" looks like milliseconds`,
          `${c} = ${p[c]}. JWT dates are seconds since the epoch; a millisecond value pushes expiry thousands of years into the future.`));
      }
    }

    const exp = typeof p.exp === 'number' ? p.exp : undefined;
    const nbf = typeof p.nbf === 'number' ? p.nbf : undefined;
    const iat = typeof p.iat === 'number' ? p.iat : undefined;

    if (p.exp === undefined) {
      out.push(finding('medium', 'exp-missing', 'No expiration (exp)',
        'The token never expires. A leaked token stays valid until the signing key is rotated.'));
    } else if (exp !== undefined && exp + clockSkew <= now) {
      out.push(finding('medium', 'expired', `Token expired ${fmtDuration(now - exp)} ago`,
        `exp = ${new Date(exp * 1000).toISOString()}. A verifier must reject it.`));
    }
    if (nbf !== undefined && nbf - clockSkew > now) {
      out.push(finding('medium', 'nbf-future', `Not valid for another ${fmtDuration(nbf - now)}`,
        `nbf = ${new Date(nbf * 1000).toISOString()}.`));
    }
    if (iat !== undefined && iat - clockSkew > now + 60) {
      out.push(finding('medium', 'iat-future', `Issued in the future (${fmtDuration(iat - now)} ahead)`,
        'Indicates clock skew on the issuer or a forged token.'));
    }
    if (exp !== undefined && exp < 1e11) {
      const start = iat ?? nbf;
      if (start !== undefined && exp > start) {
        const life = exp - start;
        if (life > 30 * 86400) {
          out.push(finding('medium', 'lifetime-long', `Very long lifetime (${fmtDuration(life)})`,
            'Long-lived bearer tokens widen the window for replay. Prefer short-lived access tokens plus refresh tokens.'));
        } else if (life > 86400) {
          out.push(finding('low', 'lifetime', `Long lifetime (${fmtDuration(life)})`,
            'Access tokens are typically valid for minutes to an hour.'));
        }
      }
    }
    if (p.iss === undefined) {
      out.push(finding('low', 'iss-missing', 'No issuer (iss)', 'Without iss, verifiers cannot tell which authority minted the token.'));
    }
    if (p.aud === undefined) {
      out.push(finding('low', 'aud-missing', 'No audience (aud)',
        'Without aud, a token issued for one service can be replayed against another that trusts the same issuer.'));
    }

    const sensitive = [];
    walkKeys(p, (k, v, path) => {
      if (SENSITIVE_KEY_RE.test(k) && v !== null && v !== '' && typeof v !== 'object') sensitive.push(path.join('.'));
    });
    if (sensitive.length) {
      out.push(finding('high', 'sensitive-data', 'Possible secrets in the payload',
        `Claims ${sensitive.map((s) => `"${s}"`).join(', ')} look sensitive. JWS payloads are only base64url-encoded, not encrypted: anyone holding the token can read them.`));
    }
  }

  return sortFindings(out);
}

export function sortFindings(list) {
  return [...list].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

/**
 * Human-readable descriptions of time claims.
 */
export function describeTimeClaim(value, now = Math.floor(Date.now() / 1000)) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  const secs = value > 1e11 ? Math.floor(value / 1000) : value;
  const d = new Date(secs * 1000);
  if (Number.isNaN(d.getTime())) return null;
  const diff = secs - now;
  const rel = diff === 0 ? 'now' : diff > 0 ? `in ${fmtDuration(diff)}` : `${fmtDuration(diff)} ago`;
  return { iso: d.toISOString(), relative: rel };
}
