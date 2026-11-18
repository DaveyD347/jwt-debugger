// UI wiring. All DOM writes use textContent / createElement: token data is never parsed as HTML.

import { bytesToHex } from './base64url.js';
import {
  algParams, jwkThumbprint, scanWeakSecrets, signJwt, testKeyConfusion, verifyJwt,
} from './crypto.js';
import {
  analyzeJwt, decodeJwt, describeTimeClaim, HEADER_PARAMS, KNOWN_ALGS, REGISTERED_CLAIMS, TIME_CLAIMS,
} from './jwt.js';
import {
  classifyToken, computeOidcHash, extractScopes, inspectAuthorizationUrl,
} from './oauth.js';
import { COMMON_SECRETS } from './wordlist.js';

const $ = (id) => document.getElementById(id);
const SIGN_ALGS = KNOWN_ALGS.filter((a) => a !== 'Ed25519');

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function show(node, on = true) { node.hidden = !on; }

function setResult(node, kind, title, ...details) {
  clear(node);
  node.className = `result ${kind}`;
  node.append(el('strong', { text: title }));
  for (const d of details.filter(Boolean)) node.append(el('div', { class: 'small' }, d));
}

function nowSecs() { return Math.floor(Date.now() / 1000); }

// ------------------------------------------------------------ JSON rendering

const JSON_TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

function renderJson(pre, value) {
  clear(pre);
  const text = JSON.stringify(value, null, 2);
  let last = 0;
  for (const m of text.matchAll(JSON_TOKEN)) {
    if (m.index > last) pre.append(text.slice(last, m.index));
    if (m[1]) {
      pre.append(el('span', { class: m[2] ? 'j-key' : 'j-str' }, m[1]));
      if (m[2]) pre.append(m[2]);
    } else if (m[3]) pre.append(el('span', { class: 'j-lit' }, m[3]));
    else pre.append(el('span', { class: 'j-num' }, m[4]));
    last = m.index + m[0].length;
  }
  pre.append(text.slice(last));
}

function renderColoredToken(target, token) {
  clear(target);
  const parts = token.split('.');
  const classes = parts.length === 5 ? ['hdr', 'jwe1', 'jwe2', 'jwe3', 'sig'] : ['hdr', 'pay', 'sig'];
  parts.forEach((p, i) => {
    if (i) target.append(el('span', { class: 'tok-dot' }, '.'));
    target.append(el('span', { class: `tok-${classes[i] || 'sig'}` }, p));
  });
}

// ------------------------------------------------------------ tabs

function initTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const select = (tab) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !on;
    }
  };
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t));
    t.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
        select(next); next.focus();
      }
    });
  });
  return (id) => select($(id));
}

// ------------------------------------------------------------ debugger

let current = null; // decoded token
let scanAbort = null;

function renderClaimsTable(table, obj, dict, isPayload) {
  clear(table);
  const now = nowSecs();
  const body = el('tbody');
  for (const [k, v] of Object.entries(obj)) {
    let note = dict[k] || '';
    if (isPayload && TIME_CLAIMS.includes(k)) {
      const t = describeTimeClaim(v, now);
      if (t) note = `${note}: ${t.iso.replace('.000Z', 'Z')} (${t.relative})`;
    }
    if (!note) continue;
    body.append(el('tr', {},
      el('th', { class: 'mono' }, k),
      el('td', {}, note)));
  }
  if (body.children.length) table.append(body);
}

function renderFindings(list, target, countEl) {
  clear(target);
  const counts = {};
  for (const f of list) counts[f.severity] = (counts[f.severity] || 0) + 1;
  countEl.textContent = list.length ? String(list.length) : '0';
  if (!list.length) {
    target.append(el('li', { class: 'finding ok' }, el('div', { class: 'f-title' }, 'No issues found')));
    return counts;
  }
  for (const f of list) {
    target.append(el('li', { class: `finding sev-${f.severity}` },
      el('span', { class: `sev sev-${f.severity}` }, f.severity),
      el('div', {},
        el('div', { class: 'f-title' }, f.title),
        el('div', { class: 'f-detail' }, f.detail))));
  }
  return counts;
}

function riskLabel(counts) {
  if (counts.critical) return ['critical', 'Critical'];
  if (counts.high) return ['high', 'High risk'];
  if (counts.medium) return ['medium', 'Review'];
  return ['ok', 'No static issues'];
}

// Dynamic tests (scan, key confusion) can prove a token forgeable; reflect that in the summary.
function markCompromised(label) {
  const score = $('score');
  score.className = 'score risk-critical';
  score.textContent = label;
}

function resetOutput() {
  for (const id of ['summary', 'findings-card', 'header-card', 'payload-card', 'sig-card', 'oidc-card']) show($(id), false);
  show($('empty'), true);
  clear($('token-colored'));
  clear($('verify-result')); $('verify-result').className = 'result';
  clear($('scan-result')); $('scan-result').className = 'result';
  clear($('oidc-result')); $('oidc-result').className = 'result';
  $('scan-progress').value = 0;
}

function decodeAndRender() {
  const raw = $('token').value;
  const errBox = $('token-error');
  current = null;
  resetOutput();
  if (!raw.trim()) { show(errBox, false); return; }
  let d;
  try {
    d = decodeJwt(raw);
  } catch (e) {
    errBox.textContent = e.message;
    show(errBox, true);
    return;
  }
  show(errBox, false);
  current = d;
  show($('empty'), false);
  renderColoredToken($('token-colored'), d.token);

  const skew = Math.max(0, Number($('skew').value) || 0);
  const findings = analyzeJwt(d, { now: nowSecs(), clockSkew: skew });
  show($('findings-card'));
  const counts = renderFindings(findings, $('findings'), $('findings-count'));

  // summary
  const [cls, label] = riskLabel(counts);
  const score = $('score');
  score.className = `score risk-${cls}`;
  score.textContent = label;
  const kind = d.kind === 'JWE' ? { label: 'Encrypted JWT (JWE)' } : classifyToken(d.header, d.payload);
  $('token-kind').textContent = kind.label;
  const meta = [`alg ${d.header.alg ?? '(missing)'}`];
  if (d.header.kid !== undefined) meta.push(`kid ${d.header.kid}`);
  if (d.signature) meta.push(`${d.signature.length}-byte signature`);
  if (kind.reason) meta.push(kind.reason);
  $('token-meta').textContent = meta.join(' · ');
  const scopesBox = $('scopes');
  clear(scopesBox);
  const scopes = d.payload && typeof d.payload === 'object' ? extractScopes(d.payload) : [];
  for (const s of scopes) scopesBox.append(el('span', { class: 'scope mono' }, s));
  show($('summary'));

  show($('header-card'));
  renderJson($('header-json'), d.header);
  renderClaimsTable($('header-table'), d.header, HEADER_PARAMS, false);

  if (d.kind === 'JWS') {
    show($('payload-card'));
    if (d.payload !== undefined) {
      renderJson($('payload-json'), d.payload);
      if (typeof d.payload === 'object' && d.payload) renderClaimsTable($('payload-table'), d.payload, REGISTERED_CLAIMS, true);
      else clear($('payload-table'));
    } else {
      $('payload-json').textContent = d.payloadText;
      clear($('payload-table'));
    }
    show($('sig-card'));
    $('sig-hex').textContent = d.signature.length ? bytesToHex(d.signature).replace(/(.{64})/g, '$1\n').trim() : '(empty)';

    const hashes = ['at_hash', 'c_hash'].filter((c) => d.payload && d.payload[c] !== undefined);
    if (hashes.length) {
      $('oidc-claims').textContent = hashes.join(' and ');
      show($('oidc-card'));
    }
  }
  // Point the verify panel at the right kind of key.
  const alg = String(d.header.alg || '');
  $('verify-key').placeholder = alg.startsWith('HS')
    ? 'Shared secret, e.g. your-256-bit-secret'
    : '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\nor a JWK / JWKS';
}

async function onVerify() {
  const out = $('verify-result');
  if (!current) return setResult(out, 'warn', 'Decode a token first.');
  if (current.kind !== 'JWS') return setResult(out, 'warn', 'JWE tokens are encrypted, not signed; they cannot be verified here.');
  try {
    const r = await verifyJwt(current, $('verify-key').value, {
      secretEncoding: $('secret-enc').value,
      expectedAlg: $('pin-alg').value || undefined,
    });
    const extra = [];
    if (current.payload && typeof current.payload.exp === 'number' && current.payload.exp <= nowSecs()) {
      extra.push('Note: the signature is checked, but the token is expired.');
    }
    const keyNote = r.keyInfo && r.keyInfo !== 'n/a' ? `Key: ${r.keyInfo}` : '';
    if (r.valid) setResult(out, 'ok', `Signature verified (${r.alg})`, keyNote, ...r.warnings, ...extra);
    else setResult(out, 'bad', 'Invalid signature', keyNote, ...r.warnings);
  } catch (e) {
    setResult(out, 'warn', 'Could not verify', e.message);
  }
}

async function onConfusion() {
  const out = $('verify-result');
  if (!current || current.kind !== 'JWS') return setResult(out, 'warn', 'Decode a signed token first.');
  const key = $('verify-key').value.trim();
  if (!key) return setResult(out, 'warn', 'Paste the server\'s public key (PEM or JWK) into the key box first.');
  try {
    const r = await testKeyConfusion(current, key);
    if (r.vulnerable) {
      markCompromised('Forgeable');
      setResult(out, 'bad', 'Key confusion: this HS token is signed with the public key',
        `Matched variant: ${r.variant}. Any verifier that accepts it is vulnerable to RS/ES to HS algorithm confusion (CVE-2016-10555 class): attackers can forge tokens using only the public key.`);
    } else {
      setResult(out, 'ok', 'No key confusion detected', `Tried ${r.tried} encodings of the public key as the HMAC secret.`);
    }
  } catch (e) {
    setResult(out, 'warn', 'Cannot run the test', e.message);
  }
}

function candidateList() {
  const extra = $('wordlist').value.split(/\r?\n/).filter((l) => l.length);
  return [...extra, ...COMMON_SECRETS];
}

async function onScan() {
  const out = $('scan-result');
  if (!current || current.kind !== 'JWS') return setResult(out, 'warn', 'Decode a signed token first.');
  const list = candidateList();
  scanAbort = new AbortController();
  $('scan').disabled = true;
  $('scan-stop').disabled = false;
  const bar = $('scan-progress');
  bar.max = list.length; bar.value = 0;
  setResult(out, '', `Scanning ${list.length.toLocaleString()} candidates…`);
  const started = performance.now();
  try {
    const r = await scanWeakSecrets(current, list, {
      signal: scanAbort.signal,
      onProgress: (n) => { bar.value = n; },
    });
    const secs = ((performance.now() - started) / 1000).toFixed(2);
    bar.value = r.found !== null ? bar.max : r.tried;
    if (r.found !== null) {
      setResult(out, 'bad', `Secret cracked: ${r.found === '' ? '(empty string)' : JSON.stringify(r.found)}`,
        `Found after ${r.tried.toLocaleString()} attempts in ${secs}s. Anyone with this token can forge new ones. Rotate the secret and use at least 32 random bytes.`);
      $('verify-key').value = r.found;
      $('secret-enc').value = 'utf8';
      markCompromised('Secret cracked');
    } else if (scanAbort.signal.aborted) {
      setResult(out, 'warn', `Stopped after ${r.tried.toLocaleString()} candidates`);
    } else {
      setResult(out, 'ok', 'No match in the wordlist',
        `${r.tried.toLocaleString()} unique candidates in ${secs}s. This rules out common defaults, not a weak secret in general.`);
    }
  } catch (e) {
    setResult(out, 'warn', 'Cannot scan', e.message);
  } finally {
    $('scan').disabled = false;
    $('scan-stop').disabled = true;
  }
}

async function onOidcCheck() {
  const out = $('oidc-result');
  const value = $('oidc-value').value.trim();
  if (!current || !value) return setResult(out, 'warn', 'Paste an access token or authorization code.');
  try {
    const h = await computeOidcHash(value, current.header.alg);
    const matches = ['at_hash', 'c_hash'].filter((c) => current.payload[c] === h);
    if (matches.length) setResult(out, 'ok', `${matches.join(', ')} matches`, `Computed ${h}`);
    else setResult(out, 'bad', 'No match', `Computed ${h}; the token has ${['at_hash', 'c_hash'].filter((c) => current.payload[c]).map((c) => `${c}=${current.payload[c]}`).join(', ')}`);
  } catch (e) {
    setResult(out, 'warn', 'Cannot compute', e.message);
  }
}

// ------------------------------------------------------------ samples

const samples = {};

async function generateKeyPair(alg) {
  const { family } = algParams(alg);
  const bits = alg.slice(2);
  const hash = { 256: 'SHA-256', 384: 'SHA-384', 512: 'SHA-512' }[bits];
  let params;
  if (family === 'RSA') {
    params = {
      name: alg.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash,
    };
  } else if (family === 'EC') params = { name: 'ECDSA', namedCurve: { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }[alg] };
  else if (family === 'OKP') params = { name: 'Ed25519' };
  else throw new Error('HMAC algorithms use a shared secret');
  const s = crypto.subtle;
  const kp = await s.generateKey(params, true, ['sign', 'verify']);
  const pem = (der, label) => {
    const b = btoa(String.fromCharCode(...new Uint8Array(der))).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
    return `-----BEGIN ${label}-----\n${b}\n-----END ${label}-----\n`;
  };
  const publicJwk = await s.exportKey('jwk', kp.publicKey);
  publicJwk.kid = (await jwkThumbprint(publicJwk)).slice(0, 16);
  return {
    privatePem: pem(await s.exportKey('pkcs8', kp.privateKey), 'PRIVATE KEY'),
    publicPem: pem(await s.exportKey('spki', kp.publicKey), 'PUBLIC KEY'),
    publicJwk,
  };
}

async function buildSamples() {
  const now = nowSecs();
  samples.weak = {
    token: await signJwt({ alg: 'HS256', typ: 'JWT' }, {
      iss: 'https://auth.example.com', sub: 'user-1842', aud: 'orders-api', scope: 'orders:read orders:write', iat: now, exp: now + 3600,
    }, 'secret123'),
    key: '',
  };
  samples.none = {
    token: await signJwt({ alg: 'none', typ: 'JWT' }, { sub: 'admin', role: 'superuser', iat: now }, ''),
    key: '',
  };
  const kp = await generateKeyPair('RS256');
  samples.rs256 = {
    token: await signJwt({ alg: 'RS256', typ: 'at+jwt', kid: kp.publicJwk.kid }, {
      iss: 'https://login.example.com', sub: 'f3a1c2', aud: 'https://api.example.com', client_id: 'web-app',
      scope: 'openid profile payments:read', iat: now, exp: now + 900, jti: crypto.randomUUID(),
    }, kp.privatePem),
    key: kp.publicPem,
  };
  samples.bad = {
    token: await signJwt({ alg: 'HS256', kid: '../../../../dev/null', jku: 'https://attacker.example/jwks.json' }, {
      sub: 'bob', password: 'hunter2', iat: now - 86400 * 400, exp: (now - 3600) * 1000, nonce: 'n-0S6',
    }, ''),
    key: '',
  };
}

async function loadSample(name) {
  if (!samples[name]) await buildSamples();
  const s = samples[name];
  $('token').value = s.token;
  $('verify-key').value = s.key;
  $('secret-enc').value = 'utf8';
  $('pin-alg').value = '';
  decodeAndRender();
}

// ------------------------------------------------------------ encoder

function parseJsonField(id, label) {
  try {
    const v = JSON.parse($(id).value);
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('must be a JSON object');
    return v;
  } catch (e) {
    throw new Error(`${label}: ${e.message}`);
  }
}

function encError(msg) {
  const box = $('enc-error');
  box.textContent = msg || '';
  show(box, Boolean(msg));
}

let lastSigned = '';

async function onSign() {
  encError('');
  try {
    const header = parseJsonField('enc-header', 'Header');
    const payload = parseJsonField('enc-payload', 'Payload');
    lastSigned = await signJwt(header, payload, $('enc-key').value, { secretEncoding: $('enc-secret-enc').value });
    renderColoredToken($('enc-output'), lastSigned);
  } catch (e) {
    lastSigned = '';
    clear($('enc-output'));
    encError(e.message);
  }
}

function syncAlgFromHeader() {
  try {
    const h = JSON.parse($('enc-header').value);
    if (h && typeof h.alg === 'string' && [...$('enc-alg').options].some((o) => o.value === h.alg)) $('enc-alg').value = h.alg;
  } catch { /* header is being edited */ }
}

function setHeaderField(updates) {
  let h;
  try { h = JSON.parse($('enc-header').value); } catch { h = {}; }
  for (const [k, v] of Object.entries(updates)) {
    if (v === undefined) delete h[k]; else h[k] = v;
  }
  $('enc-header').value = JSON.stringify(h, null, 2);
  syncAlgFromHeader();
}

function setPayloadClaim(kind) {
  let p;
  try { p = JSON.parse($('enc-payload').value || '{}'); } catch (e) { encError(`Payload: ${e.message}`); return; }
  const now = nowSecs();
  if (kind === 'iat') p.iat = now;
  if (kind === 'exp') p.exp = now + 3600;
  if (kind === 'expired') { p.iat = now - 7200; p.exp = now - 3600; }
  if (kind === 'jti') p.jti = crypto.randomUUID();
  $('enc-payload').value = JSON.stringify(p, null, 2);
}

async function onGenerateKey() {
  encError('');
  const alg = $('enc-alg').value;
  if (alg.startsWith('HS')) {
    const bytes = crypto.getRandomValues(new Uint8Array(Number(alg.slice(2)) / 8));
    $('enc-key').value = bytesToHex(bytes);
    $('enc-secret-enc').value = 'hex';
    show($('gen-public-wrap'), false);
    return;
  }
  try {
    const kp = await generateKeyPair(alg);
    $('enc-key').value = kp.privatePem;
    $('gen-public').value = kp.publicPem;
    show($('gen-public-wrap'));
    setHeaderField({ alg, kid: kp.publicJwk.kid });
  } catch (e) {
    encError(e.message);
  }
}

const ATTACK_HELP = {
  none: 'Header alg set to "none" and signature removed. A safe verifier rejects it because "none" is not in its algorithm allowlist.',
  None: 'Same as alg none, with different capitalisation to slip past blocklists that compare case-sensitively.',
  'empty-sig': 'Header alg kept, signature removed. Some libraries skip verification when the signature segment is empty.',
  confusion: 'Paste the server\'s RSA/EC public key PEM as the "secret" and sign. The token is HS256 with the public key as the HMAC secret. A verifier that picks the algorithm from the header accepts it.',
  'kid-null': 'kid points at /dev/null and the HMAC secret is empty. If the server reads key files by kid, it HMACs with an empty key.',
  jwk: 'Generates a fresh key pair, embeds the public JWK in the header and signs with it. Verifiers that trust the embedded key (CVE-2018-0114) accept it.',
};

async function onAttack(kind) {
  encError('');
  $('attack-help').textContent = ATTACK_HELP[kind] || '';
  try {
    const payload = parseJsonField('enc-payload', 'Payload');
    let header = parseJsonField('enc-header', 'Header');
    if (kind === 'none' || kind === 'None') {
      header = { ...header, alg: kind };
      lastSigned = await signJwt(header, payload, '');
    } else if (kind === 'empty-sig') {
      if (!header.alg || header.alg.toLowerCase() === 'none') header.alg = 'HS256';
      const t = await signJwt({ ...header, alg: 'none' }, payload, '');
      const [, p] = t.split('.');
      const { base64urlEncode } = await import('./base64url.js');
      lastSigned = `${base64urlEncode(JSON.stringify(header))}.${p}.`;
    } else if (kind === 'confusion') {
      const key = $('enc-key').value;
      if (!/-----BEGIN (PUBLIC KEY|CERTIFICATE|RSA PUBLIC KEY)-----/.test(key)) {
        throw new Error('Paste the target\'s public key PEM into the key box first (it becomes the HMAC secret).');
      }
      header = { ...header, alg: 'HS256' };
      lastSigned = await signJwt(header, payload, key);
    } else if (kind === 'kid-null') {
      header = { ...header, alg: 'HS256', kid: '../../../../../../dev/null' };
      lastSigned = await signJwt(header, payload, '');
    } else if (kind === 'jwk') {
      const kp = await generateKeyPair('RS256');
      header = { ...header, alg: 'RS256', jwk: kp.publicJwk, kid: kp.publicJwk.kid };
      lastSigned = await signJwt(header, payload, kp.privatePem);
    }
    $('enc-header').value = JSON.stringify(header, null, 2);
    syncAlgFromHeader();
    renderColoredToken($('enc-output'), lastSigned);
  } catch (e) {
    encError(e.message);
  }
}

// ------------------------------------------------------------ OAuth

const OAUTH_SAMPLES = {
  bad: 'http://idp.example.com/oauth2/authorize?response_type=token%20id_token&client_id=spa-client&redirect_uri=http%3A%2F%2Fapp.example.com%2Fcallback%3Fnext%3D%2Fhome&scope=openid%20profile%20email',
  good: 'https://idp.example.com/oauth2/authorize?response_type=code&client_id=spa-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20profile&state=af0ifjsldkjK8sd2&nonce=n-0S6_WzA2Mj&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256',
};

function onOauthInspect() {
  const err = $('oauth-error');
  show(err, false);
  try {
    const r = inspectAuthorizationUrl($('oauth-url').value);
    show($('oauth-out'));
    renderFindings(r.findings, $('oauth-findings'), $('oauth-count'));
    $('oauth-endpoint').textContent = r.endpoint;
    const table = $('oauth-params');
    clear(table);
    const body = el('tbody');
    for (const [k, v] of Object.entries(r.params)) {
      body.append(el('tr', {}, el('th', { class: 'mono' }, k), el('td', { class: 'mono' }, v)));
    }
    table.append(body);
  } catch (e) {
    show($('oauth-out'), false);
    err.textContent = e.message;
    show(err);
  }
}

// ------------------------------------------------------------ init

function init() {
  const selectTab = initTabs();

  for (const a of KNOWN_ALGS) $('pin-alg').append(el('option', { value: a }, a));
  for (const a of [...SIGN_ALGS, 'none']) $('enc-alg').append(el('option', { value: a }, a));
  $('wordlist-count').textContent = `${new Set(COMMON_SECRETS).size} built-in candidates.`;

  let debounce;
  $('token').addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(decodeAndRender, 120); });
  $('skew').addEventListener('change', decodeAndRender);
  $('clear').addEventListener('click', () => { $('token').value = ''; $('verify-key').value = ''; decodeAndRender(); $('token').focus(); });
  for (const b of document.querySelectorAll('[data-sample]')) b.addEventListener('click', () => loadSample(b.dataset.sample));
  $('verify').addEventListener('click', onVerify);
  $('confusion').addEventListener('click', onConfusion);
  $('scan').addEventListener('click', onScan);
  $('scan-stop').addEventListener('click', () => scanAbort && scanAbort.abort());
  $('oidc-check').addEventListener('click', onOidcCheck);
  $('wordlist-file').addEventListener('change', async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    if (f.size > 50 * 1024 * 1024) { setResult($('scan-result'), 'warn', 'Wordlist too large', 'Keep it under 50 MB.'); return; }
    $('wordlist').value = await f.text();
    e.target.closest('details').open = true;
  });

  const now = nowSecs();
  $('enc-payload').value = JSON.stringify({ sub: '1234567890', name: 'Jane Analyst', admin: false, iat: now, exp: now + 3600 }, null, 2);
  $('enc-key').value = '';
  $('enc-alg').addEventListener('change', () => setHeaderField({ alg: $('enc-alg').value }));
  $('enc-header').addEventListener('input', syncAlgFromHeader);
  for (const b of document.querySelectorAll('[data-claim]')) b.addEventListener('click', () => setPayloadClaim(b.dataset.claim));
  for (const b of document.querySelectorAll('[data-attack]')) b.addEventListener('click', () => onAttack(b.dataset.attack));
  $('gen-key').addEventListener('click', onGenerateKey);
  $('sign').addEventListener('click', onSign);
  $('to-debugger').addEventListener('click', async () => {
    if (!lastSigned) await onSign();
    if (!lastSigned) return;
    $('token').value = lastSigned;
    const header = JSON.parse($('enc-header').value);
    $('verify-key').value = String(header.alg || '').startsWith('HS') ? $('enc-key').value : $('gen-public').value;
    $('secret-enc').value = $('enc-secret-enc').value;
    decodeAndRender();
    selectTab('tab-debug');
  });
  $('copy-token').addEventListener('click', async () => {
    if (!lastSigned) return;
    try { await navigator.clipboard.writeText(lastSigned); $('copy-token').textContent = 'Copied'; } catch { $('copy-token').textContent = 'Copy failed'; }
    setTimeout(() => { $('copy-token').textContent = 'Copy'; }, 1500);
  });

  $('oauth-inspect').addEventListener('click', onOauthInspect);
  for (const b of document.querySelectorAll('[data-oauth-sample]')) {
    b.addEventListener('click', () => { $('oauth-url').value = OAUTH_SAMPLES[b.dataset.oauthSample]; onOauthInspect(); });
  }

  if (!globalThis.crypto || !crypto.subtle) {
    $('token-error').textContent = 'WebCrypto is unavailable. Open this page over https:// or from localhost.';
    show($('token-error'));
  }
}

init();
