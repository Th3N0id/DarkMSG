/* DarkMSG — password-protected, end-to-end encrypted two-party terminal.
 *
 * Transport : public MQTT broker over WSS (relay sees only ciphertext)
 * Keys      : passphrase -> PBKDF2-SHA256 -> HKDF -> { topic, roomKey, storageKey }
 * Handshake : SYN / SYN-ACK / ACK carrying ephemeral ECDH P-256 keys -> sessionKey
 * Messages  : AES-256-GCM under sessionKey (forward secrecy per connection)
 * History   : AES-256-GCM under storageKey in localStorage
 */
(() => {
'use strict';

/* ------------------------------------------------------------------ */
/* constants                                                           */
/* ------------------------------------------------------------------ */
const APP_SALT        = 'DarkMSG-v1';
const PBKDF2_ITER     = 300000;
const TOPIC_PREFIX    = 'darkmsg/v1/';
const DEFAULT_BROKERS = [
  'wss://broker.emqx.io:8084/mqtt',
  'wss://broker.hivemq.com:8884/mqtt',
  'wss://test.mosquitto.org:8081',
];
const PING_MS         = 15000;   // presence heartbeat
const PEER_TIMEOUT_MS = 45000;   // no heartbeat for this long => link lost
const RESYN_MS        = 20000;   // re-broadcast SYN while unlinked
const MAX_SKEW_MS     = 120000;  // reject packets older/newer than this
const MAX_HISTORY     = 500;
const RESUME_REDIAL_MS = 10000;  // hidden longer than this => full reconnect
const LS_BROKER       = 'darkmsg.broker';
const SS_CLIENT_ID    = 'darkmsg.cid';
// Verifier for the fixed access code (HKDF 'verify' of the PBKDF2 output). Only this code is accepted.
// To change the code, recompute this with the snippet in README.md.
const ACCESS_HASH     = 'e6c883f97928206f9a49242c84ddaafd1109fc8cb65a8bac793cf846b6f5058a';

/* ------------------------------------------------------------------ */
/* utils                                                               */
/* ------------------------------------------------------------------ */
const $  = (s) => document.querySelector(s);
const te = new TextEncoder();
const td = new TextDecoder();
const now = () => Date.now();

function b64enc(buf) {
  const u = new Uint8Array(buf); let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64dec(s) {
  const b = atob(s); const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
}
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const randId = () => hex(crypto.getRandomValues(new Uint8Array(8)));
const fmtTime = (ts) => { const d = new Date(ts); return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hostOf = (url) => { try { return new URL(url).host; } catch (e) { return url; } };

/* ------------------------------------------------------------------ */
/* crypto                                                              */
/* ------------------------------------------------------------------ */
async function deriveBase(pass) {
  const km = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(APP_SALT), iterations: PBKDF2_ITER }, km, 256);
  return crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits', 'deriveKey']);
}
const hkdfParams = (info, salt) => ({ name: 'HKDF', hash: 'SHA-256', salt: salt || new Uint8Array(32), info: te.encode(info) });
const hkdfBits = (base, info, len) => crypto.subtle.deriveBits(hkdfParams(info), base, len);
const hkdfAes  = (base, info, salt) => crypto.subtle.deriveKey(hkdfParams(info, salt), base,
  { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

async function seal(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)));
  const out = new Uint8Array(12 + ct.byteLength); out.set(iv); out.set(new Uint8Array(ct), 12);
  return b64enc(out);
}
async function unseal(key, s) {
  try {
    const u = b64dec(s);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12));
    return JSON.parse(td.decode(pt));
  } catch (e) { return null; }
}
async function genEph() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { priv: kp.privateKey, pub: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}
async function deriveSession(priv, peerPub, idA, idB) {
  const peerKey = await crypto.subtle.importKey('jwk', { ...peerPub, ext: true },
    { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, priv, 256);
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return hkdfAes(base, 'session', te.encode([idA, idB].sort().join('|')));
}

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */
const S = {
  topic: null, roomKey: null, storageKey: null, storeId: null, fp: null,
  client: null, brokers: [], brokerIdx: 0, brokerUrl: null, everConnected: false, switching: false,
  myId: null, eph: null, peerId: null, sessionKey: null, linked: false,
  lastPeerSeen: 0, lastSyn: 0, peers: new Map(), seen: new Set(), seenList: [],
  history: [], saveChain: Promise.resolve(), hiddenAt: 0, audio: null, unread: 0,
};

/* ------------------------------------------------------------------ */
/* ui                                                                  */
/* ------------------------------------------------------------------ */
const el = {
  app: $('#app'), hdrStatus: $('#hdr-status'), hdrStatusTxt: $('#hdr-status-txt'), btnSettings: $('#btn-settings'),
  bootLog: $('#boot-log'), scrBoot: $('#scr-boot'), scrAccess: $('#scr-access'), scrTerm: $('#scr-term'),
  formAccess: $('#form-access'), pass: $('#passphrase'), btnAuth: $('#btn-auth'), accessMsg: $('#access-msg'),
  hs: $('#hs'), msgs: $('#msgs'), formSend: $('#form-send'), msgInput: $('#msg-input'), btnSend: $('#btn-send'),
  settings: $('#settings'), btnSettingsClose: $('#btn-settings-close'),
  cfgFp: $('#cfg-fp'), cfgId: $('#cfg-id'), cfgRelay: $('#cfg-relay'), cfgPeer: $('#cfg-peer'), cfgBroker: $('#cfg-broker'),
  btnBrokerApply: $('#btn-broker-apply'), btnBrokerReset: $('#btn-broker-reset'), btnWipe: $('#btn-wipe'), btnLogout: $('#btn-logout'),
};

function showScreen(sec) {
  for (const s of document.querySelectorAll('.screen')) s.classList.toggle('active', s === sec);
}
function setStatus(txt, cls) {
  el.hdrStatusTxt.textContent = txt;
  el.hdrStatus.className = cls || 'st-off';
}
function setStage(stage) {
  const order = ['syn', 'synack', 'ack', 'linked'];
  const idx = order.indexOf(stage);
  el.hs.classList.toggle('linked', stage === 'linked');
  for (const step of el.hs.querySelectorAll('.step')) {
    const i = order.indexOf(step.dataset.step);
    step.classList.toggle('done', i < idx || stage === 'linked');
    step.classList.toggle('active', i === idx && stage !== 'linked');
  }
}
function scrollBottom() { el.msgs.scrollTop = el.msgs.scrollHeight; }

function renderLine(m) {
  const div = document.createElement('div');
  if (m.dir === 'sys') {
    div.className = 'm sys' + (m.cls ? ' ' + m.cls : '');
    div.textContent = m.text;
  } else {
    div.className = 'm ' + m.dir;
    const who = document.createElement('span'); who.className = 'who'; who.textContent = m.dir === 'out' ? 'YOU' : 'PEER';
    const t = document.createElement('span'); t.className = 't'; t.textContent = fmtTime(m.ts);
    const txt = document.createElement('span'); txt.className = 'txt'; txt.textContent = m.text;
    div.append(who, t, txt);
  }
  el.msgs.appendChild(div);
  scrollBottom();
}
function sys(text, cls) { renderLine({ dir: 'sys', text, cls }); }
function addMsg(dir, text, ts) {
  const m = { dir, text, ts: ts || now() };
  S.history.push(m);
  if (S.history.length > MAX_HISTORY) S.history.splice(0, S.history.length - MAX_HISTORY);
  renderLine(m);
  saveHistory();
}
function setInputEnabled(on) {
  el.msgInput.disabled = !on; el.btnSend.disabled = !on;
  el.msgInput.placeholder = on ? 'type message' : 'waiting for peer...';
}

/* audio + title notifications */
function unlockAudio() {
  try {
    if (!S.audio) S.audio = new (window.AudioContext || window.webkitAudioContext)();
    if (S.audio.state === 'suspended') S.audio.resume();
  } catch (e) { /* no audio */ }
}
function beep(freq, ms) {
  try {
    if (!S.audio || S.audio.state !== 'running') return;
    const o = S.audio.createOscillator(); const g = S.audio.createGain();
    o.type = 'square'; o.frequency.value = freq || 880;
    g.gain.value = 0.05; o.connect(g); g.connect(S.audio.destination);
    o.start(); o.stop(S.audio.currentTime + (ms || 80) / 1000);
  } catch (e) { /* ignore */ }
}
function notifyIncoming() {
  beep(880, 70); setTimeout(() => beep(1320, 70), 90);
  if (document.hidden) { S.unread++; document.title = `[${S.unread}] DarkMSG`; }
}

/* ------------------------------------------------------------------ */
/* history storage                                                     */
/* ------------------------------------------------------------------ */
const histKey = () => 'darkmsg.h.' + S.storeId;
async function loadHistory() {
  try {
    const raw = localStorage.getItem(histKey());
    if (!raw) return [];
    const arr = await unseal(S.storageKey, raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) { return []; }
}
function saveHistory() {
  S.saveChain = S.saveChain.then(async () => {
    try { localStorage.setItem(histKey(), await seal(S.storageKey, S.history.slice(-MAX_HISTORY))); }
    catch (e) { /* storage full or unavailable */ }
  });
  return S.saveChain;
}

/* ------------------------------------------------------------------ */
/* transport                                                           */
/* ------------------------------------------------------------------ */
function brokerList() {
  let custom = null;
  try { custom = localStorage.getItem(LS_BROKER); } catch (e) { /* ignore */ }
  return custom ? [custom, ...DEFAULT_BROKERS.filter((b) => b !== custom)] : DEFAULT_BROKERS.slice();
}
function disconnect() {
  const c = S.client; S.client = null;
  if (c) { try { c.removeAllListeners(); c.end(true); } catch (e) { /* ignore */ } }
  S.everConnected = false;
}
async function connect() {
  disconnect();
  if (typeof mqtt === 'undefined') { sys('MQTT MODULE FAILED TO LOAD. CHECK NETWORK / RELOAD.', 'err'); setStatus('ERROR', 'st-err'); return; }
  S.brokers = brokerList();
  const url = S.brokers[S.brokerIdx % S.brokers.length];
  S.brokerUrl = url; el.cfgRelay.textContent = hostOf(url);
  setStatus('DIALING', 'st-busy');
  sys(`DIALING ${hostOf(url)} ...`, 'dim');
  const will = await seal(S.roomKey, { t: 'bye', id: S.myId, ts: now(), n: randId() });
  let c;
  try {
    c = mqtt.connect(url, {
      clientId: 'dm_' + S.myId, clean: true, keepalive: 20, connectTimeout: 8000, reconnectPeriod: 3000,
      resubscribe: true, protocolVersion: 4,
      will: { topic: S.topic, payload: 'R.' + will, qos: 1, retain: false },
    });
  } catch (e) { sys('DIAL FAILED: ' + (e.message || e), 'err'); nextBroker(); return; }
  S.client = c;
  c.on('connect', () => onConnect(c));
  c.on('message', (topic, payload) => onMessage(payload));
  c.on('error', (e) => { if (S.client === c) sys('SOCKET ERROR: ' + (e && e.message ? e.message : e), 'err'); });
  c.on('close', () => {
    if (S.client !== c) return;
    if (!S.everConnected) nextBroker();
    else { setStatus('RECONNECTING', 'st-busy'); linkLost('CARRIER DROPPED', false); }
  });
}
function nextBroker() {
  if (S.switching) return;
  S.switching = true;
  disconnect();
  S.brokerIdx = (S.brokerIdx + 1) % S.brokers.length;
  const wrapped = S.brokerIdx === 0;
  sys(wrapped ? 'ALL RELAYS UNREACHABLE. RETRYING IN 10s...' : 'NO CARRIER. TRYING NEXT RELAY...', 'warn');
  setStatus('NO CARRIER', 'st-err');
  setTimeout(() => { S.switching = false; connect(); }, wrapped ? 10000 : 500);
}
function onConnect(c) {
  if (S.client !== c) return;
  S.everConnected = true;
  setStatus('LISTENING', 'st-busy');
  sys(`CARRIER OK [${hostOf(S.brokerUrl)}]`, 'ok');
  c.subscribe(S.topic, { qos: 1 }, (err) => {
    if (S.client !== c) return;
    if (err) { sys('SUBSCRIBE FAILED: ' + err.message, 'err'); return; }
    beginHandshake();
  });
}
async function publishRaw(prefix, key, obj) {
  const c = S.client;
  if (!c || !c.connected || !key) return false;
  obj.ts = obj.ts || now(); obj.n = obj.n || randId();
  const wire = prefix + '.' + await seal(key, obj);
  if (S.client !== c || !c.connected) return false;
  c.publish(S.topic, wire, { qos: 1, retain: false });
  return true;
}
const sendRoom = (obj) => publishRaw('R', S.roomKey, { ...obj, id: S.myId });
const sendSess = (obj) => publishRaw('S', S.sessionKey, { ...obj, from: S.myId });

/* ------------------------------------------------------------------ */
/* handshake + protocol                                                */
/* ------------------------------------------------------------------ */
async function beginHandshake() {
  S.eph = await genEph();
  S.sessionKey = null; S.linked = false; S.peerId = null;
  el.cfgPeer.textContent = 'none';
  setInputEnabled(false);
  setStage('syn');
  await sendSyn();
  sys('SYN >>> BROADCAST. WAITING FOR PEER...', 'dim');
}
async function sendSyn() {
  if (!S.eph) return;
  S.lastSyn = now();
  await sendRoom({ t: 'syn', pub: S.eph.pub });
}
function fresh(p, skipSkew) {
  if (!skipSkew && (typeof p.ts !== 'number' || Math.abs(now() - p.ts) > MAX_SKEW_MS)) return false;
  const n = p.n || ((p.id || p.from) + ':' + p.ts);
  if (S.seen.has(n)) return false;
  S.seen.add(n); S.seenList.push(n);
  if (S.seenList.length > 2000) { for (const old of S.seenList.splice(0, 1000)) S.seen.delete(old); }
  return true;
}
function notePeer(id) {
  const t = now();
  S.peers.set(id, t);
  for (const [k, v] of S.peers) if (t - v > 20000) S.peers.delete(k);
  if (S.peers.size > 1 && t - (S.lastMultiWarn || 0) > 60000) {
    S.lastMultiWarn = t;
    sys(`NOTICE: ${S.peers.size} CLIENT IDS ACTIVE ON CHANNEL (peer reconnect, or an extra device)`, 'warn');
  }
}
async function onMessage(payload) {
  let s; try { s = td.decode(payload); } catch (e) { return; }
  const kind = s[0]; const body = s.slice(2);
  if (s[1] !== '.' || body.length < 24) return;
  if (kind === 'R') {
    const p = await unseal(S.roomKey, body);
    if (!p) { sys('UNREADABLE PACKET ON CHANNEL (key mismatch?)', 'err'); return; }
    if (p.id === S.myId) return;
    if (!fresh(p, p.t === 'bye')) return;
    await handleRoom(p);
  } else if (kind === 'S') {
    if (!S.sessionKey) return;               // no session yet: peer's stale traffic
    const p = await unseal(S.sessionKey, body);
    if (!p) return;                          // old session, ignore silently
    if (p.from === S.myId) return;
    if (!fresh(p)) return;
    handleSess(p);
  }
}
async function handleRoom(p) {
  if (p.t === 'bye') {
    S.peers.delete(p.id);
    if (p.id === S.peerId) linkLost('PEER DISCONNECTED');
    return;
  }
  notePeer(p.id);
  if ((p.t === 'syn' || p.t === 'synack') && p.pub && S.eph) {
    // pairing lock: while a link is healthy, a different client cannot hijack it
    if (S.linked && S.peerId && p.id !== S.peerId && now() - S.lastPeerSeen < PEER_TIMEOUT_MS) {
      if (now() - (S.lastExtraWarn || 0) > 30000) {
        S.lastExtraWarn = now();
        sys(`EXTRA CLIENT ${p.id.slice(0, 6)} TRIED TO JOIN. CHANNEL IS TWO-PARTY; IGNORED.`, 'warn');
      }
      return;
    }
    let key;
    try { key = await deriveSession(S.eph.priv, p.pub, S.myId, p.id); }
    catch (e) { sys('KEY EXCHANGE FAILED', 'err'); return; }
    const rekey = S.linked && S.peerId === p.id;
    S.peerId = p.id; S.sessionKey = key; S.linked = false;
    el.cfgPeer.textContent = p.id;
    S.lastPeerSeen = now();
    if (p.t === 'syn') {
      setStage('synack');
      sys(`<<< SYN FROM PEER ${p.id.slice(0, 6)}. SENDING SYN/ACK >>>`, 'dim');
      await sendRoom({ t: 'synack', pub: S.eph.pub });
    } else {
      setStage('ack');
      sys('<<< SYN/ACK RECEIVED. SENDING ACK >>>', 'dim');
      await sendSess({ t: 'ack' });
      setLinked(rekey);
    }
  }
}
function handleSess(p) {
  S.lastPeerSeen = now();
  notePeer(p.from);
  switch (p.t) {
    case 'ack':  setLinked(); break;
    case 'ping': if (!S.linked) setLinked(); break;
    case 'msg':  if (typeof p.text === 'string') { addMsg('in', p.text, p.ts); notifyIncoming(); } break;
    case 'shares': onRemoteShares(p.list); break;
    default: break;
  }
}
function setLinked(quiet) {
  if (S.linked) return;
  S.linked = true; S.lastPeerSeen = now();
  setStage('linked');
  setStatus('LINK ESTABLISHED', 'st-on');
  setInputEnabled(true);
  if (!quiet) { sys('*** LINK ESTABLISHED. CHANNEL SECURE. ***', 'ok'); beep(660, 60); setTimeout(() => beep(990, 90), 80); }
  else sys('SESSION RE-KEYED', 'dim');
  setTimeout(announceShares, 300);
}
function linkLost(reason, resyn) {
  const had = S.linked || S.sessionKey;
  S.linked = false; S.sessionKey = null; S.peerId = null;
  el.cfgPeer.textContent = 'none';
  setInputEnabled(false);
  setStage('syn');
  if (S.client && S.client.connected) setStatus('LISTENING', 'st-busy');
  if (had) sys('LINK LOST: ' + reason, 'warn');
  if (resyn !== false && S.client && S.client.connected) beginHandshake();
}

/* periodic: heartbeat, watchdog, re-SYN */
setInterval(() => {
  if (!S.client) return;
  const t = now();
  if (S.linked) {
    if (t - S.lastPeerSeen > PEER_TIMEOUT_MS) linkLost('PEER TIMEOUT');
  } else if (S.client.connected && S.eph && t - S.lastSyn > RESYN_MS) {
    sendSyn();
  }
}, 5000);
setInterval(() => { if (S.linked) sendSess({ t: 'ping' }); }, PING_MS);

/* ------------------------------------------------------------------ */
/* lifecycle (iOS backgrounding, keyboard)                             */
/* ------------------------------------------------------------------ */
function onResume() {
  S.unread = 0; document.title = 'DarkMSG';
  if (!S.client || S.switching) return;
  const away = now() - S.hiddenAt;
  if (!S.client.connected || away > RESUME_REDIAL_MS) {
    sys('RESUMING. RE-DIALING...', 'dim');
    linkLost('APP RESUMED', false);
    connect();
  } else if (S.linked) {
    sendSess({ t: 'ping' });
  }
}
document.addEventListener('visibilitychange', () => {
  if (document.hidden) S.hiddenAt = now(); else onResume();
});
window.addEventListener('pageshow', (e) => { if (e.persisted) onResume(); });
window.addEventListener('online', () => { S.hiddenAt = 0; onResume(); });
window.addEventListener('offline', () => { setStatus('NO NETWORK', 'st-err'); });

if (window.visualViewport) {
  const vv = window.visualViewport;
  const fit = () => {
    el.app.style.height = vv.height + 'px';
    el.app.style.top = vv.offsetTop + 'px';
    window.scrollTo(0, 0);
    scrollBottom();
  };
  vv.addEventListener('resize', fit);
  vv.addEventListener('scroll', fit);
}

/* ------------------------------------------------------------------ */
/* file transfer: BitTorrent over WebRTC (WebTorrent), encrypted files */
/* ------------------------------------------------------------------ */
const WT_URL   = 'https://cdn.jsdelivr.net/npm/webtorrent@2.8.4/dist/webtorrent.min.js';
const TRACKERS = [
  'wss://tracker.openwebtorrent.com',
  'wss://tracker.webtorrent.dev',
];
const RTC_CONFIG = { iceServers: [
  { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
  { urls: ['turn:openrelay.metered.ca:80', 'turn:openrelay.metered.ca:443', 'turns:openrelay.metered.ca:443'],
    username: 'openrelayproject', credential: 'openrelayproject' },
] };
const XFER_CHUNK     = 4 * 1024 * 1024;   // plaintext bytes per AES-GCM chunk
const XFER_MAX_FILES = 2000;              // per share (announcement must fit one MQTT packet)
const X = { wt: null, loading: null, local: new Map(), remote: new Map(), torrents: new Map(), dl: new Map() };
const ex = {
  col: $('#xfer-col'), btnXfer: $('#btn-xfer'), pickFolder: $('#pick-folder'), pickFiles: $('#pick-files'),
  btnPickFolder: $('#btn-pick-folder'), btnPickFiles: $('#btn-pick-files'),
  local: $('#local-shares'), remote: $('#remote-shares'), status: $('#xfer-status'),
};
const fmtBytes = (n) => {
  if (!(n >= 0)) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
};
const dlKey = (sid, fi) => sid + ':' + fi;
const whenReady = (t) => (t.ready ? Promise.resolve() : new Promise((r) => t.once('ready', r)));

function loadWT() {
  if (window.WebTorrent) return Promise.resolve();
  if (!X.loading) X.loading = import(WT_URL)
    .then((m) => { window.WebTorrent = m.default || m.WebTorrent; })
    .catch((e) => { X.loading = null; throw new Error('WebTorrent failed to load: ' + (e.message || e)); });
  return X.loading;
}
async function ensureWT() {
  await loadWT();
  if (!X.wt) {
    X.wt = new WebTorrent({ tracker: { announce: TRACKERS, rtcConfig: RTC_CONFIG } });
    X.wt.on('error', (e) => sys('TORRENT ENGINE: ' + (e && e.message ? e.message : e), 'err'));
  }
  return X.wt;
}

/* chunked AES-GCM: [iv(12) | ct(len+16)] repeated */
async function encryptFile(file, key) {
  const parts = [];
  for (let off = 0; ; off += XFER_CHUNK) {
    const buf = await file.slice(off, off + XFER_CHUNK).arrayBuffer();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    parts.push(iv, await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf));
    if (off + XFER_CHUNK >= file.size) break;
  }
  return new Blob(parts, { type: 'application/octet-stream' });
}
async function decryptBlob(blob, key, plainSize) {
  const parts = []; let pos = 0, done = 0;
  while (pos < blob.size) {
    const ptLen = Math.min(XFER_CHUNK, plainSize - done);
    const encLen = 12 + ptLen + 16;
    const u = new Uint8Array(await blob.slice(pos, pos + encLen).arrayBuffer());
    parts.push(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12)));
    pos += encLen; done += ptLen;
    if (ptLen === 0) break;
  }
  return new Blob(parts);
}

/* ---- seeding ---- */
async function shareFiles(fileList, label) {
  const files = Array.from(fileList).filter((f) => !f.name.startsWith('.'));
  if (!files.length) { sys('NOTHING TO SHARE.', 'warn'); return; }
  if (files.length > XFER_MAX_FILES) { sys(`TOO MANY FILES (${files.length}). LIMIT ${XFER_MAX_FILES} PER SHARE.`, 'err'); return; }
  const id = randId();
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const keyB64 = b64enc(await crypto.subtle.exportKey('raw', key));
  const share = { id, name: label, keyB64, files: [], total: 0, torrent: null, infoHash: null, status: 'LOADING ENGINE' };
  X.local.set(id, share); renderLocal();
  try {
    const wt = await ensureWT();
    const blobs = [];
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      share.status = `ENCRYPTING ${i + 1}/${files.length}`; renderLocal();
      const enc = await encryptFile(f, key);
      blobs.push(new File([enc], i + '.bin', { type: 'application/octet-stream' }));
      share.files.push({ i, path: f.webkitRelativePath || f.name, size: f.size });
      share.total += f.size;
    }
    share.status = 'HASHING'; renderLocal();
    wt.seed(blobs, { name: 'dm-' + id, announce: TRACKERS }, (torrent) => {
      share.torrent = torrent; share.infoHash = torrent.infoHash; share.status = 'SEEDING';
      X.torrents.set(torrent.infoHash, torrent);
      torrent.on('wire', renderLocal);
      torrent.on('error', (e) => sys('SEED ERROR: ' + (e.message || e), 'err'));
      renderLocal(); announceShares();
      sys(`SHARING "${label}" (${files.length} file(s), ${fmtBytes(share.total)}) VIA BITTORRENT`, 'ok');
    });
  } catch (e) {
    X.local.delete(id); renderLocal();
    sys('SHARE FAILED: ' + (e.message || e), 'err');
  }
}
function removeShare(id) {
  const share = X.local.get(id); if (!share) return;
  X.local.delete(id);
  if (share.torrent) { X.torrents.delete(share.infoHash); try { X.wt.remove(share.torrent); } catch (e) { /* ignore */ } }
  renderLocal(); announceShares();
  sys(`STOPPED SHARING "${share.name}"`, 'dim');
}
function announceShares() {
  if (!S.linked) return;
  const list = Array.from(X.local.values()).filter((sh) => sh.infoHash).map((sh) => ({
    id: sh.id, name: sh.name, infoHash: sh.infoHash, key: sh.keyB64, total: sh.total, files: sh.files,
  }));
  sendSess({ t: 'shares', list });
}
function onRemoteShares(list) {
  if (!Array.isArray(list)) return;
  const before = Array.from(X.remote.keys()).join(',');
  X.remote.clear();
  for (const sh of list) {
    if (!sh || typeof sh.id !== 'string' || !/^[0-9a-f]{40}$/.test(sh.infoHash || '') || !Array.isArray(sh.files)) continue;
    X.remote.set(sh.id, {
      id: sh.id, name: String(sh.name || sh.id), infoHash: sh.infoHash, key: String(sh.key || ''), total: +sh.total || 0,
      files: sh.files.filter((f) => f && Number.isInteger(f.i)).map((f) => ({ i: f.i, path: String(f.path || f.i), size: +f.size || 0 })),
    });
  }
  renderRemote();
  const after = Array.from(X.remote.keys()).join(',');
  if (after && after !== before) sys(`PEER IS SHARING ${X.remote.size} ITEM(S). OPEN [XFER] TO DOWNLOAD.`, 'ok');
}

/* ---- downloading ---- */
async function getRemoteFile(sid, fi) {
  const share = X.remote.get(sid); if (!share) return;
  const f = share.files.find((x) => x.i === fi); if (!f) return;
  const k = dlKey(sid, fi);
  if (X.dl.has(k) && X.dl.get(k).status !== 'FAILED') return;
  const st = { sid, fi, name: f.path.split('/').pop() || 'file', size: f.size, status: 'CONNECTING', progress: 0, url: null, tfile: null, err: '' };
  X.dl.set(k, st); renderRemote();
  try {
    const wt = await ensureWT();
    const key = await crypto.subtle.importKey('raw', b64dec(share.key), { name: 'AES-GCM' }, false, ['decrypt']);
    let torrent = X.torrents.get(share.infoHash);
    if (!torrent) {
      torrent = wt.add(share.infoHash, { announce: TRACKERS });
      X.torrents.set(share.infoHash, torrent);
      torrent.on('error', (e) => sys('TORRENT: ' + (e.message || e), 'err'));
      await whenReady(torrent);
      torrent.deselect(0, torrent.pieces.length - 1, false);
    } else {
      await whenReady(torrent);
    }
    // multi-file torrents keep our 0.bin/1.bin names; a single-file torrent is named after the torrent itself
    let tf = torrent.files.find((x) => x.name === fi + '.bin');
    if (!tf && torrent.files.length === 1 && fi === 0) tf = torrent.files[0];
    if (!tf) throw new Error('file not in torrent');
    st.tfile = tf; st.status = 'DOWNLOADING'; renderRemote();
    tf.select();
    if (!tf.done) await new Promise((r) => tf.once('done', r));
    st.status = 'DECRYPTING'; st.progress = 1; renderRemote();
    const dec = await decryptBlob(await tf.blob(), key, f.size);
    if (dec.size !== f.size) throw new Error('size mismatch after decrypt');
    st.url = URL.createObjectURL(dec); st.status = 'READY'; renderRemote();
    sys(`RECEIVED "${st.name}" (${fmtBytes(dec.size)}). TAP [SAVE] IN XFER IF IT DID NOT AUTO-SAVE.`, 'ok');
    autoSave(st);
  } catch (e) {
    st.status = 'FAILED'; st.err = e && e.message ? e.message : String(e); renderRemote();
    sys(`DOWNLOAD FAILED: ${st.name}: ${st.err}`, 'err');
  }
}
function autoSave(st) {
  try { const a = document.createElement('a'); a.href = st.url; a.download = st.name; document.body.appendChild(a); a.click(); a.remove(); }
  catch (e) { /* user taps SAVE */ }
}

/* ---- rendering ---- */
function shareMeta(share, isLocal) {
  const t = share.torrent || X.torrents.get(share.infoHash);
  let m = `${share.files.length} file(s) · ${fmtBytes(share.total)}`;
  if (isLocal) m += ` · ${share.status}` + (t ? ` · peers ${t.numPeers} · up ${fmtBytes(t.uploadSpeed)}/s` : '');
  else if (t) m += ` · peers ${t.numPeers} · down ${fmtBytes(t.downloadSpeed)}/s`;
  return m;
}
function dlText(st) {
  if (st.status === 'DOWNLOADING' && st.tfile) { st.progress = st.tfile.progress || 0; return `${Math.round(st.progress * 100)}%`; }
  return st.status;
}
function mk(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
function shareRow(share, isLocal) {
  const box = mk('div', 'share');
  const hd = mk('div', 'share-hd');
  hd.append(mk('span', 'share-name', (share.files.length > 1 ? '[DIR] ' : '[FILE] ') + share.name));
  const meta = mk('span', 'share-meta', shareMeta(share, isLocal)); meta.dataset.share = share.id; hd.appendChild(meta);
  if (isLocal) { const rm = mk('button', 'mini', '[X]'); rm.type = 'button'; rm.title = 'stop sharing'; rm.onclick = () => removeShare(share.id); hd.appendChild(rm); }
  box.appendChild(hd);
  const list = mk('div', 'share-files');
  for (const f of share.files) {
    const row = mk('div', 'frow');
    row.append(mk('span', 'fpath', f.path), mk('span', 'fsize', fmtBytes(f.size)));
    if (!isLocal) {
      const k = dlKey(share.id, f.i); const st = X.dl.get(k);
      if (!st || st.status === 'FAILED') {
        const b = mk('button', 'mini', st ? '[RETRY]' : '[GET]'); b.type = 'button'; b.onclick = () => getRemoteFile(share.id, f.i); row.appendChild(b);
        if (st) row.appendChild(mk('span', 'ferr', st.err));
      } else if (st.status === 'READY') {
        const a = mk('a', 'mini', '[SAVE]'); a.href = st.url; a.download = st.name; row.appendChild(a);
      } else {
        const pr = mk('span', 'fprog', dlText(st)); pr.dataset.dl = k; row.appendChild(pr);
        const bar = mk('div', 'bar'); const i = mk('i'); i.dataset.bar = k; i.style.width = Math.round(st.progress * 100) + '%'; bar.appendChild(i); row.appendChild(bar);
      }
    }
    list.appendChild(row);
  }
  box.appendChild(list);
  return box;
}
function renderLocal()  { ex.local.textContent = '';  for (const sh of X.local.values())  ex.local.appendChild(shareRow(sh, true)); }
function renderRemote() { ex.remote.textContent = ''; for (const sh of X.remote.values()) ex.remote.appendChild(shareRow(sh, false)); }
function xferTick() {
  if (!X.local.size && !X.remote.size) return;
  for (const m of ex.col.querySelectorAll('[data-share]')) {
    const l = X.local.get(m.dataset.share); const r = X.remote.get(m.dataset.share);
    if (l) m.textContent = shareMeta(l, true); else if (r) m.textContent = shareMeta(r, false);
  }
  for (const p of ex.col.querySelectorAll('[data-dl]')) { const st = X.dl.get(p.dataset.dl); if (st) p.textContent = dlText(st); }
  for (const b of ex.col.querySelectorAll('[data-bar]')) { const st = X.dl.get(b.dataset.bar); if (st) b.style.width = Math.round(st.progress * 100) + '%'; }
}
setInterval(xferTick, 1000);

/* ---- xfer ui wiring ---- */
ex.btnXfer.addEventListener('click', () => {
  const open = el.app.classList.toggle('xfer-open');
  ex.btnXfer.textContent = open ? '[CHAT]' : '[XFER]';
});
ex.btnPickFolder.addEventListener('click', () => ex.pickFolder.click());
ex.btnPickFiles.addEventListener('click', () => ex.pickFiles.click());
ex.pickFolder.addEventListener('change', () => {
  const fl = ex.pickFolder.files; if (!fl.length) return;
  const label = (fl[0].webkitRelativePath || '').split('/')[0] || 'folder';
  shareFiles(fl, label); ex.pickFolder.value = '';
});
ex.pickFiles.addEventListener('change', () => {
  const fl = ex.pickFiles.files; if (!fl.length) return;
  shareFiles(fl, fl.length === 1 ? fl[0].name : `${fl.length} files`); ex.pickFiles.value = '';
});
if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') window.__dmx = { X, shareFiles };

/* ------------------------------------------------------------------ */
/* boot + access                                                       */
/* ------------------------------------------------------------------ */
const BOOT_LINES = [
  ['DARKMSG TERMINAL v1.0', 'ok', 250],
  ['(c) 1996 NO-SUCH-AGENCY. ALL RIGHTS RESERVED.', '', 150],
  ['', '', 100],
  ['INITIALIZING SECURE UPLINK ........ OK', 'ok', 250],
  ['LOADING CRYPTO MODULE (AES-256-GCM) OK', 'ok', 250],
  ['CHECKING WEBCRYPTO SUBSYSTEM ....... ' + (window.crypto && crypto.subtle ? 'OK' : 'FAIL'), crypto.subtle ? 'ok' : 'warn', 250],
  ['CHECKING RELAY MODULE .............. ' + (typeof mqtt !== 'undefined' ? 'OK' : 'PENDING'), 'ok', 250],
  ['SCANNING FOR WIRETAPS .............. NONE FOUND', 'ok', 350],
  ['', '', 100],
  ['ACCESS RESTRICTED. AUTHENTICATE TO CONTINUE.', 'warn', 400],
];
let bootSkipped = false;
async function boot() {
  el.scrBoot.addEventListener('click', () => { bootSkipped = true; }, { once: true });
  for (const [line, cls, delay] of BOOT_LINES) {
    if (bootSkipped) break;
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = line + '\n';
    el.bootLog.appendChild(span);
    await sleep(delay);
  }
  showScreen(el.scrAccess);
  setTimeout(() => el.pass.focus(), 50);
}

el.formAccess.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pass = el.pass.value.trim().toUpperCase();   // access code is case-insensitive
  if (!pass) return;
  unlockAudio();
  if (!window.crypto || !crypto.subtle) {
    el.accessMsg.textContent = 'WEBCRYPTO UNAVAILABLE. USE HTTPS / MODERN SAFARI.'; el.accessMsg.className = 'err'; return;
  }
  el.btnAuth.disabled = true; el.pass.disabled = true;
  el.accessMsg.className = ''; el.accessMsg.textContent = 'DERIVING KEYS (300000 ROUNDS) ...';
  try {
    const base = await deriveBase(pass);
    el.pass.value = '';
    const verify = hex(await hkdfBits(base, 'verify', 256));
    if (verify !== ACCESS_HASH) {
      el.accessMsg.textContent = 'ACCESS DENIED. INVALID CODE.'; el.accessMsg.className = 'err';
      beep(220, 250);
      return;
    }
    S.topic      = TOPIC_PREFIX + hex(await hkdfBits(base, 'topic', 256));
    S.roomKey    = await hkdfAes(base, 'room');
    S.storageKey = await hkdfAes(base, 'storage');
    S.storeId    = hex(await hkdfBits(base, 'store', 128));
    S.fp         = hex(await hkdfBits(base, 'fingerprint', 32)).toUpperCase().match(/.{4}/g).join('-');
    try { S.myId = sessionStorage.getItem(SS_CLIENT_ID); } catch (err) { /* ignore */ }
    if (!S.myId) { S.myId = randId(); try { sessionStorage.setItem(SS_CLIENT_ID, S.myId); } catch (err) { /* ignore */ } }
    el.cfgFp.textContent = S.fp; el.cfgId.textContent = S.myId;
    el.accessMsg.textContent = 'ACCESS GRANTED.';
    S.history = await loadHistory();
    el.msgs.textContent = '';
    for (const m of S.history) renderLine(m);
    if (S.history.length) sys(`${S.history.length} MESSAGE(S) RESTORED FROM ENCRYPTED STORE`, 'dim');
    sys(`CHANNEL FINGERPRINT ${S.fp} — compare with peer`, 'dim');
    el.btnSettings.hidden = false; ex.btnXfer.hidden = false;
    showScreen(el.scrTerm);
    scrollBottom();
    S.brokerIdx = 0;
    connect();
  } catch (err) {
    el.accessMsg.textContent = 'KEY DERIVATION FAILED: ' + (err.message || err); el.accessMsg.className = 'err';
  } finally {
    el.btnAuth.disabled = false; el.pass.disabled = false;
  }
});

/* ------------------------------------------------------------------ */
/* sending                                                             */
/* ------------------------------------------------------------------ */
el.formSend.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = el.msgInput.value.trim();
  if (!text) return;
  if (!S.linked) { sys('NO LINK. MESSAGE NOT SENT.', 'err'); return; }
  const ts = now();
  const ok = await sendSess({ t: 'msg', text, ts });
  if (!ok) { sys('SEND FAILED (NO CARRIER).', 'err'); return; }
  addMsg('out', text, ts);
  el.msgInput.value = '';
  el.msgInput.focus();
});

el.msgInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); if (el.formSend.requestSubmit) el.formSend.requestSubmit(); else el.btnSend.click(); }
});

/* ------------------------------------------------------------------ */
/* settings                                                            */
/* ------------------------------------------------------------------ */
el.btnSettings.addEventListener('click', () => {
  let custom = ''; try { custom = localStorage.getItem(LS_BROKER) || ''; } catch (e) { /* ignore */ }
  el.cfgBroker.value = custom;
  el.cfgRelay.textContent = S.brokerUrl ? hostOf(S.brokerUrl) : '--';
  el.settings.hidden = false;
});
el.btnSettingsClose.addEventListener('click', () => { el.settings.hidden = true; });
el.settings.addEventListener('click', (e) => { if (e.target === el.settings) el.settings.hidden = true; });
el.btnBrokerApply.addEventListener('click', () => {
  const v = el.cfgBroker.value.trim();
  if (!/^wss:\/\/.+/.test(v)) { sys('RELAY URL MUST START WITH wss://', 'err'); return; }
  try { localStorage.setItem(LS_BROKER, v); } catch (e) { /* ignore */ }
  el.settings.hidden = true;
  sys('RELAY CHANGED. RE-DIALING...', 'warn');
  S.brokerIdx = 0; linkLost('RELAY CHANGED', false); connect();
});
el.btnBrokerReset.addEventListener('click', () => {
  try { localStorage.removeItem(LS_BROKER); } catch (e) { /* ignore */ }
  el.cfgBroker.value = '';
  el.settings.hidden = true;
  sys('RELAY RESET TO DEFAULTS. RE-DIALING...', 'warn');
  S.brokerIdx = 0; linkLost('RELAY CHANGED', false); connect();
});
el.btnWipe.addEventListener('click', () => {
  if (!confirm('Wipe encrypted history for this channel on this device?')) return;
  S.history = [];
  try { localStorage.removeItem(histKey()); } catch (e) { /* ignore */ }
  el.msgs.textContent = '';
  sys('LOCAL HISTORY WIPED.', 'warn');
  el.settings.hidden = true;
});
el.btnLogout.addEventListener('click', () => {
  disconnect();
  location.reload();
});

/* ------------------------------------------------------------------ */
boot();
})();
