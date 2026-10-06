#!/usr/bin/env node
// hosted demo mode, one public port: landing page, a server side bridge per signed in user, and the relay itself
// bridges here run on the server, so unlike the local setup the host sees plaintext while a session is open

import { createServer, get } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket, WebSocketServer } from 'ws';
import { startServer } from '../server/server.js';
import { startBridge } from '../bridge/bridge.js';

const PORT = Number(process.env.PORT || 10000);
const DATA_DIR = process.env.DATA_DIR || fileURLToPath(new URL('./data/', import.meta.url));
const RELAY_PORT = Number(process.env.RELAY_PORT || 7777);
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS || 12);
// a tab can reload inside this window and keep its unlocked session, after it the bridge closes and the vault relocks
const IDLE_MS = 2 * 60_000;
const MAX_FRAME = 1 << 20;
const USERNAME = /^[a-z0-9_]{1,32}$/;
const WEB_DIR = fileURLToPath(new URL('../web/', import.meta.url));

const log = (m) => console.log(new Date().toISOString(), m);
const vaultDir = join(DATA_DIR, 'vaults');
mkdirSync(vaultDir, { recursive: true });

const relay = await startServer({ host: '127.0.0.1', port: RELAY_PORT, dbPath: join(DATA_DIR, 'pqs-server.db'), log });
const relayUrl = `ws://127.0.0.1:${relay.port}`;

// sid -> session, user -> session
const sessions = new Map();
const byUser = new Map();
const starting = new Set();

const armIdle = (s) => {
  clearTimeout(s.timer);
  s.timer = setTimeout(() => endSession(s), IDLE_MS);
};

async function endSession(s) {
  clearTimeout(s.timer);
  if (sessions.get(s.sid) !== s) return;
  sessions.delete(s.sid);
  byUser.delete(s.user);
  log(`closing session for ${s.user}`);
  await s.bridge.close().catch((e) => log(`bridge close failed: ${e.message}`));
}

// a name thats open in a live tab is refused, an idle one is replaced by a fresh locked bridge so the passphrase is asked again
async function openSession(user) {
  if (!USERNAME.test(user)) throw new Error('username must be 1-32 characters of a-z, 0-9 or _');
  if (starting.has(user)) throw new Error('that username is already being opened, try again in a moment');
  const existing = byUser.get(user);
  if (existing?.sockets > 0) throw new Error(`${user} is already open in another tab or device`);
  starting.add(user);
  try {
    if (existing) await endSession(existing);
    if (sessions.size >= MAX_SESSIONS) throw new Error('the demo server is full right now, try again in a few minutes');
    const bridge = await startBridge({ user, serverUrl: relayUrl, dataDir: vaultDir, port: 0, kdf: 'interactive', log });
    const s = { sid: randomBytes(16).toString('hex'), user, bridge, sockets: 0, timer: null };
    sessions.set(s.sid, s);
    byUser.set(user, s);
    armIdle(s);
    return s;
  } finally {
    starting.delete(user);
  }
}

const esc = (t) => String(t).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const LOGO = [
  ' ╺┳╸╻┏┓╻ ┏━╸┏━┓┏┓╻ ╻ ╻┏━┓',
  '  ┃ ┃┃┗┫ ┃  ┣━┫┃┗┫ ┃┏┛┏━┛',
  '  ╹ ╹╹ ╹ ┗━╸╹ ╹╹ ╹ ┗┛ ┗━╸',
].join('\n');

const landing = (error) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tin can v2</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="/app.css">
</head>
<body>
<div class="tui">
<main class="login">
<section class="box focus" aria-label="open tin can">
<span class="lb">open tin can</span>
<div class="bc">
<div class="logo" aria-hidden="true">${LOGO}</div>
<div class="faint">post-quantum end-to-end encrypted chat</div>
<form method="post" action="/start">
<label class="lab" for="user">username (a-z, 0-9 or _)</label>
<input class="fld" id="user" name="user" required maxlength="32" pattern="[a-z0-9_]{1,32}" autocomplete="username"
       autocapitalize="none" spellcheck="false" autofocus${error ? ' aria-invalid="true" aria-describedby="start-error"' : ''}>
<div class="actions"><button class="key" type="submit"><span class="k">[⏎]</span> continue</button></div>
${error ? `<div class="bad" id="start-error" role="alert">✗ ${esc(error)}</div>` : ''}
</form>
<div class="faint">a new name creates an identity, an existing one asks for its passphrase.
open this page on another device or browser with a different name to chat.</div>
</div>
</section>
</main>
</div>
</body>
</html>`;

const SECURITY = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' };
const csp = (host) => `default-src 'self'; connect-src 'self' wss://${host} ws://${host}; img-src 'self' data:; object-src 'none'; ` +
  `base-uri 'none'; form-action 'self'; frame-ancestors 'none'`;

const sendPage = (req, res, status, body) => {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': csp(req.headers.host), ...SECURITY });
  res.end(body);
};
const redirect = (res, to) => res.writeHead(303, { Location: to, ...SECURITY }).end();

const readForm = (req) => new Promise((resolve, reject) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (c) => {
    body += c;
    if (body.length > 2048) { reject(new Error('form too large')); req.destroy(); }
  });
  req.on('end', () => resolve(new URLSearchParams(body)));
  req.on('error', reject);
});

// static files come from the users bridge, it only answers to its own 127.0.0.1 host so we dont forward the browsers headers
const proxyStatic = (req, res, s, rest) => {
  const up = get({ host: '127.0.0.1', port: s.bridge.port, path: `/${rest}` }, (r) => {
    const headers = { ...SECURITY, 'Content-Security-Policy': csp(req.headers.host) };
    if (r.headers['content-type']) headers['Content-Type'] = r.headers['content-type'];
    res.writeHead(r.statusCode ?? 502, headers);
    r.pipe(res);
  });
  up.on('error', () => { if (!res.headersSent) res.writeHead(502).end(); });
};

const http = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/') return sendPage(req, res, 200, landing(url.searchParams.get('error')));
    if (req.method === 'GET' && url.pathname === '/app.css') {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8', ...SECURITY });
      return res.end(await readFile(join(WEB_DIR, 'app.css')));
    }
    if (req.method === 'POST' && url.pathname === '/start') {
      const user = ((await readForm(req)).get('user') ?? '').trim().toLowerCase();
      try {
        const s = await openSession(user);
        return redirect(res, `/b/${s.sid}/?token=${s.bridge.token}`);
      } catch (e) {
        return redirect(res, `/?error=${encodeURIComponent(e.message)}`);
      }
    }
    const m = url.pathname.match(/^\/b\/([0-9a-f]{32})(\/.*)?$/);
    if (req.method === 'GET' && m) {
      const s = sessions.get(m[1]);
      if (!s) return redirect(res, `/?error=${encodeURIComponent('that session ended, sign in again')}`);
      if (!m[2]) return redirect(res, `/b/${s.sid}/${url.search}`);
      return proxyStatic(req, res, s, m[2].slice(1));
    }
    res.writeHead(404, SECURITY).end();
  } catch {
    if (!res.headersSent) res.writeHead(400, SECURITY).end();
  }
});

const okCode = (c) => (c === 1000 || (c >= 1001 && c <= 1014 && ![1004, 1005, 1006].includes(c)) || (c >= 3000 && c <= 4999) ? c : 1000);

// relays frames both ways, client frames that arrive before upstream opens are held
function pipe(client, target, opts = {}) {
  const up = new WebSocket(target, { maxPayload: MAX_FRAME, ...opts });
  const held = [];
  client.on('message', (d, binary) => (up.readyState === WebSocket.OPEN ? up.send(d, { binary }) : held.push([d, binary])));
  up.on('open', () => { for (const [d, binary] of held.splice(0)) up.send(d, { binary }); });
  up.on('message', (d, binary) => { if (client.readyState === WebSocket.OPEN) client.send(d, { binary }); });
  up.on('close', (code, reason) => { if (client.readyState === WebSocket.OPEN) client.close(okCode(code), reason); });
  client.on('close', (code, reason) => {
    if (up.readyState === WebSocket.OPEN) up.close(okCode(code), reason); else up.terminate();
  });
  up.on('error', () => client.terminate());
  client.on('error', () => up.terminate());
}

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME });
http.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  const m = url.pathname.match(/^\/b\/([0-9a-f]{32})\/ws$/);
  if (!m) {
    // anything else is the relay, so local bridges can still use --server wss://<this host>
    wss.handleUpgrade(req, socket, head, (ws) => pipe(ws, relayUrl + url.pathname + url.search));
    return;
  }
  const s = sessions.get(m[1]);
  if (!s) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
  wss.handleUpgrade(req, socket, head, (ws) => {
    s.sockets++;
    clearTimeout(s.timer);
    ws.on('close', () => { if (--s.sockets === 0 && sessions.get(s.sid) === s) armIdle(s); });
    const target = `ws://127.0.0.1:${s.bridge.port}/ws${url.search}`;
    pipe(ws, target, { origin: `http://127.0.0.1:${s.bridge.port}` });
  });
});

http.listen(PORT, '0.0.0.0', () => log(`tin can hosted on :${PORT} (data: ${DATA_DIR})`));

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    await Promise.all([...sessions.values()].map(endSession));
    await relay.close();
    process.exit(0);
  });
}
