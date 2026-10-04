// the tab gets plaintext, so 127.0.0.1 only, random per run token, and host and origin checks against other sites and dns rebinding

import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { WebSocketServer } from 'ws';
import { CoreProcess } from './core.js';
import { ServerLink } from './link.js';

// state changing methods, after each one every open tab gets a changed push
const MUTATING = new Set(['create', 'unlock', 'add_contact', 'verify', 'accept_key_change', 'dm_request', 'dm_accept', 'dm_decline',
                          'dm_send']);
function convOf(method, p) {
  if (['dm_request', 'dm_send'].includes(method)) return `dm:${p.to}`;
  if (['dm_accept', 'dm_decline'].includes(method)) return `dm:${p.peer}`;
  if (['verify', 'accept_key_change', 'add_contact'].includes(method)) return `dm:${p.user}`;
  return null;
}

const DEFAULT_WEB_DIR = fileURLToPath(new URL('../web/', import.meta.url));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
                '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };

export async function startBridge({
  user, serverUrl = 'ws://127.0.0.1:7777', dataDir, port = 0, kdf = 'moderate', corePath,
  webDir = DEFAULT_WEB_DIR, log = () => {},
}) {
  if (!/^[a-z0-9_]{1,32}$/.test(user ?? '')) throw new Error('user must be 1-32 characters of a-z, 0-9 or _');
  if (!dataDir) throw new Error('dataDir is required');

  const core = new CoreProcess({ corePath });
  await core.call('ping');
  const token = randomBytes(24).toString('hex');
  const uis = new Set();
  let link = null;
  let unlocked = false;
  const presence = new Map();

  const push = (event) => {
    const data = JSON.stringify(event);
    for (const ws of uis) if (ws.readyState === ws.OPEN) ws.send(data);
  };
  const status = () => ({ user, unlocked, connected: !!link?.connected });

  // one queue for all core calls so multi step stuff like bundle -> request -> send never interleaves with deliveries
  let queue = Promise.resolve();
  const serial = (fn) => {
    const run = queue.then(fn);
    queue = run.catch(() => {});
    return run;
  };

  const sendOutgoing = async (outgoing) => {
    for (const envelope of outgoing ?? []) await link.request({ op: 'send', envelope });
  };
  const pushEvents = (events) => { for (const e of events ?? []) push(e); };

  // auto replies like accepts and receipts that failed while offline, core already moved on, so resend after reconnect
  let unsent = [];
  const sendReplies = async (outgoing) => {
    for (const envelope of outgoing ?? []) {
      try { await link.request({ op: 'send', envelope }); } catch (e) {
        if (link.connected) { log(`server refused a reply: ${e.message}`); continue; }
        log(`reply not sent yet (${e.message}); will retry after reconnecting`);
        unsent.push(envelope);
      }
    }
  };

  const onDeliver = (msg) => serial(async () => {
    let r;
    try {
      r = await core.call('receive', { envelope: msg.envelope });
    } catch (e) {
      // ack even when rejected, replay or forgery, otherwise the server keeps redelivering it
      log(`rejected from ${msg.sender}: ${e.message}`);
      push({ event: 'rejected', from: msg.sender, reason: e.message });
    }
    link.ack(msg.id);
    if (r) {
      pushEvents(r.events);
      await sendReplies(r.outgoing);
    }
  });

  const connect = () => {
    link = new ServerLink({ url: serverUrl, core, user });
    link.on('status', (connected) => {
      // no server means we dont know whos online anymore
      if (!connected) presence.clear();
      if (connected && unsent.length) {
        const retry = unsent;
        unsent = [];
        serial(() => sendReplies(retry));
      }
      push({ event: 'status', ...status(), connected });
    });
    link.on('deliver', onDeliver);
    link.on('presence', (p) => {
      if (Array.isArray(p.online)) {
        presence.clear();
        for (const u of p.online) presence.set(u, true);
        push({ event: 'presence', online: [...presence.keys()] });
      } else {
        if (p.online) presence.set(p.user, true); else presence.delete(p.user);
        push({ event: 'presence', user: p.user, online: !!p.online });
      }
    });
    link.on('problem', (message) => push({ event: 'problem', message }));
    link.start();
  };

  // refresh means always re fetch, so key changes get noticed
  const ensureContact = async (who, refresh = false) => {
    if (!refresh) {
      const { contacts } = await core.call('contacts.list');
      if (contacts.some((c) => c.user === who)) return null;
    }
    const { bundle } = await link.request({ op: 'get_bundle', user: who });
    if (!bundle) throw new Error(`no such user: ${who}`);
    const r = await core.call('contacts.add_bundle', { bundle });
    pushEvents(r.events);
    return r;
  };

  const requireUnlocked = () => {
    if (!unlocked) throw new Error('unlock your account first');
    if (!link?.connected) throw new Error('not connected to the server');
  };

  const methods = {
    status: async () => ({ ...status(), account_exists: (await core.call('client.exists', { dir: dataDir, user })).exists }),
    create: async ({ passphrase }) => {
      if (unlocked) throw new Error('already unlocked');
      const r = await core.call('client.create', { dir: dataDir, user, passphrase, kdf });
      unlocked = true;
      connect();
      return r.summary;
    },
    unlock: async ({ passphrase }) => {
      if (unlocked) throw new Error('already unlocked');
      const r = await core.call('client.open', { dir: dataDir, user, passphrase });
      unlocked = true;
      connect();
      return r.summary;
    },
    summary: async () => ({ ...(await core.call('summary')), online: [...presence.keys()], connected: !!link?.connected }),
    history: ({ conv, limit }) => core.call('history', { conv, limit }),
    users: async () => { requireUnlocked(); return (await link.request({ op: 'list_users' })).users.filter((u) => u.user !== user); },
    add_contact: async ({ user: who }) => { requireUnlocked(); return ensureContact(who, true); },
    safety_number: ({ user: who }) => core.call('contacts.safety_number', { user: who }),
    verify: ({ user: who }) => core.call('contacts.verify', { user: who }),
    accept_key_change: async ({ user: who }) => {
      requireUnlocked();
      const r = await core.call('contacts.accept_change', { user: who });
      pushEvents(r.events);
      await sendOutgoing(r.outgoing);
      return r;
    },
    dm_request: async ({ to, text }) => {
      requireUnlocked();
      // always re fetch so a new chat picks up the latest key
      await ensureContact(to);
      const r = await core.call('dm.request', { to, text: text ?? null });
      await sendOutgoing(r.outgoing);
      return r;
    },
    dm_accept: async ({ peer }) => { requireUnlocked(); const r = await core.call('dm.accept', { peer }); await sendOutgoing(r.outgoing); return r; },
    dm_decline: async ({ peer }) => { requireUnlocked(); const r = await core.call('dm.decline', { peer }); await sendOutgoing(r.outgoing); return r; },
    dm_send: async ({ to, text }) => { requireUnlocked(); const r = await core.call('dm.send', { to, text }); await sendOutgoing(r.outgoing); return r; },
  };

  let boundPort = 0;
  const allowedHosts = () => new Set([`127.0.0.1:${boundPort}`, `localhost:${boundPort}`]);
  const allowedOrigins = () => new Set([`http://127.0.0.1:${boundPort}`, `http://localhost:${boundPort}`]);
  const tokenOk = (t) => typeof t === 'string' && t.length === token.length && timingSafeEqual(Buffer.from(t), Buffer.from(token));

  const http = createServer(async (req, res) => {
    
    try {
      // keep this in the try, a bad path like percent zz makes decodeuricomponent throw, should 404 not crash
      const url = new URL(req.url, `http://${req.headers.host}`);
      const rel = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).replace(/^\/+/, '');
      const file = normalize(join(webDir, rel));
      if (!file.startsWith(normalize(webDir + sep)) || req.method !== 'GET') { res.writeHead(404).end(); return; }
      const body = await readFile(file);
      res.writeHead(200, {
        'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream',
        'Content-Security-Policy': `default-src 'self'; connect-src ws://${req.headers.host}; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`,
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
      });
      res.end(body);
    } catch {
      res.writeHead(404).end();
    }
  });

  const wss = new WebSocketServer({ noServer: true, maxPayload: 1 << 20 });
  http.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://x');
    const origin = req.headers.origin;
    if (url.pathname !== '/ws' || !allowedHosts().has(req.headers.host) || (origin && !allowedOrigins().has(origin)) ||
        !tokenOk(url.searchParams.get('token'))) {
      socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      uis.add(ws);
      ws.on('error', (e) => log(`ui connection error: ${e.message}`));
      ws.on('close', () => uis.delete(ws));
      ws.on('message', async (data) => {
        let msg;
        try {
          msg = JSON.parse(data.toString());
          const fn = methods[msg?.method];
          if (!fn) throw new Error(`unknown method: ${msg?.method}`);
          const result = await serial(() => fn(msg.params ?? {}));
          ws.send(JSON.stringify({ id: msg.id, ok: true, result }));
          if (MUTATING.has(msg.method)) push({ event: 'changed', method: msg.method, conv: convOf(msg.method, msg.params ?? {}) });
        } catch (e) {
          ws.send(JSON.stringify({ id: msg?.id ?? null, ok: false, error: e.message }));
        }
      });
    });
  });

  http.listen(port, '127.0.0.1');
  await once(http, 'listening');
  boundPort = http.address().port;
  const url = `http://127.0.0.1:${boundPort}/?token=${token}`;
  log(`bridge for ${user} at ${url}`);

  return {
    port: boundPort,
    token,
    url,
    async close() {
      link?.stop();
      for (const ws of uis) ws.terminate();
      wss.close();
      await new Promise((resolve) => http.close(resolve));
      await queue.catch(() => {});
      await core.close();
    },
  };
}
