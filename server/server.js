// never sees plaintext or private keys, only metadata, wire ops are listed in decisions doc f18

import { WebSocketServer } from 'ws';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { CoreProcess } from '../bridge/core.js';
import { Store } from './db.js';

const USERNAME = /^[a-z0-9_]{1,32}$/;
const DM_TYPES = new Set(['dm_request', 'dm_accept', 'dm_decline', 'dm_msg']);
const MAX_FRAME = 1 << 20;
const AUTH_TIMEOUT_MS = 30_000;

class ClientError extends Error {}

export async function startServer({ host = '127.0.0.1', port = 7777, dbPath, corePath, log = () => {} } = {}) {
  if (!dbPath) throw new Error('dbPath is required');
  const store = new Store(dbPath);
  const core = new CoreProcess({ corePath });
  await core.call('ping');

  // user -> conn, logged in users only
  const online = new Map();
  const wss = new WebSocketServer({ host, port, maxPayload: MAX_FRAME });
  await once(wss, 'listening');

  const send = (conn, msg) => {
    if (conn.ws.readyState === conn.ws.OPEN) conn.ws.send(JSON.stringify(msg));
  };
  const broadcastPresence = (user, isOnline) => {
    for (const other of online.values()) if (other.user !== user) send(other, { op: 'presence', user, online: isOnline });
  };

  // last sent is per connection, so a fresh login resends everything not acked yet
  const flush = (user) => {
    const conn = online.get(user);
    if (!conn) return;
    for (const m of store.pending(user, conn.lastSent)) {
      send(conn, { op: 'deliver', id: m.id, sender: m.sender, envelope: m.envelope, at: m.created });
      conn.lastSent = m.id;
    }
  };

  const welcome = (conn, user) => {
    const previous = online.get(user);
    if (previous && previous !== conn) {
      send(previous, { op: 'error', error: 'logged in from another connection' });
      previous.ws.close(4001, 'replaced');
    }
    clearTimeout(conn.authTimer);
    conn.user = user;
    conn.lastSent = 0;
    online.set(user, conn);
    send(conn, { op: 'welcome', user });
    send(conn, { op: 'presence', online: [...online.keys()].filter((u) => u !== user) });
    if (!previous) broadcastPresence(user, true);
    log(`login ${user}`);
    flush(user);
  };

  // sig is mldsa over the login v1 transcript of user and nonce, checked by the cpp core
  const checkLogin = async (user, sigPk, nonce, sig) => {
    if (typeof sig !== 'string') throw new ClientError('signature missing');
    const { valid } = await core.call('server.verify_login', { user, sig_pk: sigPk, challenge: nonce, sig });
    if (!valid) throw new ClientError('login signature is invalid');
  };

  // always exactly one recipient, and from has to be the sender so nobody can spoof
  const route = (sender, env) => {
    if (!env || typeof env !== 'object' || typeof env.type !== 'string') throw new ClientError('envelope must be an object with a type');
    if (DM_TYPES.has(env.type)) {
      if (env.from !== sender) throw new ClientError('envelope "from" must be your own username');
      if (typeof env.to !== 'string' || env.to === sender || !store.getUser(env.to)) throw new ClientError('unknown recipient');
      return env.to;
    }
    throw new ClientError(`unknown envelope type: ${env.type}`);
  };

  const handle = async (conn, msg) => {
    const { op } = msg;
    if (!conn.user) {
      if (op === 'hello') {
        if (typeof msg.user !== 'string' || !USERNAME.test(msg.user)) throw new ClientError('invalid username');
        conn.pendingUser = msg.user;
        conn.nonce = randomBytes(32).toString('base64');
        send(conn, { op: 'challenge', nonce: conn.nonce, registered: !!store.getUser(msg.user) });
        return;
      }
      if (op === 'register' || op === 'login') {
        const user = conn.pendingUser, nonce = conn.nonce;
        // single use challenge, wiped before the check so a failed try cant reuse it

        if (!user || !nonce) throw new ClientError('say hello first');
        const existing = store.getUser(user);
        if (op === 'login') {
          if (!existing) throw new ClientError('unknown user; register first');
          await checkLogin(user, existing.sig_pk, nonce, msg.sig);
        } else {
          let verified;
          try {
            verified = await core.call('server.verify_bundle', { bundle: msg.bundle });
          } catch (e) {
            throw new ClientError(`invalid bundle: ${e.message}`);
          }
          if (verified.user !== user) throw new ClientError('bundle is for a different username');
          
          await checkLogin(user, verified.sig_pk, nonce, msg.sig);
          if (!existing) store.addUser(user, verified.sig_pk, msg.bundle);
        }
        welcome(conn, user);
        return;
      }
      throw new ClientError('log in first');
    }

    switch (op) {
      case 'get_bundle': {
        const u = typeof msg.user === 'string' ? store.getUser(msg.user) : null;
        send(conn, { op: 'result', rid: msg.rid, bundle: u ? JSON.parse(u.bundle) : null });
        return;
      }
      case 'list_users':
        send(conn, { op: 'result', rid: msg.rid, users: store.listUsers().map((u) => ({ user: u, online: online.has(u) })) });
        return;
      case 'send': {
        const recipient = route(conn.user, msg.envelope);
        store.queue(recipient, conn.user, msg.envelope);
        send(conn, { op: 'result', rid: msg.rid, recipient });
        flush(recipient);
        return;
      }
      case 'ack':
        if (Number.isSafeInteger(msg.id)) store.ack(conn.user, msg.id);
        return;
      default:
        throw new ClientError(`unknown op: ${op}`);
    }
  };

  wss.on('connection', (ws) => {
    const conn = { ws, user: null, pendingUser: null, nonce: null, lastSent: 0, chain: Promise.resolve() };
    conn.authTimer = setTimeout(() => { if (!conn.user) ws.close(4000, 'login timeout'); }, AUTH_TIMEOUT_MS);
    // without this one bad socket, like an oversized frame, throws uncaught and kills the server, ws closes it itself
    ws.on('error', (e) => log(`connection error: ${e.message}`));
    ws.on('message', (data) => {
      // chain per connection so its messages run strictly in order
      conn.chain = conn.chain.then(async () => {
        let msg;
        try {
          msg = JSON.parse(data.toString());
          if (!msg || typeof msg !== 'object') throw new ClientError('messages must be JSON objects');
          await handle(conn, msg);
        } catch (e) {
          const error = e instanceof ClientError ? e.message : 'invalid request';
          if (!(e instanceof ClientError)) log(`error: ${e.message}`);
          send(conn, { op: 'error', rid: msg?.rid, error });
        }
      });
    });
    ws.on('close', () => {
      clearTimeout(conn.authTimer);
      if (conn.user && online.get(conn.user) === conn) {
        online.delete(conn.user);
        broadcastPresence(conn.user, false);
        log(`logout ${conn.user}`);
      }
    });
  });

  return {
    port: wss.address().port,
    store,
    async close() {
      for (const c of online.values()) c.ws.terminate();
      for (const ws of wss.clients) ws.terminate();
      await new Promise((resolve) => wss.close(resolve));
      await core.close();
      store.close();
    },
  };
}
