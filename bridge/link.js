// login means signing the servers challenge with the core, reconnects with backoff from 500ms up to 8s

import WebSocket from 'ws';
import { EventEmitter } from 'node:events';

export class ServerLink extends EventEmitter {
  #url;
  #core;
  #user;
  #ws = null;
  #nextRid = 1;
  #waiting = new Map();
  #stopped = false;
  #retryMs = 500;
  #timer = null;
  connected = false;

  // core needs an account already open, we sign logins and grab the bundle with it
  constructor({ url, core, user }) {
    super();
    this.#url = url;
    this.#core = core;
    this.#user = user;
  }

  start() {
    this.#stopped = false;
    this.#connect();
  }

  stop() {
    this.#stopped = true;
    clearTimeout(this.#timer);
    if (this.#ws) this.#ws.terminate();
    this.#setConnected(false);
  }

  request(msg, timeoutMs = 15_000) {
    if (!this.connected) return Promise.reject(new Error('not connected to the server'));
    const rid = this.#nextRid++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#waiting.delete(rid);
        reject(new Error('server did not answer in time'));
      }, timeoutMs);
      this.#waiting.set(rid, { resolve, reject, timer });
      this.#ws.send(JSON.stringify({ ...msg, rid }));
    });
  }

  ack(id) {
    if (this.connected) this.#ws.send(JSON.stringify({ op: 'ack', id }));
  }

  #setConnected(v) {
    if (this.connected === v) return;
    this.connected = v;
    this.emit('status', v);
  }

  #connect() {
    if (this.#stopped) return;
    const ws = new WebSocket(this.#url, { maxPayload: 1 << 20 });
    this.#ws = ws;
    ws.on('open', () => ws.send(JSON.stringify({ op: 'hello', user: this.#user })));
    ws.on('message', (data) => this.#onMessage(ws, data).catch((e) => this.emit('problem', e.message)));
    // empty on purpose, close always follows and does the retry
    ws.on('error', () => {});
    ws.on('close', (code) => {
      if (this.#ws !== ws) return;
      this.#setConnected(false);
      for (const { reject, timer } of this.#waiting.values()) {
        clearTimeout(timer);
        reject(new Error('connection to the server was lost'));
      }
      this.#waiting.clear();
      // 4001 -> logged in somewhere else, dont reconnect and fight over the session
      if (code === 4001) {
        this.emit('problem', 'this account logged in from somewhere else');
        return;
      }
      if (!this.#stopped) {
        this.#timer = setTimeout(() => this.#connect(), this.#retryMs);
        this.#retryMs = Math.min(this.#retryMs * 2, 8000);
      }
    });
  }

  async #onMessage(ws, data) {
    const msg = JSON.parse(data.toString());
    switch (msg.op) {
      case 'challenge': {
        const { sig } = await this.#core.call('auth.sign', { challenge: msg.nonce });
        if (msg.registered) ws.send(JSON.stringify({ op: 'login', sig }));
        else ws.send(JSON.stringify({ op: 'register', sig, bundle: (await this.#core.call('bundle')).bundle }));
        return;
      }
      case 'welcome':
        this.#retryMs = 500;
        this.#setConnected(true);
        return;
      case 'result':
      case 'error': {
        const w = this.#waiting.get(msg.rid);
        if (w) {
          this.#waiting.delete(msg.rid);
          clearTimeout(w.timer);
          if (msg.op === 'result') w.resolve(msg);
          else w.reject(new Error(msg.error));
        } else if (msg.op === 'error') {
          // error nobodys waiting on, like login refused
          this.emit('problem', msg.error);
        }
        return;
      }
      case 'deliver':
        this.emit('deliver', msg);
        return;
      case 'presence':
        this.emit('presence', msg);
        return;
      default:
        return;
    }
  }
}
