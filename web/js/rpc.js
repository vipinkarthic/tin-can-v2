// token comes in the url query, we move it to sessionstorage and strip the url so its not in history or copied links

const TOKEN_KEY = 'pqs-token';

export function takeToken() {
  const url = new URL(location.href);
  const fromUrl = url.searchParams.get('token');
  if (fromUrl) {
    // sessionstorage can throw in private mode or with blocked storage
    try { sessionStorage.setItem(TOKEN_KEY, fromUrl); } catch {}
    url.searchParams.delete('token');
    history.replaceState(null, '', url.pathname + url.search + url.hash);
    return fromUrl;
  }
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

export class Bridge {
  #ws;
  #next = 1;
  #waiting = new Map();
  #handlers = new Map();
  onclose = () => {};

  static connect(token) {
    return new Promise((resolve, reject) => {
      const b = new Bridge();
      // relative to the page so it also works behind the hosted gateway, wss when the page is https
      const target = new URL('ws', location.href);
      target.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      target.search = `?token=${encodeURIComponent(token ?? '')}`;
      const ws = new WebSocket(target);
      b.#ws = ws;
      let opened = false;
      ws.addEventListener('open', () => { opened = true; resolve(b); });
      ws.addEventListener('message', (e) => b.#onMessage(JSON.parse(e.data)));
      ws.addEventListener('close', () => {
        for (const w of b.#waiting.values()) w.reject(new Error('lost connection to the bridge'));
        b.#waiting.clear();
        if (opened) b.onclose(); else reject(new Error('the bridge refused this link'));
      });
    });
  }

  call(method, params = {}) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#waiting.set(id, { resolve, reject });
      this.#ws.send(JSON.stringify({ id, method, params }));
    });
  }

  // star gets every event, returns an unsubscribe fn
  on(event, fn) {
    if (!this.#handlers.has(event)) this.#handlers.set(event, []);
    this.#handlers.get(event).push(fn);
    return () => {
      const list = this.#handlers.get(event);
      const i = list.indexOf(fn);
      if (i >= 0) list.splice(i, 1);
    };
  }

  #onMessage(m) {
    if (m.event) {
      for (const fn of [...(this.#handlers.get(m.event) ?? []), ...(this.#handlers.get('*') ?? [])]) fn(m);
      return;
    }
    const w = this.#waiting.get(m.id);
    if (!w) return;
    this.#waiting.delete(m.id);
    if (m.ok) w.resolve(m.result);
    else w.reject(new Error(m.error));
  }
}
