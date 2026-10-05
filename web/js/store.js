// single source of truth, panes never keep their own copy

export const TRUST_GLYPH = { verified: ['✓', 'ok'], tofu: ['~', 'warn'], changed: ['✗', 'bad'] };

export class Store {
  me = '';
  fingerprint = '';
  connected = false;
  // problem to show the user, like logged in from somewhere else
  notice = '';
  // user -> trust, fingerprint, session
  contacts = new Map();
  // peer -> conv, state, trust, send n, recv n
  dms = new Map();
  online = new Set();
  // conv -> count
  unread = new Map();
  // conv -> entries, loaded lazily
  history = new Map();
  // conv id like dm bob
  selected = null;
  #listeners = new Set();

  subscribe(fn) { this.#listeners.add(fn); return () => this.#listeners.delete(fn); }
  notify() { for (const fn of this.#listeners) fn(); }

  applySummary(s) {
    this.me = s.user;
    this.fingerprint = s.fingerprint;
    if (typeof s.connected === 'boolean') this.connected = s.connected;
    this.contacts = new Map((s.contacts ?? []).map((c) => [c.user, c]));
    this.dms = new Map((s.dms ?? []).map((d) => [d.peer, d]));
    if (Array.isArray(s.online)) this.online = new Set(s.online);
    if (this.selected && !this.conversation(this.selected)) this.selected = null;
  }

  trustOf(user) { return this.contacts.get(user)?.trust ?? null; }

  // only dm ids exist for now, anything else gives null
  conversation(conv) {
    if (!conv?.startsWith('dm:')) return null;
    const peer = conv.slice(3), d = this.dms.get(peer);
    return d ? { conv, peer, title: `@${peer}`, ...d } : null;
  }

  rooms() {
    return [...this.dms.values()].sort((a, b) => a.peer.localeCompare(b.peer)).map((d) => this.conversation(d.conv));
  }

  select(conv) {
    this.selected = conv;
    this.unread.delete(conv);
    this.notify();
  }

  bumpUnread(conv) {
    if (conv === this.selected) return;
    this.unread.set(conv, (this.unread.get(conv) ?? 0) + 1);
  }
}
