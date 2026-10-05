// main chat screen, every pane re renders from the store

import { h, mount, box } from './dom.js';
import { Store } from './store.js';
import { renderRooms } from './panes/rooms.js';
import { Palette } from './palette.js';
import { renderChat, chatStatus } from './panes/chat.js';
import { InputLine, mountInput } from './panes/input.js';
import { renderInfo, infoTitle } from './panes/info.js';
import { openVerify } from './verify.js';
import { openShortcuts } from './shortcuts.js';

// these mean contacts or sessions changed, so re read the summary
const REFRESH_ON = new Set(['changed', 'dm_request', 'dm_accepted', 'dm_declined', 'key_changed']);

export class App {
  constructor(root, bridge) {
    this.root = root;
    this.bridge = bridge;
    this.store = new Store();
  }

  // subscribe before reading the summary and buffer events till ready, so nothing pushed in between gets lost
  async start() {
    const early = [];
    let ready = false;
    this.bridge.on('*', (e) => { if (ready) this.onEvent(e); else early.push(e); });
    this.store.applySummary(await this.bridge.call('summary'));
    this.build();
    this.input = new InputLine((text, conv) => this.send(text, conv));
    this.store.subscribe(() => this.render());
    this.palette = new Palette(this.root);
    this.registerCommands();
    ready = true;
    for (const e of early) await this.onEvent(e);
    this.render();
  }

  async refresh() {
    this.store.applySummary(await this.bridge.call('summary'));
    // keys may have changed, so drop cached safety numbers
    this.safety.clear();
    this.store.notify();
  }

  async onEvent(e) {
    const s = this.store;
    switch (e.event) {
      case 'status':
        s.connected = !!e.connected;
        if (e.connected) { s.notice = ''; await this.refresh(); } else { s.online.clear(); s.notify(); }
        return;
      case 'problem':
        s.notice = e.message;
        s.notify();
        return;
      // a forged, replayed or broken message got refused
      case 'rejected':
        s.notice = e.from ? `a message from @${e.from} was rejected: ${e.reason}` : `a message was rejected: ${e.reason}`;
        s.notify();
        return;
      case 'presence':
        if (Array.isArray(e.online)) s.online = new Set(e.online);
        else if (e.online) s.online.add(e.user);
        else s.online.delete(e.user);
        s.notify();
        return;
      case 'message':
        s.bumpUnread(e.conv);
        await this.reloadHistory(e.conv);
        return;
      case 'delivered':
        await this.reloadHistory(e.conv);
        return;
      default:
        if (REFRESH_ON.has(e.event)) {
          await this.refresh();
          if (e.conv) await this.reloadHistory(e.conv);
        }
    }
  }

  registerCommands() {
    const s = this.store, b = this.bridge;
    this.palette.addProvider(() => {
      const out = [];
      for (const d of s.dms.values()) {
        if (d.state !== 'pending_in') continue;
        out.push({ group: 'actions', label: `accept request from @${d.peer}`, run: () => this.act('dm_accept', { peer: d.peer }, d.conv) });
        out.push({ group: 'actions', label: `decline request from @${d.peer}`, run: () => this.act('dm_decline', { peer: d.peer }) });
      }
      out.push({ group: 'actions', label: 'keyboard shortcuts', run: () => openShortcuts(this) });
      for (const c of s.contacts.values()) {
        if (c.trust === 'changed') out.push({ group: 'actions', label: `review new key for @${c.user}`, hint: 'key changed', run: () => this.openVerify(c.user) });
        else out.push({ group: 'actions', label: `verify @${c.user}`, hint: c.trust === 'verified' ? 'verified' : 'compare safety numbers', run: () => this.openVerify(c.user) });
      }
      for (const r of s.rooms()) out.push({ group: 'rooms', label: r.title, hint: 'direct', run: () => this.select(r.conv) });
      return out;
    });
    this.palette.addProvider(async () => {
      const users = await b.call('users');
      return users.filter((u) => !s.dms.has(u.user) || s.dms.get(u.user).state === 'closed').map((u) => ({
        group: 'people', label: `message @${u.user}`, hint: u.online ? 'online' : 'offline',
        run: () => this.act('dm_request', { to: u.user }, `dm:${u.user}`),
      }));
    });
  }

  // rooms we never loaded and arent open just get a re render, no fetch
  async reloadHistory(conv) {
    if (!conv) return;
    if (conv !== this.store.selected && !this.store.history.has(conv)) { this.store.notify(); return; }
    const { entries } = await this.bridge.call('history', { conv });
    this.store.history.set(conv, entries);
    this.store.notify();
  }

  // peer -> safety number digits, null while loading
  safety = new Map();

  async loadSafety(peer) {
    this.safety.set(peer, null);
    try {
      const sn = await this.bridge.call('safety_number', { user: peer });
      this.safety.set(peer, sn.digits);
    } catch {
      this.safety.delete(peer);
    }
    this.store.notify();
  }

  openVerify(user) { return openVerify(this, user); }

  async select(conv) {
    this.store.select(conv);
    await this.reloadHistory(conv);
    this.input.focus();
  }

  async send(text, conv) {
    const room = this.store.conversation(conv);
    if (!room) throw new Error('that conversation no longer exists');
    await this.bridge.call('dm_send', { to: room.peer, text });
    await this.reloadHistory(room.conv);
  }

  async act(method, params, openConv) {
    const result = await this.bridge.call(method, params);
    await this.refresh();
    if (openConv && this.store.conversation(openConv)) await this.select(openConv);
    else if (this.store.selected) await this.reloadHistory(this.store.selected);
    return result;
  }

  build() {
    this.el = {
      rooms: h('div', { class: 'rooms-list', id: 'rooms-list' }),
      chatBody: h('div', { class: 'chat-body', id: 'chat-body' }),
      info: h('div', { class: 'info-body', id: 'info-body' }),
      input: h('div', { class: 'input-body', id: 'input-body' }),
    };
    this.boxes = {
      rooms: box({ title: 'rooms', cls: 'area-rm', id: 'rooms' }, this.el.rooms),
      chat: box({ title: 'tin can v2', cls: 'area-tl', id: 'chat', focus: true }, this.el.chatBody),
      info: box({ title: 'me', cls: 'area-in', id: 'info' }, this.el.info),
      input: box({ title: 'message', cls: 'area-ip', id: 'input', right: 'ctrl+k' }, this.el.input),
    };
    mount(this.root, h('main', { class: 'grid', id: 'main' }, ...Object.values(this.boxes)));
  }

  setRight(boxEl, status) {
    let rb = boxEl.querySelector(':scope > .rb');
    if (!status) { rb?.remove(); return; }
    if (!rb) { rb = h('span', { class: 'rb' }); boxEl.querySelector(':scope > .lb').after(rb); }
    rb.textContent = status.text;
    rb.className = `rb ${status.cls ?? ''}`.trim();
  }

  setTitle(boxEl, title) { boxEl.querySelector(':scope > .lb').textContent = title; boxEl.setAttribute('aria-label', title); }

  // only rebuild a pane if its data changed, otherwise we swap the element under the mouse and eat clicks
  changed(pane, data) {
    const sig = JSON.stringify(data);
    if (this.sigs?.[pane] === sig) return false;
    (this.sigs ??= {})[pane] = sig;
    return true;
  }

  render() {
    const s = this.store;
    const room = s.conversation(s.selected);
    if (this.changed('rooms', [s.rooms(), s.selected, [...s.unread], [...s.online].sort(), s.connected, s.notice, [...s.contacts.values()].map((c) => [c.user, c.trust])])) {
      renderRooms(this.el.rooms, s, (conv) => this.select(conv));
    }
    this.setTitle(this.boxes.chat, room ? room.title : 'tin can v2');
    this.setRight(this.boxes.chat, room ? chatStatus(room, s) : null);
    const entries = room ? s.history.get(room.conv) ?? [] : null;
    if (!this.changed('chat', [room, entries, room ? s.trustOf(room.peer) : null,
                               room ? [...new Set(entries.map((e) => e.from).filter(Boolean))].map((u) => s.trustOf(u)) : null])) {
      // nothing to do for the chat body
    } else if (!room) mount(this.el.chatBody, h('div', { class: 'faint', id: 'chat-empty' }, 'press ctrl+k to start a conversation'));
    else renderChat(this.el.chatBody, room, entries, s, {
      accept: (peer) => this.act('dm_accept', { peer }, `dm:${peer}`),
      decline: (peer) => this.act('dm_decline', { peer }),
      verify: (peer) => this.openVerify(peer),
    });
    this.setTitle(this.boxes.info, infoTitle(room));
    const safety = room ? this.safety.get(room.peer) : null;
    const infoData = [room, s.me, s.fingerprint, safety, room ? [...s.contacts.values()].map((c) => [c.user, c.trust, c.fingerprint]) : null];
    if (this.changed('info', infoData)) renderInfo(this.el.info, room, s, { safety, onVerify: (u) => this.openVerify(u) });
    if (room && !this.safety.has(room.peer)) this.loadSafety(room.peer);
    mountInput(this.el.input, this.input);
    this.input.update(room, s);
  }
}
