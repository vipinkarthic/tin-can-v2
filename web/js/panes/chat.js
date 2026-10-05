// author gutter layout, one block per run of messages from the same person

import { h, mount, keyButton } from '../dom.js';
import { TRUST_GLYPH } from '../store.js';

// colour by first appearance so 5 others get 5 different nick colours n0 to n4, yellow is only for me
const NICK_COLOURS = 5;

export function nickClasses(entries, me) {
  const order = new Map();
  for (const e of entries) if (e.kind === 'msg' && e.from !== me && !order.has(e.from)) order.set(e.from, order.size);
  return (user) => (user === me ? 'nick-me' : `nick-${(order.get(user) ?? 0) % NICK_COLOURS}`);
}

export function timeOf(ts) {
  const d = new Date(Number(ts));
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

export function chatStatus(room, store) {
  const trust = store.trustOf(room.peer);
  if (trust === 'changed') return { text: '✗ key changed', cls: 'bad' };
  if (trust === 'verified') return { text: '✓ verified · ml-kem-768' };
  return { text: '~ not verified · ml-kem-768' };
}

export function renderChat(el, room, entries, store, actions) {
  const me = store.me;
  const nickClass = nickClasses(entries, me);
  const blocks = [];

  if (room.state === 'pending_in') {
    blocks.push(h('div', { class: 'banner', id: 'request-banner', role: 'region', 'aria-label': 'message request' },
      h('div', {}, h('b', {}, `@${room.peer}`), ' wants to message you. You can read what they sent; reply after accepting.'),
      h('div', { class: 'actions' },
        keyButton('a', 'accept', () => actions.accept(room.peer), { id: 'request-accept' }),
        keyButton('d', 'decline', () => actions.decline(room.peer), { id: 'request-decline' }))));
  } else if (room.state === 'closed') {
    blocks.push(h('div', { class: 'ev', id: 'request-closed' }, '── this conversation is closed; its history is kept below'));
  } else if (room.state === 'pending_out') {
    blocks.push(h('div', { class: 'ev', id: 'request-waiting' }, `── waiting for @${room.peer} to accept your request`));
  }
  if (store.trustOf(room.peer) === 'changed') {
    blocks.push(h('div', { class: 'alert', id: 'key-alert', role: 'alert' },
      h('b', {}, `!! identity key changed for @${room.peer}`),
      h('div', {}, 'This can mean a new device - or someone in the middle. Sending is blocked until you decide.'),
      h('div', { class: 'actions' }, keyButton('v', 'compare safety numbers', () => actions.verify(room.peer), { id: 'key-alert-verify' }))));
  }

  // current author block
  let run = null;
  for (const e of entries) {
    if (e.kind === 'system') {
      run = null;
      const warn = /identity key changed/.test(e.text);
      blocks.push(h('div', { class: `ev ${warn ? 'warn' : ''}`.trim(), dataset: { kind: 'system' } }, `${warn ? '!!' : '──'} ${e.text}`));
      continue;
    }
    if (!run || run.from !== e.from) {
      const trust = e.from === me ? null : store.trustOf(e.from);
      const [glyph, cls] = trust ? TRUST_GLYPH[trust] : [null, null];
      run = { from: e.from, el: h('div', { class: `md ${nickClass(e.from)}`, dataset: { from: e.from } },
        h('div', { class: 'who' }, e.from, glyph ? h('span', { class: `trust ${cls}`, title: trust }, ` ${glyph}`) : null)) };
      blocks.push(run.el);
    }
    const mark = e.dir === 'out'
      ? h('span', { class: `rcpt ${e.status === 'delivered' ? 'ok' : 'faint'}`, title: e.status === 'delivered' ? 'delivered' : 'sent' },
          e.status === 'delivered' ? '✓' : '·')
      : null;
    run.el.append(h('div', { class: 'r', dataset: { mid: e.mid } },
      h('span', { class: 'txt' }, e.text),
      h('span', { class: 'ts' }, timeOf(e.ts), mark ? ' ' : null, mark)));
  }
  if (!entries.some((e) => e.kind === 'msg') && !blocks.some((b) => b.id)) {
    blocks.push(h('div', { class: 'faint', id: 'chat-nothing' }, 'no messages yet'));
  }

  // only stick to the bottom if the user was already there or just switched rooms
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24 || el.dataset.conv !== room.conv;
  const keep = el.scrollTop;
  mount(el, blocks);
  el.dataset.conv = room.conv;
  if (atBottom) el.scrollTop = el.scrollHeight;
  else el.scrollTop = keep;
}
