import { h, mount, keyButton } from '../dom.js';
import { TRUST_GLYPH } from '../store.js';

const TRUST_TEXT = { verified: 'verified', tofu: 'not verified', changed: 'key changed' };

function trustLine(trust) {
  const [glyph, cls] = TRUST_GLYPH[trust] ?? ['?', 'bad'];
  return h('span', { class: cls, id: 'info-trust' }, `${glyph} ${TRUST_TEXT[trust] ?? 'unknown'}`);
}

export function infoTitle(room) {
  return room ? 'session' : 'me';
}

export function renderInfo(el, room, store, { safety, onVerify }) {
  if (!room) {
    mount(el,
      h('div', { class: 'kv' }, h('span', {}, 'user'), h('span', { id: 'me-user' }, store.me)),
      h('div', { class: 'h' }, 'fingerprint'),
      h('div', { id: 'me-fp' }, store.fingerprint),
      h('div', { class: 'h' }, 'protection'),
      h('div', { class: 'dim' }, 'ML-KEM-768 key exchange, ML-DSA-65 signatures, XChaCha20-Poly1305 messages'));
    return;
  }

  const contact = store.contacts.get(room.peer);
  const trust = store.trustOf(room.peer);
  mount(el,
    h('div', { class: 'kv' }, h('span', {}, 'with'), h('span', { id: 'info-peer' }, `@${room.peer}`)),
    h('div', { class: 'kv' }, h('span', {}, 'state'), h('span', { id: 'info-state' },
      { active: 'active', pending_in: 'request', pending_out: 'waiting' }[room.state] ?? room.state)),
    h('div', { class: 'h' }, 'protection'),
    h('div', { class: 'kv' }, h('span', {}, 'kem'), h('span', {}, 'ml-kem-768')),
    h('div', { class: 'kv' }, h('span', {}, 'sig'), h('span', {}, 'ml-dsa-65')),
    h('div', { class: 'kv' }, h('span', {}, 'aead'), h('span', {}, 'xchacha20')),
    h('div', { class: 'kv' }, h('span', {}, 'sent / recv'), h('span', { id: 'info-counters' }, `#${room.send_n} / #${room.recv_n}`)),
    h('div', { class: 'h' }, 'their key'),
    h('div', { id: 'info-fp' }, contact?.fingerprint ?? ''),
    h('div', { class: 'h' }, 'safety number'),
    h('div', { id: 'info-safety', class: 'safety' }, safety ? [safety.slice(0, 2).join(' '), h('br'), safety.slice(2, 4).join(' '), h('br'), safety.slice(4, 6).join(' '), ' …'] : '…'),
    h('div', { class: 'trustrow' }, trustLine(trust)),
    h('div', { class: 'actions' }, keyButton('v', trust === 'changed' ? 'review new key' : trust === 'verified' ? 'show safety number' : 'verify', () => onVerify(room.peer), { id: 'info-verify' })));
}
