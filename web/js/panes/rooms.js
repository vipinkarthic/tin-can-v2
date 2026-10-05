import { h, mount } from '../dom.js';
import { TRUST_GLYPH } from '../store.js';

export function renderRooms(el, store, onSelect) {
  const dms = store.rooms();
  const item = (room, label, extras) => h('button', {
    type: 'button',
    class: `it ${room.conv === store.selected ? 'on' : ''} ${store.unread.get(room.conv) ? 'unread' : ''}`.trim(),
    dataset: { conv: room.conv },
    'aria-current': room.conv === store.selected ? 'true' : null,
    on: { click: () => onSelect(room.conv) },
  }, label, extras);

  const unread = (conv) => {
    const n = store.unread.get(conv);
    return n ? h('span', { class: 'count' }, ` (${n})`) : null;
  };

  const dmItems = dms.map((d) => {
    const online = store.online.has(d.peer);
    const [glyph, cls] = TRUST_GLYPH[store.trustOf(d.peer)] ?? ['?', 'bad'];
    const state = d.state === 'pending_in' ? h('span', { class: 'tag warn' }, ' request')
      : d.state === 'pending_out' ? h('span', { class: 'tag faint' }, ' pending')
      : d.state === 'closed' ? h('span', { class: 'tag faint' }, ' closed') : null;
    return item(d, [
      h('span', { class: `dot ${online ? 'online' : ''}`, title: online ? 'online' : 'offline' }, online ? '●' : '○'),
      ` @${d.peer}`,
    ], [unread(d.conv), ' ', h('span', { class: `trust ${cls}`, title: store.trustOf(d.peer) ?? 'unknown' }, glyph), state]);
  });

  mount(el,
    h('div', { class: 'h' }, 'direct'),
    dmItems.length ? dmItems : h('div', { class: 'empty faint' }, 'none yet'),
    store.notice ? h('div', { class: 'notice warn', id: 'notice', role: 'alert' }, `! ${store.notice}`) : null,
    h('div', { class: store.notice ? 'conn after-notice' : 'conn' }, store.connected
      ? h('span', { class: 'ok', id: 'conn' }, '● connected')
      : h('span', { class: 'bad', id: 'conn' }, '○ offline - reconnecting')));
}
