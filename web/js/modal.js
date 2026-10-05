import { h } from './dom.js';

export function openModal(root, { title, right, id, onClose }, ...body) {
  const restore = document.activeElement;
  const box = h('section', { class: 'box focus', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    h('span', { class: 'lb' }, title),
    right ? h('span', { class: 'rb' }, right) : null,
    h('div', { class: 'bc' }, ...body));
  const ov = h('div', { class: 'ov', id }, box);
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    ov.remove();
    document.removeEventListener('keydown', onKey, true);
    if (restore?.isConnected) restore.focus();
    onClose?.();
  };
  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); return; }
    if (e.key === 'Tab') {
      // firefox starts tab navigation from the last click, so we move focus ourselves or it escapes the dialog
      e.preventDefault();
      const f = [...box.querySelectorAll('button, input, [tabindex]:not([tabindex="-1"])')].filter((el) => !el.disabled);
      if (!f.length) return;
      const i = f.indexOf(document.activeElement);
      const next = i < 0 ? (e.shiftKey ? f.length - 1 : 0) : (i + (e.shiftKey ? f.length - 1 : 1)) % f.length;
      f[next].focus();
    }
  };
  ov.addEventListener('mousedown', (e) => { if (e.target === ov) close(); });
  document.addEventListener('keydown', onKey, true);
  root.append(ov);
  (box.querySelector('[autofocus]') ?? box.querySelector('button, input'))?.focus();
  return { close, box };
}
