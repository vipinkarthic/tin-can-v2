// text always goes in as text nodes, never html, so peer names and messages cant inject markup

export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === 'style') throw new Error('inline styles are not allowed (CSP); use a class');
    // non string props like disabled, value, readonly are set as properties
    else if (k in el && typeof v !== 'string') el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function mount(el, ...children) {
  el.replaceChildren();
  append(el, children);
}

// title and the optional right label sit cut into the top border
export function box({ title, right, focus = false, cls = '', id }, ...body) {
  return h('section', { class: `box ${focus ? 'focus' : ''} ${cls}`.trim(), id, 'aria-label': title },
    h('span', { class: 'lb' }, title),
    right ? h('span', { class: 'rb' }, right) : null,
    h('div', { class: 'bc' }, ...body));
}

// the key shown in brackets is the real shortcut, install hotkeys clicks it, so a shown key cant be dead
export function keyButton(key, label, onClick, props = {}) {
  return h('button', { type: 'button', class: 'key', dataset: { hotkey: key }, on: { click: onClick }, ...props },
    h('span', { class: 'k' }, `[${key}]`), ` ${label}`);
}

const isTyping = (el) => el instanceof HTMLElement && !el.disabled && (el.matches('input, textarea') || el.isContentEditable);

// single keys only fire outside text fields, and only the top dialogs keys while one is open
// esc in a field with no dialog blurs it, enter outside any field jumps back to the message line
export function installHotkeys({ focusInput } = {}) {
  document.addEventListener('keydown', (e) => {
    if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || e.isComposing) return;
    const overlay = [...document.querySelectorAll('.ov')].pop() ?? null;
    const typing = isTyping(e.target);
    if (typing) {
      if (e.key === 'Escape' && !overlay) { e.preventDefault(); e.target.blur(); }
      return;
    }
    let key = e.key === 'Escape' ? 'esc' : e.key === 'Enter' ? '⏎' : e.key.toLowerCase();
    // enter on a focused button should press that button, not a hotkey
    if (key === '⏎' && e.target instanceof HTMLButtonElement) return;
    const scope = overlay ?? document.getElementById('app');
    const button = [...scope.querySelectorAll('button[data-hotkey]')]
      .find((b) => b.dataset.hotkey === key && !b.disabled && b.getClientRects().length > 0);
    if (button) { e.preventDefault(); button.click(); return; }
    if (key === '⏎' && !overlay && focusInput) { e.preventDefault(); focusInput(); }
  });
}
