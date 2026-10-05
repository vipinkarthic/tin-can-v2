// commands come from providers, each gives entries with a group of actions, rooms or people, a label, an optional hint and run

import { h, mount } from './dom.js';

const GROUP_ORDER = ['actions', 'rooms', 'people'];

// subsequence match, null means no match, lower wins, prefix matches can go negative
export function fuzzy(query, label) {
  const q = query.toLowerCase().replace(/\s+/g, ''), l = label.toLowerCase();
  if (!q) return 0;
  let pos = -1, score = 0;
  for (const ch of q) {
    const next = l.indexOf(ch, pos + 1);
    if (next < 0) return null;
    score += next - pos - 1;
    pos = next;
  }
  return score + (l.replace(/\s+/g, '').startsWith(q) ? -100 : 0);
}

export class Palette {
  #providers = [];
  #items = [];
  #index = 0;
  #el = null;
  #input = null;
  #list = null;
  #restoreFocus = null;
  #error = null;

  constructor(root) {
    this.root = root;
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (this.isOpen) this.close(); else this.open();
      } else if (e.key === 'Escape' && this.isOpen) {
        // esc closes it wherever focus is, not just in the input
        e.preventDefault();
        this.close();
      }
    });
  }

  get isOpen() { return !!this.#el; }

  addProvider(fn) { this.#providers.push(fn); }

  async open(initial = '') {
    if (this.isOpen) return;
    this.#restoreFocus = document.activeElement;
    this.#input = h('input', { class: 'pal-q', id: 'palette-input', 'aria-label': 'command', autocomplete: 'off', spellcheck: 'false',
                               role: 'combobox', 'aria-controls': 'palette-list', 'aria-expanded': 'true', value: initial });
    this.#list = h('div', { class: 'pal-list', id: 'palette-list', role: 'listbox' });
    this.#error = h('div', { class: 'bad', id: 'palette-error', role: 'alert' });
    this.#el = h('div', { class: 'ov', id: 'palette', on: { mousedown: (e) => { if (e.target === this.#el) this.close(); } } },
      h('section', { class: 'box focus pal', 'aria-label': 'command palette' },
        h('span', { class: 'lb' }, 'command palette'),
        h('span', { class: 'rb' }, 'ctrl+k'),
        h('div', { class: 'bc' },
          h('div', { class: 'pal-qrow' }, h('span', { class: 'acc' }, '›'), ' ', this.#input),
          this.#list,
          this.#error,
          h('div', { class: 'pal-foot faint' }, '↑↓ move · ⏎ run · esc close'))));
    this.#input.addEventListener('input', () => { this.#index = 0; this.#render(); });
    this.#input.addEventListener('keydown', (e) => this.#onKey(e));
    this.root.append(this.#el);
    this.#input.focus();
    await this.#load();
  }

  close() {
    if (!this.isOpen) return;
    this.#el.remove();
    this.#el = null;
    if (this.#restoreFocus?.isConnected) this.#restoreFocus.focus();
  }

  async #load() {
    const lists = await Promise.all(this.#providers.map(async (p) => { try { return await p(); } catch { return []; } }));
    if (!this.isOpen) return;
    this.#all = lists.flat();
    this.#render();
  }

  #all = [];

  #render() {
    const q = this.#input.value;
    // group with the best match goes first, then by score, only labels are searched not hints
    const scored = this.#all.map((c) => ({ c, score: fuzzy(q, c.label) })).filter((x) => x.score !== null);
    const best = new Map();
    for (const x of scored) best.set(x.c.group, Math.min(best.get(x.c.group) ?? Infinity, x.score));
    const rank = (g) => [best.get(g), GROUP_ORDER.indexOf(g)];
    this.#items = scored
      .sort((a, b) => {
        const [ba, oa] = rank(a.c.group), [bb, ob] = rank(b.c.group);
        return ba - bb || oa - ob || a.score - b.score;
      })
      .map((x) => x.c);
    if (this.#index >= this.#items.length) this.#index = Math.max(0, this.#items.length - 1);
    const rows = [];
    let lastGroup = null;
    this.#items.forEach((c, i) => {
      if (c.group !== lastGroup) { rows.push(h('div', { class: 'h' }, c.group)); lastGroup = c.group; }
      rows.push(h('div', {
        class: `r ${i === this.#index ? 'on' : ''}`.trim(), role: 'option', id: `pal-item-${i}`,
        'aria-selected': i === this.#index ? 'true' : 'false',
        on: { mousemove: () => { if (this.#index !== i) { this.#index = i; this.#render(); } }, click: () => this.#run(i) },
      }, h('span', { class: 'pl' }, c.label), h('span', { class: 'sp' }), c.hint ? h('span', { class: 'faint' }, c.hint) : null));
    });
    if (!rows.length) rows.push(h('div', { class: 'faint empty', id: 'palette-empty' }, 'no matches'));
    mount(this.#list, rows);
    this.#input.setAttribute('aria-activedescendant', this.#items.length ? `pal-item-${this.#index}` : '');
    this.#list.querySelector('.r.on')?.scrollIntoView({ block: 'nearest' });
  }

  #onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); this.close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); if (this.#items.length) { this.#index = (this.#index + 1) % this.#items.length; this.#render(); } }
    else if (e.key === 'ArrowUp') { e.preventDefault(); if (this.#items.length) { this.#index = (this.#index - 1 + this.#items.length) % this.#items.length; this.#render(); } }
    else if (e.key === 'Enter') { e.preventDefault(); this.#run(this.#index); }
    // single field, so dont let tab wander behind the overlay
    else if (e.key === 'Tab') e.preventDefault();
  }

  async #run(i) {
    const c = this.#items[i];
    if (!c) return;
    this.#error.textContent = '';
    try {
      this.close();
      await c.run();
    } catch (err) {
      // reopen so the error is actually visible
      await this.open(this.#input?.value ?? '');
      this.#error.textContent = `✗ ${err.message}`;
    }
  }
}
