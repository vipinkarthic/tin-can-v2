import { h, mount } from '../dom.js';

export const MAX_TEXT = 4000;

export function blockedReason(room, store) {
  if (!room) return 'select a conversation (ctrl+k to start one)';
  if (!store.connected) return 'offline - reconnecting to the server';
  if (store.trustOf(room.peer) === 'changed') return `@${room.peer}'s key changed - compare safety numbers first`;
  if (room.state === 'pending_in') return 'accept the request to reply';
  if (room.state === 'closed') return `conversation closed - ctrl+k -> "message @${room.peer}" to start a new one`;
  return null;
}

export class InputLine {
  constructor(onSend) {
    this.onSend = onSend;
    this.field = h('input', { class: 'msg-in', id: 'msg-input', type: 'text', autocomplete: 'off', spellcheck: 'true',
                              maxlength: String(MAX_TEXT + 1), 'aria-label': 'message' });
    this.error = h('div', { class: 'bad', id: 'msg-error', role: 'alert' });
    this.el = h('div', { class: 'input-line' }, h('div', { class: 'in-row' }, h('span', { class: 'acc' }, '›'), ' ', this.field), this.error);
    this.field.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); this.send(); }
    });
    this.field.addEventListener('input', () => { this.error.textContent = ''; });
  }

  update(room, store) {
    const reason = blockedReason(room, store);
    this.field.disabled = !!reason;
    this.field.placeholder = reason ?? `message ${room.title}`;
    if (room?.conv !== this.conv) {
      // switched rooms, clear the old error
      this.conv = room?.conv;
      this.error.textContent = '';
    }
  }

  // never steal focus from an open palette or dialog, a late action shouldnt yank the user out
  focus() {
    if (this.field.disabled || document.querySelector('.ov')) return;
    this.field.focus();
  }

  // clear the field at once and queue sends in order, a failed send puts its text back
  send() {
    const text = this.field.value;
    if (this.field.disabled || !text.trim()) return;
    if (text.length > MAX_TEXT) { this.error.textContent = `✗ message is too long (${text.length}/${MAX_TEXT} characters)`; return; }
    // grab the room now, the user might switch before its sent
    const conv = this.conv;
    this.field.value = '';
    this.error.textContent = '';
    this.queue = (this.queue ?? Promise.resolve()).then(async () => {
      try {
        await this.onSend(text, conv);
      } catch (e) {
        this.error.textContent = `✗ ${e.message}`;
        if (this.conv === conv) this.field.value = this.field.value ? `${text} ${this.field.value}` : text;
      }
    });
    return this.queue;
  }
}

export function mountInput(container, input) {
  if (input.el.parentNode !== container) mount(container, input.el);
}
