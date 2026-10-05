import { h, keyButton } from './dom.js';
import { openModal } from './modal.js';

const ROWS = [
  ['ctrl+k', 'command palette: message someone, verify, switch rooms, …'],
  ['enter', 'send (in the message line) · go back to the message line'],
  ['esc', 'leave the message line, close a dialog or the palette'],
  ['↑ ↓', 'move in the palette'],
  ['a / d', 'accept / decline the open message request'],
  ['v', 'verify the open conversation (or review a changed key)'],
  ['y / n', 'confirm / cancel in the verify dialog'],
];

export function openShortcuts(app) {
  const modal = openModal(app.root, { title: 'keyboard shortcuts', id: 'shortcuts' },
    h('div', { class: 'dim' }, 'Single-letter keys work when you are not typing in a field; press esc to leave the message line.'),
    h('div', { class: 'shortcut-list', id: 'shortcut-list' }, ROWS.map(([k, what]) => h('div', { class: 'kv' }, h('span', { class: 'acc' }, k), h('span', {}, what)))),
    h('div', { class: 'actions verify-actions' }, keyButton('esc', 'close', () => modal.close(), { id: 'shortcuts-close', autofocus: true })));
  return modal;
}
