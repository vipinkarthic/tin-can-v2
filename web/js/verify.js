// both sides see the same 60 digits only if nobody swapped a key, comparing them is what verified means

import { h, keyButton } from './dom.js';
import { openModal } from './modal.js';

export async function openVerify(app, user) {
  const sn = await app.bridge.call('safety_number', { user });
  const changed = sn.pending_change;
  const error = h('div', { class: 'bad', id: 'verify-error', role: 'alert' });

  const run = async (method, after) => {
    error.textContent = '';
    try {
      await app.bridge.call(method, { user });
      // close right away, dont leave the dialog up while we refresh
      modal.close();
      await app.refresh();
      if (app.store.selected) await app.reloadHistory(app.store.selected);
      after?.();
    } catch (e) {
      error.textContent = `✗ ${e.message}`;
    }
  };

  const actions = changed
    ? [keyButton('y', 'accept the new key', () => run('accept_key_change'), { id: 'verify-accept', autofocus: true }),
       keyButton('n', 'not now', () => modal.close(), { id: 'verify-cancel' })]
    : sn.trust === 'verified'
      ? [keyButton('⏎', 'close', () => modal.close(), { id: 'verify-cancel', autofocus: true })]
      : [keyButton('y', 'mark verified', () => run('verify'), { id: 'verify-confirm', autofocus: true }),
         keyButton('n', 'cancel', () => modal.close(), { id: 'verify-cancel' })];

  const modal = openModal(app.root, { title: `verify @${user}`, right: 'ml-dsa-65', id: 'verify' },
    changed
      ? h('div', { class: 'bad', id: 'verify-warning' }, `@${user} has a NEW identity key. If you did not expect this, someone may be in the middle. Compare the new numbers before accepting.`)
      : h('div', { class: 'dim' }, `Compare these numbers with @${user} in person or on a call. If they match, nobody is in the middle.`),
    h('div', { class: 'sn', id: 'verify-digits' }, sn.digits.map((d) => h('span', {}, d))),
    h('div', { class: 'lab' }, 'fingerprints'),
    h('div', { class: 'faint', id: 'verify-fps' }, `you   ${sn.fingerprint_me}`, h('br'), `@${user}  ${sn.fingerprint_them}`),
    sn.trust === 'verified' ? h('div', { class: 'ok', id: 'verify-done' }, '✓ you already verified this contact') : null,
    h('div', { class: 'actions verify-actions' }, actions),
    error);

  return modal;
}
