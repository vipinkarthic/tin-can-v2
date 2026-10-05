import { h, mount, box, keyButton } from './dom.js';

const LOGO = [
  ' ╺┳╸╻┏┓╻ ┏━╸┏━┓┏┓╻ ╻ ╻┏━┓',
  '  ┃ ┃┃┗┫ ┃  ┣━┫┃┗┫ ┃┏┛┏━┛',
  '  ╹ ╹╹ ╹ ┗━╸╹ ╹╹ ╹ ┗┛ ┗━╸',
].join('\n');

const MIN_PASSPHRASE = 8;

// only resolves once were unlocked and the server connection is up
export function showLogin(root, bridge, status) {
  return new Promise((resolve) => {
    const creating = !status.account_exists;
    const log = h('div', { class: 'log', role: 'status', 'aria-live': 'polite' });
    const say = (text, cls = '') => log.append(h('div', { class: `line ${cls}`.trim() }, text));
    const error = h('div', { class: 'bad', id: 'login-error', role: 'alert' });

    const pass = h('input', { class: 'fld', type: 'password', id: 'passphrase', autocomplete: creating ? 'new-password' : 'current-password',
                              'aria-label': 'passphrase' });
    const confirm = creating
      ? h('input', { class: 'fld', type: 'password', id: 'passphrase2', autocomplete: 'new-password', 'aria-label': 'repeat passphrase' })
      : null;

    let busy = false;
    const submit = async () => {
      if (busy) return;
      error.textContent = '';
      const p = pass.value;
      if (creating) {
        if (p.length < MIN_PASSPHRASE) { error.textContent = `✗ passphrase must be at least ${MIN_PASSPHRASE} characters`; pass.focus(); return; }
        if (p !== confirm.value) { error.textContent = '✗ the two passphrases do not match'; confirm.focus(); return; }
      } else if (!p) { error.textContent = '✗ enter your passphrase'; pass.focus(); return; }

      busy = true;
      for (const el of [pass, confirm, go]) if (el) el.disabled = true;
      log.replaceChildren();
      say(creating ? '› generating ML-DSA-65 identity + ML-KEM-768 keys' : '› deriving vault key (argon2id)');
      try {
        const connected = new Promise((res) => {
          const off = bridge.on('status', (e) => { if (e.connected) { off(); res(); } });
        });
        const summary = await bridge.call(creating ? 'create' : 'unlock', { passphrase: p });
        pass.value = '';
        if (confirm) confirm.value = '';
        say(creating ? '› vault created and encrypted' : '› vault unlocked');
        say('› connecting to the server, signing its challenge');
        await connected;
        say(`✓ authenticated as ${summary.user}`, 'ok');
        resolve(summary);
      } catch (e) {
        busy = false;
        for (const el of [pass, confirm, go]) if (el) el.disabled = false;
        log.replaceChildren();
        error.textContent = `✗ ${e.message}`;
        pass.select();
        pass.focus();
      }
    };

    const go = keyButton('⏎', creating ? 'create identity' : 'sign in with identity key', submit, { id: 'login-submit' });
    const onEnter = (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } };
    pass.addEventListener('keydown', onEnter);
    confirm?.addEventListener('keydown', onEnter);

    mount(root, h('main', { class: 'login' },
      box({ title: creating ? 'create identity' : 'sign in', focus: true, id: 'login-box' },
        h('div', { class: 'logo', 'aria-hidden': 'true' }, LOGO),
        h('div', { class: 'faint' }, 'post-quantum end-to-end encrypted chat'),
        h('div', { class: 'lab' }, 'username'),
        h('div', { class: 'fld static', id: 'login-user' }, status.user),
        h('div', { class: 'lab' }, 'bridge'),
        h('div', { class: 'fld static' }, location.host),
        h('label', { class: 'lab', for: 'passphrase' }, creating ? 'new passphrase (min 8 characters)' : 'passphrase'),
        pass,
        creating ? h('label', { class: 'lab', for: 'passphrase2' }, 'repeat passphrase') : null,
        confirm,
        h('div', { class: 'actions' }, go),
        error,
        log)));
    pass.focus();
  });
}
