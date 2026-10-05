import { Bridge, takeToken } from './rpc.js';
import { h, mount, box, installHotkeys } from './dom.js';
import { showLogin } from './login.js';
import { App } from './app.js';

const root = document.getElementById('app');

function fatal(title, message) {
  mount(root, h('main', { class: 'login' }, box({ title, focus: true, id: 'fatal' }, h('div', { class: 'bad' }, message))));
}

async function boot() {
  let bridge;
  try {
    bridge = await Bridge.connect(takeToken());
  } catch {
    fatal('cannot connect', '✗ this link is not valid. Open the link the bridge printed in its terminal.');
    return;
  }
  bridge.onclose = () => fatal('disconnected', '✗ the bridge stopped. Restart it and open its new link.');
  const status = await bridge.call('status');
  let app = null;
  installHotkeys({ focusInput: () => app?.input.focus() });
  // already unlocked usually means the tab got reloaded, so skip login
  if (!status.unlocked) await showLogin(root, bridge, status);
  app = new App(root, bridge);
  await app.start();
}

boot();
