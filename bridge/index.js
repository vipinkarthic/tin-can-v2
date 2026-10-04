#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { startBridge } from './bridge.js';

const { values } = parseArgs({
  options: {
    user: { type: 'string' },
    server: { type: 'string', default: 'ws://127.0.0.1:7777' },
    data: { type: 'string', default: join(homedir(), '.pqs') },
    port: { type: 'string', default: '0' },
    kdf: { type: 'string', default: 'moderate' },
  },
});
if (!values.user) {
  console.error('usage: node bridge/index.js --user <name> [--server ws://127.0.0.1:7777] [--data ~/.pqs] [--port 0] [--kdf moderate|interactive]');
  process.exit(2);
}
if (!['moderate', 'interactive'].includes(values.kdf)) {
  console.error('--kdf must be "moderate" or "interactive"');
  process.exit(2);
}

const bridge = await startBridge({
  user: values.user,
  serverUrl: values.server,
  dataDir: values.data,
  port: Number(values.port),
  kdf: values.kdf,
  log: (m) => console.log(new Date().toISOString(), m),
});
console.log(`\n  ${values.user}: open ${bridge.url}\n`);

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    await bridge.close();
    process.exit(0);
  });
}
