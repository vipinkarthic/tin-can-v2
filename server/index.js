#!/usr/bin/env node
// optional host, port and db flags, defaults are 127.0.0.1, 7777 and pqs server db next to this file

import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { startServer } from './server.js';

const { values } = parseArgs({
  options: {
    host: { type: 'string', default: '127.0.0.1' },
    port: { type: 'string', default: '7777' },
    db: { type: 'string', default: fileURLToPath(new URL('./pqs-server.db', import.meta.url)) },
  },
});

const server = await startServer({
  host: values.host,
  port: Number(values.port),
  dbPath: values.db,
  log: (m) => console.log(new Date().toISOString(), m),
});
console.log(`pqs-server listening on ws://${values.host}:${server.port}  (db: ${values.db})`);

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    await server.close();
    process.exit(0);
  });
}
