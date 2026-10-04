// pqs core talks one json object per line over stdin and stdout, replies matched by id

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const DEFAULT_CORE_PATH = fileURLToPath(new URL('../core/build/pqs-core', import.meta.url));

export class CoreProcess {
  #proc;
  #nextId = 1;
  #pending = new Map();

  constructor({ corePath = process.env.PQS_CORE_PATH || DEFAULT_CORE_PATH } = {}) {
    this.#proc = spawn(corePath, [], { stdio: ['pipe', 'pipe', 'inherit'] });
    this.#proc.on('error', (err) => this.#failAll(err));
    this.#proc.on('exit', (code) => this.#failAll(new Error(`pqs-core exited with code ${code}`)));
    createInterface({ input: this.#proc.stdout }).on('line', (line) => this.#onLine(line));
  }

  call(cmd, args = {}) {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#proc.stdin.write(JSON.stringify({ id, cmd, args }) + '\n');
    });
  }

  // closing stdin is what tells the core to exit
  close() {
    if (this.#proc.exitCode !== null) return Promise.resolve();
    return new Promise((resolve) => {
      this.#proc.once('exit', () => resolve());
      this.#proc.stdin.end();
    });
  }

  #onLine(line) {
    let reply;
    try {
      reply = JSON.parse(line);
    } catch {
      // not a protocol line, skip it
      return;
    }
    const waiter = this.#pending.get(reply.id);
    if (!waiter) return;
    this.#pending.delete(reply.id);
    if (reply.ok) waiter.resolve(reply.result);
    else waiter.reject(Object.assign(new Error(reply.error), { code: reply.code }));
  }

  #failAll(err) {
    for (const { reject } of this.#pending.values()) reject(err);
    this.#pending.clear();
  }
}
