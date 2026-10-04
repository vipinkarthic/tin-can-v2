// needs node 22.13 or newer for built in sqlite, only public keys, routing info and envelopes we cant decrypt live here

import { DatabaseSync } from 'node:sqlite';

export class Store {
  #db;

  constructor(path) {
    this.#db = new DatabaseSync(path);
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS users (
        user     TEXT PRIMARY KEY,
        -- mldsa 65 public key in base64, checked on login
        sig_pk   TEXT NOT NULL,
        -- signed public bundle, stored as json
        bundle   TEXT NOT NULL,
        created  INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient  TEXT NOT NULL REFERENCES users(user),
        sender     TEXT NOT NULL,
        -- e2e encrypted, the server cant read it
        envelope   TEXT NOT NULL,
        created    INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS messages_by_recipient ON messages(recipient, id);
    `);
  }

  close() {
    this.#db.close();
  }

  getUser(user) {
    return this.#db.prepare('SELECT user, sig_pk, bundle, created FROM users WHERE user = ?').get(user) ?? null;
  }

  addUser(user, sigPk, bundle) {
    this.#db.prepare('INSERT INTO users (user, sig_pk, bundle, created) VALUES (?, ?, ?, ?)')
      .run(user, sigPk, JSON.stringify(bundle), Date.now());
  }

  listUsers() {
    return this.#db.prepare('SELECT user FROM users ORDER BY user').all().map((r) => r.user);
  }

  queue(recipient, sender, envelope) {
    const r = this.#db.prepare('INSERT INTO messages (recipient, sender, envelope, created) VALUES (?, ?, ?, ?)')
      .run(recipient, sender, JSON.stringify(envelope), Date.now());
    return Number(r.lastInsertRowid);
  }

  pending(recipient, afterId) {
    return this.#db.prepare('SELECT id, sender, envelope, created FROM messages WHERE recipient = ? AND id > ? ORDER BY id')
      .all(recipient, afterId)
      .map((r) => ({ id: Number(r.id), sender: r.sender, envelope: JSON.parse(r.envelope), created: Number(r.created) }));
  }

  ack(recipient, id) {
    return this.#db.prepare('DELETE FROM messages WHERE recipient = ? AND id = ?').run(recipient, id).changes > 0;
  }

  // tests and demo only, dump everything to show theres no plaintext in here
  dump() {
    return {
      users: this.#db.prepare('SELECT * FROM users').all(),
      messages: this.#db.prepare('SELECT * FROM messages').all(),
    };
  }
}
