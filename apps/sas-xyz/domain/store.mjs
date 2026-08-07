import { mkdir, open, readFile, rename } from 'node:fs/promises';
import path from 'node:path';
import { verifyReceiptChain } from './receipts.mjs';

export class StateIntegrityError extends Error {
  constructor(message) { super(message); this.name = 'StateIntegrityError'; }
}

const verifyState = (state, expectedSchema) => {
  if (!state || state.schema !== expectedSchema || !Array.isArray(state.receipts) || !Array.isArray(state.events) || !verifyReceiptChain(state.receipts)) throw new StateIntegrityError('Outcome marketplace state schema or receipt chain is invalid');
};

export class JsonStore {
  #queue = Promise.resolve();

  constructor(filePath, seed) { this.filePath = filePath; this.seed = seed; }

  async init() {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    try { const current = JSON.parse(await readFile(this.filePath, 'utf8')); verifyState(current, this.seed.schema); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await this.#write({ ...structuredClone(this.seed), revision: 0 });
    }
    return this;
  }

  async read() { return JSON.parse(await readFile(this.filePath, 'utf8')); }

  async transact(mutator) {
    const run = this.#queue.then(async () => {
      const current = await this.read();
      verifyState(current, this.seed.schema);
      const working = structuredClone(current);
      const result = await mutator(working);
      working.revision = Number(current.revision || 0) + 1;
      verifyState(working, this.seed.schema);
      await this.#write(working);
      return structuredClone(result);
    });
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #write(value) {
    const temporaryPath = `${this.filePath}.${process.pid}.tmp`;
    const handle = await open(temporaryPath, 'w', 0o600);
    try { await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8'); await handle.sync(); }
    finally { await handle.close(); }
    await rename(temporaryPath, this.filePath);
  }
}
