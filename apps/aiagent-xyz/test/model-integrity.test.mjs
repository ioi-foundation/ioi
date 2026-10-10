import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { verifyModelBytes } from '../src/product/avatar/model-integrity.js';

const bytes = (text) => new TextEncoder().encode(text).buffer;
const abc = { bytes: 3, sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' };

test('a model is accepted only when its byte count and SHA-256 match the catalog', async () => {
  assert.equal((await verifyModelBytes(bytes('abc'), abc)).byteLength, 3);
  await assert.rejects(() => verifyModelBytes(bytes('abcd'), abc), /does not match the catalog/);
  await assert.rejects(() => verifyModelBytes(bytes('abd'), abc), /does not match the catalog/);
  await assert.rejects(() => verifyModelBytes(bytes('abc'), undefined), /not in the catalog/);
  await assert.rejects(() => verifyModelBytes(bytes('abc'), abc, null), /cannot verify/);
});

test('every published model matches its catalog entry', async () => {
  const catalog = JSON.parse(await readFile(new URL('../public/models/avatars/catalog-v1.json', import.meta.url), 'utf8'));
  const levels = catalog.bodies.flatMap((body) => body.levels);
  assert.equal(levels.length, 6);
  for (const level of levels) {
    const file = await readFile(new URL('../public' + level.asset, import.meta.url));
    const buffer = file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength);
    await verifyModelBytes(buffer, level);
  }
});
