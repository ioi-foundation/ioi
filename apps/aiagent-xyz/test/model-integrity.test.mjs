import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fetchModel, integrityToken, modelTokens } from '../src/product/avatar/model-integrity.js';
import { checkModelIntegrity } from '../scripts/avatars/check_model_integrity.mjs';

const appRoot = new URL('..', import.meta.url).pathname;
const catalog = JSON.parse(await readFile(path.join(appRoot, 'public/models/avatars/catalog-v1.json'), 'utf8'));
const levels = catalog.bodies.flatMap((body) => body.levels);
const table = modelTokens(catalog);
const robot = levels.find((level) => level.asset.endsWith('robot-study-v1.glb')).asset;

// Serves the real public files, except that `tampered` paths get one changed byte, as a deployment could.
async function server(t, tampered = new Set()) {
  const listener = http.createServer(async (request, response) => {
    try {
      const bytes = Buffer.from(await readFile(path.join(appRoot, 'public', decodeURIComponent(new URL(request.url, 'http://x').pathname.replace('/__avatar-authoring/', '/models/avatars/')))));
      if (tampered.has(request.url)) bytes[bytes.length - 1] ^= 1;
      response.end(bytes);
    } catch { response.statusCode = 404; response.end(); }
  });
  await new Promise((resolve) => listener.listen(0, '127.0.0.1', resolve));
  t.after(() => listener.close());
  return `http://127.0.0.1:${listener.address().port}`;
}

test('integrity tokens are built only from well-formed digests', () => {
  const hex = createHash('sha256').update('abc').digest('hex');
  assert.equal(integrityToken(hex), `sha256-${createHash('sha256').update('abc').digest('base64')}`);
  for (const bad of ['', 'abc', hex.slice(1), hex.toUpperCase(), `${hex}0`, null, undefined]) assert.throws(() => integrityToken(bad), /malformed digest/);
});

test('nominal: every published model loads through the loaders\' fetch path against the real catalog', async (t) => {
  const base = await server(t);
  assert.equal(levels.length, 6);
  for (const level of levels) assert.equal((await fetchModel(level.asset, { base, table, development: false })).byteLength, level.bytes);
});

test('(a) production: a tampered published model is rejected by the integrity check', async (t) => {
  const base = await server(t, new Set([robot]));
  await assert.rejects(() => fetchModel(robot, { base, table, development: false }));
});

test('(b) development: a tampered PUBLISHED model is rejected too (no escape for catalogued assets)', async (t) => {
  const base = await server(t, new Set([robot]));
  await assert.rejects(() => fetchModel(robot, { base, table, development: true }));
});

test('(c) an uncatalogued model is refused before any fetch; authoring sources load only in development', async (t) => {
  const base = await server(t);
  for (const development of [false, true]) {
    await assert.rejects(() => fetchModel('/models/avatars/not-in-catalog.glb', { base, table, development }), /not in the catalog/);
  }
  await assert.rejects(() => fetchModel('/__avatar-authoring/robot-study-v1.glb', { base, table, development: false }), /not in the catalog/);
  assert.ok((await fetchModel('/__avatar-authoring/robot-study-v1.glb', { base, table, development: true })).byteLength > 0);
});

test('(d) the build gate refuses a missing, unreadable or mismatching catalog and a model that is not self-contained', async (t) => {
  assert.equal(await checkModelIntegrity(appRoot), 6);
  const copy = await mkdtemp(path.join(os.tmpdir(), 'avatar-integrity-'));
  t.after(() => rm(copy, { recursive: true, force: true }));
  await cp(path.join(appRoot, 'public/models/avatars'), path.join(copy, 'public/models/avatars'), { recursive: true, filter: (source) => !source.includes('/portraits') });
  const catalogPath = path.join(copy, 'public/models/avatars/catalog-v1.json');
  const original = await readFile(catalogPath, 'utf8');
  await rm(catalogPath);
  await assert.rejects(() => checkModelIntegrity(copy), /missing or unreadable/);
  await writeFile(catalogPath, '{ not json');
  await assert.rejects(() => checkModelIntegrity(copy), /missing or unreadable/);
  const mismatched = JSON.parse(original); mismatched.bodies[0].levels[0].sha256 = '0'.repeat(64);
  await writeFile(catalogPath, JSON.stringify(mismatched));
  await assert.rejects(() => checkModelIntegrity(copy), /SHA-256/);
  const malformed = JSON.parse(original); malformed.bodies[0].levels[0].sha256 = 'not-a-digest';
  await writeFile(catalogPath, JSON.stringify(malformed));
  await assert.rejects(() => checkModelIntegrity(copy), /Malformed digest/);
  const level = JSON.parse(original).bodies[0].levels[0];
  const file = path.join(copy, 'public', level.asset);
  const bytes = await readFile(file); const length = bytes.readUInt32LE(12);
  const document = JSON.parse(bytes.subarray(20, 20 + length).toString()); document.images = [...(document.images || []), { uri: 'external.png' }];
  let json = Buffer.from(JSON.stringify(document)); json = Buffer.concat([json, Buffer.alloc((4 - (json.length % 4)) % 4, 0x20)]);
  const rebuilt = Buffer.concat([bytes.subarray(0, 12), Buffer.from(new Uint32Array([json.length, 0x4e4f534a]).buffer), json, bytes.subarray(20 + length)]);
  rebuilt.writeUInt32LE(rebuilt.length, 8);
  await writeFile(file, rebuilt);
  const external = JSON.parse(original); const changed = external.bodies.flatMap((body) => body.levels).find((item) => item.asset === level.asset);
  changed.bytes = rebuilt.length; changed.sha256 = createHash('sha256').update(rebuilt).digest('hex');
  await writeFile(catalogPath, JSON.stringify(external));
  await assert.rejects(() => checkModelIntegrity(copy), /not self-contained/);
});

test('(b) development without WebCrypto: a tampered published model is still rejected', async (t) => {
  const base = await server(t, new Set([robot]));
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true, writable: true });
  t.after(() => Object.defineProperty(globalThis, 'crypto', descriptor));
  assert.equal(globalThis.crypto, undefined);
  await assert.rejects(() => fetchModel(robot, { base, table, development: true }));
});

test('(d) the build gate refuses a model with an empty external URI', async (t) => {
  const copy = await mkdtemp(path.join(os.tmpdir(), 'avatar-integrity-uri-'));
  t.after(() => rm(copy, { recursive: true, force: true }));
  await cp(path.join(appRoot, 'public/models/avatars'), path.join(copy, 'public/models/avatars'), { recursive: true, filter: (source) => !source.includes('/portraits') });
  const catalogPath = path.join(copy, 'public/models/avatars/catalog-v1.json');
  const edited = JSON.parse(await readFile(catalogPath, 'utf8'));
  const level = edited.bodies[0].levels[0]; const file = path.join(copy, 'public', level.asset);
  const bytes = await readFile(file); const length = bytes.readUInt32LE(12);
  const document = JSON.parse(bytes.subarray(20, 20 + length).toString()); document.images = [...(document.images || []), { uri: '' }];
  let json = Buffer.from(JSON.stringify(document)); json = Buffer.concat([json, Buffer.alloc((4 - (json.length % 4)) % 4, 0x20)]);
  const rebuilt = Buffer.concat([bytes.subarray(0, 12), Buffer.from(new Uint32Array([json.length, 0x4e4f534a]).buffer), json, bytes.subarray(20 + length)]);
  rebuilt.writeUInt32LE(rebuilt.length, 8);
  await writeFile(file, rebuilt);
  level.bytes = rebuilt.length; level.sha256 = createHash('sha256').update(rebuilt).digest('hex');
  await writeFile(catalogPath, JSON.stringify(edited));
  await assert.rejects(() => checkModelIntegrity(copy), /not self-contained/);
});

test('vite build runs the model integrity gate', async () => {
  const config = await readFile(path.join(appRoot, 'vite.config.js'), 'utf8');
  assert.match(config, /name: 'avatar-model-integrity',\s*apply: 'build',\s*async buildStart\(\) \{ await checkModelIntegrity\(appRoot\); \}/);
});

test('both loaders fetch models only through fetchModel', async () => {
  for (const file of ['asset-cache.js', 'vrm-adapter.js']) {
    const source = await readFile(path.join(appRoot, 'src/product/avatar', file), 'utf8');
    assert.match(source, /fetchModel\(body\.asset/);
    assert.doesNotMatch(source, /\bfetch\(/);
  }
});
