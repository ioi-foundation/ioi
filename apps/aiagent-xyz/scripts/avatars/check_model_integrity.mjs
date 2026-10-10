// Build gate: the committed catalog must parse, and every catalogued model must exist, match its byte count and
// SHA-256, and be self-contained (no external buffer or image URI that would load without an integrity token).
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';

export async function checkModelIntegrity(appRoot) {
  let catalog;
  try { catalog = JSON.parse(await readFile(path.join(appRoot, 'public/models/avatars/catalog-v1.json'), 'utf8')); }
  catch (error) { throw new Error(`Avatar catalog is missing or unreadable: ${error.message}`); }
  if (!Array.isArray(catalog.bodies)) throw new Error('Avatar catalog has no bodies.');
  const levels = catalog.bodies.flatMap((body) => body.levels || []);
  if (!levels.length) throw new Error('Avatar catalog lists no models.');
  for (const level of levels) {
    if (!/^[0-9a-f]{64}$/.test(level.sha256 || '')) throw new Error(`Malformed digest for ${level.asset}.`);
    const bytes = await readFile(path.join(appRoot, 'public', level.asset));
    if (bytes.length !== level.bytes) throw new Error(`${level.asset} does not match the catalog's byte count.`);
    if (createHash('sha256').update(bytes).digest('hex') !== level.sha256) throw new Error(`${level.asset} does not match the catalog's SHA-256.`);
    const document = JSON.parse(bytes.subarray(20, 20 + bytes.readUInt32LE(12)).toString());
    if ([...(document.buffers || []), ...(document.images || [])].some((item) => Object.hasOwn(item, 'uri'))) throw new Error(`${level.asset} is not self-contained.`);
  }
  return levels.length;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const count = await checkModelIntegrity(path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..'));
  console.log(`avatar model integrity: ${count} catalogued models match the committed catalog`);
}
