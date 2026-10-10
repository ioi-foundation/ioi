// Every avatar model is checked against the catalog's published byte count and SHA-256 before it is parsed.
// A mismatch, an uncatalogued model or a browser without WebCrypto refuses the model, so the caller falls back
// to the static portrait. Only a development build may load the uncatalogued authoring sources.
const CATALOG_URL = '/models/avatars/catalog-v1.json';
let catalogLevels = null;

function levels() {
  catalogLevels ||= fetch(CATALOG_URL)
    .then((response) => {
      if (!response.ok) throw new Error('The avatar catalog could not be loaded.');
      return response.json();
    })
    .then((catalog) => new Map(catalog.bodies.flatMap((body) => body.levels.map((level) => [level.asset, level]))))
    .catch((error) => { catalogLevels = null; throw error; });
  return catalogLevels;
}

export async function verifyModelBytes(buffer, expected, subtle = globalThis.crypto?.subtle) {
  if (!expected) throw new Error('This avatar model is not in the catalog.');
  if (buffer.byteLength !== expected.bytes) throw new Error('The avatar model does not match the catalog.');
  if (!subtle) throw new Error('This browser cannot verify the avatar model.');
  const digest = Array.from(new Uint8Array(await subtle.digest('SHA-256', buffer)), (byte) => byte.toString(16).padStart(2, '0')).join('');
  if (digest !== expected.sha256) throw new Error('The avatar model does not match the catalog.');
  return buffer;
}

export async function verifiedModel(asset, buffer) {
  const development = Boolean(import.meta.env?.DEV);
  if (development && asset.startsWith('/__avatar-authoring/')) return buffer;
  if (development && !globalThis.crypto?.subtle) {
    console.warn('Avatar model integrity was not checked: WebCrypto is unavailable outside a secure context.');
    return buffer;
  }
  return verifyModelBytes(buffer, (await levels()).get(asset));
}
