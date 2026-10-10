// Avatar models are fetched only through fetchModel(). Every catalogued model carries the catalog's SHA-256 as a
// Subresource Integrity token, so the browser itself refuses a body that differs from the committed catalog, in
// every build and context. The catalog is compiled into the bundle (no runtime catalog fetch), and the build
// refuses a catalog that is missing, unreadable or out of step with the model files
// (scripts/avatars/check_model_integrity.mjs).
// Scope: integrity here means "matches the committed catalog". The catalog's own supply-chain authenticity and
// the Draco decoder (application code, trusted like the bundle) are out of scope.
import catalog from '../../../public/models/avatars/catalog-v1.json' with { type: 'json' };

const AUTHORING = '/__avatar-authoring/';
const SHA256_HEX = /^[0-9a-f]{64}$/;

// An empty or malformed integrity token is ignored by fetch, which would load the body unchecked, so a token is
// built only from a well-formed digest and is refused otherwise.
export function integrityToken(sha256) {
  if (typeof sha256 !== 'string' || !SHA256_HEX.test(sha256)) throw new Error('The avatar catalog has a malformed digest.');
  const token = `sha256-${btoa(String.fromCharCode(...sha256.match(/../g).map((pair) => parseInt(pair, 16))))}`;
  if (token.length !== 51) throw new Error('The avatar catalog has a malformed digest.');
  return token;
}

export function modelTokens(source = catalog) {
  if (!source || !Array.isArray(source.bodies)) throw new Error('The avatar catalog is missing or unreadable.');
  return new Map(source.bodies.flatMap((body) => (body.levels || []).map((level) => [level.asset, integrityToken(level.sha256)])));
}

let tokens = null;
export function integrityFor(asset, { development = Boolean(import.meta.env?.DEV), table } = {}) {
  const token = (table || (tokens ||= modelTokens())).get(asset);
  if (token) return token;
  // The vite dev server's uncatalogued authoring sources are the only models loaded without a token.
  if (development && typeof asset === 'string' && asset.startsWith(AUTHORING)) return null;
  throw new Error('This avatar model is not in the catalog.');
}

export async function fetchModel(asset, { signal, development, table, base } = {}) {
  const integrity = integrityFor(asset, { development, table });
  const response = await fetch(base ? new URL(asset, base) : asset, integrity ? { signal, integrity } : { signal });
  if (!response.ok) throw new Error('The avatar model could not be loaded.');
  return response.arrayBuffer();
}
