let sessionPromise;

const readPayload = async (response) => {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error?.message || `Request failed (${response.status})`);
    // The status is what says whether asking again could change the answer. A
    // surface that decides that from the presence of an owner attribution gets
    // it wrong for an upstream failing inside an authority-owned component,
    // which carries an owner and is still worth retrying.
    error.status = response.status;
    error.code = payload.error?.code;
    error.owner = payload.error?.owner;
    error.details = payload.error?.details;
    throw error;
  }
  return payload;
};

export const productSession = () => {
  if (!sessionPromise) sessionPromise = fetch('/v1/session', { credentials: 'same-origin', headers: { accept: 'application/json' } }).then(readPayload).catch((error) => { sessionPromise = null; throw error; });
  return sessionPromise;
};

export async function api(path, options = {}) {
  const method = options.method || 'GET';
  const session = path === '/v1/session' ? null : await productSession();
  const headers = {
    'content-type': 'application/json',
    ...(method !== 'GET' ? { 'idempotency-key': options.idempotencyKey || crypto.randomUUID(), 'x-ioi-csrf': session.csrf_token } : {}),
    ...options.headers,
  };
  const response = await fetch(path, { ...options, credentials: 'same-origin', method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  return readPayload(response);
}
