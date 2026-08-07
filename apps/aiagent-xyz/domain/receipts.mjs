import { createHash } from 'node:crypto';

const canonicalize = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};

export const sha256 = (value) => `sha256:${createHash('sha256').update(typeof value === 'string' ? value : canonicalize(value)).digest('hex')}`;

export function appendReceipt(state, context, action, objectRef, body = {}, ownerReceipts = []) {
  const previous = state.receipts.at(-1)?.body_hash || null;
  const receipt = {
    receipt_ref: `receipt://aiagent/${state.receipts.length + 1}`,
    sequence: state.receipts.length + 1,
    previous_receipt_hash: previous,
    action,
    object_ref: objectRef,
    principal_ref: context.principalRef,
    tenant_ref: context.tenantRef,
    owner_receipt_refs: ownerReceipts.filter(Boolean),
    occurred_at: new Date().toISOString(),
    body,
  };
  receipt.body_hash = sha256(receipt);
  state.receipts.push(receipt);
  state.events.push({
    event_ref: `event://aiagent/${state.events.length + 1}`,
    checkpoint: state.events.length + 1,
    type: action,
    object_ref: objectRef,
    receipt_ref: receipt.receipt_ref,
    occurred_at: receipt.occurred_at,
  });
  return receipt;
}

export function verifyReceiptChain(receipts) {
  let previous = null;
  for (const receipt of receipts) {
    const { body_hash: bodyHash, ...body } = receipt;
    if (body.previous_receipt_hash !== previous || sha256(body) !== bodyHash) return false;
    previous = bodyHash;
  }
  return true;
}

