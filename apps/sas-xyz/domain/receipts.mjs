import { createHash } from 'node:crypto';

const canonical = (value) => Array.isArray(value)
  ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);

export const sha256 = (value) => `sha256:${createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex')}`;

export function appendReceipt(state, context, action, objectRef, body = {}, ownerReceipts = []) {
  const receipt = {
    receipt_ref: `receipt://sas/${state.receipts.length + 1}`,
    sequence: state.receipts.length + 1,
    previous_receipt_hash: state.receipts.at(-1)?.body_hash || null,
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
  state.events.push({ event_ref: `event://sas/${state.events.length + 1}`, checkpoint: state.events.length + 1, type: action, object_ref: objectRef, receipt_ref: receipt.receipt_ref, occurred_at: receipt.occurred_at });
  return receipt;
}

export function verifyReceiptChain(receipts) {
  let previous = null;
  return receipts.every((receipt) => {
    const { body_hash: bodyHash, ...body } = receipt;
    const valid = body.previous_receipt_hash === previous && sha256(body) === bodyHash;
    previous = bodyHash;
    return valid;
  });
}

