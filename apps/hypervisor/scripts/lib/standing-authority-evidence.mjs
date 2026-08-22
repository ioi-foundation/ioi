import crypto from "node:crypto";

import { stableStringify } from "./c7-c8-certificate.mjs";

export const sha256 = (bytes) =>
  `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

export const randomHex32 = () => crypto.randomBytes(32).toString("hex");

export function sealStandingAuthorityEnvelope(value) {
  const envelope = structuredClone(value);
  delete envelope.body_hash;
  const material = {
    ...envelope,
    domain: "ioi.standing-authority-envelope-jcs-sha256.v1",
  };
  envelope.body_hash = sha256(stableStringify(material));
  return envelope;
}

export function approvalCeremonyContextHash(context) {
  return sha256(
    Buffer.concat([
      Buffer.from("IOI-APPROVAL-CEREMONY-CONTEXT-V1\0"),
      Buffer.from(stableStringify(context)),
    ]),
  );
}

export function sealAuthFactorReceipt(value) {
  const receipt = structuredClone(value);
  delete receipt.receipt_hash;
  receipt.receipt_hash = sha256(stableStringify(receipt));
  return receipt;
}
