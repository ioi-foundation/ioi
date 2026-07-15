import type { ApprovalAuthoritySnapshot, WalletProtocolBytes } from "./types.js";

/**
 * Rust-compatible `ApprovalAuthority::artifact_hash()`.
 *
 * Rust serializes the complete struct with `serde_jcs::to_vec` and hashes the
 * resulting UTF-8 bytes directly with SHA-256. All keys are ASCII, all numeric
 * fields are protocol-validated safe integers, and the fixed key order below
 * is the RFC 8785 lexicographic order.
 */
export function approvalAuthorityArtifactHash(
  authority: ApprovalAuthoritySnapshot,
): WalletProtocolBytes {
  const canonical = canonicalApprovalAuthority(authority);
  return sha256(new TextEncoder().encode(canonical));
}

function canonicalApprovalAuthority(authority: ApprovalAuthoritySnapshot) {
  const entries: readonly (readonly [string, unknown])[] = [
    ["authority_id", authority.authority_id],
    ["expires_at", authority.expires_at],
    ["public_key", authority.public_key],
    ["revoked", authority.revoked],
    ["schema_version", authority.schema_version],
    ["scope_allowlist", authority.scope_allowlist],
    ["signature_suite", authority.signature_suite],
  ];
  return `{${entries
    .map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`)
    .join(",")}}`;
}

const SHA256_INITIAL_STATE = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const SHA256_ROUND_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256(input: Uint8Array): number[] {
  const bitLength = BigInt(input.length) * 8n;
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64;
  const message = new Uint8Array(paddedLength);
  message.set(input);
  message[input.length] = 0x80;
  for (let index = 0; index < 8; index += 1) {
    message[paddedLength - 1 - index] = Number((bitLength >> BigInt(index * 8)) & 0xffn);
  }

  const state = new Uint32Array(SHA256_INITIAL_STATE);
  const words = new Uint32Array(64);
  for (let offset = 0; offset < message.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      const wordOffset = offset + index * 4;
      words[index] =
        ((message[wordOffset] << 24) |
          (message[wordOffset + 1] << 16) |
          (message[wordOffset + 2] << 8) |
          message[wordOffset + 3]) >>>
        0;
    }
    for (let index = 16; index < 64; index += 1) {
      const x = words[index - 15];
      const y = words[index - 2];
      const sigma0 = rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
      const sigma1 = rotateRight(y, 17) ^ rotateRight(y, 19) ^ (y >>> 10);
      words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
    }

    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    let e = state[4];
    let f = state[5];
    let g = state[6];
    let h = state[7];
    for (let index = 0; index < 64; index += 1) {
      const choose = (e & f) ^ (~e & g);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const temporary1 = (h + sum1 + choose + SHA256_ROUND_CONSTANTS[index] + words[index]) >>> 0;
      const temporary2 = (sum0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temporary1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temporary1 + temporary2) >>> 0;
    }

    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
  }

  const digest = new Array<number>(32);
  for (let index = 0; index < state.length; index += 1) {
    digest[index * 4] = state[index] >>> 24;
    digest[index * 4 + 1] = (state[index] >>> 16) & 0xff;
    digest[index * 4 + 2] = (state[index] >>> 8) & 0xff;
    digest[index * 4 + 3] = state[index] & 0xff;
  }
  return digest;
}

function rotateRight(value: number, shift: number) {
  return (value >>> shift) | (value << (32 - shift));
}
