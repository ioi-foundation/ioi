/**
 * Standards bindings as REPLACEABLE TRANSPORTS for the collaboration crossing (M11.3, R-176;
 * ACC-13 clause 5).
 *
 * WHAT THIS IS. An adapter per external protocol (A2A, MCP, HTTP/JSON-RPC, …) that carries one
 * crossing envelope — a registered application record such as an `OrchestrationParticipationRequest`
 * — to a peer BYTE-IDENTICALLY and hands back a transport receipt. The envelope's hash is the
 * adapter's only fidelity check: a binding that cannot carry the envelope unchanged is not a binding
 * and is refused as such. Which protocol carried the envelope never enters the record.
 *
 * WHAT THIS IS NOT. Not an authority, not an acceptance, not a verification. A remote "task
 * completed", a tool result without `isError`, a registry entry or a reputation score is transport
 * state: the receiving application admits the envelope through its own composer exactly as if it
 * had arrived by hand, and its decision is the admission owner's (and the adjudicator's under
 * federated admission). The registered binding profile records, per protocol, what its states do
 * NOT mean (`assurance_non_equivalences`), and an inactive profile carries nothing.
 */

import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";

import { canonicalJson } from "@ioi/agent-sdk";

export const BINDING_CONTRACT = "schema://ioi/foundations/objects/aiip-external-protocol-binding-envelope/v1";
export const CROSSING_ENVELOPE_DOMAIN = "ioi.aiip-crossing-envelope-jcs-sha256.v1";

export type ProtocolKind = "native_aiip" | "a2a" | "mcp" | "http_json_rpc" | "grpc" | "oasf_directory" | "erc_8004" | "erc_8183" | "other";

/** The registered `AIIPExternalProtocolBindingEnvelope` v1, held by the application as configuration. */
export interface BindingProfile {
  schema_version: "ioi.aiip-external-protocol-binding.v1";
  binding_id: string;
  aiip_profile_ref: string;
  protocol_kind: ProtocolKind;
  protocol_name: string;
  protocol_version_or_commitment: string;
  specification_ref: string;
  identity_mapping_ref: string;
  lifecycle_and_status_mapping_ref: string | null;
  message_and_artifact_mapping_ref: string | null;
  error_and_retry_mapping_ref: string | null;
  extension_profile_refs: string[];
  required_runtime_tool_contract_refs: string[];
  required_authority_scope_refs: string[];
  assurance_non_equivalences: string[];
  conformance_profile_refs: string[];
  compatibility_range: string;
  status: "draft" | "active" | "deprecated" | "revoked";
}

export interface CrossingEnvelope {
  contract_id: string;
  record: Record<string, unknown>;
}

export interface TransportReceipt {
  binding_id: string;
  protocol_kind: ProtocolKind;
  /** The protocol's own state word, carried verbatim and meaning nothing to IOI. */
  transport_state: string;
  envelope_hash: string;
  peer_ref: string;
}

export interface Binding {
  readonly profile: BindingProfile;
  deliver(envelope: CrossingEnvelope): Promise<TransportReceipt>;
}

export class BindingRefusal extends Error {
  readonly code: string;
  readonly details: Record<string, unknown>;
  constructor(code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "BindingRefusal";
    this.code = code;
    this.details = details;
  }
}

/** The envelope's identity across every transport: sha256 over the canonical JSON of the contract id and the record. */
export function deriveCrossingEnvelopeHash(envelope: CrossingEnvelope): string {
  return `sha256:${createHash("sha256").update(canonicalJson({ domain: CROSSING_ENVELOPE_DOMAIN, contract_id: envelope.contract_id, record: envelope.record })).digest("hex")}`;
}

/** Only an ACTIVE profile carries anything; a deprecated or revoked binding is refused before any transport is opened. */
export function requireActiveProfile(profile: BindingProfile): BindingProfile {
  if (profile.status !== "active") {
    throw new BindingRefusal("binding_not_active", `binding ${profile.binding_id} is ${profile.status}; only an active binding carries a crossing`, { binding_id: profile.binding_id, status: profile.status });
  }
  if (profile.protocol_kind !== "native_aiip" && profile.assurance_non_equivalences.length === 0) {
    throw new BindingRefusal("binding_claims_equivalence", `binding ${profile.binding_id} records no assurance non-equivalence; a transport that claims none is claiming an equivalence the estate never grants`, { binding_id: profile.binding_id });
  }
  return profile;
}

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown }> {
  const payload = JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const req = httpRequest(url, { method: "POST", headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(payload)), ...headers } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        let parsed: unknown = {};
        try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { raw }; }
        resolve({ status: res.statusCode ?? 0, body: parsed });
      });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

abstract class HttpTransportBinding implements Binding {
  readonly profile: BindingProfile;
  protected readonly peerUrl: string;
  constructor(profile: BindingProfile, peerUrl: string) {
    this.profile = requireActiveProfile(profile);
    this.peerUrl = peerUrl.replace(/\/$/u, "");
  }

  async deliver(envelope: CrossingEnvelope): Promise<TransportReceipt> {
    const expected = deriveCrossingEnvelopeHash(envelope);
    const { receivedHash, transportState } = await this.carry(envelope);
    if (receivedHash !== expected) {
      throw new BindingRefusal("binding_altered_envelope", `binding ${this.profile.binding_id} did not carry the envelope byte-identically; a binding that cannot be swapped without changing the envelope is not a binding`, { binding_id: this.profile.binding_id, expected, received: receivedHash });
    }
    return { binding_id: this.profile.binding_id, protocol_kind: this.profile.protocol_kind, transport_state: transportState, envelope_hash: expected, peer_ref: this.peerUrl };
  }

  /** Carry the envelope over this protocol's wire shape; return the peer's acknowledgement of what it received. */
  protected abstract carry(envelope: CrossingEnvelope): Promise<{ receivedHash: string; transportState: string }>;
}

/** HTTP + JSON-RPC 2.0: `aiip.deliver` with the envelope as params. */
export class HttpJsonRpcBinding extends HttpTransportBinding {
  protected async carry(envelope: CrossingEnvelope): Promise<{ receivedHash: string; transportState: string }> {
    const reply = await postJson(`${this.peerUrl}/rpc`, { jsonrpc: "2.0", id: 1, method: "aiip.deliver", params: { envelope } });
    const body = reply.body as { result?: { received_hash?: string; state?: string }; error?: { message?: string } };
    if (reply.status !== 200 || !body.result) throw new BindingRefusal("binding_transport_failed", `JSON-RPC peer refused: ${body.error?.message ?? reply.status}`);
    return { receivedHash: String(body.result.received_hash ?? ""), transportState: String(body.result.state ?? "") };
  }
}

/** A2A-shaped: `tasks/send` with the envelope as a data part; the task's own status is transport state. */
export class A2aBinding extends HttpTransportBinding {
  protected async carry(envelope: CrossingEnvelope): Promise<{ receivedHash: string; transportState: string }> {
    const reply = await postJson(`${this.peerUrl}/tasks/send`, { id: `task-${Date.now()}`, message: { role: "user", parts: [{ type: "data", data: envelope }] } });
    const body = reply.body as { status?: { state?: string }; artifacts?: Array<{ parts?: Array<{ type?: string; data?: { received_hash?: string } }> }> };
    const part = body.artifacts?.[0]?.parts?.find((p) => p.type === "data");
    if (reply.status !== 200 || !part) throw new BindingRefusal("binding_transport_failed", `A2A peer refused: ${reply.status}`);
    return { receivedHash: String(part.data?.received_hash ?? ""), transportState: String(body.status?.state ?? "") };
  }
}

/** MCP-shaped: `tools/call` of `aiip_deliver` with the envelope as arguments; `isError` is transport state. */
export class McpBinding extends HttpTransportBinding {
  protected async carry(envelope: CrossingEnvelope): Promise<{ receivedHash: string; transportState: string }> {
    const reply = await postJson(`${this.peerUrl}/mcp`, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "aiip_deliver", arguments: envelope } });
    const body = reply.body as { result?: { content?: Array<{ type?: string; text?: string }>; isError?: boolean } };
    const text = body.result?.content?.find((c) => c.type === "text")?.text;
    if (reply.status !== 200 || !text) throw new BindingRefusal("binding_transport_failed", `MCP peer refused: ${reply.status}`);
    let parsed: { received_hash?: string } = {};
    try { parsed = JSON.parse(text); } catch { parsed = {}; }
    return { receivedHash: String(parsed.received_hash ?? ""), transportState: body.result?.isError ? "isError:true" : "isError:false" };
  }
}

/** Pick the active profile of a protocol kind from the application's configuration. */
export function selectBinding(profiles: BindingProfile[], kind: ProtocolKind): BindingProfile {
  const candidates = profiles.filter((p) => p.protocol_kind === kind);
  if (candidates.length === 0) throw new BindingRefusal("binding_unavailable", `no binding profile for ${kind}`);
  const active = candidates.find((p) => p.status === "active");
  if (!active) throw new BindingRefusal("binding_not_active", `every ${kind} binding is ${candidates.map((p) => p.status).join("/")}; only an active binding carries a crossing`, { statuses: candidates.map((p) => p.status) });
  return requireActiveProfile(active);
}
