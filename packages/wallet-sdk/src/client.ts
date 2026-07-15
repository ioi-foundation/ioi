import {
  type AuthorityReview,
  type CapabilityLease,
  type CapabilityLeaseRevocation,
  type LookupPrincipalAuthorityBindingParams,
  type LookupPrincipalAuthorityBindingReceipt,
  type IssuePrincipalAuthorityBindingParams,
  type PrincipalAuthorityBindingProofV1,
  type PrincipalAuthorityResolutionReceipt,
  type ResolvePrincipalAuthorityParams,
  type RevokePrincipalAuthorityBindingParams,
  type WalletNetworkProtocolMethod,
  type WalletReceipt,
  WalletProtocolValidationError,
  WALLET_NETWORK_PROTOCOL_METHODS,
  assertLookupPrincipalAuthorityBindingReceipt,
  assertIssuePrincipalAuthorityBindingParams,
  assertPrincipalAuthorityBindingProof,
  assertPrincipalAuthorityResolutionReceipt,
  assertRevokePrincipalAuthorityBindingParams,
} from "@ioi/wallet-protocol";

export interface WalletNetworkTransport {
  request<TResponse>(
    method: WalletNetworkProtocolMethod,
    body: unknown,
  ): Promise<TResponse>;
}

export class WalletNetworkClient {
  readonly #transport: WalletNetworkTransport;

  constructor(transport: WalletNetworkTransport) {
    this.#transport = transport;
  }

  createAuthorityReview(review: AuthorityReview): Promise<AuthorityReview> {
    return this.#transport.request(
      WALLET_NETWORK_PROTOCOL_METHODS.createAuthorityReview,
      review,
    );
  }

  issueCapabilityLease(lease: CapabilityLease): Promise<CapabilityLease> {
    return this.#transport.request(
      WALLET_NETWORK_PROTOCOL_METHODS.issueCapabilityLease,
      lease,
    );
  }

  revokeCapabilityLease(
    revocation: CapabilityLeaseRevocation,
  ): Promise<CapabilityLeaseRevocation> {
    return this.#transport.request(
      WALLET_NETWORK_PROTOCOL_METHODS.revokeCapabilityLease,
      revocation,
    );
  }

  async issuePrincipalAuthorityBinding(
    request: IssuePrincipalAuthorityBindingParams,
  ): Promise<PrincipalAuthorityBindingProofV1> {
    assertIssuePrincipalAuthorityBindingParams(request);
    const proof = await this.#transport.request<PrincipalAuthorityBindingProofV1>(
      WALLET_NETWORK_PROTOCOL_METHODS.issuePrincipalAuthorityBinding,
      request,
    );
    const accepted = assertIssuePrincipalAuthorityBindingParams({ proof }).proof;
    assertAcceptedBindingMatchesRequest(request.proof, accepted);
    return accepted;
  }

  async revokePrincipalAuthorityBinding(
    request: RevokePrincipalAuthorityBindingParams,
  ): Promise<PrincipalAuthorityBindingProofV1> {
    assertRevokePrincipalAuthorityBindingParams(request);
    const proof = await this.#transport.request<PrincipalAuthorityBindingProofV1>(
      WALLET_NETWORK_PROTOCOL_METHODS.revokePrincipalAuthorityBinding,
      request,
    );
    const accepted = assertRevokePrincipalAuthorityBindingParams({
      predecessor_binding_ref: request.predecessor_binding_ref,
      proof,
    }).proof;
    assertAcceptedBindingMatchesRequest(request.proof, accepted);
    return accepted;
  }

  async resolvePrincipalAuthority(
    request: ResolvePrincipalAuthorityParams,
  ): Promise<PrincipalAuthorityResolutionReceipt> {
    const receipt =
      await this.#transport.request<PrincipalAuthorityResolutionReceipt>(
        WALLET_NETWORK_PROTOCOL_METHODS.resolvePrincipalAuthority,
        request,
      );
    return assertPrincipalAuthorityResolutionReceipt(request, receipt);
  }

  async lookupPrincipalAuthorityBinding(
    request: LookupPrincipalAuthorityBindingParams,
  ): Promise<LookupPrincipalAuthorityBindingReceipt> {
    const receipt =
      await this.#transport.request<LookupPrincipalAuthorityBindingReceipt>(
        WALLET_NETWORK_PROTOCOL_METHODS.lookupPrincipalAuthorityBinding,
        request,
      );
    return assertLookupPrincipalAuthorityBindingReceipt(request, receipt);
  }

  createReceipt(receipt: WalletReceipt): Promise<WalletReceipt> {
    return this.#transport.request(
      WALLET_NETWORK_PROTOCOL_METHODS.createReceipt,
      receipt,
    );
  }
}

function assertAcceptedBindingMatchesRequest(
  requested: PrincipalAuthorityBindingProofV1,
  accepted: PrincipalAuthorityBindingProofV1,
) {
  assertPrincipalAuthorityBindingProof(accepted);
  if (!jsonValuesEqual(requested, accepted)) {
    throw new WalletProtocolValidationError({
      code: "principal_authority_binding_response_mismatch",
      message:
        "wallet.network returned a different immutable binding proof than the one submitted.",
    });
  }
}

function jsonValuesEqual(left: unknown, right: unknown): boolean {
  if (left === right) {
    return true;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => jsonValuesEqual(value, right[index]))
    );
  }
  if (
    left === null ||
    right === null ||
    typeof left !== "object" ||
    typeof right !== "object"
  ) {
    return false;
  }
  const leftRecord = left as Readonly<Record<string, unknown>>;
  const rightRecord = right as Readonly<Record<string, unknown>>;
  const leftKeys = Object.keys(leftRecord)
    .filter((key) => leftRecord[key] !== undefined)
    .sort();
  const rightKeys = Object.keys(rightRecord)
    .filter((key) => rightRecord[key] !== undefined)
    .sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) =>
        key === rightKeys[index] &&
        jsonValuesEqual(leftRecord[key], rightRecord[key]),
    )
  );
}
