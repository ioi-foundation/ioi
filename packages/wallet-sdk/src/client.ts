import {
  type AuthorityReview,
  type CapabilityLease,
  type CapabilityLeaseRevocation,
  type WalletNetworkProtocolMethod,
  type WalletReceipt,
  WALLET_NETWORK_PROTOCOL_METHODS,
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

  createReceipt(receipt: WalletReceipt): Promise<WalletReceipt> {
    return this.#transport.request(
      WALLET_NETWORK_PROTOCOL_METHODS.createReceipt,
      receipt,
    );
  }
}
