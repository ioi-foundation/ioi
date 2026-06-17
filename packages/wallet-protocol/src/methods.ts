export const WALLET_NETWORK_SERVICE_NAME = "wallet_network" as const;

export const WALLET_NETWORK_KERNEL_METHODS = [
  "configure_control_root@v1",
  "register_client@v1",
  "revoke_client@v1",
  "get_client@v1",
  "list_clients@v1",
  "create_identity@v1",
  "link_owner@v1",
  "store_secret_record@v1",
  "connector_auth_upsert@v1",
  "connector_auth_get@v1",
  "connector_auth_list@v1",
  "connector_auth_export@v1",
  "connector_auth_import@v1",
  "upsert_policy_rule@v1",
  "open_channel_init@v1",
  "open_channel_try@v1",
  "open_channel_ack@v1",
  "open_channel_confirm@v1",
  "close_channel@v1",
  "issue_session_grant@v1",
  "issue_session_lease@v1",
  "commit_receipt_root@v1",
  "record_secret_injection_request@v1",
  "grant_secret_injection@v1",
  "record_interception@v1",
  "record_approval@v1",
  "register_approval_authority@v1",
  "revoke_approval_authority@v1",
  "consume_approval_grant@v1",
  "panic_stop@v1",
] as const;

export type WalletNetworkKernelMethod =
  (typeof WALLET_NETWORK_KERNEL_METHODS)[number];

export const WALLET_NETWORK_PROTOCOL_METHODS = {
  createAuthorityReview: "wallet.authority.review.create",
  issueCapabilityLease: "wallet.capability.lease.issue",
  revokeCapabilityLease: "wallet.capability.lease.revoke",
  createExchangeIntent: "wallet.exchange.intent.create",
  createTradeIntent: "wallet.trade.intent.create",
  createReceipt: "wallet.receipt.create",
  listReceipts: "wallet.receipt.list",
} as const;

export type WalletNetworkProtocolMethod =
  (typeof WALLET_NETWORK_PROTOCOL_METHODS)[keyof typeof WALLET_NETWORK_PROTOCOL_METHODS];
