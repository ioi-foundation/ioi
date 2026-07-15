export const AUTHORITY_REVIEW_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/authority-review.schema.json" as const;

export const CAPABILITY_LEASE_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/capability-lease.schema.json" as const;

export const CAPABILITY_LEASE_REVOCATION_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/capability-lease-revocation.schema.json" as const;

export const WALLET_RECEIPT_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/wallet-receipt.schema.json" as const;

export const EXCHANGE_INTENT_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/exchange-intent.schema.json" as const;

export const TRADE_INTENT_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/trade-intent.schema.json" as const;

export const PRINCIPAL_AUTHORITY_BINDING_PROOF_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/principal-authority-binding-proof.schema.json" as const;

export const PRINCIPAL_AUTHORITY_RESOLUTION_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/principal-authority-resolution.schema.json" as const;

export const WALLET_PROTOCOL_SCHEMA_IDS = [
  AUTHORITY_REVIEW_SCHEMA_ID,
  CAPABILITY_LEASE_SCHEMA_ID,
  CAPABILITY_LEASE_REVOCATION_SCHEMA_ID,
  WALLET_RECEIPT_SCHEMA_ID,
  EXCHANGE_INTENT_SCHEMA_ID,
  TRADE_INTENT_SCHEMA_ID,
  PRINCIPAL_AUTHORITY_BINDING_PROOF_SCHEMA_ID,
  PRINCIPAL_AUTHORITY_RESOLUTION_SCHEMA_ID,
] as const;
