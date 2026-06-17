export const AUTHORITY_REVIEW_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/authority-review.schema.json" as const;

export const CAPABILITY_LEASE_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/capability-lease.schema.json" as const;

export const WALLET_RECEIPT_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/wallet-receipt.schema.json" as const;

export const EXCHANGE_INTENT_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/exchange-intent.schema.json" as const;

export const TRADE_INTENT_SCHEMA_ID =
  "https://schemas.ioi.network/wallet/trade-intent.schema.json" as const;

export const WALLET_PROTOCOL_SCHEMA_IDS = [
  AUTHORITY_REVIEW_SCHEMA_ID,
  CAPABILITY_LEASE_SCHEMA_ID,
  WALLET_RECEIPT_SCHEMA_ID,
  EXCHANGE_INTENT_SCHEMA_ID,
  TRADE_INTENT_SCHEMA_ID,
] as const;
