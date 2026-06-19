export {
  assertCandidateSourceAdapter,
  buildCandidateEvidenceFromSourceAdapter,
  exchangeRouteSourceAdapter,
  tradeVenueSourceAdapter,
} from "@ioi/wallet-protocol";

import {
  assertCandidateEvidenceExecutable,
  assertCandidateSourceAdapter,
  exchangeRouteSourceAdapter,
  tradeVenueSourceAdapter,
  type CandidateEvidence,
  type CandidateEvidenceValidationOptions,
  type WalletCandidateSourceAdapter,
} from "@ioi/wallet-protocol";

export type {
  BuildCandidateEvidenceInput,
  CandidateSourceDomain,
} from "@ioi/wallet-protocol";

export type {
  CandidateEvidence,
  CandidateEvidenceValidationOptions,
  WalletCandidateSourceAdapter,
};

export type CandidateSourceHttpFetch = (
  url: string,
  init: {
    readonly method: "POST";
    readonly headers: Readonly<Record<string, string>>;
    readonly body: string;
  },
) => Promise<{
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
  text?(): Promise<string>;
}>;

export interface CandidateSourceHttpClientOptions {
  readonly base_url: string;
  readonly fetch?: CandidateSourceHttpFetch;
  readonly headers?: Readonly<Record<string, string>>;
  readonly validation?: CandidateEvidenceValidationOptions;
}

export interface CandidateSourceHttpRequest {
  readonly adapter: WalletCandidateSourceAdapter;
  readonly path?: string;
  readonly body?: Readonly<Record<string, unknown>>;
  readonly validation?: CandidateEvidenceValidationOptions;
}

export interface CandidateSourceDomainRequest {
  readonly adapter_id: string;
  readonly source: string;
  readonly body?: Readonly<Record<string, unknown>>;
  readonly path?: string;
  readonly validation?: CandidateEvidenceValidationOptions;
}

export interface CandidateSourceHttpClient {
  readonly requestCandidateEvidence: (
    request: CandidateSourceHttpRequest,
  ) => Promise<readonly CandidateEvidence[]>;
  readonly getExchangeRouteCandidates: (
    request: CandidateSourceDomainRequest,
  ) => Promise<readonly CandidateEvidence[]>;
  readonly getTradeVenueCandidates: (
    request: CandidateSourceDomainRequest,
  ) => Promise<readonly CandidateEvidence[]>;
}

export const DECENTRALIZED_EXCHANGE_SOURCE = "decentralized.exchange" as const;
export const DECENTRALIZED_EXCHANGE_ROUTE_ADAPTER_ID =
  "adapter:decentralized-exchange" as const;
export const DECENTRALIZED_TRADE_SOURCE = "decentralized.trade" as const;
export const DECENTRALIZED_TRADE_VENUE_ADAPTER_ID =
  "adapter:decentralized-trade" as const;

export const DECENTRALIZED_EXCHANGE_ROUTE_ADAPTER =
  exchangeRouteSourceAdapter({
    adapter_id: DECENTRALIZED_EXCHANGE_ROUTE_ADAPTER_ID,
    source: DECENTRALIZED_EXCHANGE_SOURCE,
  });

export const DECENTRALIZED_TRADE_VENUE_ADAPTER = tradeVenueSourceAdapter({
  adapter_id: DECENTRALIZED_TRADE_VENUE_ADAPTER_ID,
  source: DECENTRALIZED_TRADE_SOURCE,
});

export interface FirstPartyCandidateSourceRequest {
  readonly body?: Readonly<Record<string, unknown>>;
  readonly path?: string;
  readonly validation?: CandidateEvidenceValidationOptions;
}

export interface DecentralizedExchangeCandidateSourceClient {
  readonly adapter: WalletCandidateSourceAdapter;
  readonly getRouteCandidates: (
    request?: FirstPartyCandidateSourceRequest,
  ) => Promise<readonly CandidateEvidence[]>;
}

export interface DecentralizedTradeCandidateSourceClient {
  readonly adapter: WalletCandidateSourceAdapter;
  readonly getVenueCandidates: (
    request?: FirstPartyCandidateSourceRequest,
  ) => Promise<readonly CandidateEvidence[]>;
}

export function createHttpCandidateSourceClient(
  options: CandidateSourceHttpClientOptions,
): CandidateSourceHttpClient {
  const resolvedFetch =
    options.fetch ??
    (globalThis as { readonly fetch?: CandidateSourceHttpFetch }).fetch;
  if (!resolvedFetch) {
    throw new Error("wallet candidate source HTTP client requires fetch");
  }
  const fetchImpl: CandidateSourceHttpFetch = resolvedFetch;
  const baseUrl = normalizeBaseUrl(options.base_url);
  const defaultValidation = options.validation ?? {};

  async function requestCandidateEvidence(
    request: CandidateSourceHttpRequest,
  ): Promise<readonly CandidateEvidence[]> {
    const adapter = assertCandidateSourceAdapter(request.adapter);
    const response = await fetchImpl(urlFor(baseUrl, request.path ?? defaultPathFor(adapter)), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(options.headers ?? {}),
      },
      body: JSON.stringify({
        ...(request.body ?? {}),
        adapter_id: adapter.adapter_id,
        source: adapter.source,
        domain: adapter.domain,
        candidate_kind: adapter.candidate_kind,
      }),
    });

    const payload = await response.json().catch(async () => ({
      error: typeof response.text === "function" ? await response.text() : "",
    }));
    if (!response.ok) {
      throw new Error(
        `wallet candidate source ${adapter.adapter_id} returned HTTP ${response.status}`,
      );
    }
    return extractCandidateEvidence(payload).map((candidate) =>
      validateAdapterEvidence(candidate, adapter, {
        ...defaultValidation,
        ...(request.validation ?? {}),
      }),
    );
  }

  return {
    requestCandidateEvidence,
    getExchangeRouteCandidates(request) {
      return requestCandidateEvidence({
        adapter: {
          adapter_id: request.adapter_id,
          source: request.source,
          domain: "exchange",
          candidate_kind: "route_candidate",
          trust_boundary: "candidate_source_only",
          evidence_policy: "claims_plus_refs_required",
        },
        path: request.path,
        body: request.body,
        validation: request.validation,
      });
    },
    getTradeVenueCandidates(request) {
      return requestCandidateEvidence({
        adapter: {
          adapter_id: request.adapter_id,
          source: request.source,
          domain: "trade",
          candidate_kind: "venue_candidate",
          trust_boundary: "candidate_source_only",
          evidence_policy: "claims_plus_refs_required",
        },
        path: request.path,
        body: request.body,
        validation: request.validation,
      });
    },
  };
}

export function createDecentralizedExchangeCandidateSourceClient(
  options: CandidateSourceHttpClientOptions,
): DecentralizedExchangeCandidateSourceClient {
  const client = createHttpCandidateSourceClient(options);
  return {
    adapter: DECENTRALIZED_EXCHANGE_ROUTE_ADAPTER,
    getRouteCandidates(request = {}) {
      return client.requestCandidateEvidence({
        adapter: DECENTRALIZED_EXCHANGE_ROUTE_ADAPTER,
        path: request.path,
        body: request.body,
        validation: request.validation,
      });
    },
  };
}

export function createDecentralizedTradeCandidateSourceClient(
  options: CandidateSourceHttpClientOptions,
): DecentralizedTradeCandidateSourceClient {
  const client = createHttpCandidateSourceClient(options);
  return {
    adapter: DECENTRALIZED_TRADE_VENUE_ADAPTER,
    getVenueCandidates(request = {}) {
      return client.requestCandidateEvidence({
        adapter: DECENTRALIZED_TRADE_VENUE_ADAPTER,
        path: request.path,
        body: request.body,
        validation: request.validation,
      });
    },
  };
}

function validateAdapterEvidence(
  candidate: CandidateEvidence,
  adapter: WalletCandidateSourceAdapter,
  validation: CandidateEvidenceValidationOptions,
): CandidateEvidence {
  const evidence = assertCandidateEvidenceExecutable(candidate, validation);
  if (evidence.adapter_id !== adapter.adapter_id || evidence.source !== adapter.source) {
    throw new Error(
      "wallet candidate source evidence must match the declared adapter and source",
    );
  }
  return evidence;
}

function extractCandidateEvidence(payload: unknown): CandidateEvidence[] {
  if (Array.isArray(payload)) return payload as CandidateEvidence[];
  if (payload && typeof payload === "object") {
    const body = payload as {
      readonly candidate_evidence?: unknown;
      readonly candidates?: unknown;
    };
    if (Array.isArray(body.candidate_evidence)) {
      return body.candidate_evidence as CandidateEvidence[];
    }
    if (Array.isArray(body.candidates)) {
      return body.candidates.map((candidate) => {
        if (candidate && typeof candidate === "object") {
          const candidateObject = candidate as { readonly candidate_evidence?: unknown };
          if (candidateObject.candidate_evidence) {
            return candidateObject.candidate_evidence as CandidateEvidence;
          }
        }
        return candidate as CandidateEvidence;
      });
    }
  }
  throw new Error("wallet candidate source response must include candidate evidence");
}

function defaultPathFor(adapter: WalletCandidateSourceAdapter): string {
  if (adapter.domain === "exchange") return "/v1/route-candidates";
  return "/v1/venue-candidates";
}

function normalizeBaseUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error("wallet candidate source base_url is required");
  return trimmed.replace(/\/+$/, "");
}

function urlFor(baseUrl: string, path: string): string {
  if (/^https?:\/\//.test(path)) return path;
  return `${baseUrl}/${path.replace(/^\/+/, "")}`;
}
