export type IoiAgentErrorCode =
  | "auth"
  | "config"
  | "policy"
  | "rate_limit"
  | "network"
  | "model"
  | "tool"
  | "verifier"
  | "postcondition"
  | "not_found"
  | "external_blocker"
  | "runtime";

export interface IoiAgentErrorOptions {
  code: IoiAgentErrorCode;
  message: string;
  status?: number;
  retryable?: boolean;
  requestId?: string;
  cause?: unknown;
  details?: Record<string, unknown>;
}

export class IoiAgentError extends Error {
  readonly code: IoiAgentErrorCode;
  readonly status: number;
  readonly retryable: boolean;
  readonly requestId?: string;
  readonly details: Record<string, unknown>;

  constructor(options: IoiAgentErrorOptions) {
    super(options.message);
    this.name = "IoiAgentError";
    this.code = options.code;
    this.status = options.status ?? defaultStatusForCode(options.code);
    this.retryable = options.retryable ?? defaultRetryableForCode(options.code);
    this.requestId = options.requestId;
    this.details = options.details ?? {};
    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      status: this.status,
      retryable: this.retryable,
      requestId: this.requestId,
      details: this.details,
    };
  }
}

export function ensureIoiAgentError(error: unknown): IoiAgentError {
  if (error instanceof IoiAgentError) {
    return error;
  }
  if (error instanceof Error) {
    return new IoiAgentError({
      code: "runtime",
      message: error.message,
      cause: error,
      retryable: false,
    });
  }
  return new IoiAgentError({
    code: "runtime",
    message: String(error),
    retryable: false,
  });
}

function defaultStatusForCode(code: IoiAgentErrorCode): number {
  switch (code) {
    case "auth":
      return 401;
    case "config":
      return 400;
    case "policy":
      return 403;
    case "rate_limit":
      return 429;
    case "network":
      return 503;
    case "model":
      return 502;
    case "tool":
    case "verifier":
    case "postcondition":
      return 422;
    case "not_found":
      return 404;
    case "external_blocker":
      return 424;
    case "runtime":
      return 500;
  }
}

function defaultRetryableForCode(code: IoiAgentErrorCode): boolean {
  return code === "rate_limit" || code === "network" || code === "model";
}
