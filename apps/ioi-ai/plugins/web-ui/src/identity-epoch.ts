let identityEpoch = 0;

export class IdentityEpochChangedError extends Error {
  constructor() {
    super("The authenticated principal changed while the request was in flight.");
    this.name = "IdentityEpochChangedError";
  }
}

export function advanceIdentityEpoch(): number {
  identityEpoch += 1;
  return identityEpoch;
}

export function captureIdentityEpoch(): number {
  return identityEpoch;
}

export function assertIdentityEpoch(epoch: number): void {
  if (epoch !== identityEpoch) throw new IdentityEpochChangedError();
}

export function isIdentityEpochChanged(error: unknown): error is IdentityEpochChangedError {
  return error instanceof IdentityEpochChangedError;
}
