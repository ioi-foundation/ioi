export interface GoalActivationRecovery {
  schemaVersion: "ioi.ai.goal-activation-recovery.v1";
  principal: string;
  idempotencyKey: string;
  goalText: string;
  constraints: string[];
  activationId: string | null;
  createdAt: string;
}

type RecoveryStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function storageKey(principal: string): string {
  return `ioi-ai:goal-activation-recovery:${encodeURIComponent(principal)}`;
}

function boundedText(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function validRecovery(value: unknown, principal: string): value is GoalActivationRecovery {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<GoalActivationRecovery>;
  return (
    candidate.schemaVersion === "ioi.ai.goal-activation-recovery.v1" &&
    candidate.principal === principal &&
    boundedText(candidate.idempotencyKey, 200) &&
    boundedText(candidate.goalText, 32_768) &&
    Array.isArray(candidate.constraints) &&
    candidate.constraints.length <= 128 &&
    candidate.constraints.every((item) => boundedText(item, 4_096)) &&
    (candidate.activationId === null ||
      (typeof candidate.activationId === "string" && /^gra_[A-Za-z0-9_-]{1,156}$/.test(candidate.activationId))) &&
    boundedText(candidate.createdAt, 64)
  );
}

export function createGoalActivationRecovery(
  principal: string,
  goalText: string,
  constraints: string[],
  idempotencyKey: string,
  createdAt = new Date().toISOString(),
): GoalActivationRecovery {
  return {
    schemaVersion: "ioi.ai.goal-activation-recovery.v1",
    principal,
    idempotencyKey,
    goalText,
    constraints: [...constraints],
    activationId: null,
    createdAt,
  };
}

export function readGoalActivationRecovery(storage: RecoveryStorage, principal: string): GoalActivationRecovery | null {
  let parsed: unknown;
  try {
    const raw = storage.getItem(storageKey(principal));
    if (!raw) return null;
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  return validRecovery(parsed, principal) ? parsed : null;
}

export function writeGoalActivationRecovery(storage: RecoveryStorage, recovery: GoalActivationRecovery): void {
  storage.setItem(storageKey(recovery.principal), JSON.stringify(recovery));
}

export function clearGoalActivationRecovery(storage: RecoveryStorage, principal: string): void {
  storage.removeItem(storageKey(principal));
}
