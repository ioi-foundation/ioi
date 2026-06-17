import type { SessionRewindCandidate, SessionRewindSnapshot } from "../../../types";

export function selectFocusedRewindCandidate(
  snapshot: SessionRewindSnapshot | null,
  selectedSessionId: string | null,
): SessionRewindCandidate | null {
  const candidates = snapshot?.candidates ?? [];
  if (candidates.length === 0) {
    return null;
  }

  if (selectedSessionId) {
    const selected = candidates.find(
      (candidate) => candidate.sessionId === selectedSessionId,
    );
    if (selected) {
      return selected;
    }
  }

  return (
    candidates.find((candidate) => candidate.isLastStable) ||
    candidates[0] ||
    null
  );
}

export function canCompareFocusedRewindCandidate(
  activeSessionId: string | null | undefined,
  candidate: SessionRewindCandidate | null,
): boolean {
  return Boolean(activeSessionId && candidate && candidate.sessionId !== activeSessionId);
}
