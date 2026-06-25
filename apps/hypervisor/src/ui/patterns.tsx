// Hypervisor UX kit — Layer 4 composition primitives + cross-cutting contract panels (slice 1 set).
// Token-pure (kit.css classes). The breadth skeletons (ListDetail/ObjectView/MonitoringConsole/
// Dashboard/ReviewInbox/Wizard/TraceTimeline) land in Slice 2 with their surfaces.
import type { ReactNode } from "react";
import { Badge, Tertiary } from "./primitives";

const cx = (...c: Array<string | false | undefined>) => c.filter(Boolean).join(" ");

/** Readiness mode → product-language badge. */
export function ReadinessBadge({ mode }: { mode?: string }) {
  const tone = mode === "full" ? "success" : mode === "degraded" ? "warning" : "danger";
  return <Badge tone={tone}>{mode ?? "unknown"}</Badge>;
}

/** Typed environment component grid (provisioner/sandbox/recipe/…). */
export function ComponentGrid({ components }: { components?: Record<string, { phase?: string }> }) {
  const entries = Object.entries(components ?? {});
  if (!entries.length) return null;
  return (
    <div className="hv-grid" data-testid="component-grid">
      {entries.map(([name, c]) => (
        <div key={name} className="hv-comp">
          <div className="hv-comp__name">{name}</div>
          <div className={cx("hv-comp__phase", c.phase === "ready" && "hv-comp__phase--ready")}>{c.phase ?? "—"}</div>
        </div>
      ))}
    </div>
  );
}

/** Evidence / receipt refs (advanced-label surface for proof drilldown). */
export function ReceiptRefs({ refs }: { refs: string[] }) {
  if (!refs?.length) return null;
  return (
    <ul className="hv-receipts" data-testid="receipt-refs">
      {refs.map((r) => <li key={r}>{r}</li>)}
    </ul>
  );
}

/** A named, fail-closed blocker with reason (+ optional remedy). */
export function BlockerNotice({ reasons, remedy }: { reasons?: string[]; remedy?: string }) {
  if (!reasons?.length) return null;
  return <div className="hv-blocker" data-testid="blocker">Blocked: {reasons.join("; ")}{remedy ? ` — ${remedy}` : ""}</div>;
}

/**
 * Cross-cutting Product Label Contract: an effectful action carries BOTH a productLabel (normal UI)
 * and an advancedLabel (audit/proof drawer). Disabled with a blocker reason when not permitted.
 */
export function AuthorityControl({
  productLabel, advancedLabel, onAct, disabled, blockedReason, testId,
}: { productLabel: string; advancedLabel: string; onAct?: () => void; disabled?: boolean; blockedReason?: string; testId?: string }) {
  return (
    <span className="hv-authority" title={advancedLabel} data-testid={testId}>
      <button className={cx("hv-btn", "hv-btn--sm")} onClick={onAct} disabled={disabled} title={disabled && blockedReason ? blockedReason : advancedLabel}>
        {productLabel}
      </button>
      {disabled && blockedReason && <Tertiary>{blockedReason}</Tertiary>}
    </span>
  );
}

/** Generic empty/placeholder state for not-yet-built surfaces. */
export function EmptyState({ title, hint, children }: { title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="hv-col" data-testid="empty-state">
      <div className="hv-h2">{title}</div>
      {hint && <span className="hv-muted">{hint}</span>}
      {children}
    </div>
  );
}
