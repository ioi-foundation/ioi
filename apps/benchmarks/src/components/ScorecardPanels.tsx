import type { ReactNode } from "react";

import type {
  CandidatesViewModel,
  DeploymentsViewModel,
  ScorecardViewModel,
} from "../scorecardViewModel";

type ResultPillStatus = "pass" | "near-miss" | "red" | "interrupted" | "unknown";

type OperationalSuiteSummary = {
  suite: string;
  focusResult: ResultPillStatus;
  focusCaseId: string | null;
  counts: Record<ResultPillStatus, number>;
  liveRun: {
    activeCaseId: string | null;
  } | null;
};

type OperationalContextPanelProps = {
  suiteSummaries: OperationalSuiteSummary[];
  liveSuiteCount: number;
  totalCases: number;
  totalPass: number;
  totalRed: number;
  totalInterrupted: number;
  onOpenTriage: (suite: string, caseId: string | null) => void;
  short: (id: string) => string;
  shortCaseId: (id: string | null | undefined) => string;
};

export function ResultPill({ status }: { status: ResultPillStatus }) {
  const icons: Record<ResultPillStatus, string> = {
    pass: "✓",
    "near-miss": "◐",
    red: "✗",
    interrupted: "!",
    unknown: "?",
  };

  return (
    <span className={`pill pill-${status}`}>
      <span className="pill-i">{icons[status]}</span>
      {status}
    </span>
  );
}

export function MatrixBadge({
  tone,
  children,
}: {
  tone: "neutral" | "accent" | "good" | "warn" | "danger";
  children: ReactNode;
}) {
  return <span className={`matrix-badge matrix-badge-${tone}`}>{children}</span>;
}

export function ScorecardHero({ scorecard }: { scorecard: ScorecardViewModel }) {
  return (
    <section className="panel scorecard-hero-panel">
      <div className="scorecard-hero-copy">
        <p className="eyebrow">Living scorecard</p>
        <h2>Benchmark matrix</h2>
        <p className="scorecard-hero-summary">{scorecard.summary}</p>
        <div className="scorecard-ribbon">
          <MatrixBadge tone="accent">{scorecard.statusLabel}</MatrixBadge>
          <MatrixBadge tone="neutral">{scorecard.outcomeLabel}</MatrixBadge>
          <MatrixBadge tone="neutral">{scorecard.freshnessLabel}</MatrixBadge>
          <MatrixBadge tone={scorecard.preservedDefault ? "good" : "warn"}>
            {scorecard.preservedDefault ? "default preserved" : "default changed"}
          </MatrixBadge>
          {scorecard.interruptionLabel && (
            <MatrixBadge tone="warn">interrupted run</MatrixBadge>
          )}
          {scorecard.previewMode && <MatrixBadge tone="warn">preview fixture</MatrixBadge>}
        </div>
        {scorecard.interruptionLabel && (
          <p className="scorecard-hero-summary scorecard-hero-summary-muted">
            {scorecard.interruptionLabel}
          </p>
        )}
      </div>
      <div className="scorecard-hero-stats">
        <article className="artifact-benchmark-stat">
          <span>Current leader</span>
          <strong>{scorecard.leaderLabel}</strong>
        </article>
        <article className="artifact-benchmark-stat">
          <span>Summarized / completed</span>
          <strong>
            {scorecard.summarizedPresetCount} / {scorecard.fullyCompletedPresetCount}
          </strong>
        </article>
        <article className="artifact-benchmark-stat">
          <span>Planned / executed</span>
          <strong>
            {scorecard.plannedPresetCount} / {scorecard.executedPresetCount}
          </strong>
        </article>
        <article className="artifact-benchmark-stat">
          <span>Coverage gaps</span>
          <strong>{scorecard.coverageGapCount}</strong>
        </article>
        <article className="artifact-benchmark-stat">
          <span>Baseline</span>
          <strong>{scorecard.baselineLabel}</strong>
        </article>
      </div>
    </section>
  );
}

export function PresetScorecardBoard({ scorecard }: { scorecard: ScorecardViewModel }) {
  return (
    <section className="panel scorecard-board-panel">
      <div className="panel-head scorecard-board-head">
        <div>
          <p className="eyebrow">At a glance</p>
          <h2>Preset scorecard</h2>
        </div>
        <p className="scorecard-board-note">
          Baseline comparisons use <strong>{scorecard.baselineLabel}</strong>.
        </p>
      </div>

      <div className="scorecard-layout">
        <div className="scorecard-board-wrap">
          <div className="scorecard-board">
            <div
              className="scorecard-board-row scorecard-board-header"
              style={{
                gridTemplateColumns: `minmax(260px, 1.2fr) repeat(${Math.max(
                  scorecard.schemaItems.length,
                  1,
                )}, minmax(140px, 1fr))`,
              }}
            >
              <div className="scorecard-preset-col">
                <span>Preset</span>
                <strong>Role and runtime</strong>
              </div>
              {scorecard.schemaItems.map((item) => (
                <div
                  key={`matrix-head-${item.id}`}
                  className="scorecard-cell scorecard-cell-header"
                >
                  <span>{item.label}</span>
                  <small>{item.qualifier}</small>
                </div>
              ))}
            </div>

            {scorecard.rows.map((row) => (
              <div
                key={row.presetId}
                className={`scorecard-board-row ${
                  row.titleBadges.some((badge) => badge.label === "leader")
                    ? "is-leader"
                    : ""
                } ${
                  row.titleBadges.some((badge) => badge.label === "default")
                    ? "is-baseline"
                    : ""
                }`}
                style={{
                  gridTemplateColumns: `minmax(260px, 1.2fr) repeat(${Math.max(
                    row.cells.length,
                    1,
                  )}, minmax(140px, 1fr))`,
                }}
              >
                <div className="scorecard-preset-col scorecard-preset-body">
                  <div className="scorecard-preset-title">
                    <strong>{row.label}</strong>
                    {row.titleBadges.map((badge) => (
                      <MatrixBadge
                        key={`${row.presetId}-${badge.label}`}
                        tone={badge.tone}
                      >
                        {badge.label}
                      </MatrixBadge>
                    ))}
                  </div>
                  <p>
                    {row.roleLabel} · {row.availabilityLabel}
                  </p>
                  <div className="artifact-benchmark-tags">
                    {row.runtimeTags.map((tag) => (
                      <span key={`${row.presetId}-${tag}`}>{tag}</span>
                    ))}
                  </div>
                  {row.findings && <p className="model-matrix-findings">{row.findings}</p>}
                </div>

                {row.cells.map((cell) => (
                  <article
                    key={`${row.presetId}-${cell.categoryId}`}
                    className={`scorecard-cell ${cell.isBlocked ? "is-blocked" : ""}`}
                  >
                    <div className="scorecard-cell-top">
                      <strong>{cell.primaryValue}</strong>
                      {cell.isBest && <MatrixBadge tone="good">best</MatrixBadge>}
                    </div>
                    <span className="scorecard-cell-label">{cell.metricLabel}</span>
                    <div className="scorecard-cell-badges">
                      {cell.badges.map((badge) => (
                        <MatrixBadge
                          key={`${row.presetId}-${cell.categoryId}-${badge.label}`}
                          tone={badge.tone}
                        >
                          {badge.label}
                        </MatrixBadge>
                      ))}
                    </div>
                    <p className={`scorecard-cell-note scorecard-cell-note-${cell.noteTone}`}>
                      {cell.note}
                    </p>
                  </article>
                ))}
              </div>
            ))}
          </div>
        </div>

        <div className="scorecard-side">
          <div className="artifact-benchmark-side-block">
            <span className="eyebrow">Decision</span>
            <p>{scorecard.summary}</p>
            {scorecard.coverageGaps.length > 0 && (
              <ul>
                {scorecard.coverageGaps.map((entry) => (
                  <li key={`matrix-gap-${entry}`}>{entry}</li>
                ))}
              </ul>
            )}
          </div>
          <div className="artifact-benchmark-side-block">
            <span className="eyebrow">Schema</span>
            <ul>
              {scorecard.schemaItems.map((item) => (
                <li key={`matrix-schema-${item.id}`}>
                  {item.label} · {item.qualifier}
                </li>
              ))}
            </ul>
          </div>
          <div className="artifact-benchmark-side-block">
            <span className="eyebrow">Evidence</span>
            <div className="artifact-benchmark-link-list">
              {scorecard.evidenceLinks.map((link) => (
                <a key={link.label} href={link.href} target="_blank" rel="noreferrer">
                  {link.label} ↗
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export function OperationalContextPanel({
  suiteSummaries,
  liveSuiteCount,
  totalCases,
  totalPass,
  totalRed,
  totalInterrupted,
  onOpenTriage,
  short,
  shortCaseId,
}: OperationalContextPanelProps) {
  return (
    <section className="panel scorecard-context-panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Operational context</p>
          <h2>Suite health</h2>
        </div>
        <div className="artifact-benchmark-headline">
          <span>{suiteSummaries.length} suites</span>
          <span>{totalCases} retained cases</span>
          <span>{liveSuiteCount} live</span>
          <span>{totalRed} reds</span>
          <span>{totalInterrupted} interrupted</span>
        </div>
      </div>

      <div className="scorecard-context-kpis">
        <article className="kpi">
          <span>Retained cases</span>
          <strong>{totalCases}</strong>
        </article>
        <article className="kpi">
          <span>Pass rate</span>
          <strong>{totalCases ? Math.round((totalPass / totalCases) * 100) : 0}%</strong>
        </article>
        <article className="kpi kpi-d">
          <span>Active reds</span>
          <strong>{totalRed}</strong>
        </article>
        <article className="kpi kpi-w">
          <span>Interrupted</span>
          <strong>{totalInterrupted}</strong>
        </article>
        <article className="kpi">
          <span>Live suites</span>
          <strong>{liveSuiteCount}</strong>
        </article>
      </div>

      <div className="hcards">
        {suiteSummaries.map((suite) => {
          const total =
            suite.counts.pass +
            suite.counts["near-miss"] +
            suite.counts.red +
            suite.counts.interrupted +
            suite.counts.unknown;

          return (
            <button
              key={suite.suite}
              type="button"
              className={`hc hc-${suite.focusResult}`}
              onClick={() => onOpenTriage(suite.suite, suite.focusCaseId)}
            >
              <div className="hc-top">
                <h3>{suite.suite}</h3>
                <ResultPill status={suite.focusResult} />
              </div>
              {total > 0 && (
                <div className="hc-cnts">
                  {suite.counts.red > 0 && <span className="hc-r">{suite.counts.red} red</span>}
                  {suite.counts.interrupted > 0 && (
                    <span className="hc-i">{suite.counts.interrupted} interrupted</span>
                  )}
                  {suite.counts["near-miss"] > 0 && (
                    <span className="hc-n">{suite.counts["near-miss"]} near</span>
                  )}
                  {suite.counts.pass > 0 && (
                    <span className="hc-p">{suite.counts.pass} pass</span>
                  )}
                </div>
              )}
              <p className="hc-f">
                {suite.focusCaseId
                  ? short(suite.focusCaseId)
                  : suite.liveRun?.activeCaseId
                    ? shortCaseId(suite.liveRun.activeCaseId)
                    : "No retained cases yet"}
              </p>
              <span className="hc-cta">Open in Triage →</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

export function DeploymentsView({
  deployments,
}: {
  deployments: DeploymentsViewModel;
}) {
  return (
    <div className="dash deployments-page">
      <section className="panel deployments-summary-panel">
        <div className="panel-head deployments-head">
          <div>
            <p className="eyebrow">Deployments</p>
            <h2>Tiered defaults</h2>
          </div>
          <div className="scorecard-ribbon">
            {deployments.previewMode && <MatrixBadge tone="warn">preview fixture</MatrixBadge>}
            <MatrixBadge tone="neutral">read only</MatrixBadge>
          </div>
        </div>
        <p className="deployments-summary">{deployments.summary}</p>
        <p className="deployments-note">{deployments.assignmentNote}</p>
        <div className="deployments-stats">
          {deployments.stats.map((item) => (
            <article key={item.label} className="artifact-benchmark-stat">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </article>
          ))}
        </div>
      </section>

      <section className="panel deployments-grid-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Deployment lanes</p>
            <h2>Selected winners</h2>
          </div>
        </div>
        <div className="deployments-grid">
          {deployments.profiles.map((profile) => (
            <article key={profile.id} className="deployment-card">
              <div className="deployment-card-head">
                <div>
                  <span className="deployment-label">{profile.label}</span>
                  <strong>{profile.winnerLabel}</strong>
                  <p>{profile.sublabel}</p>
                </div>
                <div className="deployment-badges">
                  {profile.badges.map((badge) => (
                    <MatrixBadge
                      key={`${profile.id}-${badge.label}`}
                      tone={badge.tone}
                    >
                      {badge.label}
                    </MatrixBadge>
                  ))}
                </div>
              </div>

              <p className="deployment-summary">{profile.summary}</p>
              {profile.roleLabel && <p className="deployment-role">{profile.roleLabel}</p>}

              {profile.runtimeTags.length > 0 && (
                <div className="artifact-benchmark-tags">
                  {profile.runtimeTags.map((tag) => (
                    <span key={`${profile.id}-${tag}`}>{tag}</span>
                  ))}
                </div>
              )}

              <div className="deployment-divider" />

              <div className="deployment-section">
                <span className="deployment-section-label">Highlights</span>
                {profile.highlights.length > 0 ? (
                  <div className="deployment-highlights">
                    {profile.highlights.map((highlight) => (
                      <div
                        key={`${profile.id}-${highlight.label}`}
                        className="deployment-highlight"
                      >
                        <span>{highlight.label}</span>
                        <strong>{highlight.value}</strong>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="deployment-empty">No retained comparison highlights yet.</p>
                )}
              </div>

              <div className="deployment-section">
                <span className="deployment-section-label">Constraints</span>
                <ul className="deployment-blockers">
                  {profile.blockers.map((blocker) => (
                    <li key={`${profile.id}-${blocker}`}>{blocker}</li>
                  ))}
                </ul>
              </div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

export function CandidatesView({
  candidates,
}: {
  candidates: CandidatesViewModel;
}) {
  return (
    <div className="dash candidates-page">
      <section className="panel candidates-summary-panel">
        <div className="panel-head candidates-head">
          <div>
            <p className="eyebrow">Candidates</p>
            <h2>Retained change review</h2>
          </div>
          <div className="scorecard-ribbon">
            {candidates.previewMode && <MatrixBadge tone="warn">preview fixture</MatrixBadge>}
            <MatrixBadge tone="neutral">read only</MatrixBadge>
          </div>
        </div>
        <p className="candidates-summary">{candidates.summary}</p>
        <p className="candidates-note">{candidates.assignmentNote}</p>
        <div className="candidates-stats">
          {candidates.stats.map((item) => (
            <article key={item.label} className="artifact-benchmark-stat">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </article>
          ))}
        </div>
      </section>

      <section className="panel candidates-grid-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Candidate lane</p>
            <h2>Candidate lineage</h2>
          </div>
        </div>
        <div className="candidates-grid">
          {candidates.candidates.map((candidate) => (
            <article key={candidate.id} className="candidate-card">
              <div className="candidate-card-head">
                <div>
                  <span className="candidate-label">{candidate.deploymentLabel}</span>
                  <strong>{candidate.label}</strong>
                  <p>{candidate.targetFamily}</p>
                </div>
                <div className="candidate-badges">
                  <MatrixBadge tone={candidate.status.tone}>
                    {candidate.status.label}
                  </MatrixBadge>
                </div>
              </div>

              <p className="candidate-summary">{candidate.summary}</p>
              {candidate.roleLabel && <p className="candidate-role">{candidate.roleLabel}</p>}

              {candidate.runtimeTags.length > 0 && (
                <div className="artifact-benchmark-tags">
                  {candidate.runtimeTags.map((tag) => (
                    <span key={`${candidate.id}-${tag}`}>{tag}</span>
                  ))}
                </div>
              )}

              <div className="candidate-divider" />

              <div className="candidate-meta">
                <div className="candidate-meta-block">
                  <span className="candidate-section-label">Lineage</span>
                  <strong>{candidate.lineage}</strong>
                </div>
                <div className="candidate-meta-block">
                  <span className="candidate-section-label">Mutation intent</span>
                  <strong>{candidate.mutationIntent}</strong>
                </div>
              </div>

              <div className="candidate-section">
                <span className="candidate-section-label">Touched surfaces</span>
                <div className="candidate-chip-row">
                  {candidate.touchedSurfaces.map((surface) => (
                    <span key={`${candidate.id}-${surface}`} className="candidate-chip">
                      {surface}
                    </span>
                  ))}
                </div>
              </div>

              <div className="candidate-section">
                <span className="candidate-section-label">Validation</span>
                <div className="candidate-metric-grid">
                  {candidate.validationReadings.map((reading) => (
                    <div
                      key={`${candidate.id}-${reading.label}`}
                      className="candidate-metric"
                    >
                      <span>{reading.label}</span>
                      <strong>{reading.value}</strong>
                    </div>
                  ))}
                </div>
              </div>

              <div className="candidate-section">
                <span className="candidate-section-label">Regressions</span>
                <ul className="candidate-list">
                  {candidate.regressions.map((item) => (
                    <li key={`${candidate.id}-${item}`}>{item}</li>
                  ))}
                </ul>
              </div>

              {candidate.evidenceLinks.length > 0 && (
                <div className="candidate-link-row">
                  {candidate.evidenceLinks.map((link) => (
                    <a key={`${candidate.id}-${link.label}`} href={link.href} target="_blank" rel="noreferrer">
                      {link.label} ↗
                    </a>
                  ))}
                </div>
              )}
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
