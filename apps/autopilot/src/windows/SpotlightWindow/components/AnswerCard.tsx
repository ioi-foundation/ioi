import { useCallback, useMemo, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type {
  AnswerPresentation,
  ChatContractResultColumn,
  ChatContractResultRow,
  ChatContractScalar,
  ChatContractValue,
  SourceSummary,
} from "../../../types";
import { icons } from "./Icons";
import { MarkdownMessage } from "./MarkdownMessage";

interface AnswerCardProps {
  answer: AnswerPresentation;
  sourceSummary: SourceSummary | null;
  sourceDurationLabel?: string;
  onDownloadContext: () => Promise<void> | void;
  onOpenArtifacts?: () => void;
  onOpenSources?: (summary: SourceSummary) => void;
}

const MAX_CITATION_PILLS = 8;
const MAX_RESULT_ROWS = 8;

function formatTitleCase(value: string): string {
  return value
    .replace(/_/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatScalar(value: ChatContractScalar): string {
  if (value === null) return "null";
  return String(value);
}

function formatValue(value: ChatContractValue): string {
  if (Array.isArray(value)) {
    return value.map((entry) => formatScalar(entry)).join(", ");
  }
  return formatScalar(value);
}

function deriveResultColumns(rows: ChatContractResultRow[]): ChatContractResultColumn[] {
  if (rows.length === 0) {
    return [];
  }
  return Object.keys(rows[0]).map((key) => ({
    key,
    label: formatTitleCase(key),
  }));
}

function rowCellValue(row: ChatContractResultRow, key: string): string {
  const cell = row[key];
  if (cell === undefined) return "—";
  return formatScalar(cell);
}

export function AnswerCard({
  answer,
  sourceSummary,
  sourceDurationLabel,
  onDownloadContext,
  onOpenArtifacts,
  onOpenSources,
}: AnswerCardProps) {
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const citations = useMemo(
    () => answer.citations.slice(0, MAX_CITATION_PILLS),
    [answer.citations],
  );
  const contract = answer.contract;
  const interpretationEntries = useMemo(
    () => (contract ? Object.entries(contract.interpretation) : []),
    [contract],
  );
  const resultRows = useMemo(
    () => (contract ? contract.result_rows.slice(0, MAX_RESULT_ROWS) : []),
    [contract],
  );
  const resultColumns = useMemo(() => {
    if (!contract) return [];
    if (contract.result_columns && contract.result_columns.length > 0) {
      return contract.result_columns;
    }
    return deriveResultColumns(resultRows);
  }, [contract, resultRows]);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(answer.copyText);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }, [answer.copyText]);

  const handleOpenCitation = useCallback(async (url: string) => {
    try {
      await openUrl(url);
    } catch {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }, []);

  const handleDownload = useCallback(async () => {
    setDownloading(true);
    try {
      await onDownloadContext();
    } finally {
      setDownloading(false);
    }
  }, [onDownloadContext]);

  const handleOpenArtifacts = useCallback(() => {
    onOpenArtifacts?.();
  }, [onOpenArtifacts]);

  const sourcePreviewDomains = useMemo(
    () => sourceSummary?.domains.slice(0, 4) || [],
    [sourceSummary],
  );
  const canOpenSources = !!sourceSummary && sourceSummary.totalSources > 0 && !!onOpenSources;

  return (
    <section className="answer-card" aria-label="Final answer">
      <div className="answer-card-header">
        <div className="answer-card-title-wrap">
          <div className="answer-card-eyebrow">Results</div>
          <h3 className="answer-card-title">Autopilot</h3>
        </div>
        <div className="answer-card-actions">
          <button
            className={`answer-action-btn ${copied ? "success" : ""}`}
            onClick={handleCopy}
            title="Copy answer"
            type="button"
          >
            {copied ? icons.check : icons.copy}
            <span>{copied ? "Copied" : "Copy"}</span>
          </button>
          <button
            className="answer-action-btn"
            onClick={() => void handleDownload()}
            type="button"
            disabled={downloading}
            title="Download full context"
          >
            {icons.code}
            <span>{downloading ? "Exporting..." : "Download Context"}</span>
          </button>
          <button
            className="answer-action-btn"
            onClick={handleOpenArtifacts}
            type="button"
            disabled={!onOpenArtifacts}
            title="Open evidence drawer"
          >
            {icons.externalLink}
            <span>Evidence</span>
          </button>
        </div>
      </div>

      <div className="answer-card-body">
        {contract ? (
          <div className="answer-contract">
            {answer.displayText.trim().length > 0 && (
              <div className="answer-contract-summary">
                <MarkdownMessage text={answer.displayText} />
              </div>
            )}

            <section className="answer-contract-block" aria-label="Outcome">
              <h4>Outcome</h4>
              <p>
                <strong>{contract.outcome.status}</strong>
                {typeof contract.outcome.count === "number"
                  ? ` • ${contract.outcome.count} result${contract.outcome.count === 1 ? "" : "s"}`
                  : ""}
                {contract.outcome.summary ? ` • ${contract.outcome.summary}` : ""}
              </p>
            </section>

            {interpretationEntries.length > 0 && (
              <section className="answer-contract-block" aria-label="Interpretation">
                <h4>Interpretation</h4>
                <dl className="answer-contract-kv">
                  {interpretationEntries.map(([key, value]) => (
                    <div key={key} className="answer-contract-kv-row">
                      <dt>{formatTitleCase(key)}</dt>
                      <dd>{formatValue(value)}</dd>
                    </div>
                  ))}
                </dl>
              </section>
            )}

            {resultRows.length > 0 && resultColumns.length > 0 && (
              <section className="answer-contract-block" aria-label="Results">
                <h4>Results</h4>
                <div className="answer-contract-table-wrap">
                  <table className="answer-contract-table">
                    <thead>
                      <tr>
                        {resultColumns.map((column) => (
                          <th key={column.key}>{column.label}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {resultRows.map((row, rowIndex) => (
                        <tr key={`row-${rowIndex}`}>
                          {resultColumns.map((column) => (
                            <td key={`${rowIndex}-${column.key}`}>{rowCellValue(row, column.key)}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {contract.result_rows.length > MAX_RESULT_ROWS && (
                  <p className="answer-contract-note">
                    Showing {MAX_RESULT_ROWS} of {contract.result_rows.length} rows.
                  </p>
                )}
              </section>
            )}

            {!!contract.actions?.length && (
              <section className="answer-contract-block" aria-label="Actions">
                <h4>Actions</h4>
                <div className="answer-contract-actions">
                  {contract.actions.map((action) => (
                    <span key={action.id} className="answer-contract-action-chip" title={action.id}>
                      {action.label}
                    </span>
                  ))}
                </div>
              </section>
            )}

            {!!contract.artifact_ref && !!onOpenArtifacts && (
              <button
                className="answer-contract-artifact-link"
                type="button"
                onClick={handleOpenArtifacts}
              >
                View supporting output
              </button>
            )}
          </div>
        ) : (
          <MarkdownMessage text={answer.displayText} />
        )}
      </div>

      {citations.length > 0 && (
        <div className="answer-citations" aria-label="Citations">
          {citations.map((citation, idx) => (
            <button
              key={`${citation}-${idx}`}
              className="answer-citation-pill"
              onClick={() => void handleOpenCitation(citation)}
              type="button"
              title={citation}
            >
              <span className="citation-index">[{idx + 1}]</span>
              <span className="citation-url">{citation}</span>
            </button>
          ))}
        </div>
      )}

      {sourceSummary && sourceSummary.totalSources > 0 && (
        <div className="answer-source-strip">
          <button
            className="answer-source-chip"
            type="button"
            onClick={() => sourceSummary && onOpenSources?.(sourceSummary)}
            aria-label={`${sourceSummary.totalSources} sources`}
            title="Open source activity"
            disabled={!canOpenSources}
          >
            {sourceDurationLabel && (
              <span className="answer-source-latency">{sourceDurationLabel}</span>
            )}
            <span className="answer-source-favicon-stack">
              {sourcePreviewDomains.map((entry, index) => (
                <span
                  key={`${entry.domain}-${index}`}
                  className="answer-source-favicon-wrap"
                  style={{
                    zIndex: sourcePreviewDomains.length - index,
                    marginLeft: index === 0 ? 0 : -10,
                  }}
                >
                  <img
                    className="answer-source-favicon"
                    src={entry.faviconUrl}
                    alt={`${entry.domain} favicon`}
                    loading="lazy"
                  />
                </span>
              ))}
            </span>
            <span className="answer-source-chip-label">
              {sourceSummary.totalSources}{" "}
              {sourceSummary.totalSources === 1 ? "source" : "sources"}
            </span>
          </button>
        </div>
      )}
    </section>
  );
}
