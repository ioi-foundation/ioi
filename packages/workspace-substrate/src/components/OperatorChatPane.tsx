import type { ReactNode } from "react";
import clsx from "clsx";

export type OperatorChatPaneMode =
  | "full"
  | "sidebar"
  | "docked"
  | "embedded"
  | "floating";

export interface OperatorChatPaneAction {
  id: string;
  label: string;
  icon?: ReactNode;
  title?: string;
  active?: boolean;
  disabled?: boolean;
  onClick?: () => void;
}

export interface OperatorChatEmptyStateModel {
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  footer?: ReactNode;
}

export interface OperatorChatPaneProps {
  mode: OperatorChatPaneMode;
  label?: string;
  tabLabel?: string;
  className?: string;
  sidebar?: ReactNode;
  children?: ReactNode;
  composer?: ReactNode;
  artifactDrawer?: ReactNode;
  artifactDrawerVisible?: boolean;
  artifactMenuVisible?: boolean;
  emptyState?: OperatorChatEmptyStateModel;
  suggestedActions?: ReactNode;
  leadingControls?: ReactNode;
  primaryActions?: OperatorChatPaneAction[];
  secondaryActions?: OperatorChatPaneAction[];
  trailingControls?: ReactNode;
  dataOperatorChatPane?: string;
  dataInspectionTarget?: string;
  dataChatPaneMode?: string;
  onTabClick?: () => void;
}

function renderAction(action: OperatorChatPaneAction) {
  return (
    <button
      key={action.id}
      type="button"
      className={clsx(
        "operator-chat-pane__action",
        action.active && "is-active",
      )}
      aria-label={action.label}
      title={action.title ?? action.label}
      data-operator-chat-control={action.id}
      disabled={action.disabled}
      onClick={action.onClick}
    >
      {action.icon ? (
        <span className="operator-chat-pane__action-icon" aria-hidden="true">
          {action.icon}
        </span>
      ) : null}
    </button>
  );
}

function OperatorChatEmptyState({
  emptyState,
  suggestedActions,
}: {
  emptyState: OperatorChatEmptyStateModel;
  suggestedActions?: ReactNode;
}) {
  return (
    <div className="operator-chat-pane__empty">
      {emptyState.icon ? (
        <div className="operator-chat-pane__empty-icon" aria-hidden="true">
          {emptyState.icon}
        </div>
      ) : null}
      <h3>{emptyState.title}</h3>
      {emptyState.description ? <p>{emptyState.description}</p> : null}
      {suggestedActions ? (
        <div className="operator-chat-pane__suggestions">
          <div className="operator-chat-pane__section-label">
            Suggested Actions
          </div>
          <div className="operator-chat-pane__suggestion-row">
            {suggestedActions}
          </div>
        </div>
      ) : null}
      {emptyState.footer ? (
        <div className="operator-chat-pane__empty-footer">
          {emptyState.footer}
        </div>
      ) : null}
    </div>
  );
}

export function OperatorChatPane({
  mode,
  label = "Operator chat",
  tabLabel = "Chat",
  className,
  sidebar,
  children,
  composer,
  artifactDrawer,
  artifactDrawerVisible = false,
  artifactMenuVisible = false,
  emptyState,
  suggestedActions,
  leadingControls,
  primaryActions = [],
  secondaryActions = [],
  trailingControls,
  dataOperatorChatPane,
  dataInspectionTarget,
  dataChatPaneMode,
  onTabClick,
}: OperatorChatPaneProps) {
  const tab = (
    <button
      type="button"
      className="operator-chat-pane__tab is-active"
      data-operator-chat-control="tab"
      onClick={onTabClick}
    >
      {tabLabel}
    </button>
  );

  return (
    <section
      className={clsx(
        "operator-chat-pane",
        `operator-chat-pane--${mode}`,
        sidebar && "has-sidebar",
        artifactDrawerVisible && "has-artifact-drawer",
        artifactMenuVisible && "has-artifact-menu",
        className,
      )}
      aria-label={label}
      data-operator-chat-pane={dataOperatorChatPane ?? mode}
      data-inspection-target={dataInspectionTarget ?? "operator-chat-pane"}
      data-chat-pane-mode={dataChatPaneMode ?? mode}
    >
      {sidebar ? (
        <div className="operator-chat-pane__sidebar">{sidebar}</div>
      ) : null}

      <div className="operator-chat-pane__main">
        <header className="operator-chat-pane__header">
          {tab}
          <div
            className="operator-chat-pane__drag-region"
            data-tauri-drag-region
            aria-hidden="true"
          />
          <div
            className="operator-chat-pane__actions"
            aria-label={`${tabLabel} actions`}
          >
            {leadingControls ? (
              <span className="operator-chat-pane__control-slot">
                {leadingControls}
              </span>
            ) : null}
            {primaryActions.map(renderAction)}
            {secondaryActions.length > 0 ? (
              <span className="operator-chat-pane__divider" aria-hidden="true" />
            ) : null}
            {secondaryActions.map(renderAction)}
            {trailingControls ? (
              <span className="operator-chat-pane__control-slot">
                {trailingControls}
              </span>
            ) : null}
          </div>
        </header>

        <div className="operator-chat-pane__body">
          {children ??
            (emptyState ? (
              <OperatorChatEmptyState
                emptyState={emptyState}
                suggestedActions={suggestedActions}
              />
            ) : null)}
        </div>

        {composer ? (
          <div
            className="operator-chat-pane__composer"
            data-inspection-target="workspace-chat-composer"
          >
            {composer}
          </div>
        ) : null}
      </div>

      {artifactDrawerVisible ? artifactDrawer : null}
    </section>
  );
}
