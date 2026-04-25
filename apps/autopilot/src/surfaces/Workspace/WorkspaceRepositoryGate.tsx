import {
  ArrowLeft,
  Check,
  ChevronRight,
  ExternalLink,
  FolderOpen,
  GitPullRequest,
  Plus,
  Search,
  Star,
} from "lucide-react";
import { createElement, useMemo, useState, type ComponentType } from "react";

import {
  createUniqueRepositorySlug,
  getGeneratedRepositoryPath,
  slugifyRepositoryName,
  type WorkspaceRepositoryCategory,
  type WorkspaceRepositoryRecord,
} from "../../services/workspaceRepositoryRegistry";

interface WorkspaceRepositoryCategoryOption {
  id: WorkspaceRepositoryCategory;
  label: string;
  summary: string;
}

interface WorkspaceRepositoryTemplateOption {
  id: string;
  label: string;
  language: string;
  summary: string;
  recommended?: boolean;
}

export interface WorkspaceRepositoryCreateRequest {
  name: string;
  category: WorkspaceRepositoryCategory;
  categoryLabel: string;
  template: string;
  templateLabel: string;
}

interface WorkspaceRepositoryGateProps {
  repositories: WorkspaceRepositoryRecord[];
  createError: string | null;
  creating: boolean;
  onCreateRepository: (request: WorkspaceRepositoryCreateRequest) => void;
  onOpenRepository: (repository: WorkspaceRepositoryRecord) => void;
  onToggleFavorite: (repository: WorkspaceRepositoryRecord) => void;
}

type CreateStep = "landing" | "category" | "template" | "details";

type IconProps = {
  size?: number;
  strokeWidth?: number;
  fill?: string;
  className?: string;
  "aria-hidden"?: boolean | "true" | "false";
};

function renderIcon(Icon: unknown, props: IconProps = {}) {
  return createElement(Icon as ComponentType<IconProps>, props);
}

const CATEGORY_OPTIONS: WorkspaceRepositoryCategoryOption[] = [
  {
    id: "pipelines",
    label: "Pipelines",
    summary: "Data movement and orchestration repositories.",
  },
  {
    id: "functions",
    label: "Functions",
    summary: "Small services and event handlers.",
  },
  {
    id: "analytics",
    label: "Analytics",
    summary: "Notebooks, dashboards, and reporting workspaces.",
  },
  {
    id: "models",
    label: "Models",
    summary: "Model training and evaluation repositories.",
  },
  {
    id: "applications",
    label: "Applications",
    summary: "Full application projects and UI surfaces.",
  },
];

const TEMPLATE_OPTIONS: Record<
  WorkspaceRepositoryCategory,
  WorkspaceRepositoryTemplateOption[]
> = {
  pipelines: [
    {
      id: "python",
      label: "Python",
      language: "Python",
      summary: "Pipeline project with a Python-first workflow.",
      recommended: true,
    },
    {
      id: "sql",
      label: "SQL",
      language: "SQL",
      summary: "Transformation project centered on SQL assets.",
    },
    {
      id: "typescript",
      label: "TypeScript",
      language: "TypeScript",
      summary: "Pipeline utilities with typed automation.",
    },
  ],
  functions: [
    {
      id: "python",
      label: "Python",
      language: "Python",
      summary: "Function project with lightweight handlers.",
      recommended: true,
    },
    {
      id: "typescript",
      label: "TypeScript",
      language: "TypeScript",
      summary: "Typed functions and integration glue.",
    },
    {
      id: "java",
      label: "Java",
      language: "Java",
      summary: "Service functions for JVM teams.",
    },
  ],
  analytics: [
    {
      id: "jupyter",
      label: "Jupyter",
      language: "Python",
      summary: "Notebook-oriented analysis repository.",
      recommended: true,
    },
    {
      id: "r",
      label: "R",
      language: "R",
      summary: "Statistical analysis and reporting workspace.",
    },
    {
      id: "sql",
      label: "SQL",
      language: "SQL",
      summary: "Reusable queries and dashboard sources.",
    },
  ],
  models: [
    {
      id: "training",
      label: "Training",
      language: "Python",
      summary: "Training scripts, features, and artifacts.",
      recommended: true,
    },
    {
      id: "evaluation",
      label: "Evaluation",
      language: "Python",
      summary: "Model evaluation and benchmark harnesses.",
    },
    {
      id: "adapter",
      label: "Adapter",
      language: "TypeScript",
      summary: "Adapters that expose models to applications.",
    },
  ],
  applications: [
    {
      id: "react",
      label: "React",
      language: "TypeScript",
      summary: "Application project with a web UI surface.",
      recommended: true,
    },
    {
      id: "service",
      label: "Service",
      language: "TypeScript",
      summary: "Backend application and API workspace.",
    },
    {
      id: "notebook-app",
      label: "Notebook app",
      language: "Python",
      summary: "Application experiments with notebook assets.",
    },
  ],
};

function RepositoryGateIcon() {
  return (
    <svg
      className="workspace-repository-gate__icon"
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id="repoGatePanel" x1="78%" y1="115%" x2="19%" y2="-3%">
          <stop offset="0%" stopColor="#E1E8ED" />
          <stop offset="56.8%" stopColor="#EAF0F3" />
          <stop offset="100%" stopColor="#F5F8FA" />
        </linearGradient>
        <linearGradient id="repoGateBorder" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#BFCCD6" />
          <stop offset="100%" stopColor="#A7B6C2" />
        </linearGradient>
        <linearGradient id="repoGateGlyph" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#5C7080" />
          <stop offset="100%" stopColor="#394B59" />
        </linearGradient>
      </defs>
      <rect x="2" y="3.25" width="16" height="13.5" rx="1.6" fill="url(#repoGatePanel)" />
      <rect x="2.5" y="3.75" width="15" height="0.5" fill="#FFFFFF" opacity="0.6" />
      <rect
        x="2"
        y="3.25"
        width="16"
        height="13.5"
        rx="1.6"
        fill="none"
        stroke="url(#repoGateBorder)"
        strokeWidth="0.6"
      />
      <path
        fill="url(#repoGateGlyph)"
        d="M7.653 7.575a.665.665 0 0 0-1.14.684L7.557 10l-1.044 1.741a.666.666 0 0 0 1.14.685l1.25-2.083a.67.67 0 0 0 0-.685z"
      />
      <path
        fill="url(#repoGateGlyph)"
        d="M10.833 11.418a.665.665 0 0 0 0 1.33h2.5a.665.665 0 0 0 0-1.33z"
      />
    </svg>
  );
}

function getDefaultTemplate(category: WorkspaceRepositoryCategory) {
  return (
    TEMPLATE_OPTIONS[category].find((template) => template.recommended) ??
    TEMPLATE_OPTIONS[category][0]
  );
}

export function WorkspaceRepositoryGate({
  repositories,
  createError,
  creating,
  onCreateRepository,
  onOpenRepository,
  onToggleFavorite,
}: WorkspaceRepositoryGateProps) {
  const [step, setStep] = useState<CreateStep>("landing");
  const [repositoryQuery, setRepositoryQuery] = useState("");
  const [selectedCategory, setSelectedCategory] =
    useState<WorkspaceRepositoryCategory>("pipelines");
  const [selectedTemplateId, setSelectedTemplateId] = useState("python");
  const [repositoryName, setRepositoryName] = useState("new-pipeline");

  const selectedCategoryOption = CATEGORY_OPTIONS.find(
    (category) => category.id === selectedCategory,
  ) ?? CATEGORY_OPTIONS[0];
  const selectedTemplate =
    TEMPLATE_OPTIONS[selectedCategory].find(
      (template) => template.id === selectedTemplateId,
    ) ?? getDefaultTemplate(selectedCategory);
  const existingRootPaths = useMemo(
    () => repositories.map((repository) => repository.rootPath),
    [repositories],
  );
  const previewSlug = createUniqueRepositorySlug(
    repositoryName.trim() || slugifyRepositoryName(selectedCategoryOption.label),
    existingRootPaths,
  );
  const previewPath = getGeneratedRepositoryPath(previewSlug);
  const filteredRepositories = useMemo(() => {
    const query = repositoryQuery.trim().toLowerCase();
    if (!query) {
      return repositories;
    }

    return repositories.filter((repository) =>
      [repository.name, repository.rootPath, repository.description]
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [repositories, repositoryQuery]);
  const favoriteRepositories = filteredRepositories.filter(
    (repository) => repository.favorite,
  );
  const canCreate = repositoryName.trim().length > 0 && !creating;

  const startCreateFlow = () => {
    setStep("category");
    setSelectedCategory("pipelines");
    setSelectedTemplateId("python");
    if (!repositoryName.trim()) {
      setRepositoryName("new-pipeline");
    }
  };

  const selectCategory = (category: WorkspaceRepositoryCategory) => {
    const nextTemplate = getDefaultTemplate(category);
    setSelectedCategory(category);
    setSelectedTemplateId(nextTemplate.id);
    if (!repositoryName.trim() || repositoryName === "new-pipeline") {
      setRepositoryName(`new-${slugifyRepositoryName(category)}`);
    }
    setStep("template");
  };

  const selectTemplate = (template: WorkspaceRepositoryTemplateOption) => {
    setSelectedTemplateId(template.id);
    setStep("details");
  };

  const submitCreate = () => {
    if (!canCreate) {
      return;
    }

    onCreateRepository({
      name: repositoryName.trim(),
      category: selectedCategory,
      categoryLabel: selectedCategoryOption.label,
      template: selectedTemplate.id,
      templateLabel: selectedTemplate.label,
    });
  };

  const renderRepositoryList = (
    items: WorkspaceRepositoryRecord[],
    emptyLabel: string,
  ) => (
    <div className="workspace-repository-gate__repo-list">
      {items.length > 0 ? (
        items.map((repository) => (
          <div className="workspace-repository-gate__repo-row" key={repository.id}>
            <button
              type="button"
              className="workspace-repository-gate__repo-open"
              onClick={() => onOpenRepository(repository)}
            >
              {renderIcon(FolderOpen, { size: 16, "aria-hidden": true })}
              <span>
                <strong>{repository.name}</strong>
                <small>{repository.rootPath}</small>
              </span>
              {renderIcon(ChevronRight, { size: 15, "aria-hidden": true })}
            </button>
            <button
              type="button"
              className="workspace-repository-gate__favorite-button"
              aria-label={
                repository.favorite
                  ? `Remove ${repository.name} from favorites`
                  : `Add ${repository.name} to favorites`
              }
              title={
                repository.favorite
                  ? "Remove from favorites"
                  : "Add to favorites"
              }
              onClick={() => onToggleFavorite(repository)}
            >
              {renderIcon(Star, {
                size: 15,
                fill: repository.favorite ? "currentColor" : "none",
                "aria-hidden": true,
              })}
            </button>
          </div>
        ))
      ) : (
        <div className="workspace-repository-gate__empty-small">{emptyLabel}</div>
      )}
    </div>
  );

  return (
    <div className="workspace-repository-gate">
      <header className="workspace-repository-gate__header">
        <div className="workspace-repository-gate__title">
          <span className="workspace-repository-gate__icon-shell">
            <RepositoryGateIcon />
          </span>
          <h1>Code repositories</h1>
        </div>
        <button
          type="button"
          className="workspace-repository-gate__primary-button"
          onClick={startCreateFlow}
        >
          {renderIcon(Plus, { size: 16, "aria-hidden": true })}
          <span>New repository</span>
        </button>
      </header>

      {step === "landing" ? (
        <div className="workspace-repository-gate__content">
          <main className="workspace-repository-gate__main">
            <div className="workspace-repository-gate__pr-toolbar">
              <div className="workspace-repository-gate__tabs" role="tablist">
                <button type="button" className="is-active">
                  Pull requests
                </button>
                <button type="button">Created by you</button>
                <button type="button">Review requested</button>
              </div>
              <label className="workspace-repository-gate__search-field">
                {renderIcon(Search, { size: 16, "aria-hidden": true })}
                <input type="search" placeholder="Find pull requests..." />
              </label>
            </div>
            <section className="workspace-repository-gate__pr-empty">
              {renderIcon(GitPullRequest, {
                size: 46,
                strokeWidth: 1.4,
                "aria-hidden": true,
              })}
              <h2>No pull requests created by you</h2>
              <p>
                There are no open pull requests created by you. Here are the
                recently visited code repositories and their pull requests.
              </p>
            </section>
          </main>

          <aside className="workspace-repository-gate__rail">
            <section className="workspace-repository-gate__news">
              <div className="workspace-repository-gate__rail-heading">
                <h2>What&apos;s new?</h2>
                <button type="button">
                  <span>See all</span>
                  {renderIcon(ExternalLink, { size: 16, "aria-hidden": true })}
                </button>
              </div>
              <article className="workspace-repository-gate__news-card">
                <div>
                  <span>Feature</span>
                  <time dateTime="2026-04-21">Apr 21, 2026</time>
                </div>
                <p>
                  Ontology Manager now displays run history directly within
                  function and action observability dashboards.
                </p>
                <button type="button">More</button>
              </article>
            </section>

            <section className="workspace-repository-gate__repositories">
              <div className="workspace-repository-gate__rail-heading">
                <h2>Repositories</h2>
                {renderIcon(Search, { size: 18, "aria-hidden": true })}
              </div>
              <label className="workspace-repository-gate__repository-search">
                {renderIcon(Search, { size: 15, "aria-hidden": true })}
                <input
                  type="search"
                  placeholder="Search repositories"
                  value={repositoryQuery}
                  onChange={(event) => setRepositoryQuery(event.target.value)}
                />
              </label>
              <div className="workspace-repository-gate__repo-card">
                <h3>Recents</h3>
                {renderRepositoryList(filteredRepositories, "No recent activity")}
              </div>
              <div className="workspace-repository-gate__repo-card">
                <h3>Favorites</h3>
                {renderRepositoryList(favoriteRepositories, "You have no favorites")}
              </div>
            </section>
          </aside>
        </div>
      ) : (
        <div className="workspace-repository-gate__create">
          <div className="workspace-repository-gate__create-panel">
            <div className="workspace-repository-gate__create-head">
              <button
                type="button"
                className="workspace-repository-gate__back-button"
                onClick={() =>
                  setStep(step === "category" ? "landing" : step === "template" ? "category" : "template")
                }
              >
                {renderIcon(ArrowLeft, { size: 16, "aria-hidden": true })}
                <span>Back</span>
              </button>
              <div className="workspace-repository-gate__steps" aria-label="Create progress">
                <span className={step === "category" ? "is-active" : ""}>Type</span>
                <span className={step === "template" ? "is-active" : ""}>Template</span>
                <span className={step === "details" ? "is-active" : ""}>Review</span>
              </div>
            </div>

            {step === "category" ? (
              <>
                <div className="workspace-repository-gate__create-title">
                  <p>Developer Tools</p>
                  <h2>Find and select repository type</h2>
                </div>
                <div className="workspace-repository-gate__category-grid">
                  {CATEGORY_OPTIONS.map((category) => (
                    <button
                      type="button"
                      key={category.id}
                      className="workspace-repository-gate__choice-card"
                      onClick={() => selectCategory(category.id)}
                    >
                      <span>
                        {renderIcon(FolderOpen, {
                          size: 18,
                          "aria-hidden": true,
                        })}
                      </span>
                      <strong>{category.label}</strong>
                      <small>{category.summary}</small>
                      {renderIcon(ChevronRight, {
                        size: 16,
                        "aria-hidden": true,
                      })}
                    </button>
                  ))}
                </div>
              </>
            ) : null}

            {step === "template" ? (
              <>
                <div className="workspace-repository-gate__create-title">
                  <p>{selectedCategoryOption.label}</p>
                  <h2>Choose template</h2>
                </div>
                <div className="workspace-repository-gate__template-grid">
                  {TEMPLATE_OPTIONS[selectedCategory].map((template) => (
                    <button
                      type="button"
                      key={template.id}
                      className="workspace-repository-gate__template-card"
                      onClick={() => selectTemplate(template)}
                    >
                      <span className="workspace-repository-gate__template-meta">
                        {template.language}
                      </span>
                      <strong>{template.label}</strong>
                      <small>{template.summary}</small>
                      {template.recommended ? (
                        <span className="workspace-repository-gate__recommended">
                          {renderIcon(Check, {
                            size: 13,
                            "aria-hidden": true,
                          })}
                          Recommended
                        </span>
                      ) : null}
                    </button>
                  ))}
                </div>
              </>
            ) : null}

            {step === "details" ? (
              <>
                <div className="workspace-repository-gate__create-title">
                  <p>
                    {selectedCategoryOption.label} / {selectedTemplate.label}
                  </p>
                  <h2>Name and location</h2>
                </div>
                <div className="workspace-repository-gate__review-card">
                  <label>
                    <span>Repository name</span>
                    <input
                      value={repositoryName}
                      onChange={(event) => setRepositoryName(event.target.value)}
                      autoFocus
                    />
                  </label>
                  <div className="workspace-repository-gate__review-row">
                    <span>Location</span>
                    <code>{previewPath}</code>
                  </div>
                  <div className="workspace-repository-gate__review-row">
                    <span>Template</span>
                    <strong>{selectedTemplate.label}</strong>
                  </div>
                  {createError ? (
                    <p className="workspace-repository-gate__create-error">
                      {createError}
                    </p>
                  ) : null}
                  <button
                    type="button"
                    className="workspace-repository-gate__primary-button"
                    disabled={!canCreate}
                    onClick={submitCreate}
                  >
                    {renderIcon(Plus, { size: 16, "aria-hidden": true })}
                    <span>{creating ? "Creating..." : "Create repository"}</span>
                  </button>
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
