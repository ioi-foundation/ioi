// Project detail surface — source-owned React, source-derived from the product-ui /projects/:id
// route. Same route anatomy (breadcrumb back → project header with repo/branch/env/prebuilds →
// an environments/sessions section); the only change is the data boundary: the native daemon
// project-state + environment planes (projectsModel.getProject + listProjectEnvironments).
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  ArrowLeft,
  Box,
  FolderGit2,
  GitBranch,
  Link2,
  Play,
  Square,
  Zap,
} from "lucide-react";
import "./Projects.css";
import {
  getProject,
  listProjectEnvironments,
  relativeTime,
  type Project,
  type ProjectEnvironment,
} from "./projectsModel";

type LoadState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "missing" }
  | { status: "ready"; project: Project; envs: ProjectEnvironment[] };

function EnvRow({ e }: { e: ProjectEnvironment }) {
  return (
    <a
      className="pjd-env"
      href={`/sessions/${encodeURIComponent(e.id)}`}
      data-testid="project-environment"
    >
      <span
        className={"pjd-env-dot" + (e.running ? " is-running" : "")}
        aria-hidden="true"
      />
      <span className="pjd-env-id" title={e.id}>
        {e.id}
      </span>
      <span className="pjd-env-class">{e.classId}</span>
      <span className="pjd-env-phase" data-phase={e.phase}>
        {e.running ? <Play size={12} /> : <Square size={12} />} {e.phase}
      </span>
      <span className="pjd-env-age">{relativeTime(e.createdAt)}</span>
    </a>
  );
}

export function ProjectDetailView() {
  const params = useParams();
  const id = params.id || "";
  const [state, setState] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    let live = true;
    setState({ status: "loading" });
    (async () => {
      try {
        const project = await getProject(id);
        if (!live) return;
        if (!project) {
          setState({ status: "missing" });
          return;
        }
        const envs = await listProjectEnvironments(project.id);
        if (!live) return;
        setState({ status: "ready", project, envs });
      } catch (e) {
        if (live) setState({ status: "error", message: String((e as Error)?.message || e) });
      }
    })();
    return () => {
      live = false;
    };
  }, [id]);

  return (
    <div className="pj-wrap" data-testid="project-detail-page">
      <a className="pjd-back" href="/projects" data-testid="project-detail-back">
        <ArrowLeft size={14} /> Projects
      </a>

      {state.status === "loading" && (
        <div className="pj-state" data-testid="project-detail-loading">
          Loading project…
        </div>
      )}

      {state.status === "error" && (
        <div className="pj-state" data-testid="project-detail-error">
          Daemon unavailable: {state.message}
        </div>
      )}

      {state.status === "missing" && (
        <div className="pj-empty" data-testid="project-detail-missing">
          <span className="pj-empty-icon" aria-hidden="true">
            <FolderGit2 size={40} strokeWidth={1.3} />
          </span>
          <h2 className="pj-empty-title">Project not found</h2>
          <p className="pj-empty-sub">
            No project matches <code>{id}</code>. It may have been removed.
          </p>
          <a className="pj-new pj-new-lg" href="/projects">
            Back to projects
          </a>
        </div>
      )}

      {state.status === "ready" && (
        <ProjectDetailBody project={state.project} envs={state.envs} />
      )}
    </div>
  );
}

function ProjectDetailBody({
  project,
  envs,
}: {
  project: Project;
  envs: ProjectEnvironment[];
}) {
  const running = envs.filter((e) => e.running).length;
  return (
    <>
      <header className="pjd-head" data-testid="project-detail-header">
        <span className="pjd-head-icon" aria-hidden="true">
          <FolderGit2 size={22} />
        </span>
        <div className="pjd-head-main">
          <h1 className="pjd-title" data-testid="project-detail-name">
            {project.name}
            {project.archived && (
              <span className="pj-pill pj-pill-muted">archived</span>
            )}
          </h1>
          {project.repoUrl && (
            <a
              className="pjd-repo"
              href={project.repoUrl}
              target="_blank"
              rel="noopener"
              data-testid="project-detail-repo"
            >
              <Link2 size={13} /> {project.repoLabel || project.repoUrl}
            </a>
          )}
        </div>
      </header>

      <dl className="pjd-facts" data-testid="project-detail-facts">
        <div className="pjd-fact">
          <dt>
            <GitBranch size={13} /> Branch
          </dt>
          <dd>{project.branch}</dd>
        </div>
        <div className="pjd-fact">
          <dt>
            <Box size={13} /> Environment
          </dt>
          <dd>{project.environment}</dd>
        </div>
        <div className="pjd-fact">
          <dt>
            <Zap size={13} /> Prebuilds
          </dt>
          <dd className={project.prebuilds ? "pjd-on" : ""}>
            {project.prebuilds ? "Enabled" : "Off"}
          </dd>
        </div>
        {project.classRefs.length > 0 && (
          <div className="pjd-fact">
            <dt>
              <Box size={13} /> Classes
            </dt>
            <dd>{project.classRefs.join(", ")}</dd>
          </div>
        )}
        {project.createdAt && (
          <div className="pjd-fact">
            <dt>Created</dt>
            <dd>{relativeTime(project.createdAt)}</dd>
          </div>
        )}
      </dl>

      <section className="pjd-section" data-testid="project-detail-environments">
        <div className="pjd-section-head">
          <h2 className="pjd-h2">Environments &amp; sessions</h2>
          <span className="pjd-count">
            {envs.length} total{running ? ` · ${running} running` : ""}
          </span>
        </div>
        {envs.length === 0 ? (
          <div className="pj-state" data-testid="project-detail-environments-empty">
            No environments yet. Start a session against this project to spin one up.
          </div>
        ) : (
          <div className="pjd-envlist">
            {envs.map((e) => (
              <EnvRow key={e.id} e={e} />
            ))}
          </div>
        )}
      </section>
    </>
  );
}
