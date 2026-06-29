// Projects surface — source-owned React, source-derived from the product-ui Projects route.
// Same route anatomy (page header → search + New project → card grid, with the "No projects"
// empty state); the only change is the data boundary: the native daemon project-state plane
// (projectsModel.listProjects → GET /v1/hypervisor/projects).
import { useEffect, useMemo, useState } from "react";
import { FolderGit2, Search, Plus, GitBranch, Box, Zap } from "lucide-react";
import "./Projects.css";
import { Skeleton } from "../../components/Skeleton";
import {
  filterProjects,
  listProjects,
  relativeTime,
  type Project,
} from "./projectsModel";

function ProjectCard({ p }: { p: Project }) {
  return (
    <a
      className="pj-card"
      href={`/projects/${encodeURIComponent(p.id)}`}
      data-testid="project-card"
    >
      <div className="pj-card-head">
        <span className="pj-card-icon" aria-hidden="true">
          <FolderGit2 size={18} />
        </span>
        <span className="pj-card-name" title={p.name}>
          {p.name}
        </span>
        {p.archived && <span className="pj-pill pj-pill-muted">archived</span>}
      </div>
      {p.repoLabel && (
        <div className="pj-card-repo" title={p.repoUrl}>
          {p.repoLabel}
        </div>
      )}
      <div className="pj-card-meta">
        <span className="pj-meta-item">
          <GitBranch size={13} /> {p.branch}
        </span>
        <span className="pj-meta-item">
          <Box size={13} /> {p.environment}
        </span>
        {p.prebuilds && (
          <span className="pj-meta-item pj-meta-on">
            <Zap size={13} /> prebuilds
          </span>
        )}
      </div>
      {p.createdAt && <div className="pj-card-foot">Created {relativeTime(p.createdAt)}</div>}
    </a>
  );
}

export function ProjectsView() {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let live = true;
    listProjects()
      .then((p) => live && setProjects(p))
      .catch((e) => live && setError(String(e?.message || e)));
    return () => {
      live = false;
    };
  }, []);

  const visible = useMemo(
    () => (projects ? filterProjects(projects, query) : []),
    [projects, query],
  );

  const loading = !error && projects === null;
  const hasAny = !!projects && projects.length > 0;
  const noMatches = hasAny && visible.length === 0;

  return (
    <div className="pj-wrap" data-testid="projects-page">
      <div className="pj-head">
        <h1 className="pj-h1">Projects</h1>
        <a className="pj-new" href="/projects/new" data-testid="create-project-button">
          <Plus size={15} /> New project
        </a>
      </div>

      <div className="pj-toolbar">
        <div className="pj-search">
          <Search size={15} className="pj-search-icon" />
          <input
            className="pj-search-input"
            type="text"
            placeholder="Search projects"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            data-testid="projects-search"
            disabled={!hasAny}
          />
        </div>
      </div>

      {error && (
        <div className="pj-state" data-testid="projects-error">
          Daemon unavailable: {error}
        </div>
      )}

      {loading && (
        <div className="pj-grid" data-testid="projects-loading" role="status" aria-label="Loading projects" aria-busy="true">
          {Array.from({ length: 6 }).map((_, i) => (
            <div className="pj-card pj-card-skel" key={i} aria-hidden="true">
              <div className="pj-card-head">
                <Skeleton w={26} h={26} r={8} />
                <Skeleton w={`${40 + ((i * 11) % 30)}%`} h={14} />
              </div>
              <Skeleton w={`${55 + ((i * 7) % 25)}%`} h={11} r={5} />
              <div className="pj-card-meta">
                <Skeleton w={70} h={11} r={5} />
                <Skeleton w={54} h={11} r={5} />
              </div>
            </div>
          ))}
        </div>
      )}

      {!error && !loading && !hasAny && (
        <div className="pj-empty" data-testid="projects-empty">
          <span className="pj-empty-icon" aria-hidden="true">
            <FolderGit2 size={40} strokeWidth={1.3} />
          </span>
          <h2 className="pj-empty-title">No projects</h2>
          <p className="pj-empty-sub">
            Projects are repository-backed work containers. Create one from a repository to start
            running environments and agents against it.
          </p>
          <a className="pj-new pj-new-lg" href="/projects/new" data-testid="create-project-button-empty">
            <Plus size={16} /> New project
          </a>
        </div>
      )}

      {!error && !loading && noMatches && (
        <div className="pj-state" data-testid="projects-no-matches">
          No projects match “{query}”.
        </div>
      )}

      {!error && !loading && hasAny && visible.length > 0 && (
        <div className="pj-grid" data-testid="projects-grid">
          {visible.map((p) => (
            <ProjectCard key={p.id} p={p} />
          ))}
        </div>
      )}
    </div>
  );
}
