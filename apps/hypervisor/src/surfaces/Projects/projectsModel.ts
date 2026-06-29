// Projects model — source-owned, native daemon boundary (/v1/hypervisor/projects).
// Source-derived from the product-ui Projects route: same anatomy (header → search → card grid /
// empty state), but the data boundary is the daemon's own project-state plane instead of an
// upstream wire. Projects are repository-backed work containers; the daemon admits and persists
// the canonical record (RuntimeKernelService project-create planner) and lists them here.
import { daemon } from "../../data/daemon";

// Shape mirrored from the daemon JSON (GET /v1/hypervisor/projects → the persisted project-state
// record built by the kernel project-create planner; schema ioi.hypervisor.project_state.v1).
export type ProjectRecord = {
  project_id?: string;
  name?: string;
  description?: string;
  repository_url?: string;
  repository_ref?: string | null;
  repository_branch?: string;
  created_at?: string;
  environment?: string;
  environment_class_refs?: string[];
  prebuilds_enabled?: boolean;
  restore_state?: string;
  root_path?: string;
  custody_posture?: string;
};

export type Project = {
  id: string;
  name: string;
  repoUrl: string;
  repoLabel: string;
  branch: string;
  environment: string;
  classRefs: string[];
  prebuilds: boolean;
  archived: boolean;
  createdAt?: string;
};

// Collapse a clone URL down to "owner/repo" for the card subtitle (host/.git stripped).
export function repoLabel(url: string): string {
  if (!url) return "";
  const cleaned = url.replace(/\.git$/i, "").replace(/\/+$/, "");
  const m = cleaned.match(/[:/]([^/]+\/[^/]+)$/);
  if (m) return m[1];
  try {
    return new URL(cleaned).pathname.replace(/^\//, "") || cleaned;
  } catch {
    return cleaned;
  }
}

export function toProject(r: ProjectRecord): Project {
  const id = r.project_id || "";
  const repoUrl = r.repository_url || "";
  const name =
    r.name && r.name.trim() ? r.name.trim() : repoLabel(repoUrl) || id.replace(/^project:/, "") || "Untitled project";
  return {
    id,
    name,
    repoUrl,
    repoLabel: repoLabel(repoUrl),
    branch: r.repository_branch || "main",
    environment: r.environment || "No environment yet",
    classRefs: r.environment_class_refs || [],
    prebuilds: r.prebuilds_enabled === true,
    archived: r.restore_state === "archived",
    createdAt: r.created_at,
  };
}

export async function listProjects(): Promise<Project[]> {
  const r = await daemon
    .get<{ projects?: ProjectRecord[] } | ProjectRecord[]>("/hypervisor/projects")
    .catch(() => ({}) as { projects?: ProjectRecord[] });
  const records = Array.isArray(r) ? r : r.projects || [];
  return records
    .map(toProject)
    .filter((p) => p.id)
    .sort((a, b) => Date.parse(b.createdAt || "") - Date.parse(a.createdAt || ""));
}

// The slug the daemon's environment specs key by (env spec.project_id is the bare slug, while a
// project record's id is "project:<slug>") — match a project against its environments by either.
export function projectSlug(id: string): string {
  return id.replace(/^project:/, "");
}

// Fetch one project by id. The daemon list is the source of truth (there is no per-project GET);
// we resolve the record from the persisted project-state plane. Returns null if not found.
export async function getProject(id: string): Promise<Project | null> {
  const all = await listProjects();
  const wantSlug = projectSlug(id);
  return all.find((p) => p.id === id || projectSlug(p.id) === wantSlug) || null;
}

// An environment record as projected by the daemon (GET /v1/hypervisor/environments). Only the
// fields the project-detail surface reads are typed; the spec.project_id binds it to a project.
export type EnvironmentRecord = {
  id?: string;
  created_at?: string;
  updated_at?: string;
  spec?: {
    project_id?: string | null;
    environment_class_id?: string;
    desired_phase?: string;
    declared_ports?: { port?: number }[];
  } | null;
  status?: {
    phase?: string;
    message?: string;
    deleted?: boolean;
    ports?: { port?: number }[];
  } | null;
};

export type ProjectEnvironment = {
  id: string;
  phase: string;
  classId: string;
  createdAt?: string;
  running: boolean;
};

export function envIsLive(e: EnvironmentRecord): boolean {
  const phase = e.status?.phase || "";
  return !e.status?.deleted && phase !== "deleted";
}

export function toProjectEnvironment(e: EnvironmentRecord): ProjectEnvironment {
  const phase = e.status?.phase || "unknown";
  return {
    id: e.id || "",
    phase,
    classId: e.spec?.environment_class_id || "—",
    createdAt: e.created_at,
    running: phase === "running",
  };
}

// List the live environments bound to a project (env spec.project_id == project slug). Newest first.
export async function listProjectEnvironments(projectId: string): Promise<ProjectEnvironment[]> {
  const r = await daemon
    .get<{ environments?: EnvironmentRecord[] }>("/hypervisor/environments")
    .catch(() => ({}) as { environments?: EnvironmentRecord[] });
  const wantSlug = projectSlug(projectId);
  return (r.environments || [])
    .filter(envIsLive)
    .filter((e) => {
      const pid = e.spec?.project_id || "";
      return pid === projectId || projectSlug(pid) === wantSlug;
    })
    .map(toProjectEnvironment)
    .filter((e) => e.id)
    .sort((a, b) => Date.parse(b.createdAt || "") - Date.parse(a.createdAt || ""));
}

export function filterProjects(projects: Project[], query: string): Project[] {
  const q = query.trim().toLowerCase();
  if (!q) return projects;
  return projects.filter(
    (p) =>
      p.name.toLowerCase().includes(q) ||
      p.repoLabel.toLowerCase().includes(q) ||
      p.repoUrl.toLowerCase().includes(q),
  );
}

export function relativeTime(iso?: string): string {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.round(days / 7)}w ago`;
}
