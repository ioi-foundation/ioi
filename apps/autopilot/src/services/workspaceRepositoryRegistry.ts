export type WorkspaceRepositoryCategory =
  | "pipelines"
  | "functions"
  | "analytics"
  | "models"
  | "applications";

export type WorkspaceRepositorySource = "seed" | "created";

export interface SeedWorkspaceRepositoryProject {
  id: string;
  name: string;
  description?: string;
  environment?: string;
  rootPath: string;
}

export interface WorkspaceRepositoryRecord {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
  source: WorkspaceRepositorySource;
  category: WorkspaceRepositoryCategory | null;
  template: string | null;
  createdAtMs: number | null;
  lastOpenedAtMs: number | null;
  favorite: boolean;
}

type StoredWorkspaceRepositoryRecord = Partial<WorkspaceRepositoryRecord> & {
  id?: unknown;
  source?: unknown;
};

interface StoredWorkspaceRepositoryRegistry {
  version: 1;
  records: StoredWorkspaceRepositoryRecord[];
}

const STORAGE_KEY = "autopilot.workspace-repositories.v1";
export const GENERATED_REPOSITORY_ROOT = "examples/generated-code-repositories";

const VALID_CATEGORIES = new Set<WorkspaceRepositoryCategory>([
  "pipelines",
  "functions",
  "analytics",
  "models",
  "applications",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeText(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeOptionalText(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  return normalizeText(value);
}

function normalizeTimestamp(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return null;
  }
  return Math.floor(value);
}

function normalizeCategory(value: unknown): WorkspaceRepositoryCategory | null {
  const category = normalizeOptionalText(value);
  if (!category || !VALID_CATEGORIES.has(category as WorkspaceRepositoryCategory)) {
    return null;
  }
  return category as WorkspaceRepositoryCategory;
}

function getLocalStorage(): Storage | null {
  if (typeof globalThis === "undefined" || !("localStorage" in globalThis)) {
    return null;
  }

  try {
    return globalThis.localStorage;
  } catch {
    return null;
  }
}

function normalizeStoredRecord(
  record: StoredWorkspaceRepositoryRecord,
): StoredWorkspaceRepositoryRecord | null {
  const id = normalizeText(record.id);
  if (!id) {
    return null;
  }

  const source = record.source === "created" ? "created" : "seed";
  const lastOpenedAtMs = normalizeTimestamp(record.lastOpenedAtMs);
  const favorite = record.favorite === true;

  if (source === "seed") {
    return {
      id,
      source,
      lastOpenedAtMs,
      favorite,
    };
  }

  const name = normalizeText(record.name);
  const rootPath = normalizeText(record.rootPath);
  if (!name || !rootPath) {
    return null;
  }

  return {
    id,
    name,
    description: normalizeOptionalText(record.description) ?? "",
    environment: normalizeOptionalText(record.environment) ?? "Local",
    rootPath,
    source,
    category: normalizeCategory(record.category),
    template: normalizeOptionalText(record.template),
    createdAtMs: normalizeTimestamp(record.createdAtMs) ?? Date.now(),
    lastOpenedAtMs,
    favorite,
  };
}

function readStoredRecords(): StoredWorkspaceRepositoryRecord[] {
  const storage = getLocalStorage();
  if (!storage) {
    return [];
  }

  const raw = storage.getItem(STORAGE_KEY);
  if (!raw) {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    storage.removeItem(STORAGE_KEY);
    return [];
  }

  if (!isRecord(parsed) || !Array.isArray(parsed.records)) {
    storage.removeItem(STORAGE_KEY);
    return [];
  }

  const normalized = parsed.records
    .map((record) =>
      isRecord(record)
        ? normalizeStoredRecord(record as StoredWorkspaceRepositoryRecord)
        : null,
    )
    .filter((record): record is StoredWorkspaceRepositoryRecord => Boolean(record));

  if (normalized.length !== parsed.records.length) {
    writeStoredRecords(normalized);
  }

  const deduped = new Map<string, StoredWorkspaceRepositoryRecord>();
  for (const record of normalized) {
    if (typeof record.id === "string") {
      deduped.set(record.id, record);
    }
  }

  return Array.from(deduped.values());
}

function writeStoredRecords(records: StoredWorkspaceRepositoryRecord[]) {
  const storage = getLocalStorage();
  if (!storage) {
    return;
  }

  const registry: StoredWorkspaceRepositoryRegistry = {
    version: 1,
    records,
  };

  storage.setItem(STORAGE_KEY, JSON.stringify(registry));
}

function toSeedRepository(
  project: SeedWorkspaceRepositoryProject,
  stored: StoredWorkspaceRepositoryRecord | undefined,
): WorkspaceRepositoryRecord {
  return {
    id: project.id,
    name: project.name,
    description: project.description ?? "",
    environment: project.environment ?? "Local",
    rootPath: project.rootPath,
    source: "seed",
    category: null,
    template: null,
    createdAtMs: null,
    lastOpenedAtMs: normalizeTimestamp(stored?.lastOpenedAtMs),
    favorite: stored?.favorite === true,
  };
}

function toCreatedRepository(
  record: StoredWorkspaceRepositoryRecord,
): WorkspaceRepositoryRecord | null {
  const normalized = normalizeStoredRecord(record);
  if (!normalized || normalized.source !== "created") {
    return null;
  }

  return {
    id: normalized.id as string,
    name: normalized.name as string,
    description: (normalized.description as string | undefined) ?? "",
    environment: (normalized.environment as string | undefined) ?? "Local",
    rootPath: normalized.rootPath as string,
    source: "created",
    category: normalizeCategory(normalized.category),
    template: normalizeOptionalText(normalized.template),
    createdAtMs: normalizeTimestamp(normalized.createdAtMs),
    lastOpenedAtMs: normalizeTimestamp(normalized.lastOpenedAtMs),
    favorite: normalized.favorite === true,
  };
}

function compareRepositories(
  left: WorkspaceRepositoryRecord,
  right: WorkspaceRepositoryRecord,
) {
  const leftLastOpened = left.lastOpenedAtMs ?? -1;
  const rightLastOpened = right.lastOpenedAtMs ?? -1;
  if (leftLastOpened !== rightLastOpened) {
    return rightLastOpened - leftLastOpened;
  }

  const leftCreated = left.createdAtMs ?? -1;
  const rightCreated = right.createdAtMs ?? -1;
  if (leftCreated !== rightCreated) {
    return rightCreated - leftCreated;
  }

  return left.name.localeCompare(right.name);
}

export function loadWorkspaceRepositories(
  seedProjects: SeedWorkspaceRepositoryProject[],
): WorkspaceRepositoryRecord[] {
  const storedRecords = readStoredRecords();
  const storedById = new Map(
    storedRecords
      .filter((record) => typeof record.id === "string")
      .map((record) => [record.id as string, record]),
  );
  const seedIds = new Set(seedProjects.map((project) => project.id));

  const seedRepositories = seedProjects.map((project) =>
    toSeedRepository(project, storedById.get(project.id)),
  );
  const createdRepositories = storedRecords
    .filter((record) => record.source === "created")
    .map(toCreatedRepository)
    .filter((record): record is WorkspaceRepositoryRecord => Boolean(record))
    .filter((record) => !seedIds.has(record.id));

  return [...seedRepositories, ...createdRepositories].sort(compareRepositories);
}

export function persistCreatedWorkspaceRepository(record: WorkspaceRepositoryRecord) {
  if (record.source !== "created") {
    return;
  }

  const storedRecords = readStoredRecords().filter(
    (storedRecord) => storedRecord.id !== record.id,
  );
  storedRecords.push({
    id: record.id,
    name: record.name,
    description: record.description,
    environment: record.environment,
    rootPath: record.rootPath,
    source: "created",
    category: record.category,
    template: record.template,
    createdAtMs: record.createdAtMs,
    lastOpenedAtMs: record.lastOpenedAtMs,
    favorite: record.favorite,
  });
  writeStoredRecords(storedRecords);
}

export function markWorkspaceRepositoryOpened(id: string) {
  const storedRecords = readStoredRecords();
  const existing = storedRecords.find((record) => record.id === id);
  const openedAtMs = Date.now();

  if (existing) {
    existing.lastOpenedAtMs = openedAtMs;
  } else {
    storedRecords.push({
      id,
      source: "seed",
      lastOpenedAtMs: openedAtMs,
      favorite: false,
    });
  }

  writeStoredRecords(storedRecords);
}

export function toggleWorkspaceRepositoryFavorite(id: string): boolean {
  const storedRecords = readStoredRecords();
  const existing = storedRecords.find((record) => record.id === id);

  if (existing) {
    existing.favorite = existing.favorite !== true;
    writeStoredRecords(storedRecords);
    return existing.favorite === true;
  }

  storedRecords.push({
    id,
    source: "seed",
    lastOpenedAtMs: null,
    favorite: true,
  });
  writeStoredRecords(storedRecords);
  return true;
}

export function slugifyRepositoryName(name: string): string {
  const slug = name
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
    .replace(/-+$/g, "");

  const safeSlug = slug || "repository";
  return /^[0-9]/.test(safeSlug) ? `repository-${safeSlug}` : safeSlug;
}

export function getGeneratedRepositoryPath(slug: string): string {
  return `${GENERATED_REPOSITORY_ROOT}/${slug}`;
}

export function createUniqueRepositorySlug(
  name: string,
  existingRootPaths: Iterable<string>,
): string {
  const baseSlug = slugifyRepositoryName(name);
  const existingPaths = new Set(existingRootPaths);
  let candidate = baseSlug;
  let suffix = 2;

  while (existingPaths.has(getGeneratedRepositoryPath(candidate))) {
    candidate = `${baseSlug}-${suffix}`;
    suffix += 1;
  }

  return candidate;
}
