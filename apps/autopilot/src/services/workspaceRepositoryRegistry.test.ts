import { strict as assert } from "node:assert";
import test from "node:test";

import {
  createUniqueRepositorySlug,
  getGeneratedRepositoryPath,
  loadWorkspaceRepositories,
  markWorkspaceRepositoryOpened,
  persistCreatedWorkspaceRepository,
  slugifyRepositoryName,
  toggleWorkspaceRepositoryFavorite,
  type WorkspaceRepositoryRecord,
} from "./workspaceRepositoryRegistry.ts";

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length() {
    return this.values.size;
  }

  clear() {
    this.values.clear();
  }

  getItem(key: string) {
    return this.values.get(key) ?? null;
  }

  key(index: number) {
    return Array.from(this.values.keys())[index] ?? null;
  }

  removeItem(key: string) {
    this.values.delete(key);
  }

  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
}

const seedProjects = [
  {
    id: "autopilot-core",
    name: "Autopilot Core",
    description: "Main repository",
    environment: "Local",
    rootPath: ".",
  },
  {
    id: "capability-lab",
    name: "Capability Lab",
    description: "Autopilot application",
    environment: "Local",
    rootPath: "apps/autopilot",
  },
];

const createdRepository: WorkspaceRepositoryRecord = {
  id: "created:demo-pipeline",
  name: "Demo Pipeline",
  description: "Pipelines / Python",
  environment: "Local",
  rootPath: "examples/generated-code-repositories/demo-pipeline",
  source: "created",
  category: "pipelines",
  template: "python",
  createdAtMs: 1_000,
  lastOpenedAtMs: 5_000,
  favorite: false,
};

function installMemoryStorage() {
  const storage = new MemoryStorage();
  Object.defineProperty(globalThis, "localStorage", {
    value: storage,
    configurable: true,
  });
  return storage;
}

test("slugifyRepositoryName creates safe repository slugs", () => {
  assert.equal(slugifyRepositoryName("My Cool Repo!!"), "my-cool-repo");
  assert.equal(slugifyRepositoryName("123 Model"), "repository-123-model");
  assert.equal(slugifyRepositoryName("Cafe deja vu"), "cafe-deja-vu");
  assert.equal(slugifyRepositoryName("   "), "repository");
});

test("createUniqueRepositorySlug appends duplicate-name suffixes", () => {
  const slug = createUniqueRepositorySlug("My Repo", [
    getGeneratedRepositoryPath("my-repo"),
    getGeneratedRepositoryPath("my-repo-2"),
  ]);

  assert.equal(slug, "my-repo-3");
});

test("loadWorkspaceRepositories repairs invalid localStorage payloads", () => {
  const storage = installMemoryStorage();
  storage.setItem("autopilot.workspace-repositories.v1", "not-json");

  const repositories = loadWorkspaceRepositories(seedProjects);

  assert.equal(storage.getItem("autopilot.workspace-repositories.v1"), null);
  assert.deepEqual(
    repositories.map((repository) => repository.id).sort(),
    ["autopilot-core", "capability-lab"],
  );
});

test("loadWorkspaceRepositories includes created repositories and orders recents", () => {
  installMemoryStorage();
  persistCreatedWorkspaceRepository(createdRepository);
  markWorkspaceRepositoryOpened("capability-lab");

  const repositories = loadWorkspaceRepositories(seedProjects);

  assert.equal(repositories[0]?.id, "capability-lab");
  assert.equal(repositories[1]?.id, "created:demo-pipeline");
  assert.ok(repositories.some((repository) => repository.rootPath === createdRepository.rootPath));
});

test("toggleWorkspaceRepositoryFavorite persists favorite state", () => {
  installMemoryStorage();

  assert.equal(toggleWorkspaceRepositoryFavorite("autopilot-core"), true);
  assert.equal(
    loadWorkspaceRepositories(seedProjects).find(
      (repository) => repository.id === "autopilot-core",
    )?.favorite,
    true,
  );
  assert.equal(toggleWorkspaceRepositoryFavorite("autopilot-core"), false);
  assert.equal(
    loadWorkspaceRepositories(seedProjects).find(
      (repository) => repository.id === "autopilot-core",
    )?.favorite,
    false,
  );
});
