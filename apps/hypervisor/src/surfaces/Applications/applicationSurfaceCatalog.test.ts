import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  APPLICATION_SURFACE_CATALOG,
  applicationViewForId,
  openApplicationForView,
} from "./applicationSurfaceCatalog.ts";

const railSource = readFileSync(
  "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRail.tsx",
  "utf8",
);
const catalogSource = readFileSync(
  "apps/hypervisor/src/surfaces/Applications/ApplicationsCatalogView.tsx",
  "utf8",
);

test("applicationViewForId resolves catalog ids to primary views", () => {
  assert.equal(applicationViewForId("foundry"), "foundry");
  assert.equal(applicationViewForId("workers"), "agents");
  assert.equal(applicationViewForId("policies"), "authority");
  assert.equal(applicationViewForId("monitoring"), "insights");
  assert.equal(applicationViewForId("does-not-exist"), null);
});

test("openApplicationForView is the singular active slot, excluding the catalog itself", () => {
  // The Applications catalog surface is the launcher, not an Open Application.
  assert.equal(openApplicationForView("applications"), null);
  const foundry = openApplicationForView("foundry");
  assert.equal(foundry?.id, "foundry");
  assert.equal(foundry?.label, "Foundry");
  // A non-application primary view yields no Open Application.
  assert.equal(openApplicationForView("home"), null);
  // Every catalog entry except the catalog-routed one resolves to itself.
  for (const entry of APPLICATION_SURFACE_CATALOG) {
    if (entry.view === "applications") continue;
    assert.equal(openApplicationForView(entry.view)?.id, entry.id);
  }
});

test("activity rail is a query launcher with a singular Open Application, not a pinned rail", () => {
  assert.ok(
    railSource.includes('data-applications-launcher="true"'),
    "rail must expose an Applications launcher trigger",
  );
  assert.ok(
    railSource.includes("data-open-application={openApplication.id}"),
    "rail must render the singular Open Application slot",
  );
  // The obsolete permanent pinned rail and its data hooks must be gone.
  assert.ok(
    !railSource.includes("data-pinned-application-id"),
    "rail must not render a permanent pinned-application rail",
  );
  assert.ok(
    !railSource.includes("PINNED_APPLICATION_RAIL_ITEMS"),
    "rail must not reference the removed pinned-rail item list",
  );
});

test("applications catalog is query-first and launchable", () => {
  assert.ok(
    catalogSource.includes('data-applications-catalog-query="true"'),
    "catalog must expose a query/search input",
  );
  assert.ok(
    catalogSource.includes("onLaunchApplication"),
    "catalog must support launching an entry as the Open Application",
  );
  assert.ok(
    catalogSource.includes("data-application-launch-id"),
    "catalog entries must be launchable",
  );
});
