import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

// The legacy HypervisorShellWindow activity rail was removed when the reference-parity
// UX became the app's primary surface. The parity sidebar (HypervisorReferenceSidebar,
// exported from the Home shell) is its single replacement, so this contract now guards
// the parity sidebar's durable structure — the parts that mirror the IOI reference and
// must not silently regress. Volatile content (which applications are pinned, the
// session list, org name) is intentionally NOT asserted here.
const SIDEBAR =
  "apps/hypervisor/src/surfaces/Home/HypervisorReferenceShell.tsx";
const sidebar = readFileSync(SIDEBAR, "utf8");

test("the legacy HypervisorShellWindow activity rail is fully removed", () => {
  assert.equal(
    existsSync("apps/hypervisor/src/windows/HypervisorShellWindow"),
    false,
  );
  // No remnant of the old rail's unique container/control classes. (The reference
  // brand mark legitimately carries `hypervisor-activity-brand*` classes — that is the
  // server-injected reference brand, not the retired rail.)
  assert.doesNotMatch(sidebar, /hypervisor-activity-(?:bar|button|group|collapse)/);
});

test("parity sidebar owns the reference brand mark and is the single sidebar identity", () => {
  assert.match(sidebar, /export function HypervisorReferenceSidebar\(/);
  assert.match(sidebar, /data-testid="sidebar"/);
  assert.match(sidebar, /const BrandMark = \(\) =>/);
  assert.match(sidebar, /aria-label="Go to Hypervisor home"/);
  assert.match(sidebar, /hypervisor-logo-home-link/);
});

test("parity sidebar exposes the New Session action with the Ctrl+O shortcut", () => {
  assert.match(sidebar, /data-testid="create-session-button"/);
  assert.match(sidebar, /aria-label="New Session"/);
  assert.match(sidebar, /<span data-testid="session-text"[^>]*>New Session<\/span>/);
  assert.match(sidebar, /data-testid="keyboard-shortcut"/);
  assert.match(sidebar, /<kbd className=\{KBD\}>Ctrl<\/kbd><kbd className=\{KBD\}>O<\/kbd>/);
});

test("parity sidebar carries the reference primary navigation (Home/Projects/Automations/Applications)", () => {
  assert.match(
    sidebar,
    /<NavLink href="\/ai" label="Home"[\s\S]*active=\{activeView === "home"\}/,
  );
  assert.match(
    sidebar,
    /<NavLink href="\/projects" label="Projects"[\s\S]*active=\{activeView === "projects"\}/,
  );
  assert.match(
    sidebar,
    /<NavLink href="\/automations" label="Automations"[\s\S]*active=\{activeView === "automations"\}/,
  );
  // Applications is a launcher entry (opens the catalog modal), not a route.
  assert.match(sidebar, /<NavLink href="#applications" label="Applications"/);
  assert.match(sidebar, /data-hypervisor-applications-launcher": "true"/);
});

test("parity sidebar carries the Sessions group and the Organization settings entry", () => {
  assert.match(sidebar, /data-testid="sidebar-tab-sessions"/);
  assert.match(sidebar, /data-testid="environments-list"/);
  assert.match(
    sidebar,
    /<NavLink href="\/settings" label="Organization settings"[\s\S]*active=\{activeView === "settings"\}/,
  );
  assert.match(sidebar, /data-testid="org-switcher"/);
});
