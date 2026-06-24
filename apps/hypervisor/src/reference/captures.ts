// Registry of vendored verbatim route captures + a path resolver.
//
// Maps a live pathname onto the captured reference DOM to render. Dynamic routes
// (/projects/:id, /details/:id) resolve to a single representative capture; unknown
// settings sections fall back to the settings index. Returns null when no capture
// matches (the caller renders the reference 404).
import home from "./html/home.html?raw";
import projects from "./html/projects.html?raw";
import projectDetail from "./html/project-detail.html?raw";
import automations from "./html/automations.html?raw";
import automationNew from "./html/automation-new.html?raw";
import workspace from "./html/workspace.html?raw";
import insights from "./html/insights.html?raw";
import settings from "./html/settings.html?raw";
import settingsAgentPolicies from "./html/settings-agent-policies.html?raw";
import settingsBilling from "./html/settings-billing.html?raw";
import settingsCreditUsage from "./html/settings-credit-usage.html?raw";
import settingsEnvironments from "./html/settings-environments.html?raw";
import settingsManageOrganization from "./html/settings-manage-organization.html?raw";
import settingsMembers from "./html/settings-members.html?raw";
import settingsOrganizationSecrets from "./html/settings-organization-secrets.html?raw";
import settingsOrgIntegrations from "./html/settings-org-integrations.html?raw";
import settingsPolicies from "./html/settings-policies.html?raw";
import settingsRunners from "./html/settings-runners.html?raw";
import settingsScim from "./html/settings-scim.html?raw";

const STATIC: Record<string, string> = {
  "/": home,
  "/ai": home,
  "/home": home,
  "/projects": projects,
  "/automations": automations,
  "/automations/new": automationNew,
  "/insights": insights,
  "/settings": settings,
  "/settings/agent-policies": settingsAgentPolicies,
  "/settings/billing": settingsBilling,
  "/settings/credit-usage": settingsCreditUsage,
  "/settings/environments": settingsEnvironments,
  "/settings/manage-organization": settingsManageOrganization,
  "/settings/members": settingsMembers,
  "/settings/organization-secrets": settingsOrganizationSecrets,
  "/settings/org-integrations": settingsOrgIntegrations,
  "/settings/policies": settingsPolicies,
  "/settings/runners": settingsRunners,
  "/settings/scim": settingsScim,
};

export function resolveCapture(pathname: string): string | null {
  const clean = pathname.replace(/\/+$/, "") || "/";
  if (STATIC[clean]) return STATIC[clean];
  // project detail + its tab sub-routes
  if (/^\/projects\/[^/]+(\/(settings|secrets|prebuilds))?$/.test(clean)) return projectDetail;
  // workspace / session detail
  if (/^\/details\/[^/]+$/.test(clean)) return workspace;
  // unknown settings section -> settings index (keeps the settings chrome)
  if (clean.startsWith("/settings/")) return settings;
  return null;
}

/** True when an internal href has a capture we can SPA-navigate to. */
export function hasCapture(pathname: string): boolean {
  return resolveCapture(pathname) != null;
}

/**
 * Which persistent shell a capture belongs to. Navigation morphs (persistent shell)
 * only within the same shell; crossing shells does a full replace (the sidebar content
 * differs — main nav vs settings nav — and morphing between them leaves stale state).
 */
export function shellKey(html: string): string {
  if (html.includes('href="/settings/billing"')) return "settings";
  if (html.includes("data-sidebar-container")) return "main";
  return "other";
}
