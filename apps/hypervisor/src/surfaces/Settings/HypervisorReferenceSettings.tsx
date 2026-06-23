// Parity Phase E — Settings tree, ported from the reference live /settings/** DOM
// (:9228). Settings is a full-page surface with its OWN sidebar (the org-governance
// nav, grouped: Organization Settings / Infrastructure / Agents / Login & Identity)
// replacing the app shell, plus a content area. This module ports the settings shell
// (sidebar + General content = /settings/manage-organization). Additional sub-section
// content is added incrementally; the sidebar is the shared chrome across all routes.
import { useReferenceTheme } from "../Home/HypervisorReferenceShell";

const ArrowLeft = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 5.75L3.75 12L10 18.25M4.5 12H20.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const OrgChevron = () => (
  <svg className="flex-shrink-0 text-content-primary" aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 9L12 5L16 9M16 15L12 19L8 15" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const CopyGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8.75 8.75V2.75H21.25V15.25H15.25M15.25 8.75H2.75V21.25H15.25V8.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const UsersGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-users size-4"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></svg>
);
const BuildingGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-building2 size-4"><path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z" /><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" /><path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2" /><path d="M10 6h4" /><path d="M10 10h4" /><path d="M10 14h4" /><path d="M10 18h4" /></svg>
);

const SETTINGS_NAV = [
  { group: "Organization Settings", items: [
    { label: "General", href: "/settings/manage-organization" },
    { label: "Terms of Service", href: "/settings/terms-of-service" },
    { label: "Members", href: "/settings/members" },
    { label: "Secrets", href: "/settings/organization-secrets" },
    { label: "Integrations", href: "/settings/org-integrations" },
    { label: "Policies", href: "/settings/policies" },
    { label: "Billing", href: "/settings/billing" },
    { label: "Cost & Budgets", href: "/settings/credit-usage" },
  ] },
  { group: "Infrastructure", items: [
    { label: "Runners", href: "/settings/runners" },
    { label: "Environments", href: "/settings/environments" },
  ] },
  { group: "Agents", items: [
    { label: "Policies", href: "/settings/agent-policies" },
    { label: "Skills", href: "/settings/agent-skills" },
  ] },
  { group: "Login & Identity", items: [
    { label: "Login Configuration", href: "/settings/login" },
    { label: "SCIM", href: "/settings/scim" },
    { label: "OIDC Tokens", href: "/settings/security/oidc" },
  ] },
];

function SettingsSidebar({ activeHref = "/settings/manage-organization" }: { activeHref?: string }) {
  return (
    <div data-sidebar-container="true" className="relative flex-shrink-0 overflow-hidden bg-surface-primary">
      <div className="h-full overflow-hidden" data-track-location="settings-sidebar">
        <div className="relative h-full" style={{ width: "300px" }}>
          <div data-testid="sidebar" className="flex size-full flex-col pb-[6px] pt-0.5">
            <div className="px-2 pt-2">
              <a className="flex h-8 flex-row items-center gap-1 rounded-lg px-2 text-content-strong hover:bg-surface-hover" href="/">
                <div className="w-5"><ArrowLeft /></div>
                <div className="flex-grow truncate text-start text-base font-normal">Back to Hypervisor</div>
              </a>
            </div>
            <div className="relative [scrollbar-gutter:stable] overflow-y-auto overflow-x-hidden mr-0.5 flex-grow pr-[1px] pt-2" data-orientation="vertical">
              <div className="flex flex-col gap-4 pl-2" data-testid="settings-menu">
                {SETTINGS_NAV.map((g) => (
                  <div key={g.group} className="flex w-full flex-col gap-1" translate="no">
                    <div className="h-8 select-none p-2 text-sm font-bold text-content-secondary">{g.group}</div>
                    {g.items.map((it) => {
                      const active = it.href === activeHref;
                      return (
                        <a key={it.href} className={`flex flex-row items-center rounded-lg h-8 min-w-0 ${active ? "bg-surface-hover" : "hover:bg-surface-hover"}`} translate="no" href={it.href} {...(active ? { "aria-current": "page" } : {})}>
                          <div className="relative flex w-full flex-row items-center">
                            <div className="flex-grow text-start text-base min-w-0 overflow-hidden whitespace-nowrap transform-gpu transition-opacity duration-200 ease-out opacity-100 px-2">{it.label}</div>
                          </div>
                        </a>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
            <div className="flex flex-col gap-2 p-2 pb-2 pt-4">
              <div className="rounded-lg">
                <button type="button" className="select-none items-center font-medium whitespace-nowrap transition-colors text-content-primary hover:text-content-accent focus-visible:outline-border-brand text-base h-[48px] w-full flex gap-2 border-0 p-2 bg-transparent rounded-lg group justify-between hover:bg-surface-hover" aria-label="Switch organization. Currently in Levi Josman's Workspace 320" aria-haspopup="menu" data-testid="org-switcher">
                  <div className="flex w-full min-w-0 items-center gap-2 transform-gpu transition-all duration-200 ease-out translate-x-0">
                    <div className="relative flex-shrink-0 rounded-lg" data-testid="org-switcher-icon">
                      <span data-slot="avatar" className="relative flex shrink-0 overflow-hidden size-8 rounded-lg">
                        <div className="inline-flex size-full select-none items-center justify-center font-medium text-xs leading-8 bg-surface-brand-accent-09 text-content-brand-accent-07" role="img" aria-label="Levi Josman's Workspace 320's avatar"><span className="inline-block text-center">LJ</span></div>
                      </span>
                    </div>
                    <div className="flex min-w-0 flex-1 flex-col items-start justify-start overflow-hidden transform-gpu transition-all duration-200 ease-out max-w-full opacity-100" data-testid="org-switcher-text">
                      <div className="min-w-0 max-w-full truncate whitespace-nowrap text-left text-base font-bold leading-tight">Levi Josman's Workspace 320</div>
                      <div className="min-w-0 max-w-full truncate whitespace-nowrap text-left text-base font-normal leading-tight">Levi Josman</div>
                    </div>
                    <div className="flex flex-shrink-0 items-center overflow-hidden transform-gpu transition-all duration-200 ease-out max-w-full opacity-100" data-testid="org-switcher-chevron"><OrgChevron /></div>
                  </div>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

const BTN_SECONDARY = "select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 active:outline-0 focus:ring-0 bg-surface-button-secondary text-content-primary hover:bg-surface-button-secondary-accent disabled:opacity-50 gap-2 px-4 py-2 h-9 text-base";
const INPUT_BOX = "flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input";

function GeneralContent() {
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div className="relative [scrollbar-gutter:stable] overflow-x-auto overflow-y-auto size-full max-w-full p-6" data-orientation="both">
        <div className="flex flex-col gap-2" data-testid="settings-page-layout">
          <div className="flex flex-row items-center justify-between gap-2">
            <div className="relative min-w-0">
              <ol className="flex min-w-0 flex-row items-center h-9 gap-2 text-2xl">
                <li className="flex min-w-0 shrink items-center text-content-primary gap-2 text-2xl font-semibold tracking-[-0.2px]"><span className="truncate" title="General">General</span></li>
              </ol>
            </div>
          </div>
          <div className="flex flex-col gap-8">
            <form>
              <div className="group flex flex-col gap-1">
                <label className="text-base font-normal text-content-primary" htmlFor="settings-org-name">Display name</label>
                <input className={`p-0 outline-none placeholder:text-content-muted text-content-primary ${INPUT_BOX}`} data-testid="organization_name" id="settings-org-name" type="text" name="organization_name" defaultValue="Levi Josman's Workspace 320" />
              </div>
              <button type="submit" className={`${BTN_SECONDARY} mt-3`}><span className="truncate">Update</span></button>
            </form>

            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2"><span className="text-base font-bold text-content-primary">Tier</span></div>
              <div className="flex flex-col gap-3">
                <div className="flex flex-wrap gap-3">
                  <div className="bg-surface-02 border-0.5 flex w-full max-w-[350px] flex-col justify-between rounded-lg p-4 text-base text-content-primary border-brand-foreground">
                    <div className="flex flex-col gap-2">
                      <h5 className="mb-1 flex items-center gap-1.5 font-medium leading-none tracking-tight"><UsersGlyph />Core<span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal px-1.5 py-0.5 text-xs bg-brand-background text-brand-foreground/90"><span>Active</span></span></h5>
                      <div className="text-base">Ideal for individual users and teams</div>
                    </div>
                    <div className="mt-3 flex gap-2"><a className={BTN_SECONDARY} href="/settings/billing"><span className="flex items-center gap-1">Manage billing</span></a></div>
                  </div>
                  <div className="bg-surface-02 border-border-base border-0.5 flex w-full max-w-[350px] flex-col justify-between rounded-lg p-4 text-base text-content-primary">
                    <div className="flex flex-col gap-2">
                      <h5 className="mb-1 flex items-center gap-1.5 font-medium leading-none tracking-tight"><BuildingGlyph />Enterprise</h5>
                      <div className="text-base">Maximum security, compliance, and full control</div>
                    </div>
                    <div className="mt-3 flex gap-2"><button type="button" className={BTN_SECONDARY}><span className="truncate">Request free trial</span></button></div>
                  </div>
                </div>
                <div className="flex gap-1 text-base text-content-secondary">Under<a className="underline" href="/settings/billing">Billing</a>you can manage your tier and OCUs.</div>
              </div>
            </div>

            <div className="flex flex-col gap-3">
              <div className="group flex flex-col gap-1">
                <label className="text-base font-normal text-content-primary" htmlFor="settings-org-id">Organization ID</label>
                <div className="max-w-[600px]">
                  <div className="relative">
                    <div data-readonly="" className={INPUT_BOX}>
                      <input className="flex h-full max-w-[600px] text-base p-0 border-0 outline-none text-content-primary bg-transparent pr-12 w-full" title="Copy organization ID" readOnly id="settings-org-id" disabled defaultValue="019ed02a-f96e-754b-af4c-02e6c513d17a" />
                    </div>
                    <div className="absolute inset-y-0 right-2 flex items-center">
                      <button type="button" className="select-none inline-flex items-center justify-center transition-colors border-0 bg-surface-button-clear hover:bg-surface-button-clear-accent gap-2 text-base h-6 rounded-lg p-1 text-content-tertiary hover:text-content-secondary" aria-label="Copy organization ID" title="Copy organization ID"><CopyGlyph /></button>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <hr className="border-border-subtle" />

            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-lg font-bold text-content-primary">Delete organization</h3>
                <p className="text-base text-content-secondary">This permanently removes the organization and everything within it, including members and resources.</p>
                <p className="text-base text-content-secondary">You won't be able to restore the organization once it's deleted.</p>
              </div>
              <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg focus:ring-0 bg-surface-button-clear border border-border-error-strong text-content-destructive hover:bg-surface-destructive-subtle gap-2 px-4 py-2 h-9 text-base"><span className="truncate">Delete this organization</span></button>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

export function HypervisorReferenceSettings() {
  useReferenceTheme();
  return (
    <div className="app-background flex size-full overflow-hidden">
      <SettingsSidebar activeHref="/settings/manage-organization" />
      <GeneralContent />
    </div>
  );
}

export default HypervisorReferenceSettings;
