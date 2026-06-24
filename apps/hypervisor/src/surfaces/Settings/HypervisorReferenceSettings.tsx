// Parity Phase E — Settings tree, ported from the reference live /settings/** DOM
// (:9228). Settings is a full-page surface with its OWN sidebar (the org-governance
// nav, grouped: Organization Settings / Infrastructure / Agents / Login & Identity)
// replacing the app shell. Navigable in-page: the sidebar switches the content section.
// Ported sections so far: General (manage-organization), Terms of Service, Secrets,
// Skills, OIDC Tokens. Remaining data-heavy sections (Members, Integrations, Policies,
// Billing, Cost & Budgets, Runners, Environments, agent Policies, Login, SCIM) keep the
// reference href (navigate to the live route) until ported.
import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ToggleSwitch } from "../parityControls";
import { ReferenceModal } from "../parityOverlays";
import { AddCreditsDialog, ConnectIntegrationDialog } from "./HypervisorReferenceSettingsDialogs";
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
const ExternalLink = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M18.25 14V20.25H3.75V5.75H9.25M13.75 3.75H20.25V10.25M11 13L19.5 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const SelectChevron = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 10L12 14L16 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const InfoIcon = () => (
  <svg className="text-content-info shrink-0" aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10.75 11H12L12 16.25M21.25 12C21.25 17.1086 17.1086 21.25 12 21.25C6.89137 21.25 2.75 17.1086 2.75 12C2.75 6.89137 6.89137 2.75 12 2.75C17.1086 2.75 21.25 6.89137 21.25 12Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /><path d="M11.5 7.375H11.375V7.5V8.5V8.625H11.5H12.5H12.625V8.5V7.5V7.375H12.5H11.5Z" fill="currentColor" stroke="currentColor" strokeWidth="0.25" /></svg>
);
const UsersGlyph = ({ cls = "lucide lucide-users size-4" }: { cls?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={cls}><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></svg>
);
const BuildingGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-building2 size-4"><path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z" /><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" /><path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2" /><path d="M10 6h4" /><path d="M10 10h4" /><path d="M10 14h4" /><path d="M10 18h4" /></svg>
);
const ShieldCheck = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-shield-check"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><path d="m9 12 2 2 4-4" /></svg>
);
const KeyGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-key"><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4" /><path d="m21 2-9.6 9.6" /><circle cx="7.5" cy="15.5" r="5.5" /></svg>
);

const SETTINGS_NAV = [
  { group: "Organization Settings", items: [
    { label: "General", href: "/settings/manage-organization", key: "manage-organization" },
    { label: "Terms of Service", href: "/settings/terms-of-service", key: "terms-of-service" },
    { label: "Members", href: "/settings/members", key: "members" },
    { label: "Secrets", href: "/settings/organization-secrets", key: "organization-secrets" },
    { label: "Integrations", href: "/settings/org-integrations", key: "org-integrations" },
    { label: "Policies", href: "/settings/policies", key: "policies" },
    { label: "Billing", href: "/settings/billing", key: "billing" },
    { label: "Cost & Budgets", href: "/settings/credit-usage", key: "credit-usage" },
  ] },
  { group: "Infrastructure", items: [
    { label: "Runners", href: "/settings/runners", key: "runners" },
    { label: "Environments", href: "/settings/environments", key: "environments" },
  ] },
  { group: "Agents", items: [
    { label: "Policies", href: "/settings/agent-policies", key: "agent-policies" },
    { label: "Skills", href: "/settings/agent-skills", key: "agent-skills" },
  ] },
  { group: "Login & Identity", items: [
    { label: "Login Configuration", href: "/settings/login", key: "login" },
    { label: "SCIM", href: "/settings/scim", key: "scim" },
    { label: "OIDC Tokens", href: "/settings/security/oidc", key: "security/oidc" },
  ] },
];
const PORTED = new Set(["manage-organization", "terms-of-service", "organization-secrets", "agent-skills", "security/oidc", "runners", "billing", "scim", "login", "credit-usage", "members", "agent-policies", "org-integrations", "environments", "policies"]);

// Recharts usage chart captured verbatim from :9228/settings/credit-usage (the svg
// scales via viewBox; tick/grid colors resolve from the app's vendored tokens).
const USAGE_CHART = `<div class="recharts-responsive-container" style="width:100%;height:100%;min-width:0px;"><div class="recharts-wrapper" style="position:relative;cursor:default;width:100%;height:100%;max-height:250px;"><svg class="recharts-surface" width="1195" height="250" viewBox="0 0 1195 250" style="width:100%;height:100%;"><defs><clipPath id="recharts1-clip"><rect x="60" y="10" height="210" width="1125"></rect></clipPath></defs><defs><linearGradient id="r1t-total" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stop-color="#0048FF" stop-opacity="0.35"></stop><stop offset="95%" stop-color="#0048FF" stop-opacity="0.06"></stop></linearGradient></defs><g class="recharts-cartesian-grid"><g class="recharts-cartesian-grid-horizontal"><line stroke-dasharray="3 3" stroke="rgb(var(--border-base) / var(--border-base-baseline-opacity))" fill="none" x1="60" y1="10" x2="1185" y2="10"></line><line stroke-dasharray="3 3" stroke="rgb(var(--border-base) / var(--border-base-baseline-opacity))" fill="none" x1="60" y1="220" x2="1185" y2="220"></line></g></g><g class="recharts-cartesian-axis recharts-xAxis xAxis"><line orientation="bottom" x1="60" y1="220" x2="1185" y2="220" stroke="rgb(var(--content-tertiary))" stroke-width="1" fill="none"></line><g class="recharts-cartesian-axis-ticks"><g><text x="60" y="234" text-anchor="middle" fill="#666"><tspan x="60" dy="0.71em">Jun 15</tspan></text></g><g><text x="220.7" y="234" text-anchor="middle" fill="#666"><tspan x="220.7" dy="0.71em">Jun 16</tspan></text></g><g><text x="381.4" y="234" text-anchor="middle" fill="#666"><tspan x="381.4" dy="0.71em">Jun 17</tspan></text></g><g><text x="542.1" y="234" text-anchor="middle" fill="#666"><tspan x="542.1" dy="0.71em">Jun 18</tspan></text></g><g><text x="702.9" y="234" text-anchor="middle" fill="#666"><tspan x="702.9" dy="0.71em">Jun 19</tspan></text></g><g><text x="863.6" y="234" text-anchor="middle" fill="#666"><tspan x="863.6" dy="0.71em">Jun 20</tspan></text></g><g><text x="1024.3" y="234" text-anchor="middle" fill="#666"><tspan x="1024.3" dy="0.71em">Jun 21</tspan></text></g><g><text x="1179.5" y="234" text-anchor="middle" fill="#666"><tspan x="1179.5" dy="0.71em">Jun 22</tspan></text></g></g></g><g class="recharts-cartesian-axis recharts-yAxis yAxis"><g class="recharts-cartesian-axis-ticks"><g><text x="46" y="220" text-anchor="end" fill="#666"><tspan x="46" dy="0.355em">0</tspan></text></g><g><text x="46" y="167.5" text-anchor="end" fill="#666"><tspan x="46" dy="0.355em">6</tspan></text></g><g><text x="46" y="115" text-anchor="end" fill="#666"><tspan x="46" dy="0.355em">12</tspan></text></g><g><text x="46" y="62.5" text-anchor="end" fill="#666"><tspan x="46" dy="0.355em">18</tspan></text></g><g><text x="46" y="10" text-anchor="end" fill="#666"><tspan x="46" dy="0.355em">24</tspan></text></g></g></g><g class="recharts-area"><path fill="url(#r1t-total)" stroke="none" fill-opacity="0.6" d="M60,220L220.714,32.076L381.429,220L542.143,220L702.857,154.141L863.571,214.526L1024.286,212.836L1185,220L1185,220L1024.286,220L863.571,220L702.857,220L542.143,220L381.429,220L220.714,220L60,220Z"></path><path stroke="#0048FF" fill="none" stroke-width="2" d="M60,220L220.714,32.076L381.429,220L542.143,220L702.857,154.141L863.571,214.526L1024.286,212.836L1185,220"></path></g></svg></div></div>`;

function SettingsSidebar({ activeKey, onSelect }: { activeKey: string; onSelect: (key: string) => void }) {
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
                      const active = it.key === activeKey;
                      const ported = PORTED.has(it.key);
                      return (
                        <a key={it.href} className={`flex flex-row items-center rounded-lg h-8 min-w-0 ${active ? "bg-surface-hover" : "hover:bg-surface-hover"}`} translate="no" href={it.href} onClick={ported ? (e) => { e.preventDefault(); onSelect(it.key); } : undefined} {...(active ? { "aria-current": "page" } : {})}>
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
const BTN_PRIMARY = "select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 active:outline-0 focus:ring-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 gap-2 px-4 py-2 h-9 text-base";
const INPUT_BOX = "flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input";

function SettingsMain({ children }: { children: React.ReactNode }) {
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div className="relative [scrollbar-gutter:stable] overflow-x-auto overflow-y-auto size-full max-w-full p-6" data-orientation="both">
        <div className="flex flex-col gap-2" data-testid="settings-page-layout">{children}</div>
      </div>
    </main>
  );
}
function SettingsTitle({ title }: { title: string }) {
  return (
    <div className="flex flex-row items-center justify-between gap-2">
      <div className="relative min-w-0">
        <ol className="flex min-w-0 flex-row items-center h-9 gap-2 text-2xl">
          <li className="flex min-w-0 shrink items-center text-content-primary gap-2 text-2xl font-semibold tracking-[-0.2px]"><span className="truncate" title={title}>{title}</span></li>
        </ol>
      </div>
    </div>
  );
}
function EnterpriseBanner({ children }: { children: React.ReactNode }) {
  return (
    <div data-testid="enterprise-tier-banner" className="flex items-center gap-2 rounded-lg text-base border px-3 shadow-sm bg-surface-banner-info-subtle text-content-info border-border-info justify-center py-4">
      <div className="flex min-w-0 flex-1 gap-2 pr-2 items-start"><span className="flex h-[18px] shrink-0 items-center"><InfoIcon /></span>
        <div data-testid="banner-text" className="min-w-0 [overflow-wrap:anywhere]">{children}</div></div>
    </div>
  );
}

function GeneralContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="General" />
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
    </SettingsMain>
  );
}

function TermsContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Terms of Service" />
      <div className="flex max-w-[46rem] flex-col gap-6" data-testid="terms-of-service-page">
        <p className="text-base text-content-secondary">Require members to accept your organization's terms before continuing in Hypervisor.</p>
        <EnterpriseBanner>Upgrade to <a className="font-medium text-content-brand hover:underline" href="/settings/manage-organization">Enterprise tier</a> to configure terms of service.</EnterpriseBanner>
      </div>
    </SettingsMain>
  );
}

function OidcContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="OIDC Tokens" />
      <div className="flex max-w-[46rem] flex-col gap-4" data-testid="oidc-config-page">
        <div className="text-base text-content-secondary">Configure OIDC token settings for your organization. <a className="inline-flex items-center gap-1 text-content-link" target="_blank" rel="noreferrer" href="https://ona.com/docs/ona/configuration/oidc">Learn more.<ExternalLink /></a></div>
        <EnterpriseBanner>Upgrade to <a className="font-medium text-content-brand hover:underline" href="/settings/manage-organization">Enterprise tier</a> to configure OIDC tokens.</EnterpriseBanner>
      </div>
    </SettingsMain>
  );
}

function SkillsContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Skills" />
      <div className="flex flex-col gap-4" data-testid="agent-skills-section">
        <div className="flex flex-col items-center gap-4 overflow-hidden rounded-xl border-[0.5px] border-border-base bg-surface-primary px-5 py-4" data-testid="agent-skills-empty-state">
          <div className="flex flex-col items-center gap-2 py-10 text-center">
            <h2 className="font-bold tracking-[-0.2px] text-xl text-content-primary">No skills yet</h2>
            <div className="text-base text-content-secondary">Create skills for your organization. Skills let the agent discover and use workflows proactively. They can optionally be made available as slash commands.</div>
            <div className="mt-4 flex flex-row gap-2"><div className="flex gap-2">
              <button type="button" className={BTN_PRIMARY}><span className="truncate">Import defaults</span></button>
              <button type="button" className={BTN_SECONDARY}><span className="truncate">New skill</span></button>
            </div></div>
          </div>
        </div>
      </div>
    </SettingsMain>
  );
}

function SecretsBenefit({ icon, color, title, body }: { icon: React.ReactNode; color: string; title: string; body: string }) {
  return (
    <div className="flex gap-3 rounded-xl border border-border-subtle bg-surface-popover p-4">
      <div className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-lg ${color}`}>{icon}</div>
      <div className="flex flex-col gap-0.5"><p className="text-base font-medium text-content-primary">{title}</p><p className="text-sm text-content-secondary">{body}</p></div>
    </div>
  );
}
function SecretsContent() {
  return (
    <SettingsMain>
      <div className="flex w-full flex-col gap-6 md:mx-auto md:max-w-5xl">
        <div className="flex flex-col gap-2">
          <span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-brand-subtle text-content-brand px-3 py-1.5 text-base w-fit"><span>Available on Enterprise ✨</span></span>
          <h1 className="truncate text-2xl font-semibold tracking-[-0.2px] text-content-primary">Secure organization-wide secrets management</h1>
          <p className="text-md text-content-secondary">Organization-wide secrets provide a centralized way to manage sensitive information like API keys, tokens, and credentials that are automatically available across all environments in your organization.</p>
          <div data-testid="banner" className="flex items-center gap-2 rounded-lg text-base border px-3 py-2 shadow-sm bg-surface-banner-info-subtle text-content-info border-border-info justify-between flex-wrap">
            <div className="flex min-w-0 flex-1 gap-2 pr-2 items-start"><span className="flex h-[18px] shrink-0 items-center"><InfoIcon /></span>
              <div data-testid="banner-text" className="min-w-0 [overflow-wrap:anywhere]">In the meantime, you can manage personal secrets that are available in your own environments.</div></div>
            <div className="flex shrink-0 items-center gap-2 mt-2 w-full sm:mt-0 sm:w-auto">
              <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg bg-surface-button-clear hover:bg-surface-button-clear-accent border gap-2 px-4 py-2 h-9 text-base border-current text-inherit w-full sm:w-auto">View personal secrets</button>
            </div>
          </div>
          <div className="mt-2 flex flex-col gap-3 sm:flex-row">
            <button type="button" className={BTN_PRIMARY}><span className="truncate">Request trial</span></button>
            <a className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg bg-surface-button-clear hover:bg-surface-button-clear-accent border border-border-base text-content-primary hover:text-content-accent gap-2 px-4 py-2 h-9 text-base" target="_blank" rel="noreferrer" href="https://ona.com/docs/ona/organizations/organization-secrets"><span className="flex items-center gap-1">Learn more</span><ExternalLink /></a>
          </div>
        </div>
        <div className="flex flex-col gap-3">
          <p className="text-base font-medium text-content-primary">Key benefits:</p>
          <SecretsBenefit icon={<ShieldCheck />} color="bg-surface-success-subtle text-content-success" title="Centralized security management" body="Manage all your organization's secrets in one secure location. No more scattered API keys or credentials across different projects." />
          <SecretsBenefit icon={<KeyGlyph />} color="bg-surface-brand-subtle text-content-brand" title="Automatic availability across environments" body="Organization secrets are automatically injected into all environments, ensuring consistent access to required credentials without manual setup." />
          <SecretsBenefit icon={<UsersGlyph cls="lucide lucide-users" />} color="bg-surface-brand-accent-01 text-content-brand-accent-01" title="Team collaboration and access control" body="Enable secure collaboration by providing controlled access to shared secrets while maintaining security and audit trails." />
        </div>
      </div>
    </SettingsMain>
  );
}

const CloudGlyph = ({ cls }: { cls: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={cls}><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" /></svg>
);
const Ellipsis = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-ellipsis size-5 text-content-primary"><circle cx="12" cy="12" r="1" /><circle cx="19" cy="12" r="1" /><circle cx="5" cy="12" r="1" /></svg>
);
const PlusRound = () => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10.25 5V10.25M10.25 10.25V15.5M10.25 10.25H5M10.25 10.25H15.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);

function RunnersContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Runners" />
      <div className="flex flex-col gap-6">
        <p className="text-base text-content-secondary">Manage where environments run for your organization.</p>
        <div className="flex justify-between"><h3 className="text-lg font-bold text-content-primary">Self-hosted runners</h3></div>
        <div data-testid="runners-list">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
            <div data-testid="add-new-runner-card" className="min-h-40 rounded-lg text-content-secondary">
              <button type="button" className="select-none items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg focus:ring-0 hover:text-content-accent px-4 py-2 text-base flex size-full flex-col gap-0 border-0.5 border-border-light bg-surface-primary text-content-secondary hover:bg-surface-hover"><PlusRound /><span className="truncate">Set up a new runner</span></button>
            </div>
          </div>
        </div>
        <div className="flex justify-between"><h3 className="text-lg font-bold text-content-primary">Hosted by Hypervisor Cloud</h3></div>
        <div data-testid="runners-list">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
            <div role="button" tabIndex={0} className="flex flex-col gap-2 rounded-xl border-0.5 border-solid border-border-base bg-surface-glass px-5 py-4 text-left text-xs cursor-pointer hover:outline hover:outline-1 hover:outline-border-brand" aria-label="View details for Hypervisor Cloud (US01)">
              <div className="flex grow"><div className="flex grow flex-col gap-0.5">
                <div className="flex flex-row"><div className="grow"><CloudGlyph cls="lucide lucide-cloud h-8 w-8 text-content-primary" /></div><div><button type="button" className="select-none inline-flex items-center justify-center transition-colors rounded-lg bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent gap-2 text-base size-6 p-0" aria-label="More actions"><Ellipsis /></button></div></div>
                <div className="flex items-center gap-2"><p className="min-w-0 flex-shrink truncate text-base font-bold text-content-primary max-w-48">Hypervisor Cloud (US01)</p></div>
              </div></div>
              <div className="flex flex-row gap-2"><span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-success-subtle text-content-success dark:text-content-success-subtle px-2 py-1 text-sm"><span>Online</span></span></div>
              <div className="flex flex-col gap-1"><div className="flex flex-col"><p className="text-sm text-content-primary">Created <span title="2026-06-16T11:22:19.089Z">1 week ago</span></p><div data-testid="creator" className="text-sm text-content-primary"><span>by <span>You</span></span></div></div></div>
            </div>
            <div className="flex flex-col gap-2 rounded-xl border-0.5 border-solid border-border-base bg-surface-glass px-5 py-4 text-left text-xs cursor-default" aria-label="Available Runner Manager">
              <div className="flex grow"><div className="flex grow flex-col gap-0.5">
                <div className="flex flex-row"><div className="grow opacity-60"><CloudGlyph cls="lucide lucide-cloud h-8 w-8 text-content-primary" /></div><div><button type="button" className={BTN_SECONDARY}><span className="truncate">Enable</span></button></div></div>
                <div className="opacity-60"><p className="min-w-0 flex-shrink truncate text-base font-bold text-content-primary max-w-48">Hypervisor Cloud (EU01)</p></div>
                <div className="opacity-60"><div className="flex grow text-sm text-content-primary">Hypervisor Cloud</div></div>
              </div></div>
              <div className="flex flex-row gap-2"><span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-muted text-content-strong px-2 py-1 text-sm"><span>Disabled</span></span></div>
              <div className="flex flex-col"><div className="text-xs text-content-tertiary">Region: eu-central-1</div><div className="text-xs text-content-tertiary">by Hypervisor</div></div>
            </div>
          </div>
        </div>
      </div>
    </SettingsMain>
  );
}

function BillingContent() {
  const [autoTopUp, setAutoTopUp] = useState(false);
  const [creditsOpen, setCreditsOpen] = useState(false);
  return (
    <SettingsMain>
      <SettingsTitle title="Billing" />
      <div className="flex max-w-[820px] flex-col gap-6">
        <div className="text-base text-content-secondary">Manage usage and billing details</div>
        <div className="rounded-xl border-border-base border-0.5 space-y-2 bg-surface-glass p-6">
          <h2 className="mb-4 text-lg font-semibold text-content-primary">Plan</h2>
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div className="flex flex-col gap-1">
              <div className="flex gap-1"><span className="text-base font-medium text-content-primary">Core plan</span><p className="text-base font-medium text-content-secondary"> · $20/month</p><span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-muted text-content-strong px-1.5 py-0.5 text-xs"><span>Cancelled</span></span></div>
              <p className="text-sm text-content-secondary">Remains till Jul 16, 2026</p>
            </div>
            <div className="flex flex-wrap gap-2"><button type="button" className={`${BTN_PRIMARY} w-fit`}><span className="truncate">Manage</span></button></div>
          </div>
        </div>
        <div className="rounded-xl border-border-base border-0.5 bg-surface-glass p-6">
          <div className="mb-6"><h2 className="flex flex-row items-center text-lg font-semibold text-content-primary">Hypervisor Compute Units</h2><p className="text-sm text-content-secondary">Hypervisor Compute Units (OCUs) represent credits that are used for environment runtime and agent sessions. <a className="inline-flex items-center gap-1 text-content-link underline" target="_blank" rel="noreferrer" href="https://ona.com/pricing">Learn more</a></p></div>
          <div className="mb-6 flex flex-wrap gap-x-8 gap-y-4">
            <div className="flex-grow"><p className="mb-1 text-sm text-content-secondary">Total Purchased</p><p className="text-2xl font-semibold text-content-primary">120<span className="pl-2 text-md text-content-secondary">($30.00)</span></p></div>
            <div className="flex-grow"><p className="mb-1 text-sm text-content-secondary">Available</p><p className="text-2xl font-semibold text-content-primary">89.6</p></div>
            <div className="flex-grow"><p className="mb-1 text-sm text-content-secondary">Used</p><p className="text-2xl font-semibold text-content-primary">30.4</p></div>
          </div>
          <div className="mb-6"><div className="h-4 w-full rounded-full border border-surface-04 bg-surface-glass p-0.5"><div className="h-full overflow-hidden rounded-full bg-surface-glass"><div className="h-full rounded-full bg-gradient-to-r from-orange-100 to-orange-300 transition-all duration-300" style={{ width: "75%" }} /></div></div></div>
          <div className="flex flex-col gap-2">
            <div data-testid="banner" className="flex items-center gap-2 rounded-lg text-base border px-3 py-2 shadow-sm bg-surface-banner-info-subtle text-content-info border-border-info justify-between">
              <div className="flex min-w-0 flex-1 gap-2 pr-2 items-start"><span className="flex h-[18px] shrink-0 items-center"><InfoIcon /></span><div data-testid="banner-text" className="min-w-0 [overflow-wrap:anywhere]">Need more OCUs? Add credits any time.</div></div>
              <div className="flex shrink-0 items-center gap-2"><button type="button" className={BTN_PRIMARY} onClick={() => setCreditsOpen(true)}>Add Credits</button></div>
            </div>
          </div>
        </div>
        <div className="rounded-xl border-border-base border-0.5 bg-surface-glass p-6">
          <div className="mb-6"><h2 className="text-lg font-semibold text-content-primary">Auto Top-up</h2><p className="text-sm text-content-secondary">Automatically add credits when your balance drops below 20 OCUs.</p></div>
          <div className="flex flex-col gap-6"><div className="flex items-center gap-4">
            <div className="flex w-9 justify-center"><ToggleSwitch checked={autoTopUp} onChange={setAutoTopUp} ariaLabel="Enable auto top-up" className="h-5 w-9 cursor-pointer rounded-full bg-black/10 dark:bg-white/10 data-[state=checked]:bg-content-success" knobClassName="flex size-5 items-center justify-center data-[state=checked]:translate-x-[16px]" /></div>
            <label className="cursor-pointer font-medium text-content-primary" htmlFor="auto-topup-toggle">Enable auto top-up</label>
          </div></div>
        </div>
        <div className="rounded-xl border-border-base border-0.5 flex flex-col gap-6 bg-surface-glass p-6">
          <div><h2 className="text-lg font-semibold text-content-primary">Billing </h2><p className="text-sm text-content-secondary">View payment history, download invoices, update payment methods, and modify VAT information.</p></div>
          <div className="flex items-center justify-between"><button type="button" className={BTN_PRIMARY}><span className="truncate">Access billing portal</span><svg aria-hidden="true" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M7.66667 3H7.07273C5.64714 3 4.93434 3 4.38984 3.27744C3.91088 3.52148 3.52148 3.91088 3.27744 4.38984C3 4.93434 3 5.64714 3 7.07273V12.9273C3 14.3529 3 15.0656 3.27744 15.6102C3.52148 16.0892 3.91088 16.4785 4.38984 16.7225C4.93434 17 5.64714 17 7.07273 17H12.9273C14.3529 17 15.0656 17 15.6102 16.7225C16.0892 16.4785 16.4785 16.0892 16.7225 15.6102C17 15.0656 17 14.3529 17 12.9273V12.3333M11.4848 3H17M17 3V8.51515M17 3L9.15152 10.8485" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg></button></div>
        </div>
      </div>
      <ReferenceModal open={creditsOpen} onClose={() => setCreditsOpen(false)} maxWidth="480px"><AddCreditsDialog /></ReferenceModal>
    </SettingsMain>
  );
}

const SCIM_TAB = "inline-flex flex-row h-7 items-center @md:justify-center gap-2 overflow-hidden rounded-md border-transparent px-1.5 py-1 text-base text-content-strong text-left @md:text-center min-w-0 flex-shrink flex-grow hover:text-content-primary data-[state=active]:bg-surface-button-tab-primary data-[state=active]:border-transparent data-[state=active]:text-content-primary";

function ScimContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="SCIM" />
      <div className="flex w-full max-w-none flex-col gap-6" data-testid="scim-page">
        <div className="text-base text-content-secondary">Manage SCIM provisioning for your organization.</div>
        <div data-testid="free-tier-banner" className="flex items-center gap-2 rounded-lg text-base border px-3 shadow-sm bg-surface-banner-info-subtle text-content-info border-border-info justify-between py-4">
          <div className="flex min-w-0 flex-1 gap-2 pr-2 items-start"><span className="flex h-[18px] shrink-0 items-center"><InfoIcon /></span><div data-testid="banner-text" className="min-w-0 [overflow-wrap:anywhere]">Upgrade to <a className="font-medium text-content-brand hover:underline" href="/settings/manage-organization">Enterprise tier</a> to manage SCIM provisioning settings.</div></div>
          <div className="flex shrink-0 items-center gap-2"><button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg bg-surface-button-clear hover:bg-surface-button-clear-accent border gap-2 px-4 py-2 h-9 text-base border-current text-inherit">Upgrade now</button></div>
        </div>
        <div dir="ltr" data-orientation="horizontal" className="@container flex w-full flex-col gap-6">
          <div role="tablist" aria-orientation="horizontal" className="scrollbar-hide flex min-h-9 flex-col justify-stretch gap-0.5 overflow-x-auto rounded-lg border border-transparent bg-surface-button-tab-base p-[3px] @md:flex-row @md:justify-between dark:border-border-subtle w-fit" tabIndex={0}>
            <button type="button" role="tab" aria-selected="true" data-state="active" className={SCIM_TAB}><svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M14.3334 8.33333V3H1.66669V13.6667H8.33335" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M9.33331 9.33325L14.3333 10.8717L12.0256 12.0256L10.8718 14.3333L9.33331 9.33325Z" stroke="currentColor" strokeWidth="1.07143" strokeLinecap="round" strokeLinejoin="round" /></svg><span className="truncate">Configuration</span></button>
            <button type="button" role="tab" aria-selected="false" data-state="inactive" className={SCIM_TAB}><svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8.66667 1.66675H3V14.3334H13V6.00008M8.66667 1.66675L13 6.00008M8.66667 1.66675V6.00008H13M5.66667 9.00008H8.33333M5.66667 11.6667H10.3333" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg><span className="truncate">Operations Log</span></button>
          </div>
          <div role="tabpanel" className="flex w-full flex-col gap-6">
            <div className="flex w-full max-w-[550px] flex-col gap-6"><div className="flex flex-col gap-4">
              <div className="flex flex-col gap-1"><h3 className="text-lg font-bold text-content-primary">SCIM Provisioning</h3><p className="text-base text-content-secondary">Automatically manage users and groups from your identity provider.</p></div>
              <div className="rounded-xl border-border-base border-0.5 flex flex-col items-start gap-4 bg-surface-glass p-6 text-left">
                <div className="flex flex-col gap-1"><p className="text-base font-medium text-content-primary">SCIM is not currently configured</p><p className="text-base text-content-secondary">Connect your identity provider to automatically create and manage users and groups.</p></div>
                <button type="button" className={BTN_PRIMARY} disabled><span className="truncate">Set up now</span></button>
              </div>
            </div></div>
          </div>
        </div>
      </div>
    </SettingsMain>
  );
}

function Toggle({ checked, disabled = true }: { checked?: boolean; disabled?: boolean }) {
  const state = checked ? "checked" : "unchecked";
  return (
    <div className="flex w-9 justify-center">
      <button type="button" role="switch" aria-checked={checked ? "true" : "false"} data-state={state} disabled={disabled} className={`h-5 w-9 cursor-pointer rounded-full bg-black/10 dark:bg-white/10 ${disabled ? "disabled:cursor-default opacity-50" : ""} data-[state=checked]:bg-content-success`}>
        <span data-state={state} className="flex size-5 items-center justify-center data-[state=checked]:translate-x-[16px]"><svg width="25" height="25" viewBox="0 0 25 25" fill="none" xmlns="http://www.w3.org/2000/svg" className="size-5"><circle cx="12.5" cy="12.5" r="10" className="fill-[rgb(var(--ona-white))]" /></svg></span>
      </button>
    </div>
  );
}
const GlobeGlyph = () => (
  <svg className="text-content-primary" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M15.5 14.25C18.6756 14.25 21.25 11.6756 21.25 8.5C21.25 5.32436 18.6756 2.75 15.5 2.75C12.3244 2.75 9.75 5.32436 9.75 8.5C9.75 8.98191 9.80928 9.44996 9.92095 9.89728L3.75 16.0682V20.2501H7.93182L9.25 18.9319V16.2501H11.9318L14.1028 14.0791C14.5501 14.1907 15.0181 14.25 15.5 14.25Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /><path d="M17.25 8.5C17.25 9.4665 16.4665 10.25 15.5 10.25C14.5335 10.25 13.75 9.4665 13.75 8.5C13.75 7.5335 14.5335 6.75 15.5 6.75C16.4665 6.75 17.25 7.5335 17.25 8.5Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const GoogleGlyph = () => (
  <svg className="size-6" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3 12C3 7.0374 7.0374 3 12 3C14.0043 3 15.9013 3.64483 17.4861 4.8648L15.3946 7.5816C14.4147 6.82731 13.2409 6.42857 12 6.42857C8.92791 6.42857 6.42857 8.92791 6.42857 12C6.42857 15.0721 8.92791 17.5714 12 17.5714C14.4743 17.5714 16.577 15.9503 17.3016 13.7143H12V10.2857H21V12C21 16.9626 16.9626 21 12 21C7.0374 21 3 16.9626 3 12Z" fill="currentColor" /></svg>
);
const GithubGlyph = () => (
  <svg className="size-6" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M11.9732 3.18369C7.01125 3.18369 3 7.2245 3 12.2235C3 16.2195 5.57014 19.6021 9.13561 20.7993C9.58139 20.8893 9.74467 20.6047 9.74467 20.3654C9.74467 20.1558 9.72998 19.4375 9.72998 18.689C7.23386 19.2279 6.71406 17.6114 6.71406 17.6114C6.31292 16.5637 5.71855 16.2945 5.71855 16.2945C4.90157 15.7407 5.77806 15.7407 5.77806 15.7407C6.68431 15.8006 7.15984 16.6686 7.15984 16.6686C7.96194 18.0454 9.25445 17.6564 9.77443 17.4169C9.84863 16.8332 10.0865 16.4291 10.339 16.2047C8.3482 15.9951 6.25359 15.2169 6.25359 11.7445C6.25359 10.7567 6.60992 9.94856 7.17453 9.32003C7.08545 9.09558 6.77339 8.16748 7.2638 6.9253C7.2638 6.9253 8.02145 6.68579 9.7298 7.85322C10.4612 7.65534 11.2155 7.55468 11.9732 7.55383C12.7308 7.55383 13.5032 7.65871 14.2164 7.85322C15.9249 6.68579 16.6826 6.9253 16.6826 6.9253C17.173 8.16748 16.8607 9.09558 16.7717 9.32003C17.3511 9.94856 17.6928 10.7567 17.6928 11.7445C17.6928 15.2169 15.5982 15.98 13.5924 16.2047C13.9194 16.489 14.2015 17.0277 14.2015 17.8809C14.2015 19.0931 14.1868 20.066 14.1868 20.3652C14.1868 20.6047 14.3503 20.8893 14.7959 20.7994C18.3613 19.6019 20.9315 16.2195 20.9315 12.2235C20.9462 7.2245 16.9202 3.18369 11.9732 3.18369Z" fill="currentColor" /></svg>
);
const PlusCircle = () => (
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M14.3334 7.99996C14.3334 11.4978 11.4978 14.3333 8.00002 14.3333C4.50222 14.3333 1.66669 11.4978 1.66669 7.99996C1.66669 4.50216 4.50222 1.66663 8.00002 1.66663C11.4978 1.66663 14.3334 4.50216 14.3334 7.99996Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M8 5.17188V10.8287" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M10.8284 8H5.17157" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const CARD = "rounded-xl border-border-base border-0.5 flex w-full max-w-[550px] flex-col gap-4 bg-surface-glass p-4";

function LoginContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Login Configuration" />
      <div className="flex w-full max-w-none flex-col" data-testid="login-and-security-page">
        <div className="flex flex-col gap-6">
          <div className="text-base text-content-secondary">Configure SSO for your organization.</div>
          <div data-testid="free-tier-banner" className="flex items-center gap-2 rounded-lg text-base border px-3 shadow-sm bg-surface-banner-info-subtle text-content-info border-border-info justify-between py-4">
            <div className="flex min-w-0 flex-1 gap-2 pr-2 items-start"><span className="flex h-[18px] shrink-0 items-center"><InfoIcon /></span><div data-testid="banner-text" className="min-w-0 [overflow-wrap:anywhere]">Upgrade to <a className="font-medium text-content-brand hover:underline" href="/settings/manage-organization">Enterprise tier</a> to manage login and security settings.</div></div>
            <div className="flex shrink-0 items-center gap-2"><button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg bg-surface-button-clear hover:bg-surface-button-clear-accent border gap-2 px-4 py-2 h-9 text-base border-current text-inherit">Upgrade now</button></div>
          </div>
          <div className="flex w-full max-w-[550px] flex-col gap-6">
            <div className="flex flex-col gap-4">
              <h3 className="text-lg font-bold text-content-primary">Organization Login Link</h3>
              <p className="text-base text-content-secondary">Share this link with members to login using supported methods.</p>
              <div className="relative">
                <div data-readonly="" className="flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input">
                  <input className="flex h-full w-full max-w-[600px] text-base p-0 border-0 outline-none text-content-primary bg-transparent pr-12" readOnly disabled defaultValue="http://localhost:9228/login?inviteId=019eecd9-9789-72e8-893c-22a9baf94f41" />
                </div>
                <div className="absolute inset-y-0 right-2 flex items-center"><button type="button" className="select-none inline-flex items-center justify-center transition-colors border-0 bg-surface-button-clear hover:bg-surface-button-clear-accent gap-2 text-base h-6 rounded-lg p-1 text-content-tertiary hover:text-content-secondary" aria-label="Copy to clipboard"><CopyGlyph /></button></div>
              </div>
            </div>
            <div className="flex flex-col gap-4">
              <h3 className="text-lg font-bold text-content-primary">Custom Domain</h3>
              <div className={CARD}>
                <div className="flex gap-4">
                  <div className="flex w-11 items-center justify-center"><GlobeGlyph /></div>
                  <div className="flex flex-1 flex-col gap-3"><div className="flex flex-col gap-1"><p className="text-base font-normal text-content-primary">Custom domain</p><span className="text-sm text-content-secondary">Set up a private, branded domain for your organization's Hypervisor deployment.</span></div></div>
                  <div className="flex items-start"><button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap rounded-lg bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 gap-2 px-3 py-2 h-8 text-base" disabled><span className="truncate">Set up</span></button></div>
                </div>
              </div>
              <div className={CARD}>
                <div className="flex gap-4">
                  <div className="flex w-11 items-center justify-center"><Toggle /></div>
                  <div className="flex flex-1 flex-col gap-3"><div className="flex flex-col gap-1"><p className="text-base font-normal text-content-primary">Enforce custom domain at login</p><span className="text-sm text-content-secondary">Configure a custom domain first to enable enforcement</span></div></div>
                </div>
              </div>
            </div>
            <div className="flex flex-col gap-4">
              <h3 className="text-lg font-bold text-content-primary">Login Methods</h3>
              <div className={CARD}><div className="flex items-center gap-2"><div className="flex items-center"><Toggle checked /></div><GoogleGlyph /><p className="text-base font-normal text-content-primary">Google</p></div></div>
              <div className={CARD}><div className="flex items-center gap-2"><div className="flex items-center"><Toggle /></div><GithubGlyph /><p className="text-base font-normal text-content-primary">GitHub</p></div></div>
              <div className="flex flex-col gap-4 mt-4">
                <div className="flex flex-wrap items-center gap-2"><h3 className="text-lg font-bold text-content-primary">Single Sign On</h3><div className="ml-auto"><button type="button" className={BTN_SECONDARY.replace("px-4 py-2 h-9", "px-3 py-2 h-8")} disabled><PlusCircle /><span className="truncate">New SSO</span></button></div></div>
                <div className="rounded-xl border-border-base border-0.5 flex w-full flex-col gap-2 bg-surface-glass p-4"><p className="text-base text-content-primary">No custom SSO configurations yet.</p><p className="text-sm text-content-secondary">Create an SSO configuration to restrict access based on email domain.</p></div>
                <div className="flex flex-col gap-3">
                  <div className="flex flex-wrap items-center gap-2"><h4 className="text-base font-bold text-content-primary">Login Domains</h4><div className="ml-auto"><button type="button" className={BTN_SECONDARY.replace("px-4 py-2 h-9", "px-3 py-2 h-8")} disabled><PlusCircle /><span className="truncate">New domain</span></button></div></div>
                  <div className="rounded-xl border-border-base border-0.5 flex flex-col gap-2 bg-surface-glass p-4"><p className="text-base text-content-primary">No email domains yet.</p><p className="text-sm text-content-secondary">Add an email domain to control who can sign in with SSO.</p></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </SettingsMain>
  );
}

function CreditUsageContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Cost & Budgets" />
      <div className="flex flex-col gap-6" data-testid="credit-usage-page">
        <div className="flex flex-col gap-3 text-sm text-content-strong sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-x-1 gap-y-2"><span>View your usage, measured in Hypervisor Compute Units (OCUs).</span><a className="inline-flex items-center gap-1 text-content-link underline" target="_blank" rel="noreferrer" href="https://ona.com/pricing">Learn about OCUs</a></div>
          <div className="flex items-center gap-1 sm:justify-end"><span>Showing the last</span>
            <div className="relative inline-flex w-auto"><button type="button" aria-label="Select" aria-haspopup="listbox" className="flex w-full items-center justify-between gap-2 text-sm text-content-primary outline-none h-auto px-2 py-1 rounded-lg border border-border-input-default bg-surface-input"><span className="truncate"><span>7 days</span></span><SelectChevron /></button></div>
          </div>
        </div>
        <div className="rounded-xl border border-border-light p-6">
          <div className="mb-1 flex items-baseline justify-between"><p className="text-lg font-semibold text-content-primary">Credits</p><p className="text-sm text-content-secondary">90 OCUs remaining</p></div>
          <div className="h-4 w-full cursor-default rounded-full border border-surface-04 bg-surface-glass p-0.5"><div className="h-full overflow-hidden rounded-full bg-surface-glass"><div className="h-full rounded-full bg-gradient-to-r from-orange-100 to-orange-300 transition-all duration-300" style={{ width: "75%" }} /></div></div>
          <div className="mt-1 flex justify-between"><p className="text-sm text-content-secondary">0</p><p className="text-sm text-content-secondary">120 OCUs total</p></div>
        </div>
        <div className="rounded-xl border border-border-light p-6">
          <div className="mb-4 flex items-center justify-between"><p className="text-lg font-semibold text-content-primary">Total Usage<span className="ml-2 text-sm font-normal text-content-secondary">(30 OCUs in 7 days)</span></p><button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg bg-surface-button-clear hover:bg-surface-button-clear-accent border border-border-base text-content-primary hover:text-content-accent gap-2 px-3 py-2 h-8 text-base"><span className="truncate">Forecast</span></button></div>
          <div className="flex size-full"><div className="flex aspect-video justify-center text-xs w-full" style={{ height: "250px" }} dangerouslySetInnerHTML={{ __html: USAGE_CHART }} /></div>
        </div>
      </div>
    </SettingsMain>
  );
}

const SearchGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 20L16.1265 16.1265M16.1265 16.1265C17.4385 14.8145 18.25 13.002 18.25 11C18.25 6.99594 15.0041 3.75 11 3.75C6.99594 3.75 3.75 6.99594 3.75 11C3.75 15.0041 6.99594 18.25 11 18.25C13.002 18.25 14.8145 17.4385 16.1265 16.1265Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const SortGlyph = () => (
  <span className="inline-flex opacity-0 group-hover:opacity-100"><svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.25 16.25L7.25 20.25L11.25 16.25M12.75 7.75L16.75 3.75L20.75 7.75M7.25 19V3.75M16.75 20.25V4.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg></span>
);
const DotsBig = () => (
  <svg className="size-6 rounded-md p-0.5 text-content-primary" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M7.5 12C7.5 12.932 6.74448 13.6875 5.8125 13.6875C4.88052 13.6875 4.125 12.932 4.125 12C4.125 11.068 4.88052 10.3125 5.8125 10.3125C6.74448 10.3125 7.5 11.068 7.5 12ZM13.6875 12C13.6875 12.932 12.932 13.6875 12 13.6875C11.068 13.6875 10.3125 12.932 10.3125 12C10.3125 11.068 11.068 10.3125 12 10.3125C12.932 10.3125 13.6875 11.068 13.6875 12ZM18.1875 13.6875C19.1194 13.6875 19.875 12.932 19.875 12C19.875 11.068 19.1194 10.3125 18.1875 10.3125C17.2556 10.3125 16.5 11.068 16.5 12C16.5 12.932 17.2556 13.6875 18.1875 13.6875Z" fill="currentColor" /></svg>
);
const MEMBER_TABS: { label: string; icon: React.ReactNode }[] = [
  { label: "People", icon: <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M10.6666 4.33329C10.6666 5.80605 9.47268 6.99996 7.99992 6.99996C6.52716 6.99996 5.33325 5.80605 5.33325 4.33329C5.33325 2.86053 6.52716 1.66663 7.99992 1.66663C9.47268 1.66663 10.6666 2.86053 10.6666 4.33329Z" stroke="currentColor" strokeLinejoin="round" /><path d="M8.00008 8.33337C5.02038 8.33337 2.92911 10.6766 2.66675 13.6667H13.3334C13.0711 10.6766 10.9798 8.33337 8.00008 8.33337Z" stroke="currentColor" strokeLinejoin="round" /></svg> },
  { label: "Groups", icon: <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M7.16707 4.66667C7.16707 5.86328 6.19702 6.83333 5.00041 6.83333C3.80379 6.83333 2.83374 5.86328 2.83374 4.66667C2.83374 3.47005 3.80379 2.5 5.00041 2.5C6.19702 2.5 7.16707 3.47005 7.16707 4.66667Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M13.1671 4.66667C13.1671 5.86328 12.197 6.83333 11.0004 6.83333C9.80379 6.83333 8.83374 5.86328 8.83374 4.66667C8.83374 3.47005 9.80379 2.5 11.0004 2.5C12.197 2.5 13.1671 3.47005 13.1671 4.66667Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M0.747638 12.7869C0.686977 13.1688 0.995382 13.5 1.38203 13.5H8.52283C8.90948 13.5 9.21788 13.1688 9.15722 12.7869C8.24922 7.07102 1.65564 7.07102 0.747638 12.7869Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M9.61743 8.78695C11.8587 7.85608 14.6828 9.19005 15.2535 12.7889C15.3141 13.1707 15.0055 13.5 14.6188 13.5H11.1674" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg> },
  { label: "Teams", icon: <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 12V15M9.5 17.5H7M14.5 17.5H17M16.75 7.5C16.75 10.1234 14.6234 12.25 12 12.25C9.37665 12.25 7.25 10.1234 7.25 7.5C7.25 4.87665 9.37665 2.75 12 2.75C14.6234 2.75 16.75 4.87665 16.75 7.5ZM7.25 17.5C7.25 19.0188 6.01878 20.25 4.5 20.25C2.98122 20.25 1.75 19.0188 1.75 17.5C1.75 15.9812 2.98122 14.75 4.5 14.75C6.01878 14.75 7.25 15.9812 7.25 17.5ZM14.75 17.5C14.75 19.0188 13.5188 20.25 12 20.25C10.4812 20.25 9.25 19.0188 9.25 17.5C9.25 15.9812 10.4812 14.75 12 14.75C13.5188 14.75 14.75 15.9812 14.75 17.5ZM22.25 17.5C22.25 19.0188 21.0188 20.25 19.5 20.25C17.9812 20.25 16.75 19.0188 16.75 17.5C16.75 15.9812 17.9812 14.75 19.5 14.75C21.0188 14.75 22.25 15.9812 22.25 17.5Z" stroke="currentColor" strokeWidth="1.5" /></svg> },
  { label: "Service Accounts", icon: <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 3.75H4.78125V13.25H19.2188V3.75H12ZM12 3.75V1.75M8.75 7.75V9.25M15.25 7.75V9.25M5.75 13.25V14.25V15C5.75 18.4518 8.54822 21.25 12 21.25C15.4518 21.25 18.25 18.4518 18.25 15V14.25V13.25M3.75 16.25L5.27085 14.7292M20.25 16.25L18.7292 14.7292" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg> },
  { label: "Terms Acceptance", icon: <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fillRule="evenodd" clipRule="evenodd" d="M11.8793 6.30686L7.99043 10.9735C7.63686 11.3978 7.0063 11.4551 6.58202 11.1016L4.24869 9.15712L5.52906 7.62067L7.09417 8.92493L10.3429 5.02649L11.8793 6.30686Z" fill="currentColor" /></svg> },
];
const TH = "px-4 py-3.5 h-11 text-base font-bold text-content-primary outline-none";
const AVATAR_SRC = "https://lh3.googleusercontent.com/a/ACg8ocIBE-yWc_g6QMTLx_fI4gV6NkJ6Q1ERKa4YxbkEy2U9RsS3DCHb=s96-c";

function MembersContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Members" />
      <div className="mt-4 flex flex-col gap-4">
        <div dir="ltr" data-orientation="horizontal" className="@container w-full">
          <div className="mb-4 flex w-full flex-row flex-wrap justify-between gap-4">
            <div role="tablist" aria-orientation="horizontal" className="scrollbar-hide flex min-h-9 flex-col justify-stretch overflow-x-auto rounded-lg border border-transparent bg-surface-button-tab-base p-[3px] @md:flex-row @md:justify-between dark:border-border-subtle w-full gap-1 @md:w-fit" tabIndex={0}>
              {MEMBER_TABS.map((t, i) => (
                <button key={t.label} type="button" role="tab" aria-selected={i === 0 ? "true" : "false"} data-state={i === 0 ? "active" : "inactive"} className={SCIM_TAB}>{t.icon}<span className="truncate">{t.label}</span></button>
              ))}
            </div>
            <a className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent gap-2 px-3 py-2 h-8 text-base" href="/settings/members/invite"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M10.6666 4.33329C10.6666 5.80605 9.47268 6.99996 7.99992 6.99996C6.52716 6.99996 5.33325 5.80605 5.33325 4.33329C5.33325 2.86053 6.52716 1.66663 7.99992 1.66663C9.47268 1.66663 10.6666 2.86053 10.6666 4.33329Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M10.3334 8.87714C9.64453 8.52818 8.85924 8.33337 8.00008 8.33337C5.02038 8.33337 2.92911 10.6766 2.66675 13.6667H8.33341" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M12.3333 10.3334V12.3334M12.3333 12.3334V14.3334M12.3333 12.3334H10.3333M12.3333 12.3334H14.3333" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg><span className="flex items-center gap-1">Invite</span></a>
          </div>
          <div role="tabpanel">
            <div className="flex flex-col gap-2 @container @lg:flex-row @lg:items-center">
              <div className="relative [&>div]:max-w-none flex-1"><div className="flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input"><span className="flex-shrink-0 text-content-secondary"><SearchGlyph /></span><input className="flex h-full w-full text-base p-0 border-0 outline-none placeholder:text-content-muted text-content-primary bg-transparent max-w-none @sm:min-w-[20ch]" type="text" placeholder="Search by name, email or ID" defaultValue="" /></div></div>
              <div className="flex flex-col items-stretch gap-2 @sm:flex-row">
                <div className="relative w-full grow @lg:min-w-36"><button type="button" aria-label="Select" aria-haspopup="listbox" className="flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none h-9 px-3 rounded-lg border border-border-input-default bg-surface-input"><span className="truncate">All roles</span><SelectChevron /></button></div>
                <div className="relative w-full grow @lg:min-w-56"><button type="button" aria-label="Select" aria-haspopup="listbox" className="flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none h-9 px-3 rounded-lg border border-border-input-default bg-surface-input"><span className="truncate"><span>Status: All (0)</span></span><SelectChevron /></button></div>
              </div>
            </div>
            <div className="flex w-full flex-col"><div className="mt-4" /><div className="@container"><div className="relative w-full overflow-x-auto mt-4">
              <table aria-label="Organization members" className="w-full text-left text-base">
                <thead><tr className="relative border-b border-border-base">
                  <th className={`${TH} group cursor-pointer select-none`}><span className="flex items-center gap-1">Name<SortGlyph /></span></th>
                  <th className={`${TH} group cursor-pointer select-none hidden @md:table-cell w-40`}><span className="flex items-center gap-1">Date joined<SortGlyph /></span></th>
                  <th className={`${TH} hidden @lg:table-cell w-40`}><span className="flex items-center gap-1">Role</span></th>
                  <th className={`${TH} hidden @xl:table-cell w-40`}><span className="flex items-center gap-1">Authenticated with</span></th>
                  <th className={TH}><span className="flex items-center gap-1" /></th>
                </tr></thead>
                <tbody><tr className="group border-b border-border-base last:border-b-0 border-l-2 outline-none hover:bg-muted/5 border-l-transparent">
                  <td className="px-4 py-3.5 whitespace-nowrap text-base outline-none"><div className="flex min-w-0 items-center gap-3"><img loading="lazy" referrerPolicy="no-referrer" src={AVATAR_SRC} className="h-8 w-8 shrink-0 rounded-full" alt="" /><div className="flex min-w-0 flex-col"><p className="text-content-primary inline-flex min-w-0 items-center gap-2 text-base font-bold"><span className="truncate" title="Levi Josman">Levi Josman</span><span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-success-subtle text-content-success dark:text-content-success-subtle px-2 py-1 text-sm"><span>me</span></span></p><p className="truncate text-base text-content-secondary" title="josmanlevi@gmail.com">josmanlevi@gmail.com</p></div></div></td>
                  <td className="px-4 py-3.5 whitespace-nowrap text-base outline-none hidden @md:table-cell w-40"><p className="text-content-primary text-base">6/16/2026</p></td>
                  <td className="px-4 py-3.5 whitespace-nowrap text-base outline-none hidden @lg:table-cell w-40"><p className="text-content-primary text-base">Admin</p></td>
                  <td className="px-4 py-3.5 whitespace-nowrap text-base outline-none hidden @xl:table-cell w-40"><p className="text-content-primary text-base">Google</p></td>
                  <td className="px-4 py-3.5 whitespace-nowrap text-base outline-none"><span className="flex justify-end"><button type="button" className="select-none items-center font-medium justify-center whitespace-nowrap transition-colors border-0 text-content-primary hover:text-content-accent gap-2 h-9 text-base flex rounded-md bg-transparent p-1 hover:bg-surface-hover" aria-label="More actions"><DotsBig /></button></span></td>
                </tr></tbody>
              </table>
            </div></div></div>
          </div>
        </div>
      </div>
    </SettingsMain>
  );
}

const HelpIcon = () => (
  <button type="button" className="select-none inline-flex items-center justify-center rounded-lg bg-surface-button-clear hover:bg-surface-button-clear-accent gap-2 text-sm aspect-square p-0 size-5 shrink-0 text-content-tertiary hover:text-content-secondary" aria-label="About"><svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M8 13.6875C11.1412 13.6875 13.6875 11.1412 13.6875 8C13.6875 4.85888 11.1412 2.3125 8 2.3125C4.85888 2.3125 2.3125 4.85888 2.3125 8C2.3125 11.1412 4.85888 13.6875 8 13.6875ZM8 15C11.866 15 15 11.866 15 8C15 4.134 11.866 1 8 1C4.134 1 1 4.134 1 8C1 11.866 4.134 15 8 15ZM6.46875 7.125H7.125H7.78124C8.26449 7.125 8.65624 7.51676 8.65624 8V11.0625V11.7188H7.34374V11.0625V8.4375H7.125H6.46875V7.125ZM8 6.25C8.48325 6.25 8.875 5.85824 8.875 5.375C8.875 4.89176 8.48325 4.5 8 4.5C7.51676 4.5 7.125 4.89176 7.125 5.375C7.125 5.85824 7.51676 6.25 8 6.25Z" fill="currentColor" /></svg></button>
);
const HexAgent = () => (
  <svg width="20" height="20" viewBox="0 0 32 32" fill="currentColor" xmlns="http://www.w3.org/2000/svg" className="text-content-strong"><path d="M30.9471 9.86238C31.588 10.5033 32 11.3731 32 12.3803V20.6664C32 21.6735 31.588 22.5434 30.9471 23.1843L22.6609 31.4704C22.02 32.1571 21.1044 32.5233 20.1431 32.5233H11.8569C10.8498 32.5233 9.97997 32.1571 9.29328 31.4704L1.00715 23.1843C0.366237 22.5434 0 21.6735 0 20.6664V12.3803C0 11.3731 0.366237 10.5033 1.00715 9.8166L9.29328 1.53047C9.97997 0.889556 10.8498 0.477539 11.8569 0.477539H20.1431C21.1044 0.477539 22.02 0.889557 22.6609 1.57625L30.9471 9.86238ZM24.4101 21.3626V11.6841C24.4101 9.71554 22.8078 8.06747 20.8393 8.06747H11.1607C9.14644 8.06747 7.54415 9.71554 7.54415 11.6841V21.3626C7.54415 23.3311 9.14644 24.9334 11.1607 24.9334H20.8393C22.8078 24.9334 24.4101 23.3311 24.4101 21.3626Z" /></svg>
);
const OpenAIGlyph = () => (
  <svg className="size-4" width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364l2.0201-1.1638a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.4114-.6878zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0974-2.3616l2.603-1.506 2.6029 1.506v3.012l-2.6029 1.506-2.603-1.506z" fill="currentColor" /></svg>
);
const AGENT_PILL = "inline-flex h-9 select-none items-center gap-2 whitespace-nowrap rounded-xl border-0.5 border-border-base bg-surface-primary p-2 px-4 pb-[6.5px] pt-[5.5px] text-base font-medium";
const CAP_CARD = "flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4";

function CapabilityCard({ label, desc, children }: { label: string; desc: string; children?: React.ReactNode }) {
  const id = `cap-${label.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <div className={CAP_CARD}>
      <div className="flex gap-4">
        <Toggle checked disabled={false} />
        <div className="flex flex-col"><label className="cursor-pointer text-base text-content-primary" htmlFor={id}>{label}</label><p className="text-sm text-content-secondary">{desc}</p></div>
      </div>
      {children}
    </div>
  );
}

function AgentPoliciesContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Policies" />
      <div className="flex max-w-[46rem] flex-col gap-4">
        <div className="flex flex-col gap-4" data-testid="agent-policies-section">
          <p className="text-base text-content-secondary">Configure security policies and restrictions for AI agents in your organization.</p>
          <div className="flex flex-col gap-4">
            <h2 className="text-xl font-semibold">Agents</h2>
            <div className="flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4">
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-1.5"><h3 className="text-lg font-bold text-content-primary">Available agents</h3><HelpIcon /></div>
                <button type="button" className={BTN_SECONDARY.replace("px-4 py-2 h-9", "px-3 py-2 h-8")}><span className="truncate">Manage</span></button>
              </div>
              <div className="flex flex-wrap gap-2">
                <div className={AGENT_PILL}><span className="flex size-[20px] items-center justify-center"><HexAgent /></span><span>Hypervisor</span></div>
                <div className={AGENT_PILL}><span className="flex size-[20px] items-center justify-center"><OpenAIGlyph /></span><span>Codex</span></div>
              </div>
            </div>
            <div className="flex flex-col gap-5 rounded-lg border border-border-subtle px-5 py-4">
              <div className="flex items-center justify-between gap-4"><div className="flex flex-col gap-1"><h3 className="text-lg font-bold text-content-primary">Codex settings</h3><p className="text-sm text-content-secondary">Manage the Codex models, reasoning effort, and service tier available to members.</p></div></div>
              <div className="flex flex-col gap-4">
                <div className="flex items-center justify-between"><label className="font-normal text-content-primary text-sm">Available models</label><button type="button" className={BTN_SECONDARY.replace("px-4 py-2 h-9", "px-3 py-2 h-8")}><span className="truncate">Manage</span></button></div>
                <div className="flex flex-wrap gap-2"><div className={AGENT_PILL}>GPT-5.5</div><div className={AGENT_PILL}>GPT-5.4</div><div className={AGENT_PILL}>GPT-5.4 Mini</div></div>
              </div>
              <div className="grid gap-x-8 gap-y-5 md:grid-cols-2">
                <div className="flex flex-col gap-2"><div className="flex items-center gap-1.5"><label className="font-normal text-content-primary text-sm">Highest reasoning effort</label><HelpIcon /></div><div className="relative w-full max-w-64"><button type="button" aria-label="Select" aria-haspopup="listbox" className="flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none h-9 px-3 rounded-lg border border-border-input-default bg-surface-input"><span className="truncate"><span className="truncate text-base text-content-primary">Extra high</span></span><SelectChevron /></button></div></div>
                <div className="flex flex-col gap-2"><div className="flex items-center gap-1.5"><label className="font-normal text-content-primary text-sm">Highest service tier</label><HelpIcon /></div><div className="relative w-full max-w-64"><button type="button" aria-label="Select" aria-haspopup="listbox" className="flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none h-9 px-3 rounded-lg border border-border-input-default bg-surface-input"><span className="truncate"><span className="truncate text-base text-content-primary">Fast</span></span><SelectChevron /></button></div></div>
              </div>
            </div>
          </div>
          <div className="flex flex-col gap-4">
            <h2 className="text-xl font-semibold">Agent capabilities</h2>
            <CapabilityCard label="Model Context Protocol (MCP)" desc="Allow agents to use MCP servers for extended functionality" />
            <div className={CAP_CARD}>
              <div className="flex gap-4"><Toggle checked disabled={false} /><div className="flex flex-col"><label className="cursor-pointer text-base text-content-primary">SCM Tools</label><p className="text-sm text-content-secondary">Allow agents to interact with source control management systems (GitHub, GitLab, etc.)</p></div></div>
              <div className="ml-12 flex flex-col gap-2"><label className="font-normal text-content-primary text-sm">Restrict access to</label><button type="button" aria-label="Search" aria-haspopup="listbox" className="flex h-9 min-w-40 items-center justify-between gap-2 rounded-lg border border-border-input-default bg-surface-input px-3 outline-none w-fit max-w-80"><span className="truncate"><span className="truncate text-base text-content-primary flex items-center gap-2"><span className="flex size-5 items-center justify-center rounded bg-surface-tertiary text-xs">∞</span><span>All</span></span></span><SelectChevron /></button></div>
            </div>
            <CapabilityCard label="Conversation sharing" desc="Allow users to share agent conversation transcripts with other members of the organization." />
          </div>
          <div className="flex flex-col gap-4">
            <h2 className="text-xl font-semibold">Command deny list</h2>
            <div className="flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4">
              <p className="text-sm text-content-secondary">Enter commands or patterns that should be blocked (one per line).</p>
              <textarea aria-label="Command deny list" placeholder={"rm -rf\nsudo\ncurl\nwget"} className="p-0 outline-none placeholder:text-content-muted text-content-primary flex items-center gap-2 w-full px-3 py-2 rounded-lg border border-border-light bg-surface-input h-auto max-w-full resize-none overflow-y-auto font-mono text-sm" style={{ minHeight: "122px", maxHeight: "400px", height: "122px" }} />
            </div>
          </div>
          <div className="flex gap-2"><button type="button" className={BTN_PRIMARY} disabled><span className="truncate">Save changes</span></button></div>
        </div>
      </div>
    </SettingsMain>
  );
}

const INTEGRATIONS = [
  { id: "atlassian", name: "Atlassian", icon: "https://www.atlassian.com/favicon-32x32.png", cats: ["Project management", "Knowledge", "MCP"], enabled: true, desc: "Atlassian provides collaboration and project management software like Jira and Confluence for teams." },
  { id: "linear", name: "Linear", icon: "https://linear.app/favicon.ico", cats: ["Project management", "MCP"], enabled: false, desc: "Linear is a modern issue tracking and project management tool for software teams." },
  { id: "granola", name: "Granola", icon: "https://www.granola.ai/icon.png", cats: ["Knowledge", "MCP"], enabled: true, desc: "Granola takes your raw meeting notes and makes them awesome." },
  { id: "notion", name: "Notion", icon: "https://www.notion.so/images/favicon.ico", cats: ["Knowledge", "MCP"], enabled: true, desc: "Notion is an all-in-one workspace for notes, docs, wikis, and project management." },
  { id: "github", name: "GitHub", icon: "https://github.com/favicon.ico", cats: ["Source control"], install: true, desc: "GitHub integration" },
  { id: "sentry", name: "Sentry", icon: "https://avatars.githubusercontent.com/u/1396951?s=200&v=4", cats: ["Observability", "MCP"], enabled: true, desc: "Sentry tracks application errors and performance issues in real-time." },
];
const INT_BADGE = "inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-muted text-content-strong px-1.5 py-0.5 text-xs";
const INSTALL_BTN = "select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent gap-2 px-3 py-2 h-8 text-base";

function IntegrationRow({ it }: { it: (typeof INTEGRATIONS)[number] }) {
  const control = it.install ? <button type="button" className={INSTALL_BTN}><span className="truncate">Install app</span></button> : <Toggle checked={it.enabled} disabled={false} />;
  return (
    <li role="row" data-list-item={it.id} className="col-span-full grid grid-cols-subgrid">
      <div role="gridcell" aria-colindex={1} className="col-span-full grid grid-cols-subgrid">
        <div className="select-none hover:bg-surface-button-clear-accent duration-75 group/item col-span-full grid grid-cols-subgrid items-center gap-2 p-4" data-list-interactive="" data-tracking-id="list-item">
          <div className="items-center justify-center @xl:flex flex"><div data-list-slot="icon" className="flex shrink-0 items-center justify-center rounded-full bg-surface-muted" style={{ width: "36px", height: "36px" }}><img src={it.icon} alt={`${it.name} icon`} className="h-8 w-8" /></div></div>
          <div className="flex min-w-0 flex-col gap-0.5">
            <p className="text-base font-medium leading-tight text-content-primary" data-list-slot="title"><span className="flex flex-wrap items-center gap-2"><span>{it.name}</span><div className="flex flex-wrap items-center gap-2">{it.cats.map((c) => <span key={c} className={INT_BADGE}><span>{c}</span></span>)}</div></span></p>
            <p className="text-base leading-tight text-content-strong" data-list-slot="description">{it.desc}</p>
            <div className="mt-1 @xl:hidden"><div className="flex items-center gap-3">{control}</div></div>
          </div>
          <div className="hidden items-center @xl:flex @xl:col-span-2"><div data-list-slot="content" className="flex grow items-center justify-end"><div className="flex items-center gap-3">{control}</div></div></div>
          <div className="items-center justify-end hidden" />
        </div>
      </div>
    </li>
  );
}

function IntegrationsContent() {
  const [connectOpen, setConnectOpen] = useState(false);
  return (
    <SettingsMain>
      <div className="flex flex-row items-center justify-between gap-2">
        <div className="relative min-w-0"><ol className="flex min-w-0 flex-row items-center h-9 gap-2 text-2xl"><li className="flex min-w-0 shrink items-center text-content-primary gap-2 text-2xl font-semibold tracking-[-0.2px]"><span className="truncate" title="Integrations">Integrations</span></li></ol></div>
        <button type="button" className={INSTALL_BTN} data-testid="create-custom-integration-button" onClick={() => setConnectOpen(true)}><svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 6.75V12M12 12V17.25M12 12H6.75M12 12H17.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg><span className="truncate">Add MCP integration</span></button>
      </div>
      <div data-testid="org-integrations-page"><div className="flex flex-col gap-4"><div className="flex flex-col gap-6">
        <div className="flex flex-col">
          <p className="text-base text-content-secondary">Manage integrations available to your organization members. <a className="inline-flex items-center gap-1 text-content-link" target="_blank" rel="noreferrer" href="https://ona.com/docs/ona/agents/integrations">Learn more.<ExternalLink /></a></p>
          <p className="text-base text-content-secondary">To use the enabled integrations individual members will need to connect their personal accounts to the integrations in <a className="text-content-link" href="/settings/org-integrations?user-settings=integrations">User Settings &gt; Integrations</a>. </p>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative [&>div]:max-w-none flex-1"><div className="flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input"><span className="flex-shrink-0 text-content-secondary"><SearchGlyph /></span><input className="flex h-full w-full text-base p-0 border-0 outline-none placeholder:text-content-muted text-content-primary bg-transparent max-w-none" type="text" placeholder="Search integrations..." defaultValue="" /></div></div>
          <button type="button" aria-label="Filter by category" aria-haspopup="listbox" className="flex h-9 min-w-40 items-center justify-between gap-2 rounded-lg border border-border-input-default bg-surface-input px-3 outline-none w-48"><span className="truncate"><span className="truncate text-base text-content-primary">All</span></span><SelectChevron /></button>
        </div>
        <div className="@container">
          <ul aria-label="Integrations" role="grid" className="grid grid-cols-[auto_1fr_0fr_auto] @xl:grid-cols-[auto_minmax(120px,1fr)_1fr_auto] divide-y divide-border-base overflow-clip rounded-xl border border-border-base bg-surface-primary [&>*:first-child]:rounded-t-xl [&>*:last-child]:rounded-b-xl [&>li:first-child>*]:rounded-t-xl [&>li:last-child>*]:rounded-b-xl">
            {INTEGRATIONS.map((it) => <IntegrationRow key={it.id} it={it} />)}
          </ul>
        </div>
      </div></div></div>
      <ReferenceModal open={connectOpen} onClose={() => setConnectOpen(false)} maxWidth="560px"><ConnectIntegrationDialog /></ReferenceModal>
    </SettingsMain>
  );
}

const ENVIRONMENTS = [
  { id: "019ee1b5-0cdd-72af-81e4-327345446648", project: "From scratch", created: "Jun 19", createdLong: "June 19", lastStarted: "Jun 20", lastStartedLong: "June 20", phase: "Auto-stopped" },
  { id: "019ee101-d37f-7537-bd92-2eeca49b6532", project: "ioi", created: "Jun 19", createdLong: "June 19", lastStarted: "Jun 20", lastStartedLong: "June 20", phase: "Auto-stopped" },
  { id: "019ed139-ddf8-7c5d-a655-2a2a04a0eee6", project: "From scratch", created: "Jun 16", createdLong: "June 16", lastStarted: "Jun 19", lastStartedLong: "June 19", phase: "Auto-stopped" },
  { id: "019ed128-a3fd-7433-8cc3-99afed4a8ac4", project: "From scratch", created: "Jun 16", createdLong: "June 16", lastStarted: "Jun 16", lastStartedLong: "June 16", phase: "Auto-stopped" },
  { id: "019ed124-ebcf-734a-87b7-4014d206be51", project: "From scratch", created: "Jun 16", createdLong: "June 16", lastStarted: "Jun 16", lastStartedLong: "June 16", phase: "Stopped" },
];
const ENV_FILTERS = ["All projects", "All members", "All runners", "All phases"];
const TH_STICKY = "px-4 py-3.5 h-11 text-base font-bold text-content-primary outline-none sticky -top-6 z-10 bg-surface-primary pt-6 shadow-[0_2px_0_0_var(--color-border-base)]";
const TD = "px-4 py-3.5 whitespace-nowrap text-base outline-none";
const ENV_CHECKBOX = "size-4 rounded border pointer-coarse:size-5 cursor-pointer accent-content-brand focus:outline-none focus-visible:ring-2 focus-visible:ring-border-brand focus-visible:ring-offset-1";

function PhaseTag({ phase }: { phase: string }) {
  return (
    <div className="max-w-[140px]"><span className="inline-flex items-center gap-0.5"><span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-muted text-content-strong px-2 py-1 text-sm"><div className="inline-flex h-4 flex-row items-center gap-2 rounded-full text-sm"><div className="size-2 rounded-full bg-content-tertiary" /></div><span className="truncate">{phase}</span></span>
      {phase === "Auto-stopped" ? <button type="button" aria-haspopup="dialog" className="inline-flex items-center rounded p-0.5 text-current hover:bg-surface-hover"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-chevron-down"><path d="m6 9 6 6 6-6" /></svg></button> : null}
    </span></div>
  );
}

function EnvironmentsContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Environments" />
      <div className="flex h-full flex-col">
        <div className="text-base">Inventory of running and stopped environments in your organization.</div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 pt-4">
          {ENV_FILTERS.map((f) => (
            <button key={f} type="button" aria-label={f} aria-haspopup="listbox" className="flex h-9 min-w-40 items-center justify-between gap-2 rounded-lg border border-border-input-default bg-surface-input px-3 outline-none"><span className="truncate"><span className="truncate text-base text-content-primary">{f}</span></span><SelectChevron /></button>
          ))}
        </div>
        <div className="flex flex-grow flex-col pt-4"><div className="@container"><div className="relative w-full overflow-x-auto">
          <table aria-label="Environment inventory" className="w-full text-left text-base">
            <thead><tr className="relative border-b border-border-base">
              <th className="py-4 pl-4 pr-2 h-11 w-10 overflow-visible sticky -top-6 z-10 bg-surface-primary pt-6 shadow-[0_2px_0_0_var(--color-border-base)]"><div className="flex items-center gap-2"><input aria-label="Select All" type="checkbox" className={ENV_CHECKBOX} /></div></th>
              <th className={`${TH_STICKY} max-w-[280px]`}><span className="flex items-center gap-1">Project</span></th>
              <th className={`${TH_STICKY} max-w-[200px]`}><span className="flex items-center gap-1">Member</span></th>
              <th className={TH_STICKY}><span className="flex items-center gap-1">Runner</span></th>
              <th className={TH_STICKY}><span className="flex items-center gap-1">Created</span></th>
              <th className={TH_STICKY}><span className="flex items-center gap-1">Last started</span></th>
              <th className={TH_STICKY}><span className="flex items-center gap-1">Phase</span></th>
              <th className={TH_STICKY}><span className="flex items-center gap-1" /></th>
            </tr></thead>
            <tbody>
              {ENVIRONMENTS.map((e) => (
                <tr key={e.id} className="group border-b border-border-base last:border-b-0 border-l-2 outline-none hover:bg-muted/5 border-l-transparent [&>td]:cursor-auto">
                  <td className="py-2.5 pl-4 pr-2 w-10"><div className="flex items-center gap-2"><input aria-label="Select" type="checkbox" className={ENV_CHECKBOX} /></div></td>
                  <td className={`${TD} max-w-[280px]`}><p className="text-content-primary block truncate text-base" title={e.project}>{e.project}</p></td>
                  <td className={`${TD} max-w-[200px]`}><div className="inline-flex grow items-center gap-2 overflow-hidden"><span data-slot="avatar" className="relative flex overflow-hidden rounded-full size-8 shrink-0"><img className="aspect-square size-full object-cover" referrerPolicy="no-referrer" loading="lazy" alt="Levi Josman's avatar" src={AVATAR_SRC} /></span><p className="text-content-primary truncate text-base" title="Levi Josman">Levi Josman</p></div></td>
                  <td className={TD}><p className="text-content-primary text-base">Hypervisor Cloud (US01)</p></td>
                  <td className={TD}><div className="flex items-center gap-1"><p className="text-content-primary truncate text-base"><span className="@[1650px]:hidden">{e.created}</span><span className="hidden @[1650px]:inline">{e.createdLong}</span></p></div></td>
                  <td className={TD}><p className="text-content-primary truncate text-base"><span className="@[1650px]:hidden">{e.lastStarted}</span><span className="hidden @[1650px]:inline">{e.lastStartedLong}</span></p></td>
                  <td className={TD}><div><PhaseTag phase={e.phase} /></div></td>
                  <td className={TD}><span className="flex justify-end"><button type="button" className="select-none items-center font-medium justify-center whitespace-nowrap transition-colors border-0 text-content-primary hover:text-content-accent gap-2 h-9 text-base flex rounded-md bg-transparent p-1 hover:bg-surface-hover" aria-label="More actions"><DotsBig /></button></span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div></div></div>
      </div>
    </SettingsMain>
  );
}

const POLICY_EDITORS = ["VS Code", "VS Code Insiders", "Cursor", "Windsurf", "Devin", "VS Code Browser", "IntelliJ IDEA Ultimate", "GoLand", "PyCharm Professional", "PhpStorm", "RubyMine", "WebStorm", "CLion", "RustRover", "Rider"];
const EditorPill = ({ name, def }: { name: string; def?: boolean }) => (
  <div className={`inline-flex h-9 select-none items-center gap-2 whitespace-nowrap rounded-xl border-0.5 bg-surface-primary p-2 px-4 pb-[6.5px] pt-[5.5px] text-base font-medium ${def ? "border-border-brand" : "border-border-base"}`}>
    <span aria-hidden="true"><svg className="size-[20px]" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" xmlns="http://www.w3.org/2000/svg"><rect x="2.75" y="4.75" width="18.5" height="14.5" rx="2" /><path d="M9 9l-2 3 2 3M15 9l2 3-2 3" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
    <span>{name}</span>
    {def ? <span className="rounded-md bg-surface-secondary px-2 py-0.5 text-xs text-content-secondary">default</span> : null}
  </div>
);
const POL_CARD = "flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4";
const SelectTrigger = ({ value, wide }: { value: string; wide?: boolean }) => (
  <div className={`relative w-full ${wide ? "max-w-lg" : "max-w-64"}`}><button type="button" aria-label="Select" aria-haspopup="listbox" className="flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none h-9 px-3 rounded-lg border border-border-input-default bg-surface-input"><span className="truncate"><div className="flex w-full items-center justify-between">{value}</div></span><SelectChevron /></button></div>
);
function PolicyTitleCard({ title, desc, children }: { title: string; desc: string; children?: React.ReactNode }) {
  return (
    <div className={POL_CARD}>
      <div className="flex flex-col gap-0.5"><h3 className="font-bold text-content-primary text-base">{title}</h3><p className="text-sm text-content-secondary">{desc}</p></div>
      {children}
    </div>
  );
}
function PolicyToggleCard({ label, desc, checked, children }: { label: string; desc?: string; checked?: boolean; children?: React.ReactNode }) {
  return (
    <div className={POL_CARD}>
      <div className="flex gap-4"><Toggle checked={checked} disabled={false} /><div className="flex flex-col"><label className="cursor-pointer text-base text-content-primary">{label}</label>{desc ? <p className="text-sm text-content-secondary">{desc}</p> : null}</div></div>
      {children}
    </div>
  );
}
const NUM_INPUT = "flex items-center gap-2 h-9 w-full max-w-64 px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input";

function PoliciesContent() {
  return (
    <SettingsMain>
      <SettingsTitle title="Policies" />
      <div className="flex flex-col gap-6">
        <p className="text-base text-content-secondary">Configure organization-wide policies.</p>
        <EnterpriseBanner>Upgrade to <a className="font-medium text-content-brand hover:underline" href="/settings/manage-organization">Enterprise tier</a> to manage policies and unlock more features.</EnterpriseBanner>

        <div className="flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4">
          <div className="flex items-center justify-between"><h3 className="text-lg font-bold text-content-primary">Available editors</h3><button type="button" className={BTN_SECONDARY.replace("px-4 py-2 h-9", "px-3 py-2 h-8")} disabled><span className="truncate">Manage</span></button></div>
          <div className="flex flex-wrap gap-2">{POLICY_EDITORS.map((e, i) => <EditorPill key={e} name={e} def={i === 0} />)}</div>
        </div>

        <div className="flex flex-col gap-4">
          <h2 className="text-xl font-semibold">Environment policies</h2>
          <PolicyTitleCard title="Maximum environment inactivity timeout" desc="Limit the maximum length of time that an environment can be in a running state without explicit user input"><SelectTrigger value="No max timeout" wide /></PolicyTitleCard>
          <PolicyTitleCard title="Maximum environment lifetime" desc="Sets the default maximum age for new environments. Environments past this limit become non-compliant. Users receive a warning, and restarting non-compliant environments may be restricted by policy. Existing environments are not affected. Learn more">
            <SelectTrigger value="No maximum lifetime" wide />
            <div className="flex gap-4 pt-1"><Toggle disabled={false} /><div className="flex flex-col"><label className="cursor-pointer text-base text-content-primary">Strict enforcement</label><p className="text-sm text-content-secondary">Restricts starting environments past their set lifetime. Users see a warning but can still restart non-compliant environments.</p></div></div>
          </PolicyTitleCard>
          <PolicyTitleCard title="Auto-delete archived environments" desc="Controls the maximum time an environment stays archived, before deletion."><SelectTrigger value="2 weeks" wide /></PolicyTitleCard>
          <PolicyTitleCard title="Maximum total environments" desc="Limits total environments (running or stopped) per user. Reducing this limit helps control infrastructure costs. Learn more"><div className={NUM_INPUT}><input className="flex h-full w-full text-base p-0 border-0 outline-none text-content-primary bg-transparent" type="text" placeholder="No limit" defaultValue="" /></div></PolicyTitleCard>
          <PolicyTitleCard title="Maximum concurrent environments" desc="Maximum running environments per user. Learn more"><div className={NUM_INPUT}><input className="flex h-full w-full text-base p-0 border-0 outline-none text-content-primary bg-transparent" type="text" placeholder="No limit" defaultValue="" /></div></PolicyTitleCard>
          <PolicyTitleCard title="Default environment image" desc="Default devcontainer image used when no configuration is present in the repository. Leave empty to use the Hypervisor system default. Learn more"><div className="flex items-center gap-2 h-9 w-full max-w-lg px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input"><input className="flex h-full w-full text-base p-0 border-0 outline-none text-content-primary bg-transparent" type="text" placeholder="" defaultValue="" /></div></PolicyTitleCard>
        </div>

        <div className="flex flex-col gap-4">
          <h2 className="text-xl font-semibold">Project policies</h2>
          <PolicyToggleCard label="Only admins can start from scratch" />
          <PolicyToggleCard label="Allow Port Sharing in Environments" checked desc="Control whether users can share ports from their environments with external access. VS Code Browser and agents are exempt from this policy and will continue to work when disabled.">
            <div className="ml-12 flex flex-col gap-2"><label className="font-normal text-content-primary text-sm">Maximum port admission level</label><p className="text-sm text-content-secondary">Control the most permissive access level users can choose for shared environment ports. Learn more</p><SelectTrigger value="Anyone (no login required)" /></div>
          </PolicyToggleCard>
          <PolicyToggleCard label="Only admins can create projects" />
        </div>

        <div className="flex flex-col gap-4">
          <h2 className="text-xl font-semibold">Security Agents</h2>
          <PolicyToggleCard label="CrowdStrike Falcon" desc="Run the CrowdStrike Falcon agent inside environments for endpoint security monitoring." />
        </div>

        <div className="flex flex-col gap-4">
          <h2 className="text-xl font-semibold">Identity &amp; Access</h2>
          <PolicyToggleCard label="Restrict Account Creation to SCIM" desc="When enabled, only users provisioned via SCIM can access this organization. Users attempting to login via SSO without a SCIM-provisioned account will be blocked. Configure SCIM provisioning to enable this policy." />
        </div>
      </div>
    </SettingsMain>
  );
}

function SettingsContent({ section }: { section: string }) {
  switch (section) {
    case "login": return <LoginContent />;
    case "credit-usage": return <CreditUsageContent />;
    case "members": return <MembersContent />;
    case "agent-policies": return <AgentPoliciesContent />;
    case "org-integrations": return <IntegrationsContent />;
    case "environments": return <EnvironmentsContent />;
    case "policies": return <PoliciesContent />;
    case "terms-of-service": return <TermsContent />;
    case "organization-secrets": return <SecretsContent />;
    case "agent-skills": return <SkillsContent />;
    case "security/oidc": return <OidcContent />;
    case "runners": return <RunnersContent />;
    case "billing": return <BillingContent />;
    case "scim": return <ScimContent />;
    default: return <GeneralContent />;
  }
}

const SETTINGS_KEYS = new Set(SETTINGS_NAV.flatMap((g) => g.items.map((i) => i.key)));

export function HypervisorReferenceSettings() {
  useReferenceTheme();
  const navigate = useNavigate();
  const location = useLocation();
  // The URL is the source of truth for the active section (so deep links like
  // /settings/billing and cross-surface links land on the right section). The key may
  // contain a slash (e.g. security/oidc). Unknown/empty -> General.
  const raw = location.pathname.replace(/^\/settings\/?/, "").replace(/\/+$/, "");
  const section = SETTINGS_KEYS.has(raw) ? raw : "manage-organization";
  return (
    <div className="app-background flex size-full overflow-hidden">
      <SettingsSidebar activeKey={section} onSelect={(key) => navigate(`/settings/${key}`)} />
      <SettingsContent section={section} />
    </div>
  );
}

export default HypervisorReferenceSettings;
