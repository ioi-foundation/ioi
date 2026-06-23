// Parity Phase E — Settings tree, ported from the reference live /settings/** DOM
// (:9228). Settings is a full-page surface with its OWN sidebar (the org-governance
// nav, grouped: Organization Settings / Infrastructure / Agents / Login & Identity)
// replacing the app shell. Navigable in-page: the sidebar switches the content section.
// Ported sections so far: General (manage-organization), Terms of Service, Secrets,
// Skills, OIDC Tokens. Remaining data-heavy sections (Members, Integrations, Policies,
// Billing, Cost & Budgets, Runners, Environments, agent Policies, Login, SCIM) keep the
// reference href (navigate to the live route) until ported.
import { useState } from "react";
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
const PORTED = new Set(["manage-organization", "terms-of-service", "organization-secrets", "agent-skills", "security/oidc", "runners"]);

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

function SettingsContent({ section }: { section: string }) {
  switch (section) {
    case "terms-of-service": return <TermsContent />;
    case "organization-secrets": return <SecretsContent />;
    case "agent-skills": return <SkillsContent />;
    case "security/oidc": return <OidcContent />;
    case "runners": return <RunnersContent />;
    default: return <GeneralContent />;
  }
}

export function HypervisorReferenceSettings() {
  useReferenceTheme();
  const [section, setSection] = useState("manage-organization");
  return (
    <div className="app-background flex size-full overflow-hidden">
      <SettingsSidebar activeKey={section} onSelect={setSection} />
      <SettingsContent section={section} />
    </div>
  );
}

export default HypervisorReferenceSettings;
