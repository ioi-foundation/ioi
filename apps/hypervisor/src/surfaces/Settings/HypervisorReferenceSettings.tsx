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
const PORTED = new Set(["manage-organization", "terms-of-service", "organization-secrets", "agent-skills", "security/oidc", "runners", "billing", "scim", "login"]);

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
              <div className="flex shrink-0 items-center gap-2"><button type="button" className={BTN_PRIMARY}>Add Credits</button></div>
            </div>
          </div>
        </div>
        <div className="rounded-xl border-border-base border-0.5 bg-surface-glass p-6">
          <div className="mb-6"><h2 className="text-lg font-semibold text-content-primary">Auto Top-up</h2><p className="text-sm text-content-secondary">Automatically add credits when your balance drops below 20 OCUs.</p></div>
          <div className="flex flex-col gap-6"><div className="flex items-center gap-4">
            <div className="flex w-9 justify-center"><button type="button" role="switch" aria-checked="false" data-state="unchecked" aria-label="Enable auto top-up" className="h-5 w-9 cursor-pointer rounded-full bg-black/10 dark:bg-white/10 data-[state=checked]:bg-content-success"><span data-state="unchecked" className="flex size-5 items-center justify-center data-[state=checked]:translate-x-[16px]"><svg width="25" height="25" viewBox="0 0 25 25" fill="none" xmlns="http://www.w3.org/2000/svg" className="size-5"><circle cx="12.5" cy="12.5" r="10" className="fill-[rgb(var(--ona-white))]" /></svg></span></button></div>
            <label className="cursor-pointer font-medium text-content-primary" htmlFor="auto-topup-toggle">Enable auto top-up</label>
          </div></div>
        </div>
        <div className="rounded-xl border-border-base border-0.5 flex flex-col gap-6 bg-surface-glass p-6">
          <div><h2 className="text-lg font-semibold text-content-primary">Billing </h2><p className="text-sm text-content-secondary">View payment history, download invoices, update payment methods, and modify VAT information.</p></div>
          <div className="flex items-center justify-between"><button type="button" className={BTN_PRIMARY}><span className="truncate">Access billing portal</span><svg aria-hidden="true" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M7.66667 3H7.07273C5.64714 3 4.93434 3 4.38984 3.27744C3.91088 3.52148 3.52148 3.91088 3.27744 4.38984C3 4.93434 3 5.64714 3 7.07273V12.9273C3 14.3529 3 15.0656 3.27744 15.6102C3.52148 16.0892 3.91088 16.4785 4.38984 16.7225C4.93434 17 5.64714 17 7.07273 17H12.9273C14.3529 17 15.0656 17 15.6102 16.7225C16.0892 16.4785 16.4785 16.0892 16.7225 15.6102C17 15.0656 17 14.3529 17 12.9273V12.3333M11.4848 3H17M17 3V8.51515M17 3L9.15152 10.8485" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg></button></div>
        </div>
      </div>
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

function Toggle({ checked }: { checked?: boolean }) {
  const state = checked ? "checked" : "unchecked";
  return (
    <div className="flex w-9 justify-center">
      <button type="button" role="switch" aria-checked={checked ? "true" : "false"} data-state={state} disabled className="h-5 w-9 cursor-pointer rounded-full bg-black/10 dark:bg-white/10 disabled:cursor-default opacity-50 data-[state=checked]:bg-content-success">
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

function SettingsContent({ section }: { section: string }) {
  switch (section) {
    case "login": return <LoginContent />;
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
