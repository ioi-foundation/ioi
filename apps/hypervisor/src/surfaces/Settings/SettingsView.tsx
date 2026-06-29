// Settings surface — source-owned React, source-derived from the product-ui Settings route tree.
// The shell is a settings-nav rail (grouped: Organization / Infrastructure / Agents / Login &
// Identity, plus a User-settings group) + a content pane. It is route-addressable: nested <Routes>
// resolve the active pane off the URL, so mounting it at `/settings/*` makes every section a real
// route (e.g. /settings/members, /settings/runners, /settings/secrets, /settings/tokens,
// /settings/metering). High-value panes are wired to the native daemon; the rest are honest
// "not yet ported" placeholders — never fabricated data.
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import {
  Building2,
  ChevronLeft,
  CreditCard,
  FileText,
  GitBranch,
  Gauge,
  KeyRound,
  LayoutGrid,
  type LucideIcon,
  Plug,
  Server,
  ShieldCheck,
  Sparkles,
  Ticket,
  Users,
} from "lucide-react";
import "./Settings.css";
import {
  MembersPane,
  MeteringPane,
  NotFoundPane,
  RunnersPane,
  SecretsPane,
  StubPane,
  TokensPane,
} from "./panes";

type NavEntry = {
  to: string; // relative path under /settings
  label: string;
  icon: LucideIcon;
  wired?: boolean; // false = honest placeholder
};
type NavGroup = { head: string; items: NavEntry[] };

// The settings-nav structure, source-derived from the product-ui Settings route tree.
const NAV: NavGroup[] = [
  {
    head: "Organization",
    items: [
      { to: "general", label: "General", icon: Building2 },
      { to: "members", label: "Members", icon: Users, wired: true },
      { to: "secrets", label: "Secrets", icon: KeyRound, wired: true },
      { to: "integrations", label: "Integrations", icon: Plug },
      { to: "policies", label: "Policies", icon: FileText },
      { to: "billing", label: "Billing", icon: CreditCard },
      { to: "metering", label: "Metering & Cost", icon: Gauge, wired: true },
    ],
  },
  {
    head: "Infrastructure",
    items: [
      { to: "runners", label: "Runners", icon: Server, wired: true },
      { to: "environments", label: "Environments", icon: LayoutGrid },
    ],
  },
  {
    head: "Agents",
    items: [
      { to: "agent-policies", label: "Policies", icon: ShieldCheck },
      { to: "agent-skills", label: "Skills", icon: Sparkles },
    ],
  },
  {
    head: "Login & identity",
    items: [
      { to: "login", label: "Login configuration", icon: ShieldCheck },
      { to: "sso", label: "SSO / SCIM", icon: ShieldCheck },
    ],
  },
  {
    head: "User settings",
    items: [
      { to: "account", label: "Account", icon: Users },
      { to: "git-authentications", label: "Git authentications", icon: GitBranch, wired: true },
      { to: "tokens", label: "API access tokens", icon: Ticket, wired: true },
    ],
  },
];

function SettingsNav() {
  return (
    <nav className="st-nav" data-testid="settings-nav">
      <NavLink to="/" className="st-nav-back">
        <ChevronLeft size={15} /> Back to IOI
      </NavLink>
      {NAV.map((group) => (
        <div className="st-nav-group" key={group.head}>
          <div className="st-nav-grouphead">{group.head}</div>
          {group.items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                "st-nav-item" + (isActive ? " is-active" : "") + (item.wired ? "" : " st-nav-stub")
              }
              data-testid="settings-nav-item"
              data-wired={item.wired ? "true" : "false"}
            >
              <item.icon size={16} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  );
}

const STUBS: Record<string, { title: string; sub: string }> = {
  general: { title: "General", sub: "Organization name, branding, and deletion." },
  integrations: { title: "Integrations", sub: "Thin projection of MCP-backed integrations. The full capability estate lives in Connections." },
  policies: { title: "Policies", sub: "Environment, project, and agent policies for the organization." },
  billing: { title: "Billing", sub: "Self-hosted entitlement posture. Metering & cost is the live economic plane." },
  environments: { title: "Environments", sub: "Default environment images and environment-class configuration." },
  "agent-policies": { title: "Agent policies", sub: "Guardrails governing what agents may do." },
  "agent-skills": { title: "Agent skills", sub: "Reusable skills available to agents." },
  login: { title: "Login configuration", sub: "OIDC login-IdP configuration for the workspace." },
  sso: { title: "SSO / SCIM", sub: "SSO login connections and SCIM 2.0 user provisioning." },
  account: { title: "Account", sub: "Your personal profile and preferences." },
};

export function SettingsView() {
  return (
    <div className="st" data-testid="settings-view">
      <SettingsNav />
      <div className="st-pane" data-testid="settings-content">
        <Routes>
          <Route index element={<Navigate to="members" replace />} />
          {/* Wired-to-daemon panes */}
          <Route path="members" element={<MembersPane />} />
          <Route path="members/*" element={<MembersPane />} />
          <Route path="runners" element={<RunnersPane />} />
          <Route path="git-authentications" element={<RunnersPane />} />
          <Route path="secrets" element={<SecretsPane />} />
          <Route path="tokens" element={<TokensPane />} />
          <Route path="metering" element={<MeteringPane />} />
          {/* Honest placeholders for unported panes */}
          {Object.entries(STUBS).map(([path, s]) => (
            <Route key={path} path={path} element={<StubPane title={s.title} sub={s.sub} />} />
          ))}
          <Route path="*" element={<NotFoundPane />} />
        </Routes>
      </div>
    </div>
  );
}
