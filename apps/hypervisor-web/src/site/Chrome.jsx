const React = window.React;
// hypervisor.com chrome — header nav + footer. Composes the DS Wordmark + Button.
const { Button: HvButton, Wordmark: HvWordmark, Logo: HvLogo, ByIOI: HvByIOI } = window.IoiDesignSystem;

const NAV = [
  ["Platform", "platform.html"],
  ["Solutions", "solutions.html"],
  ["Developers", "developers.html"],
  ["Pricing", "pricing.html"],
  ["Docs", "docs.html"],
];

function Header({ active } = {}) {
  const [open, setOpen] = React.useState(false);
  return (
    <header style={{ position: "sticky", top: 0, zIndex: 20, background: "rgba(255,255,255,0.9)", backdropFilter: "saturate(180%) blur(12px)", WebkitBackdropFilter: "saturate(180%) blur(12px)", borderBottom: "0.5px solid var(--color-grey-500)" }}>
      <div className="hv-header-inner" style={{ maxWidth: "75rem", margin: "0 auto", display: "flex", alignItems: "center", gap: "1.25rem", padding: "1rem 2.5rem" }}>
        <a href="index.html" aria-label="Hypervisor" style={{ display: "flex", flexShrink: 0, color: "var(--color-onyx-black)", textDecoration: "none" }}>
          <HvWordmark height={24} />
        </a>
        <ul className="hv-nav-links" style={{ display: "flex", listStyle: "none", margin: "0 0 0 1.5rem", padding: 0, gap: "0.25rem" }}>
          {NAV.map(([label, href]) => {
            const on = active === label;
            return (
            <li key={label} style={{ display: "flex" }}>
              <a href={href} style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "0.6875rem 0.625rem", fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: on ? "var(--color-onyx-black)" : "var(--color-grey-800)", fontWeight: on ? 500 : 400, textDecoration: "none" }}>
                {label}
              </a>
            </li>
            );
          })}
        </ul>
        <div className="hv-nav-cta" style={{ marginLeft: "auto", display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <HvButton theme="grey" size="md">Sign in</HvButton>
          <HvButton size="md">Get started</HvButton>
        </div>
        <button className="hv-navtoggle" aria-label="Menu" aria-expanded={open} onClick={() => setOpen((o) => !o)} style={{ marginLeft: "auto", width: 40, height: 40, alignItems: "center", justifyContent: "center", background: "none", border: "0.5px solid var(--color-grey-500)", borderRadius: 8, color: "var(--color-onyx-black)", cursor: "pointer", padding: 0 }}>
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
            {open
              ? <path d="M4 4l10 10M14 4L4 14" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
              : <path d="M2.5 5h13M2.5 9h13M2.5 13h13" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />}
          </svg>
        </button>
      </div>
      {open && (
        <div className="hv-mobile-menu" style={{ borderTop: "0.5px solid var(--color-grey-500)", padding: "0.5rem 1.25rem 1.25rem", flexDirection: "column" }}>
          {NAV.map(([label, href]) => {
            const on = active === label;
            return <a key={label} href={href} style={{ display: "block", padding: "0.875rem 0.25rem", fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: on ? "var(--color-onyx-black)" : "var(--color-grey-800)", fontWeight: on ? 500 : 400, textDecoration: "none", borderBottom: "0.5px solid var(--color-grey-500)" }}>{label}</a>;
          })}
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "1rem" }}>
            <HvButton theme="grey" size="md">Sign in</HvButton>
            <HvButton size="md">Get started</HvButton>
          </div>
        </div>
      )}
    </header>
  );
}

function FCol({ title, links }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.875rem" }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>{title}</div>
      <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: "0.625rem" }}>
        {links.map((l) => {
          const [label, href] = Array.isArray(l) ? l : [l, null];
          return <li key={label}><a href={href || "#"} onClick={href ? undefined : (e) => e.preventDefault()} style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", textDecoration: "none" }}>{label}</a></li>;
        })}
      </ul>
    </div>
  );
}

function Footer() {
  return (
    <footer style={{ borderTop: "0.5px solid var(--color-grey-500)", marginTop: "8rem" }}>
      <div className="hv-footer-grid" style={{ maxWidth: "75rem", margin: "0 auto", padding: "3.5rem 2.5rem", display: "grid", gridTemplateColumns: "1.6fr repeat(4, 1fr)", gap: "2rem" }}>
        <div style={{ color: "var(--color-onyx-black)" }}>
          <HvWordmark height={26} />
          <div style={{ marginTop: "0.75rem" }}>
            <HvByIOI height={13} />
          </div>
          <div style={{ marginTop: "1.25rem", display: "flex", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", color: "var(--color-grey-700)", border: "0.5px solid var(--color-grey-500)", borderRadius: 6, padding: "5px 9px" }}>SOC 2</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", color: "var(--color-grey-700)", border: "0.5px solid var(--color-grey-500)", borderRadius: 6, padding: "5px 9px" }}>GDPR</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", color: "var(--color-grey-700)", border: "0.5px solid var(--color-grey-500)", borderRadius: 6, padding: "5px 9px" }}>Web4</span>
          </div>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "1.5rem", lineHeight: 1.5, maxWidth: "30ch" }}>
            The open operating environment for autonomous systems.
          </p>
        </div>
        <FCol title="Platform" links={[["Hypervisor App", "hv-app.html"], ["Web", "hv-web.html"], ["CLI", "hv-cli.html"], ["MCP gateway", "hv-mcp.html"], ["HypervisorOS", "hv-os.html"], ["Embodied Runtime", "hv-embodied.html"]]} />
        <FCol title="Solutions" links={[["Background work", "background-work.html"], ["Automations", "automations-fleets.html"], ["Modernization", "code-modernization.html"], ["Security agents", "runtime-security.html"]]} />
        <FCol title="Developers" links={[["Docs", "docs.html"], ["SDK", "hv-sdk.html"], ["ADK", "hv-adk.html"], ["ODK", "hv-odk.html"], "API reference", "Changelog"]} />
        <FCol title="Company" links={["About", "Careers", "Security", "Contact"]} />
      </div>
      <div className="hv-footer-bar" style={{ maxWidth: "75rem", margin: "0 auto", padding: "1.5rem 2.5rem 3rem", borderTop: "0.5px solid var(--color-grey-500)", display: "flex", gap: "1.5rem", flexWrap: "wrap", alignItems: "center" }}>
        {["Terms", "Privacy", "Trust", "Status"].map((l) => <a key={l} href="#" onClick={(e) => e.preventDefault()} style={{ fontFamily: "var(--font-sans)", fontSize: "0.8125rem", color: "var(--color-grey-700)", textDecoration: "none" }}>{l}</a>)}
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--color-grey-700)" }}>© 2026 IOI, Inc. · hypervisor.com</span>
      </div>
    </footer>
  );
}

window.HvHeader = Header;
window.HvFooter = Footer;
