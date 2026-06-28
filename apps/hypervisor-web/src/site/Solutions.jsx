const React = window.React;
// hypervisor.com — Solutions page.
const SNS = window.IoiDesignSystem;
const { Button: SgButton, Badge: SgBadge, Card: SgCard, TextLink: SgLink, Eyebrow: SgEyebrow } = SNS;
const swrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const USECASES = [
  ["Background work", "Task in, pull request out. Delegate work to cloud workers that run end-to-end and return reviewed PRs — keep momentum from any device.", "prim:vcs.pr", "background-work.html"],
  ["Automations & fleets", "Repeatable workflows triggered on PRs, schedules, or webhooks. Run agent fleets across your codebase with one governed configuration.", "scope:repo.write", "automations-fleets.html"],
  ["Code modernization", "Migrate deprecated APIs and modernize legacy code with worker fleets — hundreds of repos, every change receipted.", "prim:fs.write", "code-modernization.html"],
  ["Runtime AI security", "Auto-resolve CVEs, patch vulnerable dependencies, triage Sentry errors, and verify merged changes under scoped authority.", "scope:secrets.read", "runtime-security.html"],
  ["AI code review", "Review pull requests with workers that carry context, cite evidence, and never act outside their granted scope.", "prim:read", "code-review.html"],
  ["Worker training", "Turn workflows, traces, and corrections into a deployable specialist worker with Foundry — train for a defined outcome.", "scope:foundry", "worker-training.html"],
];

const PATTERNS = [
  "Automatically resolve CVEs", "Modernize code with agent fleets", "Review pull requests with AI", "Fix bugs from Linear",
  "Verify merged changes", "Summarize CI failures", "Triage Sentry errors", "Patch vulnerable deps",
  "Draft release notes", "Pick up backlog work", "Migrate deprecated APIs", "Onboard a new service",
];

function HvPage() {
  return (
    <main>
      <section style={{ ...swrap, paddingTop: "4rem", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
        <SgEyebrow color="var(--color-link-green)">Solutions</SgEyebrow>
        <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.5rem", lineHeight: 1.05, letterSpacing: "-0.02em", margin: "1.25rem 0 0", maxWidth: "18ch", color: "var(--color-onyx-black)" }}>Put workers to work across your SDLC</h1>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", maxWidth: "50ch", lineHeight: 1.5 }}>One-off handoffs and durable automations are different products over the same execution substrate. Every consequential action stays scoped, gated, and receipted.</p>
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "2rem" }}><SgButton iconRight={<span>→</span>}>Get started</SgButton><SgButton variant="outline">Request a demo</SgButton></div>
      </section>

      <section style={{ ...swrap, paddingTop: "5rem" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem" }}>
          {USECASES.map(([t, d, scope, href]) => (
            <SgCard key={t} style={{ display: "flex", flexDirection: "column", gap: "0.875rem", padding: "1.75rem" }}>
              <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", letterSpacing: "-0.015em", margin: 0 }}>{t}</h3>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", margin: 0, lineHeight: 1.45, flex: 1 }}>{d}</p>
              <div style={{ display: "flex", alignItems: "center", gap: "0.875rem" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-link-green)", border: "0.5px solid var(--color-grey-500)", borderRadius: 6, padding: "5px 8px", width: "fit-content" }}>{scope}</span>
                {href && <span style={{ marginLeft: "auto" }}><SgLink href={href}>Explore</SgLink></span>}
              </div>
            </SgCard>
          ))}
        </div>
      </section>

      {/* Patterns */}
      <section style={{ ...swrap, paddingTop: "6rem" }}>
        <div style={{ background: "var(--color-porcelain-grey)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-card)", padding: "3rem" }}>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2rem", letterSpacing: "-0.02em", margin: 0, maxWidth: "24ch" }}>Ready-made patterns your workers run on day one</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.625rem", marginTop: "1.75rem" }}>
            {PATTERNS.map((p) => (
              <span key={p} style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-900)", background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-full)", padding: "8px 14px" }}>{p}</span>
            ))}
          </div>
        </div>
      </section>

      {/* Proof */}
      <section style={{ ...swrap, paddingTop: "6rem", display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "3rem" }}>
        {[["4x", "productivity increase on modernization work"], ["83%", "of PRs co-authored by Hypervisor workers"], ["400+", "repos modernized in six months"]].map(([v, l]) => (
          <div key={v}>
            <div style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.5rem", lineHeight: 1, letterSpacing: "-0.02em", color: "var(--color-onyx-black)" }}>{v}</div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: "var(--color-grey-800)", marginTop: "0.5rem", maxWidth: "22ch" }}>{l}</div>
          </div>
        ))}
      </section>

      <section style={{ ...swrap, paddingTop: "8rem", textAlign: "center" }}>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0 }}>Find the workflow that fits</h2>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}><SgButton iconRight={<span>→</span>}>Get started</SgButton><SgLink href="platform.html">Explore the platform</SgLink></div>
      </section>
    </main>
  );
}
window.HvPage = HvPage;
