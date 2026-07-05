const React = window.React;
// hypervisor.com — Pricing page.
const PrNS = window.IoiDesignSystem;
const { Button: PrButton, Badge: PrBadge, TextLink: PrLink, Eyebrow: PrEyebrow } = PrNS;
const prwrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const CHECK = <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0, marginTop: 3 }}><path d="M3 8.5l3.2 3.2L13 5" stroke="var(--color-link-green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>;

const TIERS = [
  { name: "Core", price: "$20", unit: "/ month", blurb: "For individuals running governed sessions on their own machines.", cta: "Get started", theme: "outline",
    feat: ["Local Hypervisor Daemon", "Background & ambient workers", "Bring your own models & keys", "Receipts & deterministic replay", "Community support"] },
  { name: "Team", price: "$80", unit: "/ seat · month", blurb: "For teams standardizing autonomous work with shared authority.", featured: true, cta: "Start free trial", theme: "fill",
    feat: ["Everything in Core", "Shared projects & automations", "wallet.network authority scopes", "Org policies & approvals", "SSO / SCIM", "Priority support"] },
  { name: "Enterprise", price: "Custom", unit: "", blurb: "For organizations running fleets under governance and settlement.", cta: "Talk to sales", theme: "outline",
    feat: ["Everything in Team", "Deploy in your VPC or cTEE", "HypervisorOS bare-metal / cluster nodes", "Audit trails & no-plaintext custody", "IOI L1 settlement", "Dedicated SLA & solutions"] },
];

const FAQ = [
  ["What am I billed for?", "Usage — runtime time and authorized actions. Pricing scales with the autonomous work you run, not seats alone."],
  ["Can I bring my own models and infrastructure?", "Yes. Mount any model as a cognition backend and run on your own cloud, VPC, cTEE, or DePIN compute. No vendor lock on runtime truth."],
  ["What happens to my data?", "Operational truth lives in Agentgres under your control; cTEE private workspaces keep protected data out of provider memory. Credentials are brokered, never handed to workers."],
  ["Do receipts cost extra?", "No. Every consequential action is receipted and replayable by default — accountability is part of the runtime, not an add-on."],
];

function HvPage() {
  return (
    <main>
      <section style={{ ...prwrap, paddingTop: "4rem", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
        <PrEyebrow color="var(--color-link-green)">Pricing</PrEyebrow>
        <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.5rem", lineHeight: 1.05, letterSpacing: "-0.02em", margin: "1.25rem 0 0", maxWidth: "18ch", color: "var(--color-onyx-black)" }}>Priced to scale with your autonomous work</h1>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", maxWidth: "46ch", lineHeight: 1.5 }}>Start in minutes on your own machine. Move to your VPC, cTEE, or settlement when you're ready to run fleets.</p>
      </section>

      <section style={{ ...prwrap, paddingTop: "3.5rem" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem", alignItems: "start" }}>
          {TIERS.map((t) => (
            <div key={t.name} style={{ borderRadius: "var(--radius-card)", padding: "2.25rem", border: t.featured ? "1px solid var(--color-onyx-black)" : "0.5px solid var(--color-grey-500)", background: t.featured ? "var(--color-onyx-black)" : "var(--color-white)", color: t.featured ? "var(--color-white)" : "var(--color-onyx-black)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <h2 style={{ fontFamily: "var(--font-sans)", fontSize: "1.25rem", margin: 0 }}>{t.name}</h2>
                {t.featured && <PrBadge tone="green">Most popular</PrBadge>}
              </div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginTop: "1.5rem" }}>
                <span style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", lineHeight: 1, letterSpacing: "-0.02em" }}>{t.price}</span>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: t.featured ? "var(--color-grey-600)" : "var(--color-grey-700)" }}>{t.unit}</span>
              </div>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: t.featured ? "var(--color-grey-600)" : "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.4, minHeight: 40 }}>{t.blurb}</p>
              <div style={{ marginTop: "1.5rem" }}><PrButton variant={t.theme} theme={t.featured ? "white" : "onyx"} style={{ width: "100%" }}>{t.cta}</PrButton></div>
              <ul style={{ listStyle: "none", margin: "1.75rem 0 0", padding: "1.75rem 0 0", borderTop: t.featured ? "1px solid rgba(255,255,255,0.12)" : "0.5px solid var(--color-grey-500)", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                {t.feat.map((f) => (
                  <li key={f} style={{ display: "flex", gap: 10, fontFamily: "var(--font-sans)", fontSize: "0.875rem" }}>{CHECK}<span style={{ color: t.featured ? "rgba(255,255,255,0.9)" : "var(--color-onyx-black)" }}>{f}</span></li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section style={{ ...prwrap, paddingTop: "6rem" }}>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.25rem", letterSpacing: "-0.02em", margin: "0 0 2rem", textAlign: "center" }}>Questions</h2>
        <div style={{ maxWidth: "48rem", margin: "0 auto", display: "flex", flexDirection: "column" }}>
          {FAQ.map(([q, a]) => (
            <div key={q} style={{ padding: "1.5rem 0", borderTop: "0.5px solid var(--color-grey-500)" }}>
              <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", margin: 0 }}>{q}</h3>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.625rem", lineHeight: 1.5 }}>{a}</p>
            </div>
          ))}
        </div>
      </section>

      <section style={{ ...prwrap, paddingTop: "7rem", textAlign: "center" }}>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0 }}>Start free today</h2>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}><PrButton iconRight={<span>→</span>}>Get started</PrButton><PrButton variant="outline">Talk to sales</PrButton></div>
      </section>
    </main>
  );
}
window.HvPage = HvPage;
