const React = window.React;
// hypervisor.com — Developers page.
const DNS = window.IoiDesignSystem;
const { Button: DgButton, Badge: DgBadge, Card: DgCard, TextLink: DgLink, Eyebrow: DgEyebrow } = DNS;
const dwrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const SURFACES = [
  ["CLI / Headless", "The operator, scripting, CI, and node-ops client. A TUI is an optional presentation of the same controls — never a separate runtime."],
  ["SDK", "The low-level protocol/client library. Drive runs, read receipts, and integrate the daemon API into your own tools."],
  ["ADK", "The autonomous-system builder framework. Compose workers, workflows, and policies as deployable packages."],
  ["Daemon API", "The public runtime surface: projects, GoalRuns, Automations, Sessions, delegated work queues, adapter targets, and short-lived access tokens."],
  ["AIIP", "The semantic interop protocol for bounded autonomous-work handoffs between independently governed systems; same-system work stays on native L0 coordination."],
  ["Worker packages", "Ship workers as benchmarked, manifested, installable packages routed through Mixture of Workers."],
];

const CODE = `# install the runtime + clients
npm install
cargo check --workspace

# run the local operator surface
npm run dev:hypervisor-app

# delegate work under a scoped authority
hv run "modernize payments-api" \\
  --scope prim:fs.write,scope:repo.write \\
  --receipt --replay`;

const dvINK = "var(--color-onyx-black)";
const dvHAIR = "var(--color-grey-500)";
const dvACC = "var(--color-link-green)";
const dvPANEL = { background: "color-mix(in srgb, var(--color-pistachio-green) 28%, var(--color-white))", border: `0.5px solid ${dvHAIR}`, borderRadius: "var(--radius-card)", height: 460, padding: "2rem", position: "relative", overflow: "hidden" };
const dvCard = { background: "var(--color-white)", border: `0.5px solid ${dvHAIR}`, borderRadius: 14, boxShadow: "var(--shadow-sm)" };

function dvClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.85); return; }
    let raf, start = null;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % period) / period)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}

function DvSpinner({ t, on, done }) {
  const spin = (t * 1440) % 360;
  if (done) return <span style={{ width: 17, height: 17, borderRadius: "50%", background: dvACC, display: "grid", placeItems: "center", flex: "none" }}><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>;
  if (on) return <svg width="17" height="17" viewBox="0 0 18 18" style={{ flex: "none", transform: `rotate(${spin}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={dvACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg>;
  return <svg width="17" height="17" viewBox="0 0 18 18" style={{ flex: "none" }}><circle cx="9" cy="9" r="7" fill="none" stroke="var(--color-grey-500)" strokeWidth="1.5" strokeDasharray="0.5 3.5" strokeLinecap="round" /></svg>;
}

/* ---- 1. Build custom workflows (pipeline) ---- */
function dvWorkflowDemo() {
  const t = dvClock(8000);
  const steps = [
    ["Trigger", "Daily schedule", "Runs at 9 AM on weekdays.", dvACC],
    ["Prompt", "Fetch and select issue from Jira", "Fetch first feasible issues from the current sprint. Sort by priority and due date.", "var(--color-grey-700)"],
    ["Shell Script", "Run tests", "npm test || go test ./... || yarn test || echo \"done\"", "var(--color-grey-700)"],
    ["Pull Request", "Open draft PR", "Create a draft pull request linked to the Jira issue.", dvACC],
  ];
  const active = Math.min(steps.length, Math.floor(t * (steps.length + 1.1)));
  return (
    <div style={{ ...dvPANEL, display: "flex", alignItems: "center", justifyContent: "center", padding: "0 24px" }}>
      <div style={{ width: "100%", display: "flex", flexDirection: "column" }}>
        {steps.map(([kind, title, desc, c], i) => {
          const done = i < active, on = i === active;
          return (
            <React.Fragment key={i}>
              {i > 0 && <span style={{ width: 1.5, height: 16, background: i <= active ? dvACC : dvHAIR, margin: "0 auto", transition: "background 0.3s" }} />}
              <div style={{ ...dvCard, padding: "13px 16px", opacity: i <= active ? 1 : 0.45, transform: on ? "scale(1.015)" : "scale(1)", boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)", transition: "opacity 0.35s, transform 0.35s, box-shadow 0.35s" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "var(--color-porcelain-grey)", borderRadius: 6, padding: "2px 8px", fontFamily: "var(--font-mono)", fontSize: 10.5, color: dvINK }}><span style={{ width: 6, height: 6, borderRadius: "50%", background: c }} />{kind}</span>
                  {done && <span style={{ marginLeft: "auto" }}><DvSpinner t={t} done /></span>}
                  {on && <span style={{ marginLeft: "auto" }}><DvSpinner t={t} on /></span>}
                </div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: dvINK, marginTop: 8 }}>{title}</div>
                <div style={{ fontFamily: kind === "Shell Script" ? "var(--font-mono)" : "var(--font-sans)", fontSize: kind === "Shell Script" ? "0.75rem" : "0.8125rem", color: "var(--color-grey-700)", marginTop: 4, lineHeight: 1.4, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{desc}</div>
              </div>
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

/* ---- 2. Trigger from any event (pills) ---- */
function dvTriggerDemo() {
  const t = dvClock(5600);
  const items = ["Webhooks", "Scheduled", "Pull Requests", "Manual"];
  const active = Math.min(items.length - 1, Math.floor(t * (items.length + 0.4)));
  return (
    <div style={{ ...dvPANEL, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", gap: 16 }}>
      {items.map((label, i) => {
        const fired = i < active, firing = i === active;
        return (
          <div key={label} style={{ ...dvCard, width: "82%", borderRadius: 999, padding: "15px 24px", display: "flex", alignItems: "center", gap: 14, transform: firing ? "scale(1.02)" : "scale(1)", boxShadow: firing ? "var(--shadow-md)" : "var(--shadow-xs)", transition: "transform 0.3s, box-shadow 0.3s" }}>
            <DvSpinner t={t} on={firing} done={fired} />
            <span style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: dvINK }}>{label}</span>
          </div>
        );
      })}
    </div>
  );
}

/* ---- 3. Execute across thousands of repos (migration list) ---- */
function dvScaleDemo() {
  const t = dvClock(7000);
  const rows = [
    ["JAVA 8 \u2192 JAVA 17", "Repository 01 \u00b7 1 min ago"],
    ["COBOL \u2192 JAVA", "Repository 02 \u00b7 30 sec ago"],
    ["JAVA 8 \u2192 JAVA 17", "AetherNet \u00b7 started 10s ago"],
    ["JAVA 8 \u2192 JAVA 17", "Project Phoenix \u00b7 started 9s ago"],
    ["JAVA 8 \u2192 JAVA 17", "InfernoCore \u00b7 started 8s ago"],
    ["JAVA 8 \u2192 JAVA 17", "PyroLink \u00b7 started 7s ago"],
  ];
  const done = Math.max(0, Math.min(rows.length, Math.floor((t - 0.12) / 0.12)));
  const count = 1 + done + Math.floor(t * 9);
  return (
    <div style={{ ...dvPANEL, padding: 0, overflow: "hidden" }}>
      <div style={{ ...dvCard, margin: 16, borderRadius: 14, overflow: "hidden", boxShadow: "var(--shadow-md)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "14px 18px", borderBottom: `0.5px solid ${dvHAIR}` }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: dvACC, flex: "none" }} />
          <span style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: dvINK }}>Migration in progress…</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-grey-700)", background: "var(--color-porcelain-grey)", border: `0.5px solid ${dvHAIR}`, borderRadius: 999, padding: "3px 10px" }}>{count}/210</span>
        </div>
        <div style={{ padding: "6px 0", WebkitMaskImage: "linear-gradient(180deg, #000 62%, transparent)", maskImage: "linear-gradient(180deg, #000 62%, transparent)" }}>
          {rows.map(([title, meta], i) => {
            const ok = i < done, on = i === done;
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 18px", opacity: i <= done ? 1 : Math.max(0.2, 0.85 - (i - done) * 0.22) }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--color-grey-600)", width: 16, flex: "none" }}>{i + 1}.</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: dvINK, whiteSpace: "nowrap" }}>{title}</div>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.75rem", color: "var(--color-grey-600)", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{meta}</div>
                </div>
                <DvSpinner t={t} on={on} done={ok} />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

const DV_TABS = [
  { label: "Build custom workflows", sub: "Combine prompts, scripts, and integrations into reusable automations.", demo: dvWorkflowDemo },
  { label: "Trigger from any event", sub: "Run from webhooks, pull requests, schedules, or on demand.", demo: dvTriggerDemo },
  { label: "Execute across thousands of repos", sub: "Run across one repo or thousands — no extra configuration.", demo: dvScaleDemo },
];

function DvAutomations() {
  const [active, setActive] = React.useState(0);
  const tab = DV_TABS[active];
  const Demo = tab.demo;
  return (
    <section style={{ ...dwrap, paddingTop: "6rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.1fr", gap: "3.5rem", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: 0, color: dvINK }}>Powered by automations</h2>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5, maxWidth: "38ch" }}>Repeatable workflows that combine prompts and scripts. Triggered from webhooks, PRs, schedules.</p>
          <div style={{ marginTop: "1.25rem" }}><DgLink href="docs.html">Start automating</DgLink></div>
          <ul style={{ listStyle: "none", margin: "2.25rem 0 0", padding: 0, display: "flex", flexDirection: "column", gap: 6 }}>
            {DV_TABS.map((tb, i) => {
              const on = i === active;
              return (
                <li key={tb.label}>
                  <button onClick={() => setActive(i)} style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "flex-start", gap: 12, padding: "14px 16px", borderRadius: "var(--radius-lg)", border: "none", cursor: "pointer", background: on ? "var(--color-porcelain-grey)" : "transparent" }}>
                    <span style={{ flex: 1 }}>
                      <span style={{ display: "block", fontFamily: "var(--font-sans)", fontSize: "1rem", fontWeight: on ? 600 : 500, color: dvINK }}>{tb.label}</span>
                      <span style={{ display: "block", fontFamily: "var(--font-sans)", fontSize: "0.875rem", color: "var(--color-grey-700)", marginTop: 3, lineHeight: 1.4 }}>{tb.sub}</span>
                    </span>
                    {on && <span style={{ marginTop: 2 }}><DvSpinner t={0} on /></span>}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
        <Demo />
      </div>
    </section>
  );
}

function HvPage() {
  return (
    <main>
      <section style={{ ...dwrap, paddingTop: "4rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem", alignItems: "center" }}>
        <div>
          <DgEyebrow color="var(--color-link-green)">Developers</DgEyebrow>
          <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.25rem", lineHeight: 1.05, letterSpacing: "-0.02em", margin: "1.25rem 0 0", color: "var(--color-onyx-black)" }}>Build on the runtime substrate</h1>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.125rem", color: "var(--color-grey-800)", marginTop: "1.25rem", maxWidth: "42ch", lineHeight: 1.5 }}>One execution substrate. No separate SDK, GUI, CLI, or harness owns consequential execution semantics — they all bind to the daemon.</p>
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "2rem" }}><DgButton iconRight={<span>→</span>}>Read the docs</DgButton><DgButton variant="outline">API reference</DgButton></div>
        </div>
        <div style={{ background: "var(--color-onyx-black)", borderRadius: "var(--radius-card)", padding: "1.5rem 1.75rem", overflow: "hidden" }}>
          <div style={{ display: "flex", gap: 6, marginBottom: "1rem" }}>
            {["#e1e1e1", "#cecece", "#818181"].map((c, i) => <span key={i} style={{ width: 11, height: 11, borderRadius: "50%", background: c, opacity: 0.5 }} />)}
          </div>
          <pre style={{ margin: 0, fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.6, color: "var(--color-grey-600)", whiteSpace: "pre-wrap" }}>{CODE}</pre>
        </div>
      </section>

      <section style={{ ...dwrap, paddingTop: "6rem" }}>
        <div style={{ maxWidth: "44rem" }}>
          <DgEyebrow>Surfaces</DgEyebrow>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", margin: "1rem 0 0" }}>Clients, frameworks, and protocols</h2>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem", marginTop: "2.5rem" }}>
          {SURFACES.map(([t, d]) => (
            <DgCard key={t} style={{ padding: "1.5rem 1.75rem" }}>
              <h3 style={{ fontFamily: "var(--font-mono)", fontSize: "1rem", margin: 0, color: "var(--color-onyx-black)" }}>{t}</h3>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.625rem", lineHeight: 1.45 }}>{d}</p>
            </DgCard>
          ))}
        </div>
      </section>

      <section style={{ ...dwrap, paddingTop: "6rem" }}>
        <div style={{ background: "var(--color-porcelain-grey)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-card)", padding: "3rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2.5rem", alignItems: "center" }}>
          <div>
            <DgEyebrow>The boundary</DgEyebrow>
            <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2rem", letterSpacing: "-0.02em", lineHeight: 1.1, margin: "1rem 0 0" }}>Tool calls are requests, not grants</h2>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5 }}>Raw model output is never authority for consequential action. The runtime collapses intent into a deterministic decision: allowed, denied, escalated, receipted, and replayable.</p>
            <div style={{ marginTop: "1.5rem" }}><DgLink href="docs.html">Read the conformance invariants</DgLink></div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[["prim:*", "what the runtime may execute"], ["scope:*", "what a wallet or tenant may authorize"], ["receipt", "legible, replayable evidence of every effect"]].map(([k, v]) => (
              <div key={k} style={{ display: "flex", alignItems: "baseline", gap: 12, background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-lg)", padding: "13px 15px" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--color-link-green)", minWidth: 72 }}>{k}</span>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-grey-900)" }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <DvAutomations />

      <section style={{ ...dwrap, paddingTop: "8rem", textAlign: "center" }}>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0 }}>Start building</h2>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}><DgButton iconRight={<span>→</span>}>Read the docs</DgButton><DgLink href="docs.html">Browse SDK reference</DgLink></div>
      </section>
    </main>
  );
}
window.HvPage = HvPage;
