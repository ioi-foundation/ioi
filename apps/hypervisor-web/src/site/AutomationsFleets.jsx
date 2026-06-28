const React = window.React;
// hypervisor.com — Automations & Fleets solution page.
const AFNS = window.IoiDesignSystem;
const { Button: AfButton, TextLink: AfLink, Eyebrow: AfEyebrow, Logo: AfLogo } = AFNS;
const afwrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";

/* ====================== dark workflow builder mockup ====================== */
function BuilderIcon({ d }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d={d} />
    </svg>
  );
}

const SIDEBAR_ICONS = [
  "M12 2 a7 7 0 1 0 0 14 a7 7 0 0 0 0 -14 M19.5 19.5 L15.5 15.5",
  "M3 12 a9 9 0 1 0 18 0 a9 9 0 0 0 -18 0 M12 7 v5 l3 3",
  "M3 3 h7 v7 H3 Z M14 3 h7 v7 h-7 Z M3 14 h7 v7 H3 Z M14 14 h7 v7 h-7 Z",
  "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z",
  "M12 3 a9 9 0 1 0 0 18 M12 8 v8 M8 12 h8",
];

function WorkflowBlock({ kind, accent, label, desc, active, done, t }) {
  const borderCol = accent ? ACC : "rgba(255,255,255,0.12)";
  const spin = (t * 1440) % 360;
  return (
    <div style={{ background: accent ? "rgba(80,200,120,0.08)" : "rgba(255,255,255,0.05)", border: `1px solid ${borderCol}`, borderRadius: 10, padding: "12px 14px", position: "relative" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "rgba(255,255,255,0.09)", borderRadius: 5, padding: "2px 8px", fontFamily: "var(--font-mono)", fontSize: 10.5, color: accent ? ACC : "rgba(255,255,255,0.55)" }}>
          <span style={{ width: 5, height: 5, borderRadius: "50%", background: accent ? ACC : "rgba(255,255,255,0.4)" }} />{kind}
        </span>
        <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 5 }}>
          {done && <svg width="14" height="14" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="6" fill={ACC} /><path d="M3 6.2 L5.2 8.2 L9 3.8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>}
          {active && <svg width="14" height="14" viewBox="0 0 18 18" style={{ transform: `rotate(${spin}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg>}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.3)" strokeWidth="1.8" strokeLinecap="round"><circle cx="12" cy="5" r="1" fill="rgba(255,255,255,0.3)" stroke="none" /><circle cx="12" cy="12" r="1" fill="rgba(255,255,255,0.3)" stroke="none" /><circle cx="12" cy="19" r="1" fill="rgba(255,255,255,0.3)" stroke="none" /></svg>
        </span>
      </div>
      <div style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: "rgba(255,255,255,0.9)", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "rgba(255,255,255,0.42)", lineHeight: 1.45, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{desc}</div>
    </div>
  );
}

function WorkflowBuilderDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.7); return; }
    let raf, start = null;
    const PERIOD = 9000;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % PERIOD) / PERIOD)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  const steps = [
    { kind: "Trigger", label: "Manual trigger", desc: "Runs across · 0 projects", accent: false, at: 0 },
    { kind: "Prompt", label: "Research {CVE_ID}: what is the vulnerability, whic…", desc: "Research the CVE and identify affected repos", accent: false, at: 0.18 },
    { kind: "Prompt", label: "Check if this repository has the vulnerable library. L…", desc: "Verify presence in current dependency tree", accent: false, at: 0.36 },
    { kind: "Shell Script", label: "Run fix and test suite", desc: "npm audit fix || yarn audit fix && npm test", accent: false, at: 0.54 },
    { kind: "Pull Request", label: "Open PR with fix", desc: "Create pull request with CVE details and evidence", accent: true, at: 0.72 },
  ];

  const activeIdx = Math.min(steps.length - 1, Math.floor(t * (steps.length + 0.6)));
  const concurrent = Math.floor(3 + t * 7);
  const total = Math.floor(10 + t * 90);

  return (
    <div style={{ width: "100%", maxWidth: 720, margin: "0 auto", background: "#111115", borderRadius: 14, overflow: "hidden", boxShadow: "0 32px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.08)", fontFamily: "var(--font-sans)" }}>
      {/* mac traffic lights */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "13px 16px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
        {["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => <span key={i} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />)}
        <span style={{ margin: "0 auto", fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.35)" }}>Hypervisor · Automations</span>
      </div>

      <div style={{ display: "flex", height: 520 }}>
        {/* left sidebar */}
        <div style={{ width: 48, flex: "none", borderRight: "1px solid rgba(255,255,255,0.07)", display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 16, gap: 6 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: "rgba(255,255,255,0.1)", display: "grid", placeItems: "center", color: "#fff" }}>
            <AfLogo size={14} />
          </div>
          <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
            {SIDEBAR_ICONS.map((d, i) => (
              <span key={i} style={{ width: 32, height: 32, borderRadius: 7, display: "grid", placeItems: "center", color: i === 2 ? "rgba(255,255,255,0.85)" : "rgba(255,255,255,0.28)", background: i === 2 ? "rgba(255,255,255,0.1)" : "transparent", cursor: "pointer" }}>
                <BuilderIcon d={d} />
              </span>
            ))}
          </div>
        </div>

        {/* center canvas */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* breadcrumb header */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "13px 18px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "var(--font-sans)", fontSize: 12.5 }}>
              <span style={{ color: "rgba(255,255,255,0.4)" }}>Automations</span>
              <span style={{ color: "rgba(255,255,255,0.3)" }}>›</span>
              <span style={{ color: "rgba(255,255,255,0.85)" }}>CVE mitigation and version updates</span>
            </div>
            <div style={{ display: "flex", gap: 7 }}>
              <span style={{ padding: "5px 12px", borderRadius: 6, border: "1px solid rgba(255,255,255,0.15)", color: "rgba(255,255,255,0.5)", fontSize: 12, cursor: "pointer" }}>Cancel</span>
              <span style={{ padding: "5px 12px", borderRadius: 6, background: "rgba(255,255,255,0.92)", color: "#111", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>Create</span>
            </div>
          </div>
          {/* description */}
          <div style={{ padding: "10px 18px", borderBottom: "1px solid rgba(255,255,255,0.07)", fontFamily: "var(--font-sans)", fontSize: 11.5, color: "rgba(255,255,255,0.35)", lineHeight: 1.4 }}>
            Analyzes a specific CVE, determines if the repository is affected, and if so, automatically remediates the vulnerability by updating dependencies, migrating code to new APIs, running tests, and creating a pull request with the complete fix.
          </div>
          {/* pipeline canvas */}
          <div style={{ flex: 1, overflow: "hidden", padding: "16px 18px", display: "flex", flexDirection: "column", gap: 0, WebkitMaskImage: "linear-gradient(180deg, #000 70%, transparent)", maskImage: "linear-gradient(180deg, #000 70%, transparent)" }}>
            {steps.map((s, i) => (
              <React.Fragment key={i}>
                {i > 0 && (
                  <div style={{ display: "flex", justifyContent: "flex-start", paddingLeft: 18, height: 24, alignItems: "center" }}>
                    <div style={{ width: 1.5, height: 24, background: i <= activeIdx ? ACC : "rgba(255,255,255,0.14)", transition: "background 0.4s" }} />
                  </div>
                )}
                <div style={{ opacity: i <= activeIdx ? 1 : 0.38, transition: "opacity 0.4s" }}>
                  <WorkflowBlock
                    kind={s.kind}
                    label={s.label}
                    desc={s.desc}
                    accent={s.accent}
                    active={i === activeIdx}
                    done={i < activeIdx}
                    t={t}
                  />
                </div>
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* right settings panel */}
        <div style={{ width: 260, flex: "none", borderLeft: "1px solid rgba(255,255,255,0.07)", padding: "16px 16px", display: "flex", flexDirection: "column", gap: 16, overflowY: "auto" }}>
          <div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 10 }}>Runs on</div>
            {["Projects", "Repositories"].map((opt, i) => (
              <label key={opt} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, cursor: "pointer" }}>
                <span style={{ width: 14, height: 14, borderRadius: "50%", border: `1.5px solid ${i === 1 ? ACC : "rgba(255,255,255,0.25)"}`, display: "grid", placeItems: "center" }}>
                  {i === 1 && <span style={{ width: 6, height: 6, borderRadius: "50%", background: ACC }} />}
                </span>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.7)" }}>{opt}</span>
              </label>
            ))}
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 10px", borderRadius: 7, border: "1px solid rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.05)", justifyContent: "space-between" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "rgba(255,255,255,0.6)" }}>Small 2 vCPU / 8 GiB / 45 GiB disk</span>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.4)" strokeWidth="2" strokeLinecap="round"><path d="M6 9 L12 15 L18 9" /></svg>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[["Max concurrent actions", concurrent], ["Max total actions", total]].map(([label, val]) => (
              <div key={label}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.05em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 6, lineHeight: 1.3 }}>{label}</div>
                <div style={{ padding: "7px 10px", borderRadius: 7, border: "1px solid rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.05)", fontFamily: "var(--font-mono)", fontSize: 13, color: "rgba(255,255,255,0.8)" }}>{val}</div>
              </div>
            ))}
          </div>
          <div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 8 }}>Run Automation as</div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 10px", borderRadius: 7, border: "1px solid rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.05)" }}>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.35)" }}>Select identity</span>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.3)" strokeWidth="2" strokeLinecap="round"><path d="M6 9 L12 15 L18 9" /></svg>
            </div>
          </div>
          <div style={{ marginTop: "auto", display: "flex", gap: 7 }}>
            <span style={{ flex: 1, padding: "7px 12px", borderRadius: 6, border: "1px solid rgba(255,255,255,0.15)", color: "rgba(255,255,255,0.5)", fontSize: 12, textAlign: "center", cursor: "pointer" }}>Cancel</span>
            <span style={{ flex: 1, padding: "7px 12px", borderRadius: 6, background: "rgba(255,255,255,0.92)", color: "#111", fontSize: 12, fontWeight: 600, textAlign: "center", cursor: "pointer" }}>Update</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ====================== feature rows ====================== */
function FeatureRow({ eyebrow, heading, body, link, diagram, flip }) {
  return (
    <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "3rem 3.25rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem", alignItems: "center" }}>
      <div style={{ order: flip ? 2 : 1 }}>
        <span style={{ display: "inline-block", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: ACC, marginBottom: "0.875rem" }}>{eyebrow}</span>
        <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.625rem", letterSpacing: "-0.02em", lineHeight: 1.12, margin: 0, color: INK }}>{heading}</h3>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5, maxWidth: "42ch" }}>{body}</p>
        {link && <div style={{ marginTop: "1.5rem" }}><AfLink href={link[1]}>{link[0]}</AfLink></div>}
      </div>
      <div style={{ order: flip ? 1 : 2, display: "flex", justifyContent: "center" }}>{diagram}</div>
    </div>
  );
}

/* -- trigger pills diagram -- */
function TriggerDiagram() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.5); return; }
    let raf, start = null;
    const PERIOD = 5600;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % PERIOD) / PERIOD)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const items = [["PR opened", "scope:vcs.pr"], ["Scheduled · daily", "scope:cron"], ["Webhook", "scope:webhook"], ["Manual", "scope:cli"]];
  const active = Math.min(items.length - 1, Math.floor(t * (items.length + 0.4)));
  const spin = (t * 1440) % 360;
  return (
    <div style={{ width: "100%", maxWidth: 380, display: "flex", flexDirection: "column", gap: 12 }}>
      {items.map(([label, scope], i) => {
        const fired = i < active, firing = i === active;
        return (
          <div key={label} style={{ background: "var(--color-porcelain-grey)", border: `0.5px solid ${fired || firing ? ACC : HAIR}`, borderRadius: 999, padding: "14px 22px", display: "flex", alignItems: "center", gap: 13, transform: firing ? "scale(1.02)" : "scale(1)", boxShadow: firing ? "var(--shadow-md)" : "var(--shadow-xs)", transition: "all 0.3s" }}>
            <span style={{ width: 20, height: 20, flex: "none", display: "grid", placeItems: "center" }}>
              {fired ? <span style={{ width: 18, height: 18, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center" }}><svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
                : firing ? <svg width="18" height="18" viewBox="0 0 18 18" style={{ transform: `rotate(${spin}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg>
                  : <svg width="18" height="18" viewBox="0 0 18 18"><circle cx="9" cy="9" r="7" fill="none" stroke={HAIR} strokeWidth="1.5" strokeDasharray="0.5 3.5" strokeLinecap="round" /></svg>}
            </span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: INK }}>{label}</span>
            <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 6, padding: "2px 8px" }}>{scope}</span>
          </div>
        );
      })}
    </div>
  );
}

/* -- scale / fleet diagram -- */
function FleetDiagram() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.7); return; }
    let raf, start = null;
    const PERIOD = 7000;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % PERIOD) / PERIOD)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const repos = ["billing-api", "web-dashboard", "auth-service", "payments-core", "notifications"];
  const prog = (i) => Math.max(0, Math.min(1, (t - (0.15 + i * 0.1)) / 0.4));
  const merged = repos.filter((_, i) => prog(i) >= 1).length;
  return (
    <div style={{ width: "100%", maxWidth: 380, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 14, overflow: "hidden", boxShadow: "var(--shadow-sm)" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "13px 18px", borderBottom: `0.5px solid ${HAIR}` }}>
        <span style={{ display: "flex", alignItems: "center", gap: 7, fontFamily: "var(--font-sans)", fontSize: 13.5, color: INK }}><span style={{ width: 8, height: 8, borderRadius: "50%", background: ACC }} />Fleet running</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: merged === repos.length ? ACC : "var(--color-grey-700)" }}>{merged}/{repos.length} merged</span>
      </div>
      <div style={{ padding: "6px 0" }}>
        {repos.map((r, i) => {
          const p = prog(i);
          const done = p >= 1;
          return (
            <div key={r} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 18px" }}>
              <span style={{ width: 14, height: 14, borderRadius: "50%", flex: "none", background: done ? ACC : "transparent", border: done ? "none" : `1.5px solid ${p > 0 ? ACC : HAIR}`, display: "grid", placeItems: "center" }}>
                {done && <svg width="8" height="8" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>}
                {!done && p > 0 && <span style={{ width: 5, height: 5, borderRadius: "50%", background: ACC }} />}
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: INK, width: 120, flex: "none" }}>{r}</span>
              <span style={{ flex: 1, height: 4, borderRadius: 2, background: "var(--color-porcelain-grey)", overflow: "hidden" }}>
                <span style={{ display: "block", height: "100%", width: `${p * 100}%`, background: done ? ACC : "var(--color-grey-700)", borderRadius: 2, transition: "width 0.15s" }} />
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: done ? ACC : "var(--color-grey-700)", width: 46, textAlign: "right", flex: "none" }}>{done ? "merged" : p > 0 ? "running" : "queued"}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ====================== page ====================== */
function AfHero() {
  return (
    <section style={{ ...afwrap, paddingTop: "4rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "0.7fr 1.3fr", gap: "4rem", alignItems: "center" }}>
        <div>
          <AfEyebrow color={ACC}>Solutions · Automations &amp; Fleets</AfEyebrow>
          <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.25rem", lineHeight: 1.06, letterSpacing: "-0.02em", margin: "1.25rem 0 0", color: INK }}>
            Turn any engineering task into a repeatable workflow
          </h1>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.55, maxWidth: "40ch" }}>
            Define workflows from prompts, scripts, and integrations. Trigger them from events, schedules, or PRs. Run them across one repo or thousands.
          </p>
          <div style={{ marginTop: "2rem" }}>
            <AfLink href="#">Browse automation templates</AfLink>
          </div>
        </div>
        <div style={{ position: "relative" }}>
          <WorkflowBuilderDemo />
        </div>
      </div>
    </section>
  );
}

function AfFeatures() {
  return (
    <section style={{ ...afwrap, paddingTop: "6rem", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <FeatureRow
        eyebrow="Build"
        heading="Compose workflows from prompts, scripts, and tools"
        body="Combine prompts, shell scripts, and API calls into versioned, reusable automations. Wire in any tool your team already uses — GitHub, Jira, Slack, CI."
        link={["Explore the builder", "docs.html"]}
        flip={false}
        diagram={
          <div style={{ width: "100%", maxWidth: 380 }}>
            {[
              { kind: "Trigger", label: "PR opened", dot: ACC },
              { kind: "Prompt", label: "Review for correctness and test coverage" },
              { kind: "Shell Script", label: "npm test && npm run lint" },
              { kind: "Pull Request", label: "Post review comment and suggest fix" },
            ].map(({ kind, label, dot }, i) => (
              <React.Fragment key={i}>
                {i > 0 && <div style={{ width: 1.5, height: 16, background: HAIR, margin: "0 auto 0 16px" }} />}
                <div style={{ background: "var(--color-porcelain-grey)", border: `0.5px solid ${HAIR}`, borderRadius: 10, padding: "11px 14px" }}>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 5, padding: "2px 8px", fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", marginBottom: 6 }}>
                    <span style={{ width: 5, height: 5, borderRadius: "50%", background: dot || "var(--color-grey-600)" }} />{kind}
                  </span>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: INK }}>{label}</div>
                </div>
              </React.Fragment>
            ))}
          </div>
        }
      />
      <FeatureRow
        eyebrow="Trigger"
        heading="Fire from any event in your dev workflow"
        body="Wire automations to pull requests, webhooks, cron schedules, or manual dispatch. Nothing waits for a human to hit run — but every action is still receipted."
        flip={true}
        diagram={<TriggerDiagram />}
      />
      <FeatureRow
        eyebrow="Scale"
        heading="Run a fleet across your entire codebase"
        body="One configuration fans out into a governed fleet. Parallel workers, tracked progress, merged results — the same automation that covers one repo covers five hundred."
        flip={false}
        diagram={<FleetDiagram />}
      />
    </section>
  );
}

function AfCTA() {
  return (
    <section style={{ ...afwrap, paddingTop: "8rem", textAlign: "center" }}>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0, color: INK }}>Build your first automation</h2>
      <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}>
        <AfButton iconRight={<span>→</span>}>Get started</AfButton>
        <AfLink href="solutions.html">Back to solutions</AfLink>
      </div>
    </section>
  );
}

function HvPage() {
  return (
    <main>
      <AfHero />
      <AfFeatures />
      <AfCTA />
    </main>
  );
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
