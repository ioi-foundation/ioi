const React = window.React;
// hypervisor.com — AI code review solution (under Solutions).
const CNS = window.IoiDesignSystem;
const { Button: CrButton, Badge: CrBadge, TextLink: CrLink, Eyebrow: CrEyebrow, Logo: CrLogo } = CNS;
const crwrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";
const PANEL = { background: "color-mix(in srgb, var(--color-pistachio-green) 30%, var(--color-white))", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", height: 480, padding: "2rem", position: "relative", overflow: "hidden" };
const cr_card = { background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 14, boxShadow: "var(--shadow-sm)" };

function crClock(period) {
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

const cg = (paths) => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">{paths}</svg>
);
const CR_ICON = {
  env: cg(<g><rect x="3" y="4" width="18" height="14" rx="2" /><path d="M3 8 H21" /><path d="M7 13 L9 15 L7 17" /></g>),
  rules: cg(<g><path d="M5 4 H15 L19 8 V20 H5 Z" /><path d="M14 4 V8 H19" /><path d="M8 13 L10.5 15.5 L16 10" /></g>),
  fixes: cg(<g><path d="M14 6 a3.5 3.5 0 0 0 -5 5 L4 16 v4 h4 l5 -5 a3.5 3.5 0 0 0 5 -5 l-2.5 2.5 L17 14 l-3 -3 1.5 -1.5 Z" /></g>),
  pr: cg(<g><circle cx="6" cy="6" r="2.4" /><circle cx="6" cy="18" r="2.4" /><circle cx="18" cy="18" r="2.4" /><path d="M6 8.4 V15.6" /><path d="M18 15.6 V12 a4 4 0 0 0 -4 -4 H9" /><path d="M11 6 L9 8 L11 10" /></g>),
  audit: cg(<g><path d="M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z" /><path d="M9.5 12 L11 13.5 L14.5 10" /></g>),
};

function Spinner({ t, on, done }) {
  const spin = (t * 1440) % 360;
  if (done) return <span style={{ width: 18, height: 18, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center", flex: "none" }}><svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>;
  if (on) return <svg width="18" height="18" viewBox="0 0 18 18" style={{ flex: "none", transform: `rotate(${spin}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg>;
  return <svg width="18" height="18" viewBox="0 0 18 18" style={{ flex: "none" }}><circle cx="9" cy="9" r="7" fill="none" stroke="var(--color-grey-500)" strokeWidth="1.5" strokeDasharray="0.5 3.5" strokeLinecap="round" /></svg>;
}

/* ---- 1. Reviews in a real environment ---- */
function EnvDemo() {
  const t = crClock(6800);
  const steps = ["Cloned repo and compiled project", "Ran 243 tests \u2014 all passing", "Reviewed 12 files, 3 issues fixed"];
  const active = Math.min(steps.length, Math.floor(t * (steps.length + 1.2)));
  return (
    <div style={{ ...PANEL, display: "flex", flexDirection: "column", justifyContent: "center", gap: 22 }}>
      {steps.map((s, i) => {
        const done = i < active, on = i === active;
        return (
          <div key={i} style={{ ...cr_card, borderRadius: 999, padding: "20px 26px", display: "flex", alignItems: "center", gap: 14, opacity: i <= active ? 1 : 0.5, transform: on ? "scale(1.015)" : "scale(1)", transition: "opacity 0.4s, transform 0.4s" }}>
            <Spinner t={t} on={on} done={done} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "1.0625rem", color: INK, letterSpacing: "-0.01em" }}>{s}</span>
          </div>
        );
      })}
    </div>
  );
}

/* ---- 2. Your rules, your standards ---- */
function RulesDemo() {
  const t = crClock(7000);
  const rules = [
    ["No raw SQL in handlers", "ok"],
    ["Require tests for new endpoints", "ok"],
    ["No secrets in source", "ok"],
    ["Public APIs must be documented", "warn"],
    ["Use the design-system tokens", "ok"],
  ];
  const checked = Math.min(rules.length, Math.floor((t - 0.1) / 0.14));
  return (
    <div style={{ ...PANEL, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ ...cr_card, width: "92%", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "15px 18px", borderBottom: `0.5px solid ${HAIR}` }}>
          <span style={{ width: 26, height: 26, borderRadius: 7, background: "var(--color-porcelain-grey)", display: "grid", placeItems: "center", color: INK }}>{CR_ICON.rules}</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: INK }}>review-policy.yaml</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)" }}>{Math.min(checked, rules.length)}/{rules.length}</span>
        </div>
        <div style={{ padding: "8px 0" }}>
          {rules.map(([label, kind], i) => {
            const ok = i < checked;
            const warn = ok && kind === "warn";
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 18px", opacity: i <= checked ? 1 : 0.4 }}>
                <span style={{ width: 17, height: 17, flex: "none", display: "grid", placeItems: "center" }}>
                  {ok
                    ? <span style={{ width: 17, height: 17, borderRadius: "50%", background: warn ? "var(--color-amber-500, #d98a1f)" : ACC, display: "grid", placeItems: "center" }}>{warn
                      ? <span style={{ width: 2.4, height: 8, background: "#fff", borderRadius: 2 }} />
                      : <svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>}</span>
                    : <span style={{ width: 13, height: 13, borderRadius: "50%", border: `1.5px solid var(--color-grey-500)` }} />}
                </span>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: INK }}>{label}</span>
                {warn && <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)" }}>flagged</span>}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ---- 3. Iterates until the build is green ---- */
function FixesDemo() {
  const t = crClock(8200);
  const rv = (s, d) => Math.max(0, Math.min(1, (t - s) / (d || 0.05)));
  // phase clock: run1 → fail → fix → run2 → pass → green
  const failed = t > 0.16, fixing = t > 0.34, rerun = t > 0.52, passed = t > 0.7;
  const green = t > 0.82;
  const status = green ? "build green" : passed ? "all tests passing" : rerun ? "re-running tests…" : fixing ? "applying fix…" : failed ? "2 tests failing" : "running tests…";
  const statColor = passed || green ? ACC : failed && !fixing ? RED : "var(--color-grey-700)";
  const rows = [
    { txt: "Attempt 1 · ran 243 tests", tone: failed ? "fail" : "run", show: rv(0.06) },
    { txt: "FAIL  resolver pending-state path", tone: "fail", show: failed ? rv(0.16) : 0 },
    { txt: "Fix applied · == → ===, return retry", tone: "fix", show: fixing ? rv(0.34) : 0 },
    { txt: "Attempt 2 · re-running 243 tests", tone: rerun && !passed ? "run" : "pass", show: rerun ? rv(0.52) : 0 },
    { txt: "PASS  243 passed, 0 failing", tone: "pass", show: passed ? rv(0.7) : 0 },
  ];
  const toneColor = { fail: RED, fix: INK, run: "var(--color-grey-700)", pass: ACC };
  return (
    <div style={{ ...PANEL, display: "flex", flexDirection: "column", justifyContent: "center", gap: 16 }}>
      <div style={{ ...cr_card, overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "13px 16px", borderBottom: `0.5px solid ${HAIR}` }}>
          <span style={{ display: "flex", gap: 5 }}>{[0, 1, 2].map((i) => <span key={i} style={{ width: 8, height: 8, borderRadius: "50%", background: "#dcdcdc" }} />)}</span>
          <span style={{ marginLeft: 4, fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--color-grey-700)" }}>CI · resolver.ts</span>
          <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 7, fontFamily: "var(--font-sans)", fontSize: 12, color: statColor }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: statColor, boxShadow: green ? `0 0 0 3px color-mix(in srgb, ${ACC} 28%, transparent)` : "none" }} />
            {status}
          </span>
        </div>
        <div style={{ padding: "10px 0", fontFamily: "var(--font-mono)", fontSize: 12, minHeight: 188 }}>
          {rows.map((r, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 11, padding: "8px 16px", opacity: r.show, transform: `translateY(${(1 - r.show) * 6}px)`, transition: "opacity 0.3s, transform 0.3s" }}>
              <span style={{ width: 15, flex: "none", display: "grid", placeItems: "center" }}>
                {r.tone === "pass" ? <svg width="13" height="13" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="6" fill={ACC} /><path d="M3 6.2 L5.2 8.2 L9 3.8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
                  : r.tone === "fail" ? <svg width="13" height="13" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="6" fill={RED} /><path d="M4 4 L8 8 M8 4 L4 8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" /></svg>
                    : r.tone === "fix" ? <span style={{ width: 7, height: 7, borderRadius: 2, background: INK, transform: "rotate(45deg)" }} />
                      : <span style={{ width: 9, height: 9, borderRadius: "50%", border: `1.5px solid var(--color-grey-500)` }} />}
              </span>
              <span style={{ color: toneColor[r.tone], whiteSpace: "nowrap" }}>{r.txt}</span>
            </div>
          ))}
        </div>
      </div>
      <div style={{ ...cr_card, padding: "13px 16px", display: "flex", alignItems: "center", gap: 11, opacity: rv(0.84), background: green ? `color-mix(in srgb, ${ACC} 9%, var(--color-white))` : "var(--color-white)" }}>
        <span style={{ width: 26, height: 26, borderRadius: 8, background: INK, display: "grid", placeItems: "center", flex: "none", color: "#fff" }}><CrLogo size={14} /></span>
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--color-grey-900)", lineHeight: 1.4 }}>
          Iterated twice — fixed the logic, reran the suite. <span style={{ color: INK, fontWeight: 600 }}>Build is green.</span> PR ready to review.
        </span>
      </div>
    </div>
  );
}

/* ---- 4. Triggered on every PR ---- */
function EveryPRDemo() {
  const t = crClock(7600);
  const steps = [
    ["PR opened", "Triggered when a pull request is opened or marked ready for review.", true],
    ["Gather context", "Fetch PR description, commit messages, comments, and code diff against main."],
    ["Review code changes", "Analyze diff for correctness, performance, test coverage, consistency."],
    ["Run test suite", "Execute tests in an isolated environment to validate the changes."],
    ["Post review", "Submit inline comments for medium and high severity issues."],
  ];
  const active = Math.min(steps.length - 1, Math.floor(t * (steps.length + 0.7)));
  return (
    <div style={{ ...PANEL, display: "flex", alignItems: "center", justifyContent: "center", padding: "0 24px" }}>
      <div style={{ width: "100%", display: "flex", flexDirection: "column", gap: 9 }}>
        {steps.map(([title, desc, trig], i) => {
          const done = i < active, on = i === active;
          const depth = Math.max(0, i - active);
          return (
            <div key={i} style={{ ...cr_card, padding: "13px 16px", opacity: i <= active ? 1 : Math.max(0.4, 0.92 - depth * 0.18), transform: on ? "scale(1.015)" : `scale(${1 - depth * 0.012})`, boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)", transition: "opacity 0.35s, transform 0.35s, box-shadow 0.35s" }}>
              {trig && <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))", color: "var(--color-green-700, #1f7a4d)", borderRadius: 6, padding: "2px 8px", fontFamily: "var(--font-mono)", fontSize: 10.5, marginBottom: 8 }}><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9" /><path d="M10 8 L16 12 L10 16 Z" fill="currentColor" stroke="none" /></svg>Trigger</span>}
              <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: INK }}>{title}</span>
                {done && <span style={{ marginLeft: "auto", width: 16, height: 16, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center", flex: "none" }}><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>}
                {on && <span style={{ marginLeft: "auto", flex: "none" }}><svg width="17" height="17" viewBox="0 0 18 18" style={{ transform: `rotate(${(t * 1440) % 360}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg></span>}
              </div>
              {(on || done) && <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.8125rem", color: "var(--color-grey-700)", marginTop: 5, lineHeight: 1.4 }}>{desc}</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---- 5. Every review is logged and traceable ---- */
function AuditDemo() {
  const t = crClock(8000);
  const logs = [
    ["1:21:08", "Creating VM"],
    ["1:21:08", "VM configuration · cores=8 mem=16G"],
    ["1:21:08", "nested virtualization enabled"],
    ["1:21:08", "Starting VM"],
    ["1:21:09", "Starting registry cache proxy"],
    ["1:21:10", "using SSH port=65304"],
    ["1:21:11", "Connecting to registry cache port=60"],
    ["1:21:11", "Successfully established registry cache"],
    ["1:21:11", "using supervisor port=65303"],
    ["1:21:12", "using root port=65311"],
  ];
  const shown = Math.min(logs.length, Math.max(0, Math.floor((t - 0.08) / 0.072)));
  return (
    <div style={{ ...PANEL, padding: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ background: "var(--color-white)", borderRadius: "calc(var(--radius-card) - 2px) calc(var(--radius-card) - 2px) 0 0", margin: "14px 14px 0", border: `0.5px solid ${HAIR}`, borderBottom: "none", flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", padding: "16px 20px", borderBottom: `0.5px solid ${HAIR}` }}>
          <span style={{ fontFamily: "var(--font-sans)", fontSize: "1.375rem", color: INK }}>Logs</span>
          <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 7, fontFamily: "var(--font-mono)", fontSize: 11, color: ACC }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: ACC }} />recording
          </span>
        </div>
        <div style={{ flex: 1, overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 18px", background: "var(--color-porcelain-grey)", fontFamily: "var(--font-sans)", fontSize: 13.5, color: INK }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 9 L12 15 L18 9" /></svg>Creating virtual machine
          </div>
          <div style={{ padding: "10px 18px", fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 2 }}>
            {logs.slice(0, shown).map(([ts, msg], i) => (
              <div key={i} style={{ display: "flex", gap: 10, whiteSpace: "nowrap", overflow: "hidden" }}>
                <span style={{ color: ACC, flex: "none" }}>{ts}<span style={{ color: "var(--color-grey-600)", marginLeft: 4 }}>PM</span></span>
                <span style={{ color: INK, overflow: "hidden", textOverflow: "ellipsis" }}>{msg}</span>
              </div>
            ))}
            {shown < logs.length && <span style={{ display: "inline-block", width: 7, height: 14, background: ACC, opacity: Math.sin(t * Math.PI * 2 * 6) > 0 ? 0.8 : 0 }} />}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 18px", borderTop: `0.5px solid ${HAIR}`, fontFamily: "var(--font-sans)", fontSize: 13.5, color: "var(--color-grey-700)" }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M9 6 L15 12 L9 18" /></svg>System logs
          </div>
        </div>
      </div>
    </div>
  );
}

const CR_TABS = [
  { icon: "env", label: "Reviews in a real environment", demo: EnvDemo,
    heading: "Reviews by running your app, like an engineer",
    body: ["Instead of comparing a diff, Hypervisor runs your application in an isolated environment and reviews it the way an engineer would, catching integration breaks and logic errors static tools miss."] },
  { icon: "rules", label: "Your rules, your standards", demo: RulesDemo,
    heading: "Your rules, your standards",
    body: ["Encode your team's conventions as policy. Hypervisor checks every PR against the standards you define \u2014 style, security, testing, docs \u2014 and flags what falls short."] },
  { icon: "fixes", label: "Fixes, not just flags", demo: FixesDemo,
    heading: "Iterates until the build is green",
    body: ["When Hypervisor finds an issue it fixes the code, reruns the tests, and keeps iterating until the build passes. PRs arrive ready to review, not ready to debug."] },
  { icon: "pr", label: "Every PR, every repo", demo: EveryPRDemo,
    heading: "Triggered on every PR, or before you open one",
    body: ["Runs automatically on every PR across your org with no per-repo setup \u2014 or let developers trigger a review before they push, while they're still in context."] },
  { icon: "audit", label: "Audit ready by design", demo: AuditDemo,
    heading: "Every review is logged and traceable",
    body: ["Each review runs in an isolated environment with scoped credentials and full logging, so what was checked, flagged, and approved is recorded automatically for compliance."] },
];

function CrHero() {
  return (
    <section style={{ ...crwrap, paddingTop: "4rem", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
      <CrEyebrow color="var(--color-link-green)">Solutions · AI code review</CrEyebrow>
      <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.5rem", lineHeight: 1.05, letterSpacing: "-0.02em", margin: "1.25rem 0 0", maxWidth: "18ch", color: INK }}>
        Review that runs your code, not just reads it
      </h1>
      <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", maxWidth: "54ch", lineHeight: 1.5 }}>
        Hypervisor reviews pull requests the way an engineer would — in an isolated environment, running real tests, fixing what it finds, and carrying a receipt for every action.
      </p>
    </section>
  );
}

function CrFeatureBlock() {
  const [active, setActive] = React.useState(0);
  const tab = CR_TABS[active];
  const Demo = tab.demo;
  return (
    <section style={{ ...crwrap, paddingTop: "5rem" }}>
      <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "2.5rem", display: "grid", gridTemplateColumns: "16rem 1fr", gap: "2.5rem", alignItems: "start" }}>
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
          {CR_TABS.map((tb, i) => {
            const on = i === active;
            return (
              <li key={tb.label}>
                <button onClick={() => setActive(i)} style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "center", gap: 11, padding: "12px 14px", borderRadius: "var(--radius-lg)", border: "none", cursor: "pointer", background: on ? "var(--color-porcelain-grey)" : "transparent", color: on ? INK : "var(--color-grey-800)", fontFamily: "var(--font-sans)", fontSize: "0.9375rem", fontWeight: on ? 500 : 400, lineHeight: 1.3 }}>
                  <span style={{ color: on ? ACC : "var(--color-grey-600)", display: "grid", placeItems: "center", flex: "none" }}>{CR_ICON[tb.icon]}</span>
                  {tb.label}
                </button>
              </li>
            );
          })}
        </ul>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.15fr", gap: "2.5rem", alignItems: "center" }}>
          <div>
            <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.125rem", letterSpacing: "-0.02em", lineHeight: 1.12, margin: 0, color: INK }}>{tab.heading}</h2>
            {tab.body.map((p, i) => (
              <p key={i} style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.5, maxWidth: "42ch" }}>{p}</p>
            ))}
          </div>
          <Demo />
        </div>
      </div>
    </section>
  );
}

function CrCTA() {
  return (
    <section style={{ ...crwrap, paddingTop: "8rem", textAlign: "center" }}>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0, color: INK }}>Put a reviewer on every PR</h2>
      <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}>
        <CrButton iconRight={<span>→</span>}>Get started</CrButton>
        <CrLink href="solutions.html">Back to solutions</CrLink>
      </div>
    </section>
  );
}

function HvPage() {
  return (
    <main>
      <CrHero />
      <CrFeatureBlock />
      <CrCTA />
    </main>
  );
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
