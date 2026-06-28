const React = window.React;
// hypervisor.com — Code Modernization solution page.
const CMNS = window.IoiDesignSystem;
const { Button: CmButton, TextLink: CmLink, Eyebrow: CmEyebrow, Logo: CmLogo } = CMNS;
const cmwrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";

function cmClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.82); return; }
    let raf, start = null;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % period) / period)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}

function CmSpinner({ t, on, done }) {
  const spin = (t * 1440) % 360;
  if (done) return <span style={{ width: 17, height: 17, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center", flex: "none" }}><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>;
  if (on) return <svg width="17" height="17" viewBox="0 0 18 18" style={{ flex: "none", transform: `rotate(${spin}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg>;
  return <svg width="17" height="17" viewBox="0 0 18 18" style={{ flex: "none" }}><circle cx="9" cy="9" r="7" fill="none" stroke="var(--color-grey-500)" strokeWidth="1.5" strokeDasharray="0.5 3.5" strokeLinecap="round" /></svg>;
}

/* ============================================================ *
 * Hero showcase — migration fleet dashboard (the "at scale" story)
 * ============================================================ */
function MigrationFleet() {
  const t = cmClock(11000);
  const TOTAL = 210;
  const pct = Math.min(0.92, 0.34 + t * 0.62);
  const merged = Math.round(pct * TOTAL);
  const ringR = 52, ringC = 2 * Math.PI * ringR;

  const repos = [
    ["billing-api", "JAVA 8 → 17", 0.0],
    ["web-dashboard", "JAVA 8 → 17", 0.06],
    ["ledger-core", "COBOL → JAVA", 0.13],
    ["auth-service", "JAVA 8 → 17", 0.22],
    ["payments-core", "JAVA 8 → 17", 0.32],
    ["notifications", "JS → TS", 0.44],
    ["search-index", "JAVA 8 → 17", 0.58],
    ["risk-engine", "COBOL → JAVA", 0.72],
  ];
  const rstate = (start) => {
    const p = (t - start) / 0.26;
    if (p >= 1) return { k: "merged", p: 1 };
    if (p > 0) return { k: "building", p: Math.max(0.08, p) };
    return { k: "queued", p: 0 };
  };

  return (
    <div style={{ width: "100%", maxWidth: 1060, margin: "0 auto", position: "relative" }}>
      {/* on-brand gradient frame */}
      <div style={{ position: "absolute", inset: -2, borderRadius: 18, background: `linear-gradient(135deg, color-mix(in srgb, var(--color-pistachio-green) 75%, var(--color-white)), color-mix(in srgb, var(--color-link-green) 35%, var(--color-white)) 50%, var(--color-porcelain-grey))`, zIndex: 0 }} />
      <div style={{ position: "relative", zIndex: 1, margin: 6, background: "#0d0d10", borderRadius: 14, overflow: "hidden", boxShadow: "0 40px 90px rgba(0,0,0,0.4)" }}>
        {/* header */}
        <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "16px 22px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
          <span style={{ width: 30, height: 30, borderRadius: 8, background: "rgba(255,255,255,0.08)", display: "grid", placeItems: "center", color: "#fff" }}><CmLogo size={15} /></span>
          <div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "#fff" }}>Modernization fleet</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "rgba(255,255,255,0.4)", marginTop: 1 }}>automation · legacy-java-uplift</div>
          </div>
          <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)", fontSize: 11, color: ACC, border: `1px solid color-mix(in srgb, ${ACC} 40%, transparent)`, borderRadius: 6, padding: "4px 10px" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: ACC }} />running
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "0.78fr 1.22fr", minHeight: 392 }}>
          {/* left — ring + stats */}
          <div style={{ borderRight: "1px solid rgba(255,255,255,0.07)", padding: "26px 24px", display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ position: "relative", width: 140, height: 140 }}>
              <svg width="140" height="140" viewBox="0 0 140 140">
                <circle cx="70" cy="70" r={ringR} fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="10" />
                <circle cx="70" cy="70" r={ringR} fill="none" stroke={ACC} strokeWidth="10" strokeLinecap="round" strokeDasharray={ringC} strokeDashoffset={ringC * (1 - pct)} transform="rotate(-90 70 70)" style={{ transition: "stroke-dashoffset 0.2s linear" }} />
              </svg>
              <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <span style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: 34, color: "#fff", lineHeight: 1 }}>{merged}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "rgba(255,255,255,0.4)", marginTop: 3 }}>of {TOTAL} repos</span>
              </div>
            </div>
            <div style={{ width: "100%", marginTop: 26, display: "flex", flexDirection: "column", gap: 10 }}>
              {[["Merged", merged, ACC], ["Building", Math.max(0, Math.min(8, TOTAL - merged)), "#fff"], ["Tests passing", "100%", ACC]].map(([k, v, col]) => (
                <div key={k} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 13px", background: "rgba(255,255,255,0.04)", borderRadius: 9, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.55)" }}>{k}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: col }}>{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* right — repo list */}
          <div style={{ padding: "10px 0", overflow: "hidden", WebkitMaskImage: "linear-gradient(180deg,#000 86%,transparent)", maskImage: "linear-gradient(180deg,#000 86%,transparent)" }}>
            <div style={{ display: "flex", alignItems: "center", padding: "8px 22px 12px", fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.07em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)" }}>
              <span style={{ flex: 1 }}>Repository</span><span style={{ width: 110 }}>Migration</span><span style={{ width: 90, textAlign: "right" }}>Status</span>
            </div>
            {repos.map(([name, transform, start]) => {
              const s = rstate(start);
              return (
                <div key={name} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 22px", borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                  <CmSpinner t={t} on={s.k === "building"} done={s.k === "merged"} />
                  <span style={{ flex: 1, minWidth: 0, fontFamily: "var(--font-mono)", fontSize: 12.5, color: "rgba(255,255,255,0.82)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{name}</span>
                  <span style={{ width: 110, flex: "none", fontFamily: "var(--font-mono)", fontSize: 11, color: "rgba(255,255,255,0.45)" }}>{transform}</span>
                  <span style={{ width: 90, flex: "none", textAlign: "right", fontFamily: "var(--font-mono)", fontSize: 10.5, color: s.k === "merged" ? ACC : s.k === "building" ? "rgba(255,255,255,0.6)" : "rgba(255,255,255,0.3)" }}>{s.k === "merged" ? "merged" : s.k === "building" ? "building" : "queued"}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===================== feature row ===================== */
function CmFeatureRow({ eyebrow, heading, body, link, diagram, flip }) {
  return (
    <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "3rem 3.25rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem", alignItems: "center" }}>
      <div style={{ order: flip ? 2 : 1 }}>
        <span style={{ display: "inline-block", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: ACC, marginBottom: "0.875rem" }}>{eyebrow}</span>
        <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.625rem", letterSpacing: "-0.02em", lineHeight: 1.12, margin: 0, color: INK }}>{heading}</h3>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5, maxWidth: "42ch" }}>{body}</p>
        {link && <div style={{ marginTop: "1.5rem" }}><CmLink href={link[1]}>{link[0]}</CmLink></div>}
      </div>
      <div style={{ order: flip ? 1 : 2, display: "flex", justifyContent: "center" }}>{diagram}</div>
    </div>
  );
}

/* ---- automation pipeline (define once) ---- */
function PipelineDiagram() {
  const t = cmClock(8000);
  const steps = [
    ["Trigger", "Manual · runs across 210 repos", ACC],
    ["Prompt", "Identify Java 8 APIs and replacements", "var(--color-grey-600)"],
    ["Shell Script", "mvn -q compile && mvn test", "var(--color-grey-600)"],
    ["Pull Request", "Open PR per repo with the migration", ACC],
  ];
  const active = Math.min(steps.length, Math.floor(t * (steps.length + 1)));
  return (
    <div style={{ width: "100%", maxWidth: 380, display: "flex", flexDirection: "column" }}>
      {steps.map(([kind, label, dot], i) => {
        const done = i < active, on = i === active;
        return (
          <React.Fragment key={i}>
            {i > 0 && <span style={{ width: 1.5, height: 16, background: i <= active ? ACC : HAIR, margin: "0 auto", transition: "background 0.3s" }} />}
            <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 12, boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)", padding: "13px 16px", opacity: i <= active ? 1 : 0.45, transform: on ? "scale(1.015)" : "scale(1)", transition: "all 0.35s" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "var(--color-porcelain-grey)", borderRadius: 6, padding: "2px 8px", fontFamily: "var(--font-mono)", fontSize: 10.5, color: INK }}><span style={{ width: 6, height: 6, borderRadius: "50%", background: dot }} />{kind}</span>
                {done && <span style={{ marginLeft: "auto" }}><CmSpinner t={t} done /></span>}
                {on && <span style={{ marginLeft: "auto" }}><CmSpinner t={t} on /></span>}
              </div>
              <div style={{ fontFamily: kind === "Shell Script" ? "var(--font-mono)" : "var(--font-sans)", fontSize: kind === "Shell Script" ? "0.8125rem" : "1rem", color: INK, marginTop: 8, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{label}</div>
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );
}

/* ---- verified by build & test (before/after + green build) ---- */
function VerifyDiagram() {
  const t = cmClock(7600);
  const building = t > 0.34, green = t > 0.6;
  const after = [
    ["", "var(--color-grey-700)", "// migrated to java.time"],
    ["-", RED, "Date d = new Date();"],
    ["+", ACC, "LocalDate d = LocalDate.now();"],
    ["-", RED, "cal.add(Calendar.DAY, 1);"],
    ["+", ACC, "d = d.plusDays(1);"],
  ];
  return (
    <div style={{ width: "100%", maxWidth: 380, display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 14, overflow: "hidden", boxShadow: "var(--shadow-sm)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", borderBottom: `0.5px solid ${HAIR}` }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--color-grey-700)" }}>DateUtil.java</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: ACC }}>JAVA 8 → 17</span>
        </div>
        <div style={{ padding: "12px 16px", fontFamily: "var(--font-mono)", fontSize: 12, lineHeight: 1.9 }}>
          {after.map(([sign, c, code], i) => (
            <div key={i} style={{ display: "flex", gap: 9, margin: "0 -16px", padding: "0 16px", background: sign === "+" ? `color-mix(in srgb, ${ACC} 9%, transparent)` : sign === "-" ? `color-mix(in srgb, ${RED} 8%, transparent)` : "transparent" }}>
              <span style={{ color: c, width: 8, flex: "none" }}>{sign || " "}</span>
              <span style={{ color: sign === "" ? "var(--color-grey-600)" : INK, whiteSpace: "pre", overflow: "hidden", textOverflow: "ellipsis" }}>{code}</span>
            </div>
          ))}
        </div>
      </div>
      <div style={{ background: green ? `color-mix(in srgb, ${ACC} 9%, var(--color-white))` : "var(--color-white)", border: `0.5px solid ${green ? "transparent" : HAIR}`, borderRadius: 12, padding: "13px 16px", display: "flex", alignItems: "center", gap: 11, transition: "background 0.4s" }}>
        <CmSpinner t={t} on={building && !green} done={green} />
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: INK }}>{green ? "Build green · 243 tests passing" : building ? "Running mvn test…" : "Compiling…"}</span>
        {green && <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: ACC }}>verified</span>}
      </div>
    </div>
  );
}

/* ===================== page ===================== */
function CmHero() {
  return (
    <section style={{ ...cmwrap, paddingTop: "5rem" }}>
      <div style={{ textAlign: "center", maxWidth: "42rem", margin: "0 auto 3.75rem" }}>
        <CmEyebrow color={ACC}>Solutions · Code modernization</CmEyebrow>
        <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.75rem", lineHeight: 1.03, letterSpacing: "-0.02em", margin: "1.25rem 0 0", color: INK }}>
          Code migration &amp;<br />modernization at scale
        </h1>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.5 }}>
          Migrations that sat in backlogs for years, done in days. Fleets of agents migrate your entire codebase — every change built, tested, and verified, not just rewritten.
        </p>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "2rem" }}>
          <CmButton iconRight={<span>→</span>}>Get started</CmButton>
          <CmButton variant="outline">Request a demo</CmButton>
        </div>
      </div>
      <MigrationFleet />
    </section>
  );
}

function CmBacklogSection() {
  return (
    <section style={{ ...cmwrap, paddingTop: "8rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "0.9fr 1.1fr", gap: "4rem", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: 0, color: INK }}>
            Migrations that sat in backlogs for years, done in days
          </h2>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.55, maxWidth: "44ch" }}>
            Fleets of agents run the migration end to end across your entire codebase, each in its own isolated environment that builds the code and runs the tests — so every change is verified rather than just rewritten.
          </p>
          <div style={{ marginTop: "1.75rem" }}><CmLink href="automations-fleets.html">Browse automation templates</CmLink></div>
        </div>
        <PipelineDiagram />
      </div>
    </section>
  );
}

function CmFeatures() {
  return (
    <section style={{ ...cmwrap, paddingTop: "6rem", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <CmFeatureRow
        eyebrow="Verified, not rewritten"
        heading="Every change builds and passes tests"
        body="An agent doesn't just rewrite code — it compiles the project and runs the suite in an isolated environment. A migration only lands when the build is green, so you review working changes, not guesses."
        flip={false}
        diagram={<VerifyDiagram />}
      />
    </section>
  );
}

function CmStats() {
  const stats = [
    ["210", "Repos migrated in one run"],
    ["Years → days", "Backlog cleared"],
    ["100%", "Changes built & tested"],
  ];
  return (
    <section style={{ ...cmwrap, paddingTop: "6rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem" }}>
        {stats.map(([value, label]) => (
          <div key={label} style={{ background: "var(--color-porcelain-grey)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "2.25rem 2rem" }}>
            <div style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.75rem", lineHeight: 1.05, letterSpacing: "-0.02em", color: INK }}>{value}</div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-700)", marginTop: "0.625rem" }}>{label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function CmCTA() {
  return (
    <section style={{ ...cmwrap, paddingTop: "8rem", textAlign: "center" }}>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0, color: INK }}>Clear the migration backlog</h2>
      <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}>
        <CmButton iconRight={<span>→</span>}>Get started</CmButton>
        <CmLink href="solutions.html">Back to solutions</CmLink>
      </div>
    </section>
  );
}

function HvPage() {
  return (
    <main>
      <CmHero />
      <CmBacklogSection />
      <CmFeatures />
      <CmStats />
      <CmCTA />
    </main>
  );
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
