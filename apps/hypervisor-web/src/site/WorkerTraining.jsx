const React = window.React;
// hypervisor.com — Worker Training (Foundry) solution page.
const WTNS = window.IoiDesignSystem;
const { Button: WtButton, TextLink: WtLink, Eyebrow: WtEyebrow, Logo: WtLogo } = WTNS;
const wtwrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";

function wtClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.9); return; }
    let raf, start = null;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % period) / period)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}
const ease = (x) => 1 - Math.pow(1 - Math.max(0, Math.min(1, x)), 2.4);

/* ============================================================ *
 * Hero showcase — Foundry training run: eval accuracy climbing
 * ============================================================ */
function FoundryTraining() {
  const t = wtClock(11000);
  const p = ease(Math.min(1, t * 1.12));
  const acc = 0.62 + p * 0.32;            // 62% → 94%
  const epoch = Math.min(12, Math.floor(p * 12) + (p > 0 ? 1 : 0));
  const traces = Math.round(120 + p * 1120);
  const done = p > 0.985;

  // chart geometry
  const W = 320, H = 132, pad = 8;
  const N = 26;
  const pts = [];
  for (let i = 0; i < N; i++) {
    const x = pad + (i / (N - 1)) * (W - pad * 2);
    const localP = Math.min(1, (i / (N - 1)) / Math.max(0.001, p)); // only draw up to current progress
    const drawn = (i / (N - 1)) <= p;
    const yv = 0.62 + ease(i / (N - 1)) * 0.32;
    const y = H - pad - (yv - 0.55) / 0.45 * (H - pad * 2);
    if (drawn) pts.push(`${x},${y}`);
  }
  const baselineY = H - pad - (0.62 - 0.55) / 0.45 * (H - pad * 2);
  const targetY = H - pad - (0.90 - 0.55) / 0.45 * (H - pad * 2);

  const evals = [
    ["Field extraction", 0.96, 0.0],
    ["Edge-case handling", 0.91, 0.1],
    ["Format compliance", 0.99, 0.2],
    ["Refusal accuracy", 0.94, 0.32],
  ];

  return (
    <div style={{ width: "100%", maxWidth: 1060, margin: "0 auto", position: "relative" }}>
      <div style={{ position: "absolute", inset: -2, borderRadius: 18, background: "linear-gradient(135deg, color-mix(in srgb, var(--color-pistachio-green) 75%, var(--color-white)), color-mix(in srgb, var(--color-link-green) 32%, var(--color-white)) 55%, var(--color-porcelain-grey))", zIndex: 0 }} />
      <div style={{ position: "relative", zIndex: 1, margin: 6, background: "#0d0d10", borderRadius: 14, overflow: "hidden", boxShadow: "0 40px 90px rgba(0,0,0,0.4)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "16px 22px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
          <span style={{ width: 30, height: 30, borderRadius: 8, background: "rgba(255,255,255,0.08)", display: "grid", placeItems: "center", color: "#fff" }}><WtLogo size={15} /></span>
          <div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "#fff" }}>Foundry · training run</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "rgba(255,255,255,0.4)", marginTop: 1 }}>worker · invoice-specialist</div>
          </div>
          <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)", fontSize: 11, color: done ? ACC : "rgba(255,255,255,0.7)", border: `1px solid ${done ? "color-mix(in srgb, " + ACC + " 40%, transparent)" : "rgba(255,255,255,0.15)"}`, borderRadius: 6, padding: "4px 10px" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: done ? ACC : "rgba(255,255,255,0.5)" }} />{done ? "ready to deploy" : `training · epoch ${epoch}/12`}
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", minHeight: 360 }}>
          {/* left — accuracy chart */}
          <div style={{ borderRight: "1px solid rgba(255,255,255,0.07)", padding: "22px 24px" }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase", color: "rgba(255,255,255,0.4)" }}>Eval accuracy</span>
              <span style={{ marginLeft: "auto", fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: 38, color: "#fff", lineHeight: 1 }}>{Math.round(acc * 100)}<span style={{ fontSize: 20, color: "rgba(255,255,255,0.5)" }}>%</span></span>
            </div>
            <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ marginTop: 14, display: "block" }}>
              <line x1={pad} y1={targetY} x2={W - pad} y2={targetY} stroke="rgba(255,255,255,0.18)" strokeWidth="1" strokeDasharray="3 4" />
              <text x={W - pad} y={targetY - 5} textAnchor="end" fontFamily="var(--font-mono)" fontSize="8.5" fill="rgba(255,255,255,0.35)">target 90%</text>
              <line x1={pad} y1={baselineY} x2={W - pad} y2={baselineY} stroke="rgba(255,255,255,0.12)" strokeWidth="1" />
              <text x={pad} y={baselineY - 5} fontFamily="var(--font-mono)" fontSize="8.5" fill="rgba(255,255,255,0.3)">baseline</text>
              {pts.length > 1 && <polyline points={pts.join(" ")} fill="none" stroke={ACC} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />}
              {pts.length > 0 && (() => { const [cx, cy] = pts[pts.length - 1].split(","); return <circle cx={cx} cy={cy} r="3.5" fill={ACC} />; })()}
            </svg>
            <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
              {[["Traces ingested", traces.toLocaleString()], ["Corrections", Math.round(p * 86)], ["Epoch", `${epoch}/12`]].map(([k, v]) => (
                <div key={k} style={{ flex: 1, padding: "10px 12px", background: "rgba(255,255,255,0.04)", borderRadius: 9, border: "1px solid rgba(255,255,255,0.06)" }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, letterSpacing: "0.05em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)" }}>{k}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, color: "#fff", marginTop: 4 }}>{v}</div>
                </div>
              ))}
            </div>
          </div>

          {/* right — eval categories */}
          <div style={{ padding: "22px 24px" }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase", color: "rgba(255,255,255,0.4)", marginBottom: 16 }}>Evaluation suite</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {evals.map(([label, target, delay]) => {
                const lp = ease(Math.max(0, Math.min(1, (p - delay) / (1 - delay))));
                const val = 0.5 + lp * (target - 0.5);
                const pass = val >= 0.9;
                return (
                  <div key={label}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7 }}>
                      <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.78)" }}>{label}</span>
                      <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11.5, color: pass ? ACC : "rgba(255,255,255,0.55)" }}>{Math.round(val * 100)}%</span>
                    </div>
                    <div style={{ height: 5, borderRadius: 3, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${val * 100}%`, background: pass ? ACC : "rgba(255,255,255,0.4)", borderRadius: 3, transition: "width 0.2s linear" }} />
                    </div>
                  </div>
                );
              })}
            </div>
            <div style={{ marginTop: 22, display: "flex", alignItems: "center", gap: 9, padding: "11px 14px", borderRadius: 10, background: done ? "color-mix(in srgb, var(--color-link-green) 14%, #0d0d10)" : "rgba(255,255,255,0.04)", border: `1px solid ${done ? "color-mix(in srgb, " + ACC + " 45%, transparent)" : "rgba(255,255,255,0.08)"}`, transition: "all 0.4s" }}>
              <span style={{ width: 18, height: 18, borderRadius: "50%", flex: "none", background: done ? ACC : "rgba(255,255,255,0.15)", display: "grid", placeItems: "center" }}>
                {done && <svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>}
              </span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: done ? "#fff" : "rgba(255,255,255,0.55)" }}>{done ? "Meets promotion threshold — deployable" : "Awaiting promotion threshold (90%)"}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===================== feature row ===================== */
function WtFeatureRow({ eyebrow, heading, body, link, diagram, flip }) {
  return (
    <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "3rem 3.25rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem", alignItems: "center" }}>
      <div style={{ order: flip ? 2 : 1 }}>
        <span style={{ display: "inline-block", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: ACC, marginBottom: "0.875rem" }}>{eyebrow}</span>
        <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.625rem", letterSpacing: "-0.02em", lineHeight: 1.12, margin: 0, color: INK }}>{heading}</h3>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5, maxWidth: "42ch" }}>{body}</p>
        {link && <div style={{ marginTop: "1.5rem" }}><WtLink href={link[1]}>{link[0]}</WtLink></div>}
      </div>
      <div style={{ order: flip ? 1 : 2, display: "flex", justifyContent: "center" }}>{diagram}</div>
    </div>
  );
}

const wtIcon = (d) => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>;

/* ---- training inputs diagram ---- */
function InputsDiagram() {
  const t = wtClock(6500);
  const inputs = [
    ["Session traces", "1,240 governed runs", "M4 6 h16 M4 12 h16 M4 18 h10", 0.0],
    ["Human corrections", "86 reviewer edits", "M14 6 L18 10 L8 20 L4 20 L4 16 Z", 0.16],
    ["Workflows", "12 reusable automations", "M3 8 h12 a4 4 0 0 1 0 8 H9 M6 5 L3 8 L6 11", 0.32],
  ];
  const active = Math.floor(t * 4);
  return (
    <div style={{ width: "100%", maxWidth: 380, display: "flex", flexDirection: "column", gap: 12 }}>
      {inputs.map(([label, meta, d, delay], i) => {
        const on = t >= delay;
        return (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 13, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 12, boxShadow: "var(--shadow-xs)", padding: "13px 16px", opacity: on ? 1 : 0.45, transform: on ? "translateX(0)" : "translateX(-8px)", transition: "all 0.4s" }}>
            <span style={{ width: 34, height: 34, borderRadius: 9, flex: "none", background: "var(--color-porcelain-grey)", display: "grid", placeItems: "center", color: INK }}>{wtIcon(d)}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: INK }}>{label}</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-600)", marginTop: 2 }}>{meta}</div>
            </div>
            <span style={{ width: 16, height: 16, borderRadius: "50%", flex: "none", background: ACC, display: "grid", placeItems: "center" }}><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
          </div>
        );
      })}
      <div style={{ display: "flex", justifyContent: "center", margin: "2px 0" }}>
        <svg width="20" height="22" viewBox="0 0 20 22" fill="none" stroke="var(--color-grey-500)" strokeWidth="1.5"><path d="M10 1 V17 M5 12 L10 17 L15 12" strokeLinecap="round" strokeLinejoin="round" /></svg>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 13, background: INK, borderRadius: 12, padding: "15px 18px", boxShadow: "var(--shadow-md)" }}>
        <span style={{ width: 36, height: 36, borderRadius: 9, flex: "none", background: "rgba(255,255,255,0.12)", display: "grid", placeItems: "center", color: "#fff" }}><WtLogo size={17} /></span>
        <div>
          <div style={{ fontFamily: "var(--font-sans)", fontSize: 14.5, color: "#fff" }}>invoice-specialist</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "rgba(255,255,255,0.5)", marginTop: 2 }}>specialist worker · trained in Foundry</div>
        </div>
      </div>
    </div>
  );
}

/* ---- deploy / package diagram ---- */
function DeployDiagram() {
  const t = wtClock(7000);
  const deployed = t > 0.55;
  return (
    <div style={{ width: "100%", maxWidth: 380, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 14, boxShadow: "var(--shadow-sm)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "16px 18px", borderBottom: `0.5px solid ${HAIR}` }}>
        <span style={{ width: 36, height: 36, borderRadius: 9, flex: "none", background: INK, display: "grid", placeItems: "center", color: "#fff" }}><WtLogo size={17} /></span>
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: "var(--font-sans)", fontSize: 15, color: INK }}>invoice-specialist</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-600)", marginTop: 2 }}>v1.0 · 94% eval · signed</div>
        </div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: ACC, border: `0.5px solid ${ACC}`, borderRadius: 5, padding: "3px 8px" }}>verified</span>
      </div>
      <div style={{ padding: "14px 18px", display: "flex", flexDirection: "column", gap: 11 }}>
        {[["Scope", "fs.read · invoice.parse"], ["Runtime", "any · cloud / VPC / cTEE"], ["Benchmark", "94% · promoted"]].map(([k, v]) => (
          <div key={k} style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-grey-700)" }}>{k}</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: INK }}>{v}</span>
          </div>
        ))}
      </div>
      <div style={{ padding: "0 18px 18px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 9, padding: "12px", borderRadius: 10, background: deployed ? "color-mix(in srgb, var(--color-pistachio-green) 40%, var(--color-white))" : "var(--color-porcelain-grey)", border: `0.5px solid ${deployed ? "transparent" : HAIR}`, transition: "background 0.4s" }}>
          <span style={{ width: 16, height: 16, borderRadius: "50%", background: deployed ? ACC : "var(--color-grey-500)", display: "grid", placeItems: "center" }}>
            {deployed && <svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>}
          </span>
          <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: INK }}>{deployed ? "Deployed to production" : "Deploying…"}</span>
        </div>
      </div>
    </div>
  );
}

/* ===================== page ===================== */
function WtHero() {
  return (
    <section style={{ ...wtwrap, paddingTop: "5rem" }}>
      <div style={{ textAlign: "center", maxWidth: "44rem", margin: "0 auto 3.75rem" }}>
        <WtEyebrow color={ACC}>Solutions · Worker training</WtEyebrow>
        <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.75rem", lineHeight: 1.03, letterSpacing: "-0.02em", margin: "1.25rem 0 0", color: INK }}>
          Train a specialist<br />for the work you do
        </h1>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.5 }}>
          Turn workflows, traces, and corrections into a deployable specialist worker with Foundry — trained for a defined outcome and evaluated before it ships.
        </p>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "2rem" }}>
          <WtButton iconRight={<span>→</span>}>Get started</WtButton>
          <WtButton variant="outline">Request a demo</WtButton>
        </div>
      </div>
      <FoundryTraining />
    </section>
  );
}

function WtInputsSection() {
  return (
    <section style={{ ...wtwrap, paddingTop: "8rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "0.9fr 1.1fr", gap: "4rem", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: 0, color: INK }}>
            Learns from how your team actually works
          </h2>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.55, maxWidth: "44ch" }}>
            Foundry trains on the receipts you already produce — governed session traces, reviewer corrections, and the workflows your team runs. No labeling project, no data leaving your boundary.
          </p>
          <div style={{ marginTop: "1.75rem" }}><WtLink href="platform.html">How Foundry works</WtLink></div>
        </div>
        <InputsDiagram />
      </div>
    </section>
  );
}

function WtFeatures() {
  return (
    <section style={{ ...wtwrap, paddingTop: "6rem", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <WtFeatureRow
        eyebrow="Deploy"
        heading="Ship it as a governed, versioned worker"
        body="A trained worker is a package — versioned, benchmarked, and signed. Deploy it under scoped authority on any runtime, and settle its work the same way as any other worker."
        link={["Read the worker spec", "platform.html"]}
        flip={false}
        diagram={<DeployDiagram />}
      />
    </section>
  );
}

function WtStats() {
  const stats = [
    ["94%", "Eval accuracy before it ships"],
    ["0", "Labeling projects required"],
    ["Any runtime", "Cloud · VPC · cTEE"],
  ];
  return (
    <section style={{ ...wtwrap, paddingTop: "6rem" }}>
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

function WtCTA() {
  return (
    <section style={{ ...wtwrap, paddingTop: "8rem", textAlign: "center" }}>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0, color: INK }}>Train your first specialist</h2>
      <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}>
        <WtButton iconRight={<span>→</span>}>Get started</WtButton>
        <WtLink href="solutions.html">Back to solutions</WtLink>
      </div>
    </section>
  );
}

function HvPage() {
  return (
    <main>
      <WtHero />
      <WtInputsSection />
      <WtFeatures />
      <WtStats />
      <WtCTA />
    </main>
  );
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
