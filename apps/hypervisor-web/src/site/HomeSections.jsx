const React = window.React;
// hypervisor.com — homepage sections. Real product copy from the spec.
const NS = window.IoiDesignSystem;
const { Button: SButton, Badge: SBadge, Card: SCard, Stat: SStat, TextLink: SLink, Eyebrow: SEyebrow } = NS;

const wrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

function GreenCheck() {
  return <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0, marginTop: 2 }}><path d="M3 8.5l3.2 3.2L13 5" stroke="var(--color-link-green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}

/* ---------------- Hero ---------------- */
function Hero() {
  return (
    <section id="top" className="hv-hero" style={{ ...wrap, paddingTop: "4.5rem", display: "grid", gridTemplateColumns: "1.05fr 0.95fr", gap: "3.5rem", alignItems: "center" }}>
      <div>
        <SEyebrow color="var(--color-link-green)">Web4 · Governed autonomy</SEyebrow>
        <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.75rem", lineHeight: 1.04, letterSpacing: "-0.02em", margin: "1.25rem 0 0", color: "var(--color-onyx-black)" }}>
          The operating environment for autonomous systems
        </h1>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.5rem", maxWidth: "46ch", lineHeight: 1.5 }}>
          Build, run, govern, and verify autonomous work across any machine, model, or provider — without surrendering runtime truth or authority to one vendor.
        </p>
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "2rem" }}>
          <SButton iconRight={<span>→</span>}>Get started</SButton>
          <SButton variant="outline">Request a demo</SButton>
        </div>
        <div style={{ display: "flex", gap: "1.5rem", marginTop: "2.25rem", flexWrap: "wrap" }}>
          {["Deterministic runtime", "Scoped authority", "Receipts on every action"].map((t) => (
            <span key={t} style={{ display: "inline-flex", alignItems: "center", gap: 7, fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)" }}><GreenCheck />{t}</span>
          ))}
        </div>
      </div>
      <HeroPanel />
    </section>
  );
}

/* ---------------- Proof bar (credibility strip under hero) ---------------- */
function ProofBar() {
  const badges = [["soc-2", "SOC 2 Type II"], ["gdpr", "GDPR compliant"], ["fortune-500", "Fortune 500 trusted"]];
  const proofs = ["Runs in your VPC", "Deterministic replay"];
  return (
    <div className="hv-proofbar" style={{ ...wrap, marginTop: "3.25rem" }}>
      <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: "1.25rem 2rem", padding: "1.25rem 0", borderTop: "0.5px solid var(--color-grey-500)", borderBottom: "0.5px solid var(--color-grey-500)" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>Proven in production</span>
        <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: "1.25rem 1.75rem", marginLeft: "auto" }}>
          {badges.map(([f, label]) => (
            <span key={f} style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              <img src={`assets/badges/${f}.svg`} alt="" width="28" height="28" />
              <span style={{ fontFamily: "var(--font-sans)", fontSize: "0.875rem", color: "var(--color-grey-800)" }}>{label}</span>
            </span>
          ))}
          <span style={{ width: "0.5px", height: 20, background: "var(--color-grey-500)" }} />
          {proofs.map((p) => (
            <span key={p} style={{ display: "inline-flex", alignItems: "center", gap: 7, fontFamily: "var(--font-sans)", fontSize: "0.875rem", color: "var(--color-grey-800)" }}><GreenCheck />{p}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function HeroPanel() {
  const rows = [
    ["fs.write", "src/billing/*.ts", "prim:fs.write"],
    ["proc.exec", "pnpm test — 312 passing", "prim:proc.exec"],
    ["vcs.pr", "open PR #4471", "scope:repo.write"],
  ];
  return (
    <div style={{ position: "relative" }}>
      <div style={{ position: "absolute", inset: "-8% -6%", background: "url(../assets/textures/pistachio-noise.png) center/cover", borderRadius: "var(--radius-card)", opacity: 0.9 }} />
      <SCard style={{ position: "relative", padding: 0, overflow: "hidden", boxShadow: "var(--shadow-lg)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", borderBottom: "0.5px solid var(--color-grey-500)" }}>
          <span style={{ width: 22, height: 22, color: "var(--color-onyx-black)" }}><NS.Logo size={22} /></span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-grey-800)" }}>session · modernize-billing</span>
          <span style={{ marginLeft: "auto" }}><SBadge tone="green">Running</SBadge></span>
        </div>
        <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>Receipts</div>
          {rows.map((r, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-lg)", padding: "10px 12px", background: "var(--color-white)" }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--color-green-600)", flexShrink: 0 }} />
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-onyx-black)" }}>{r[0]}</span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--color-grey-800)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r[1]}</span>
              <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)" }}>{r[2]}</span>
            </div>
          ))}
          <div style={{ display: "flex", alignItems: "center", gap: 10, border: "1px solid var(--color-onyx-black)", borderRadius: "var(--radius-lg)", padding: "11px 12px", marginTop: 2 }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.06em", color: "var(--color-link-green)" }}>AUTHORITY GATE</span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--color-onyx-black)" }}>Approve push & open PR</span>
            <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 12, background: "var(--color-onyx-black)", color: "#fff", borderRadius: 6, padding: "4px 9px" }}>Allow</span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 12, border: "1px solid var(--color-grey-500)", color: "var(--color-grey-800)", borderRadius: 6, padding: "4px 9px" }}>Deny</span>
            </span>
          </div>
        </div>
      </SCard>
    </div>
  );
}

/* ---------------- Problem framing (status quo → the turn) ---------------- */
function Problem() {
  const fails = [
    ["Run in shared clouds", "Your workloads sit next to everyone else's, on infrastructure you don't control."],
    ["Stream your code to third parties", "Source, secrets, and context leave your boundary the moment work begins."],
    ["Can't be audited or controlled", "No receipts, no scoped authority, no way to prove what an agent actually did."],
  ];
  return (
    <section className="hv-section" style={{ ...wrap, paddingTop: "8rem" }}>
      <div style={{ maxWidth: "44rem" }}>
        <SEyebrow color="var(--color-red-500)">The status quo</SEyebrow>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.75rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: "1rem 0 0", color: "var(--color-onyx-black)" }}>
          Most agents aren't enterprise-ready
        </h2>
      </div>
      <div className="hv-grid-3" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.5rem", marginTop: "2.5rem" }}>
        {fails.map(([t, b]) => (
          <div key={t} style={{ borderTop: "1px solid var(--color-grey-500)", paddingTop: "1.25rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
              <span style={{ width: 18, height: 18, borderRadius: "50%", background: "var(--color-red-500)", display: "grid", placeItems: "center", flex: "none" }}>
                <svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M3 3 L9 9 M9 3 L3 9" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" /></svg>
              </span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", fontWeight: 700, color: "var(--color-onyx-black)" }}>{t}</span>
            </div>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.75rem", lineHeight: 1.45 }}>{b}</p>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: "1.5rem", flexWrap: "wrap", marginTop: "2.75rem", paddingTop: "1.75rem", borderTop: "1px solid var(--color-onyx-black)" }}>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-onyx-black)", margin: 0, maxWidth: "52ch", lineHeight: 1.5 }}>
          Hypervisor is deployed <strong style={{ fontWeight: 700 }}>inside your VPC</strong>, governed by <strong style={{ fontWeight: 700 }}>your policies</strong>, and <strong style={{ fontWeight: 700 }}>auditable by design</strong>.
        </p>
        <span style={{ marginLeft: "auto" }}><SLink href="platform.html">Why a browser plugin isn't enough</SLink></span>
      </div>
    </section>
  );
}

/* ---------------- Capability cards (scannable overview · OpenRouter-style) ---------------- */
function CapabilityCards() {
  const D = window.HvDiagrams;
  const [cfg, setCfg] = React.useState(() => ({ variant: "A", spotlight: false, ...(window.__capCfg || {}) }));
  React.useEffect(() => {
    const h = () => setCfg({ variant: "A", spotlight: false, ...(window.__capCfg || {}) });
    window.addEventListener("capcfg", h);
    return () => window.removeEventListener("capcfg", h);
  }, []);
  const items = [
    { diagram: <D.DiagHub />,    designW: 460, designH: 338, eyebrow: "Any model",     title: "Runs inside your VPC",        desc: "Code and secrets never cross your boundary. Mount any model, seal every agent." },
    { diagram: <D.DiagCollab />, designW: 460, designH: 300, eyebrow: "Collaboration", title: "Work together, not in turns", desc: "Autonomous loops with instant human handoff \u2014 review, approve, or step in." },
    { diagram: <D.DiagAccess />, designW: 460, designH: 340, eyebrow: "Auditability",  title: "Every action receipted",      desc: "Scoped, approval-gated, and logged \u2014 traceable across your whole org." },
  ];
  const cardBase = { display: "flex", flexDirection: "column", background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-card)", overflow: "hidden" };
  const titleS = { fontFamily: "var(--font-sans)", fontSize: "1.1875rem", letterSpacing: "-0.015em", lineHeight: 1.15, margin: 0, color: "var(--color-onyx-black)" };
  const descS = { fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", margin: "10px 0 0", lineHeight: 1.5, textWrap: "pretty" };
  const eb = (color) => ({ display: "inline-block", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.09em", textTransform: "uppercase", color, marginBottom: 10 });
  function Fit({ designW, designH, children }) {
    const outer = React.useRef(null);
    const [s, setS] = React.useState(0);
    React.useLayoutEffect(() => {
      const measure = () => {
        if (!outer.current) return;
        const ow = outer.current.clientWidth, oh = outer.current.clientHeight;
        if (ow && oh) setS(Math.min(ow / designW, oh / designH, 1));
      };
      measure();
      const ro = new ResizeObserver(measure); ro.observe(outer.current);
      return () => ro.disconnect();
    }, [designW, designH]);
    return (
      <div ref={outer} style={{ width: "100%", height: "100%", position: "relative" }}>
        <div style={{ width: designW, height: designH, position: "absolute", left: "50%", top: "50%", transform: s ? `translate(-50%, -50%) scale(${s})` : "translate(-50%, -50%)", transformOrigin: "center", visibility: s ? "visible" : "hidden" }}>{children}</div>
      </div>
    );
  }
  function Well({ bg, children }) {
    return (
      <div style={{ position: "relative", height: 300, overflow: "hidden", background: bg, padding: "1rem 0.5rem" }}>
        {children}
      </div>
    );
  }
  function renderCard(c, i) {
    const featured = cfg.spotlight && i === 0;
    if (cfg.variant === "B") {
      return (
        <div key={i} style={cardBase}>
          <Well bg="var(--color-white)"><Fit designW={c.designW} designH={c.designH}>{c.diagram}</Fit></Well>
          <div style={{ borderTop: "0.5px solid var(--color-grey-500)", padding: "1.375rem 1.5rem 1.625rem" }}>
            <span style={eb("var(--color-link-green)")}>{c.eyebrow}</span>
            <h3 style={titleS}>{c.title}</h3>
            <p style={descS}>{c.desc}</p>
          </div>
        </div>
      );
    }
    return (
      <div key={i} style={{ ...cardBase, border: featured ? "1px solid var(--color-onyx-black)" : "0.5px solid var(--color-grey-500)" }}>
        <Well bg={featured ? "color-mix(in srgb, var(--color-pistachio-green) 26%, var(--color-white))" : "var(--color-porcelain-grey)"}><Fit designW={c.designW} designH={c.designH}>{c.diagram}</Fit></Well>
        <div style={{ borderTop: featured ? "1px solid var(--color-onyx-black)" : "0.5px solid var(--color-grey-500)", padding: "1.375rem 1.5rem 1.625rem" }}>
          {cfg.variant === "C" && <span style={eb(featured ? "var(--color-link-green)" : "var(--color-grey-700)")}>{c.eyebrow}</span>}
          <h3 style={titleS}>{c.title}</h3>
          <p style={descS}>{c.desc}</p>
        </div>
      </div>
    );
  }
  return (
    <section className="hv-section" style={{ ...wrap, paddingTop: "8rem" }}>
      <div style={{ maxWidth: "40rem", marginBottom: "2.75rem" }}>
        <SEyebrow>How it fits your world</SEyebrow>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.75rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: "1rem 0 0" }}>Built for enterprise, deployed in your infra</h2>
      </div>
      <div className="hv-cap-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.5rem" }}>
        {items.map(renderCard)}
      </div>
    </section>
  );
}

/* ---------------- Doctrine pipeline (inverse band) ---------------- */
function Doctrine() {
  const steps = [["Daemon", "executes"], ["wallet.network", "authorizes"], ["Agentgres", "remembers"], ["IOI L1", "settles"]];
  return (
    <section className="hv-section hv-doctrine" style={{ ...wrap, paddingTop: "8rem" }}>
      <SCard tone="inverse" style={{ padding: "3rem 3rem 3.25rem", borderRadius: "var(--radius-card)", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: "50%", right: "-2.5rem", transform: "translateY(-50%)", width: "26rem", height: "26rem", opacity: 0.9, pointerEvents: "none", WebkitMaskImage: "radial-gradient(120% 120% at 80% 50%, #000 38%, transparent 72%)", maskImage: "radial-gradient(120% 120% at 80% 50%, #000 38%, transparent 72%)" }}>
          <HvDots inverse cols={13} rows={13} gap={28} dot={6} seed={3} />
        </div>
        <div style={{ position: "relative" }}>
        <SEyebrow color="var(--color-pistachio-green)">The runtime doctrine</SEyebrow>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.25rem", letterSpacing: "-0.02em", lineHeight: 1.12, margin: "1rem 0 0", color: "#fff", maxWidth: "26ch" }}>
          The model can be fuzzy. The consequences cannot.
        </h2>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-600)", marginTop: "1rem", maxWidth: "60ch", lineHeight: 1.5 }}>
          Every consequential action is canonicalized, policy-checked, authority-scoped, approval-gated when necessary, receipted, and replayable. Probabilistic reasoning in; deterministic, accountable execution out.
        </p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem 1rem", alignItems: "center", marginTop: "2rem" }}>
          {steps.map(([k, v], i) => (
            <React.Fragment key={k}>
              <span style={{ display: "inline-flex", alignItems: "baseline", gap: 8, border: "1px solid rgba(255,255,255,0.16)", borderRadius: "var(--radius-lg)", padding: "9px 13px" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "#fff" }}>{k}</span>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--color-grey-600)" }}>{v}</span>
              </span>
              {i < steps.length - 1 && <span style={{ color: "var(--color-grey-700)" }}>→</span>}
            </React.Fragment>
          ))}
        </div>
        </div>
      </SCard>
    </section>
  );
}

/* ---------------- Feature band (alternating split + line-art diagrams) ---------------- */
function Features() {
  const D = window.HvDiagrams;
  const rows = [
    {
      diagram: <D.DiagToolStack />, flip: false, reveal: true, revealOrder: "code",
      eyebrow: "Meets you where you build",
      title: "Works in the tools you already use",
      body: "Drive sessions from the CLI, SDK, or your editor — Cursor, VS Code, JetBrains, and terminals. Review scoped tasks and jump in seamlessly, with full context and receipts on every action.",
      link: ["Explore the SDK", "developers.html"],
    },
    {
      diagram: <D.DiagPrivacy />, flip: true, reveal: true, revealOrder: "stack",
      eyebrow: "Privacy-first by design",
      title: "Your data is never training data",
      body: "Connect your own private or fine-tuned models. Every action is logged, traced, and replayable — but nothing you run is captured for training, streamed to third parties, or retained beyond your policy.",
      link: ["Read the security model", "#lifecycle"],
    },
    {
      diagram: <D.DiagAgentTree />, flip: false, reveal: true, revealOrder: "tree",
      eyebrow: "Run at scale",
      title: "Run Hypervisor, or any agent, at scale",
      body: "Compose specialized workers from git, memory, testing, reasoning, and more. Run thousands in parallel inside ephemeral, isolated environments — provisioning, isolation, and policy enforcement handled for you.",
      link: ["Explore workers", "developers.html"],
    },
  ];
  return (
    <section className="hv-section" style={{ ...wrap, paddingTop: "8rem" }}>
      <div style={{ textAlign: "center", maxWidth: "40rem", margin: "0 auto 3.5rem" }}>
        <SEyebrow>A closer look</SEyebrow>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.75rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: "1rem 0 0" }}>
          How teams build with Hypervisor
        </h2>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
        {rows.map((r) => (
          <div key={r.title} className="hv-feat-row" style={{ background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-card)", padding: "3rem 3.25rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem", alignItems: "center" }}>
            <div className="hv-feat-text" style={{ order: r.flip ? 2 : 1 }}>
              <SEyebrow>{r.eyebrow}</SEyebrow>
              <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.625rem", letterSpacing: "-0.02em", lineHeight: 1.12, margin: "0.875rem 0 0", color: "var(--color-onyx-black)" }}>{r.title}</h3>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5, maxWidth: "42ch" }}>{r.body}</p>
              <div style={{ marginTop: "1.5rem" }}><SLink href={r.link[1]}>{r.link[0]}</SLink></div>
            </div>
            <div className="hv-feat-media" style={{ order: r.flip ? 1 : 2, display: "flex", justifyContent: "center" }}>{r.reveal && window.RevealDiagram ? <window.RevealDiagram.Reveal order={r.revealOrder || "radial"}>{r.diagram}</window.RevealDiagram.Reveal> : r.diagram}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ---------------- Governance / security ---------------- */
function Govern() {
  const WM = window.WorkersMotion;
  const govStats = [
    { to: 1.2, decimals: 1, suffix: "M+", label: "sessions under scoped authority" },
    { to: 100, decimals: 0, suffix: "%", label: "consequential actions receipted" },
    { to: 6, decimals: 0, suffix: "", label: "controls between intent and effect" },
  ];
  const govNum = { fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", lineHeight: 1, letterSpacing: "-0.02em", color: "var(--color-link-green)", fontVariantNumeric: "tabular-nums" };
  const points = [
    ["Authority is explicit", "prim:* describes what the runtime may execute; scope:* what a wallet or tenant may authorize."],
    ["Credentials are never cognition", "wallet.network brokers secrets, approvals, and scoped authority — the worker never holds raw keys."],
    ["Logs become receipts", "Every run emits legible events, receipts, traces, stop reasons, and replayable evidence."],
    ["No plaintext custody", "cTEE private workspaces keep protected data out of provider-rooted memory."],
  ];
  return (
    <section id="lifecycle" className="hv-section" style={{ ...wrap, paddingTop: "8rem" }}>
      <div className="hv-grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3.5rem", alignItems: "start" }}>
        <div>
          <SEyebrow color="var(--color-link-green)">Governance & security</SEyebrow>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.75rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: "1rem 0 0", maxWidth: "16ch" }}>
            Bounded agency, not blind trust
          </h2>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.5, maxWidth: "44ch" }}>
            Traditional security protects systems from malicious software. Hypervisor protects systems from authorized-but-unbounded autonomous software.
          </p>
          <div style={{ marginTop: "2rem" }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>Production telemetry · trailing 30 days</div>
            <div className="hv-gov-stats" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", marginTop: "1rem", borderTop: "0.5px solid var(--color-grey-500)" }}>
              {govStats.map((s, i) => (
                <div key={s.label} style={{ padding: "1.25rem 1.25rem 0", paddingLeft: i ? "1.25rem" : 0, borderLeft: i ? "0.5px solid var(--color-grey-500)" : "none", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                  {WM
                    ? <WM.CountStat to={s.to} decimals={s.decimals} suffix={s.suffix} style={govNum} />
                    : <div style={govNum}>{s.to}{s.suffix}</div>}
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.6875rem", letterSpacing: "0.04em", lineHeight: 1.4, textTransform: "uppercase", color: "var(--color-grey-700)" }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {points.map(([t, b]) => (
            <SCard key={t} style={{ display: "flex", gap: 14, padding: "1.25rem 1.5rem" }}>
              <GreenCheck />
              <div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", fontWeight: 700, color: "var(--color-onyx-black)" }}>{t}</div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: 5, lineHeight: 1.45 }}>{b}</div>
              </div>
            </SCard>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------------- CTA ---------------- */
function CTA() {
  return (
    <section className="hv-section" style={{ ...wrap, paddingTop: "8rem", textAlign: "center" }}>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.25rem", letterSpacing: "-0.02em", lineHeight: 1.05, margin: 0, color: "var(--color-onyx-black)" }}>
        Put autonomous work<br />under authority
      </h2>
      <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.125rem", color: "var(--color-grey-800)", marginTop: "1.25rem" }}>
        The layer that governs above any machine, model, or provider. Start in minutes.
      </p>
      <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "2rem" }}>
        <SButton iconRight={<span>→</span>}>Get started</SButton>
        <SButton variant="outline">Talk to engineering</SButton>
      </div>
    </section>
  );
}

function Home() {
  return (
    <main>
      <Hero />
      <ProofBar />
      <Problem />
      <CapabilityCards />
      <Features />
      <Govern />
      <CTA />
    </main>
  );
}
window.HvHome = Home;
