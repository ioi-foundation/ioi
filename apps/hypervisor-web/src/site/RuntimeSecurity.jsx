const React = window.React;
// hypervisor.com — Runtime AI Security solution page.
const RSNS = window.IoiDesignSystem;
const { Button: RsButton, TextLink: RsLink, Eyebrow: RsEyebrow, Logo: RsLogo } = RSNS;
const rswrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";

function rsClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.88); return; }
    let raf, start = null;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % period) / period)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}

const rsIcon = (d, sw) => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={sw || 1.6} strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
);
const SHIELD = "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z";

/* ============================================================ *
 * Hero product mockup — browser window, two panels:
 *  left  = agent conversation (suggestions + governed footer)
 *  right = live terminal with kernel policy enforcement
 * ============================================================ */
function AppMockup() {
  const t = rsClock(11000);
  const caretOn = Math.sin(t * Math.PI * 2 * 6) > 0;

  // right-panel terminal stream
  const term = [
    { at: 0.06, c: "dim", s: "hypervisor session start --scope=fs.read,shell.exec,net.none" },
    { at: 0.13, c: "dim", s: "spawning worker · isolated sandbox (cTEE)" },
    { at: 0.20, c: "ok", s: "session 9f2c1 ready · scoped credentials issued" },
    { at: 0.29, c: "cmd", s: "worker run patch --cve CVE-2026-1042 --repo billing-api" },
    { at: 0.37, c: "log", s: "read  src/deps/lockfile.json" },
    { at: 0.44, c: "log", s: "edit  bumped libfoo 1.4.2 → 1.4.7" },
    { at: 0.52, c: "block", s: "BLOCKED  net.outbound → registry.evil.sh  (policy net.none)" },
    { at: 0.60, c: "log", s: "resolved via mirror · cache.internal" },
    { at: 0.68, c: "cmd", s: "shell.exec npm test" },
    { at: 0.76, c: "ok", s: "243 passed · 0 failing" },
    { at: 0.85, c: "ok", s: "receipt sealed · 1 action blocked · IOI L1" },
  ];
  const shown = term.filter((l) => t >= l.at);
  const termColor = { dim: "rgba(255,255,255,0.42)", ok: ACC, cmd: "rgba(255,255,255,0.92)", log: "rgba(255,255,255,0.6)", block: "#ff6b6b" };

  const chips = ["Patch a CVE", "Triage Sentry errors", "Review open PRs"];
  const activeChip = Math.floor(t * 3) % 3;

  return (
    <div style={{ width: "100%", maxWidth: 1060, margin: "0 auto", position: "relative" }}>
      {/* soft on-brand backdrop */}
      <div style={{ position: "absolute", inset: "-26px -26px -40px", borderRadius: 28, background: "radial-gradient(120% 120% at 70% 10%, color-mix(in srgb, var(--color-pistachio-green) 38%, var(--color-white)), var(--color-porcelain-grey))", zIndex: 0 }} />
      <div style={{ position: "relative", zIndex: 1, background: "#0d0d10", borderRadius: 14, overflow: "hidden", boxShadow: "0 40px 90px rgba(0,0,0,0.4), 0 0 0 1px rgba(0,0,0,0.06)" }}>
        {/* browser chrome */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 14px", background: "#17171c", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
          {["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => <span key={i} style={{ width: 11, height: 11, borderRadius: "50%", background: c }} />)}
          <div style={{ display: "flex", alignItems: "center", gap: 7, marginLeft: 10, background: "#0d0d10", borderRadius: 7, padding: "5px 12px", border: "1px solid rgba(255,255,255,0.07)" }}>
            <span style={{ color: ACC }}>{rsIcon(SHIELD, 1.5)}</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "rgba(255,255,255,0.5)" }}>app.hypervisor.io/session/9f2c1</span>
          </div>
          <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 5, fontFamily: "var(--font-mono)", fontSize: 11, color: ACC, border: `1px solid color-mix(in srgb, ${ACC} 40%, transparent)`, borderRadius: 6, padding: "3px 9px" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: ACC }} />governed
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "0.82fr 1.18fr", height: 480 }}>
          {/* LEFT — conversation */}
          <div style={{ background: "#fbfbfa", borderRight: "1px solid rgba(0,0,0,0.07)", display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "13px 18px", borderBottom: "1px solid rgba(0,0,0,0.06)" }}>
              <span style={{ color: INK }}>{rsIcon("M4 6 H20 M4 12 H20 M4 18 H14", 1.6)}</span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: INK, fontWeight: 500 }}>Conversation</span>
            </div>
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 26px", textAlign: "center" }}>
              <span style={{ width: 44, height: 44, borderRadius: 13, background: INK, display: "grid", placeItems: "center", color: "#fff", marginBottom: 18 }}><RsLogo size={22} /></span>
              <div style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "1.5rem", letterSpacing: "-0.01em", color: INK }}>What should the agent do?</div>
              <div style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-grey-600)", marginTop: 6 }}>Suggestions — every run stays inside policy</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center", marginTop: 22 }}>
                {chips.map((label, i) => (
                  <span key={label} style={{ display: "inline-flex", alignItems: "center", gap: 6, fontFamily: "var(--font-sans)", fontSize: 12.5, color: INK, background: i === activeChip ? "color-mix(in srgb, var(--color-pistachio-green) 40%, var(--color-white))" : "var(--color-white)", border: `0.5px solid ${i === activeChip ? "transparent" : HAIR}`, borderRadius: 999, padding: "8px 13px", transition: "background 0.4s" }}>
                    <span style={{ width: 5, height: 5, borderRadius: "50%", background: ACC }} />{label}
                  </span>
                ))}
              </div>
            </div>
            <div style={{ margin: "0 16px 16px", border: `0.5px solid ${HAIR}`, borderRadius: 12, background: "var(--color-white)", padding: "11px 13px" }}>
              <div style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-grey-500)" }}>Describe a task…</div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 16 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", border: `0.5px solid ${HAIR}`, borderRadius: 6, padding: "3px 8px" }}>
                  <span style={{ width: 5, height: 5, borderRadius: "50%", background: ACC }} />Agent
                  <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><path d="M6 9 L12 15 L18 9" /></svg>
                </span>
                <span style={{ marginLeft: "auto", width: 28, height: 28, borderRadius: 8, background: INK, display: "grid", placeItems: "center" }}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 19 V5 M6 11 L12 5 L18 11" /></svg>
                </span>
              </div>
            </div>
          </div>

          {/* RIGHT — terminal */}
          <div style={{ display: "flex", flexDirection: "column", background: "#0d0d10" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 18, padding: "0 18px", height: 38, borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
              {["PROBLEMS", "OUTPUT", "TERMINAL"].map((tab, i) => (
                <span key={tab} style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em", color: i === 2 ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.3)", borderBottom: i === 2 ? `1.5px solid ${ACC}` : "1.5px solid transparent", height: 38, display: "flex", alignItems: "center" }}>{tab}</span>
              ))}
              <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10.5, color: "rgba(255,255,255,0.3)" }}>bash · sandbox</span>
            </div>
            <div style={{ flex: 1, padding: "16px 20px", fontFamily: "var(--font-mono)", fontSize: 12, lineHeight: 1.95, overflow: "hidden", WebkitMaskImage: "linear-gradient(180deg,#000 78%,transparent)", maskImage: "linear-gradient(180deg,#000 78%,transparent)" }}>
              {shown.map((l, i) => (
                <div key={i} style={{ display: "flex", gap: 9, color: termColor[l.c] }}>
                  <span style={{ flex: "none", width: 10, color: l.c === "block" ? "#ff6b6b" : l.c === "ok" ? ACC : l.c === "cmd" ? "rgba(255,255,255,0.4)" : "rgba(255,255,255,0.18)" }}>
                    {l.c === "block" ? "✕" : l.c === "ok" ? "✓" : l.c === "cmd" ? "›" : "·"}
                  </span>
                  <span style={{ whiteSpace: "pre-wrap" }}>{l.s}</span>
                </div>
              ))}
              {shown.length < term.length && <span style={{ display: "inline-block", width: 7, height: 14, background: "rgba(255,255,255,0.6)", opacity: caretOn ? 0.75 : 0, marginLeft: 19 }} />}
            </div>
            <div style={{ borderTop: "1px solid rgba(255,255,255,0.07)", padding: "9px 20px", display: "flex", alignItems: "center", gap: 16 }}>
              {[["scope", "fs.read · shell.exec · net.none", "rgba(255,255,255,0.6)"], ["blocked", "1", RED], ["receipt", t > 0.85 ? "signed" : "pending", t > 0.85 ? ACC : "rgba(255,255,255,0.4)"]].map(([k, v, col]) => (
                <span key={k} style={{ display: "flex", alignItems: "center", gap: 5, fontFamily: "var(--font-mono)", fontSize: 10.5 }}>
                  <span style={{ color: "rgba(255,255,255,0.3)" }}>{k}</span><span style={{ color: col }}>{v}</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===================== feature row ===================== */
function RsFeatureRow({ eyebrow, heading, body, link, diagram, flip }) {
  return (
    <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "3rem 3.25rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem", alignItems: "center" }}>
      <div style={{ order: flip ? 2 : 1 }}>
        <span style={{ display: "inline-block", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: ACC, marginBottom: "0.875rem" }}>{eyebrow}</span>
        <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.625rem", letterSpacing: "-0.02em", lineHeight: 1.12, margin: 0, color: INK }}>{heading}</h3>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5, maxWidth: "42ch" }}>{body}</p>
        {link && <div style={{ marginTop: "1.5rem" }}><RsLink href={link[1]}>{link[0]}</RsLink></div>}
      </div>
      <div style={{ order: flip ? 1 : 2, display: "flex", justifyContent: "center" }}>{diagram}</div>
    </div>
  );
}

/* ---- scope / tool authority panel ---- */
function ScopeDiagram() {
  const t = rsClock(6000);
  const pulse = (Math.sin(t * Math.PI * 2 * 2) + 1) / 2;
  const tools = [
    ["fs.read", true, "Read files in /src"],
    ["shell.exec", true, "Run the test suite"],
    ["fs.write", false, "Write outside /src"],
    ["net.outbound", false, "External network"],
    ["secrets.vault", false, "Read raw secrets"],
  ];
  return (
    <div style={{ width: "100%", maxWidth: 380, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 14, overflow: "hidden", boxShadow: "var(--shadow-sm)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "14px 18px", borderBottom: `0.5px solid ${HAIR}` }}>
        <span style={{ color: INK }}>{rsIcon(SHIELD + " M9.5 12 L11 13.5 L14.5 10")}</span>
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: INK }}>Tool authority · 9f2c1</span>
        <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: ACC, boxShadow: `0 0 0 ${3 + pulse * 5}px color-mix(in srgb, ${ACC} 22%, transparent)` }} />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: ACC }}>active</span>
        </span>
      </div>
      <div style={{ padding: "6px 0" }}>
        {tools.map(([name, allowed, desc]) => (
          <div key={name} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 18px" }}>
            <span style={{ width: 18, height: 18, borderRadius: "50%", flex: "none", background: allowed ? ACC : RED, display: "grid", placeItems: "center" }}>
              {allowed
                ? <svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
                : <svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M3 3 L9 9 M9 3 L3 9" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" /></svg>}
            </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: INK, width: 108, flex: "none" }}>{name}</span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--color-grey-700)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---- policy enforcement log ---- */
function ViolationsDiagram() {
  const t = rsClock(7000);
  const events = [
    { at: 0.08, blocked: true, text: "net.outbound → registry.evil.sh", scope: "net.none" },
    { at: 0.22, blocked: false, text: "fs.read ← src/payment.ts", scope: "fs.read" },
    { at: 0.36, blocked: true, text: "secrets.read ← .env", scope: "not granted" },
    { at: 0.50, blocked: false, text: "shell.exec → npm test", scope: "shell.exec" },
    { at: 0.64, blocked: false, text: "fs.read ← tests/payment.test.ts", scope: "fs.read" },
    { at: 0.78, blocked: true, text: "net.outbound → api.github.com", scope: "net.none" },
  ];
  const shown = events.filter((e) => t >= e.at);
  return (
    <div style={{ width: "100%", maxWidth: 380, background: "#0d0d10", border: "0.5px solid rgba(255,255,255,0.1)", borderRadius: 14, overflow: "hidden", boxShadow: "var(--shadow-md)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "13px 18px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "rgba(255,255,255,0.7)" }}>Policy enforcement log</span>
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10.5, color: RED }}>{shown.filter((e) => e.blocked).length} blocked</span>
      </div>
      <div style={{ padding: "6px 0", fontFamily: "var(--font-mono)", fontSize: 12, WebkitMaskImage: "linear-gradient(180deg,#000 65%,transparent)", maskImage: "linear-gradient(180deg,#000 65%,transparent)", minHeight: 180 }}>
        {shown.map((e, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 18px" }}>
            <span style={{ width: 14, height: 14, borderRadius: "50%", flex: "none", background: e.blocked ? RED : ACC, display: "grid", placeItems: "center" }}>
              {e.blocked
                ? <svg width="8" height="8" viewBox="0 0 12 12" fill="none"><path d="M3 3 L9 9 M9 3 L3 9" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" /></svg>
                : <svg width="8" height="8" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>}
            </span>
            <span style={{ color: e.blocked ? "rgba(255,107,107,0.9)" : "rgba(255,255,255,0.55)", flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{e.text}</span>
            <span style={{ color: e.blocked ? "#ff6b6b" : ACC, opacity: 0.75, flex: "none" }}>{e.scope}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---- session receipt ---- */
function ReceiptDiagram() {
  const entries = [
    ["started", "session 9f2c1 · scope fs.read, shell.exec"],
    ["read", "src/payment.ts · src/resolvers/*.ts"],
    ["exec", "npm test · 243 passed"],
    ["blocked", "net.outbound × 2 (policy enforced)"],
    ["signed", "receipt sealed · IOI L1"],
  ];
  return (
    <div style={{ width: "100%", maxWidth: 380, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 14, boxShadow: "var(--shadow-sm)", padding: "20px 22px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
        <span style={{ color: ACC }}>{rsIcon(SHIELD + " M9.5 12 L11 13.5 L14.5 10")}</span>
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 15, fontWeight: 600, color: INK }}>Session receipt</span>
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10.5, color: ACC, border: `0.5px solid ${ACC}`, borderRadius: 5, padding: "2px 7px" }}>verifiable</span>
      </div>
      <div style={{ position: "relative", paddingLeft: 18 }}>
        <span style={{ position: "absolute", left: 4, top: 6, bottom: 6, width: 1, background: HAIR }} />
        {entries.map(([verb, detail], i) => (
          <div key={i} style={{ display: "flex", gap: 10, padding: "7px 0", position: "relative" }}>
            <span style={{ position: "absolute", left: -18, top: 10, width: 9, height: 9, borderRadius: "50%", background: i === entries.length - 1 ? ACC : verb === "blocked" ? RED : "var(--color-white)", border: `1.5px solid ${i === entries.length - 1 ? ACC : verb === "blocked" ? RED : "var(--color-grey-600)"}` }} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: verb === "blocked" ? RED : verb === "signed" ? ACC : INK, width: 52, flex: "none" }}>{verb}</span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-grey-800)", lineHeight: 1.4 }}>{detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ===================== page ===================== */
function RsHero() {
  return (
    <section style={{ ...rswrap, paddingTop: "5rem" }}>
      <div style={{ textAlign: "center", maxWidth: "42rem", margin: "0 auto 3.75rem" }}>
        <RsEyebrow color={ACC}>Solutions · Runtime AI security</RsEyebrow>
        <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.75rem", lineHeight: 1.03, letterSpacing: "-0.02em", margin: "1.25rem 0 0", color: INK }}>
          Give agents autonomy,<br />the kernel keeps control
        </h1>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.5 }}>
          Hypervisor enforces security policy at the runtime level — inside your VPC. Control what agents can execute, access, connect to, and read from memory. Every action receipted.
        </p>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "2rem" }}>
          <RsButton iconRight={<span>→</span>}>Get started</RsButton>
          <RsButton variant="outline">Request early access</RsButton>
        </div>
      </div>
      <AppMockup />
    </section>
  );
}

function RsKernelSection() {
  return (
    <section style={{ ...rswrap, paddingTop: "8rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "0.9fr 1.1fr", gap: "4rem", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: 0, color: INK }}>
            Enforces policy at the kernel level
          </h2>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.55, maxWidth: "44ch" }}>
            Hypervisor enforces policy within the kernel, with infrastructure running inside your VPC. You control what agents can execute, access, connect to, and read from memory.
          </p>
          <div style={{ marginTop: "1.75rem" }}><RsLink href="platform.html">Read the technical deep-dive</RsLink></div>
        </div>
        <ScopeDiagram />
      </div>
    </section>
  );
}

function RsFeatures() {
  return (
    <section style={{ ...rswrap, paddingTop: "6rem", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <RsFeatureRow
        eyebrow="Policy enforcement"
        heading="Every call is a request, not a grant"
        body="Tool calls don't inherit permissions. Each action is evaluated against the session's declared scope — blocked, allowed, and logged at the kernel level before it executes."
        flip={false}
        diagram={<ViolationsDiagram />}
      />
      <RsFeatureRow
        eyebrow="Audit"
        heading="A receipt for every action"
        body="Every session produces a verifiable receipt — what was read, executed, blocked, and approved — logged, traceable, and sealed on IOI L1. Compliance without configuration."
        link={["See the receipt format", "platform.html"]}
        flip={true}
        diagram={<ReceiptDiagram />}
      />
    </section>
  );
}

function RsStats() {
  const stats = [
    ["0", "Data left on shared infrastructure"],
    ["100%", "Actions logged before execution"],
    ["<1ms", "Policy evaluation overhead"],
  ];
  return (
    <section style={{ ...rswrap, paddingTop: "6rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem" }}>
        {stats.map(([value, label]) => (
          <div key={label} style={{ background: "var(--color-porcelain-grey)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "2.25rem 2rem" }}>
            <div style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", lineHeight: 1, letterSpacing: "-0.02em", color: INK }}>{value}</div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-700)", marginTop: "0.625rem" }}>{label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function RsCTA() {
  return (
    <section style={{ ...rswrap, paddingTop: "8rem", textAlign: "center" }}>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0, color: INK }}>Deploy under your policy</h2>
      <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", maxWidth: "44ch", margin: "1rem auto 0" }}>Hypervisor deploys inside your VPC. Bring your models, your secrets store, and your policies.</p>
      <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}>
        <RsButton iconRight={<span>→</span>}>Get started</RsButton>
        <RsLink href="solutions.html">Back to solutions</RsLink>
      </div>
    </section>
  );
}

function HvPage() {
  return (
    <main>
      <RsHero />
      <RsKernelSection />
      <RsFeatures />
      <RsStats />
      <RsCTA />
    </main>
  );
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
