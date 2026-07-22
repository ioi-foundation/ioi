const React = window.React;
// hypervisor.com — shared Platform product subpage template (install-focused).
// Each subpage sets window.HV_CURRENT_SLUG, loads ProductData.jsx + this, and gets window.HvPage.
(function () {
  const PNS = window.IoiDesignSystem;
  const { Button: PgButton, TextLink: PgLink, Eyebrow: PgEyebrow, Logo: PgLogo } = PNS;
  const wrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };
  const INK = "var(--color-onyx-black)";
  const HAIR = "var(--color-grey-500)";
  const ACC = "var(--color-link-green)";

  /* ---------- per-product install meta ---------- */
  const INSTALL = {
    app: { verb: "Install", lines: ["$ brew install --cask hypervisor", "==> Hypervisor.app installed", "$ open -a Hypervisor", "✓ daemon running · workspace ready"] },
    web: { verb: "Open Hypervisor Web", lines: ["> open https://app.hypervisor.com", "✓ signed in · org synced", "· shared projects loaded", "✓ ready — start a session"] },
    cli: { verb: "Install", lines: ["$ curl -fsSL https://get.hypervisor.com | sh", "✓ hv 1.0 installed", "$ hv login", "✓ authenticated · scoped credentials ready"] },
    sdk: { verb: "Install", lines: ["$ npm install @hypervisor/sdk", "added @hypervisor/sdk", "> import { Session } from \"@hypervisor/sdk\"", "✓ runtime primitives ready"] },
    adk: { verb: "Install", lines: ["$ npm install -g @hypervisor/adk", "✓ adk 1.0 installed", "$ hv adk init worker", "✓ manifest · harness · evals scaffolded"] },
    odk: { verb: "Install", lines: ["$ npm install -g @hypervisor/odk", "✓ odk 1.0 installed", "$ hv odk compile ontology.yaml", "✓ surfaces · domain app generated"] },
    mcp: { verb: "Create a profile", lines: ["$ hv mcp profile create reviewer", "✓ profile reviewer · scoped", "$ hv mcp grant --tools=code.read", "✓ revocable lease issued"] },
    daemon: { verb: "Install", lines: ["$ curl -fsSL https://get.hypervisor.com | sh", "✓ hv 1.0 installed · daemon ready", "$ hv daemon status", "✓ runtime truth local · receipts on"] },
    os: { verb: "Read the architecture", lines: ["# design stage — specified in the IOI architecture canon", "· measured boot · attested join · kernel-level policy", "· no HypervisorOS build ships today", "→ track it at internetofintelligence.com/roadmap"] },
    embodied: { verb: "Read the architecture", lines: ["# design stage — the authority model, extended to devices", "· safety gates · command queues · receipted telemetry", "· no Embodied Runtime build ships today", "→ track it at internetofintelligence.com/roadmap"] },
  };

  /* ---------- inverse dot-matrix panel (matches Core band) ---------- */
  /* ---------- faceted panel (interactive, large dark surfaces) ---------- */
  function DotPanel({ seed = 1 }) {
    return (
      <div style={{ position: "absolute", inset: 0, WebkitMaskImage: "radial-gradient(135% 110% at 50% 50%, transparent 28%, #000 66%)", maskImage: "radial-gradient(135% 110% at 50% 50%, transparent 28%, #000 66%)" }} aria-hidden="true">
        {window.HvDepthField
          ? <window.HvDepthField seed={seed} />
          : <window.HvDots inverse interactive cover cols={18} rows={11} gap={34} seed={seed} />}
      </div>
    );
  }

  /* ---------- terminal window ---------- */
  function termLine(str, i) {
    let color = "rgba(255,255,255,0.55)", glyph = null;
    if (str.startsWith("$ ")) { color = "rgba(255,255,255,0.92)"; glyph = <span style={{ color: "rgba(255,255,255,0.35)" }}>$ </span>; str = str.slice(2); }
    else if (str.startsWith("> ")) { color = "#6f9bff"; glyph = <span style={{ color: "rgba(255,255,255,0.35)" }}>{"> "}</span>; str = str.slice(2); }
    else if (str.startsWith("✓")) { color = ACC; }
    else if (str.startsWith("✕")) { color = "#ff6b6b"; }
    else if (str.startsWith("==>")) { color = "rgba(255,255,255,0.45)"; }
    return <div key={i} style={{ color, whiteSpace: "pre-wrap" }}>{glyph}{str}</div>;
  }

  function Terminal({ title, lines, accent }) {
    return (
      <div style={{ background: "#0c0c0f", borderRadius: 13, overflow: "hidden", border: "1px solid rgba(255,255,255,0.1)", boxShadow: "0 40px 90px rgba(0,0,0,0.5)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "12px 15px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
          {["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => <span key={i} style={{ width: 11, height: 11, borderRadius: "50%", background: c }} />)}
          <span style={{ margin: "0 auto", fontFamily: "var(--font-mono)", fontSize: 12, color: "rgba(255,255,255,0.32)" }}>{title}</span>
        </div>
        <div style={{ padding: "20px 24px", fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: 2.05 }}>
          {lines.map((l, i) => termLine(l, i))}
          {accent && <span style={{ display: "inline-block", width: 8, height: 15, background: ACC, marginTop: 4, verticalAlign: "middle", opacity: 0.8 }} />}
        </div>
      </div>
    );
  }

  /* ---------- sections ---------- */
  function Hero({ p, meta }) {
    return (
      <section style={{ paddingTop: "4.5rem" }}>
        <div style={{ ...wrap, textAlign: "center", maxWidth: "44rem" }}>
          <PgEyebrow color={ACC}>Platform · {p.name}{p.status ? ` · ${p.status}` : ""}</PgEyebrow>
          <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.75rem", lineHeight: 1.03, letterSpacing: "-0.025em", margin: "1.25rem 0 0", color: INK }}>{p.name}</h1>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", margin: "1.25rem auto 0", maxWidth: "48ch", lineHeight: 1.5 }}>{p.sub}</p>
          <div style={{ display: "flex", gap: "0.625rem", justifyContent: "center", marginTop: "2.25rem", alignItems: "center" }}>
            <PgButton>{meta.verb}</PgButton>
            <PgLink href="developers.html">Read the docs</PgLink>
          </div>
        </div>
        {/* wide install showcase */}
        <div style={{ ...wrap, marginTop: "3.5rem" }}>
          <div style={{ position: "relative", borderRadius: "26px 26px 0 0", overflow: "hidden", background: "#08080b", padding: "5.5rem 0 0", minHeight: "30rem" }}>
            <DotPanel seed={p.slug.length * 7 + 3} />
            <div style={{ position: "relative", maxWidth: "44rem", margin: "0 auto", padding: "0 2rem" }}>
              <Terminal title={"hypervisor — " + p.slug} lines={meta.lines} accent />
            </div>
          </div>
        </div>
      </section>
    );
  }

  function SectionHead({ eyebrow, title, sub, align = "left" }) {
    return (
      <div style={{ maxWidth: "46rem", textAlign: align, margin: align === "center" ? "0 auto" : undefined }}>
        {eyebrow && <PgEyebrow>{eyebrow}</PgEyebrow>}
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: eyebrow ? "1rem 0 0" : 0, color: INK }}>{title}</h2>
        {sub && <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5 }}>{sub}</p>}
      </div>
    );
  }

  /* ---------- faceted motif (light, static, feature cards) ---------- */
  function DotField({ seed = 0 }) {
    return <window.HvDots cover cols={9} rows={6} gap={26} seed={seed} />;
  }

  function Features({ p }) {
    return (
      <section style={{ ...wrap, paddingTop: "7rem" }}>
        <SectionHead title="Explore the main features" />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem", marginTop: "2.5rem" }}>
          {p.capabilities.map(([title, desc], i) => (
            <div key={title} style={{ display: "flex", flexDirection: "column", background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", overflow: "hidden" }}>
              <div style={{ position: "relative", background: "var(--color-porcelain-grey)", aspectRatio: "1.6 / 1", borderBottom: `0.5px solid ${HAIR}`, overflow: "hidden" }}>
                <div style={{ position: "absolute", inset: "1.75rem", WebkitMaskImage: "radial-gradient(120% 120% at 50% 42%, #000 42%, transparent 80%)", maskImage: "radial-gradient(120% 120% at 50% 42%, #000 42%, transparent 80%)" }}>
                  <DotField seed={p.slug.length * 3 + i * 5} />
                </div>
              </div>
              <div style={{ padding: "1.5rem 1.75rem 1.75rem" }}>
                <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.125rem", letterSpacing: "-0.015em", margin: 0, color: INK }}>{title}</h3>
                <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.625rem", lineHeight: 1.5 }}>{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>
    );
  }

  /* ---------- signature governed-session mock (echoes the home hero panel) ---------- */
  function SessionMock({ p }) {
    const rows = (p.capabilities || []).slice(0, 3).map(([t]) => t);
    const scopes = ["prim:fs.write", "scope:repo", "prim:proc.exec"];
    return (
      <div style={{ position: "relative", background: "var(--color-porcelain-grey)", display: "grid", placeItems: "center", padding: "3rem 2.75rem", overflow: "hidden" }}>
        <div style={{ position: "absolute", inset: 0, opacity: 0.6, WebkitMaskImage: "radial-gradient(120% 115% at 72% 38%, #000 26%, transparent 76%)", maskImage: "radial-gradient(120% 115% at 72% 38%, #000 26%, transparent 76%)" }} aria-hidden="true">
          <window.HvDots cover cols={12} rows={9} gap={30} seed={p.slug.length * 9 + 4} />
        </div>
        <div style={{ position: "relative", width: "100%", maxWidth: "23rem", background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", boxShadow: "var(--shadow-lg)", overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 14px", borderBottom: `0.5px solid ${HAIR}` }}>
            <span style={{ width: 20, height: 20, color: INK, display: "inline-flex" }}><PgLogo size={20} /></span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--color-grey-800)" }}>session · {p.slug}</span>
            <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.04em", color: ACC, border: `0.5px solid color-mix(in srgb, ${ACC} 35%, transparent)`, background: "color-mix(in srgb, var(--color-pistachio-green) 40%, var(--color-white))", borderRadius: 999, padding: "3px 9px" }}>Running</span>
          </div>
          <div style={{ padding: "14px", display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.09em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>Receipts</div>
            {rows.map((r, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 9, border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-lg)", padding: "9px 11px" }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--color-green-600)", flexShrink: 0 }} />
                <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: INK, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r}</span>
                <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", flexShrink: 0 }}>{scopes[i]}</span>
              </div>
            ))}
            <div style={{ display: "flex", alignItems: "center", gap: 9, border: `1px solid ${INK}`, borderRadius: "var(--radius-lg)", padding: "10px 11px", marginTop: 2 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.05em", color: ACC }}>GATE</span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: INK }}>Approve & continue</span>
              <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: 11.5, background: INK, color: "#fff", borderRadius: 6, padding: "3px 9px" }}>Allow</span>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: 11.5, border: `0.5px solid ${HAIR}`, color: "var(--color-grey-800)", borderRadius: 6, padding: "3px 9px" }}>Deny</span>
              </span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  /* ---------- editorial deep-dive band (uses p.detail) ---------- */
  function Detail({ p }) {
    const d = p.detail;
    if (!d) return null;
    const pts = d.points || [];
    return (
      <section style={{ ...wrap, paddingTop: "7rem" }}>
        <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", overflow: "hidden" }}>
          <div className="hv-pd-detail" style={{ display: "grid", gridTemplateColumns: "1.02fr 0.98fr" }}>
            <div style={{ padding: "3rem 3.25rem", borderRight: `0.5px solid ${HAIR}`, display: "flex", flexDirection: "column", justifyContent: "center" }}>
              <PgEyebrow>{d.eyebrow}</PgEyebrow>
              <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.25rem", letterSpacing: "-0.02em", lineHeight: 1.1, margin: "1rem 0 0", color: INK, maxWidth: "18ch" }}>{d.heading}</h2>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.1rem", lineHeight: 1.55, maxWidth: "44ch" }}>{d.sub}</p>
            </div>
            <SessionMock p={p} />
          </div>
          <div className="hv-pd-points" style={{ borderTop: `0.5px solid ${HAIR}`, display: "grid", gridTemplateColumns: "1fr 1fr" }}>
            {pts.map(([t, b], i) => (
              <div key={t} style={{ padding: "2rem 2.25rem", borderRight: i % 2 === 0 ? `0.5px solid ${HAIR}` : "none", borderTop: i >= 2 ? `0.5px solid ${HAIR}` : "none" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.04em", color: ACC }}>{String(i + 1).padStart(2, "0")}</span>
                <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", letterSpacing: "-0.015em", margin: "0.75rem 0 0", color: INK }}>{t}</h3>
                <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.5rem", lineHeight: 1.5 }}>{b}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    );
  }

  /* ---------- specifications strip (uses p.specs) ---------- */
  function Specs({ p }) {
    const specs = p.specs || [];
    if (!specs.length) return null;
    return (
      <section style={{ ...wrap, paddingTop: "7rem" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: "0.875rem", paddingBottom: "1.5rem", borderBottom: `1px solid ${INK}` }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.09em", textTransform: "uppercase", color: ACC }}>At a glance</span>
          <span style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-700)" }}>{p.category}</span>
        </div>
        <div className="hv-pd-specs" style={{ display: "grid", gridTemplateColumns: `repeat(${specs.length}, 1fr)` }}>
          {specs.map(([label, value], i) => (
            <div key={label} style={{ padding: "1.75rem 1.5rem 0", paddingLeft: i ? "1.5rem" : 0, borderLeft: i ? `0.5px solid ${HAIR}` : "none" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>{label}</div>
              <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: INK, marginTop: "0.6rem", lineHeight: 1.35, letterSpacing: "-0.01em" }}>{value}</div>
            </div>
          ))}
        </div>
      </section>
    );
  }

  /* ---------- related products (uses p.related) ---------- */
  function Related({ p }) {
    const rel = (p.related || []).map((slug) => {
      const prod = window.HV_PRODUCT_MAP[slug];
      if (prod) return { name: prod.name, file: prod.file, role: prod.category };
      const ext = window.HV_EXT && window.HV_EXT[slug];
      if (ext) return { name: ext.name, file: ext.file, role: "Solution" };
      return null;
    }).filter(Boolean);
    if (!rel.length) return null;
    return (
      <section style={{ ...wrap, paddingTop: "7rem" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: "0.875rem", marginBottom: "1.75rem" }}>
          <PgEyebrow>Continue across the substrate</PgEyebrow>
          <span style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-700)" }}>Binds to the same Hypervisor Core</span>
        </div>
        <div className="hv-pd-related" style={{ display: "grid", gridTemplateColumns: `repeat(${rel.length}, 1fr)`, gap: "1.25rem" }}>
          {rel.map((r) => (
            <a key={r.file} href={r.file} className="hv-relcard" style={{ display: "flex", flexDirection: "column", gap: "0.75rem", background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "1.75rem", textDecoration: "none", color: "inherit", transition: "border-color 200ms cubic-bezier(0.22,1,0.36,1)" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>{r.role}</span>
              <span style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "1.5rem", letterSpacing: "-0.02em", lineHeight: 1.1, color: INK }}>{r.name}</span>
              <span className="hv-relarrow" style={{ marginTop: "auto", display: "inline-flex", alignItems: "center", gap: 7, fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: ACC }}>Explore <span style={{ transition: "transform 200ms cubic-bezier(0.22,1,0.36,1)", display: "inline-block" }}>→</span></span>
            </a>
          ))}
        </div>
      </section>
    );
  }

  function Quickstart({ p, meta }) {
    const steps = [
      [meta.verb, p.slug === "web" ? "No install — open Hypervisor Web and sign in to your org." : "One command. The runtime is local-first and offline-capable from the start."],
      ["Authorize", "Scope credentials, tools, and spend. Nothing runs outside the grant you give it."],
      ["Run governed work", "Start a session. Every consequential action is approved, receipted, and replayable."],
    ];
    return (
      <section style={{ ...wrap, paddingTop: "7rem" }}>
        <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", overflow: "hidden" }}>
          <div style={{ padding: "2.75rem 3rem 2rem", maxWidth: "46rem" }}>
            <SectionHead eyebrow="Get started" title={"Up and running in minutes"} sub={`${p.name} binds to the same Hypervisor Core as every other surface — it operates runtime truth, it never owns it.`} />
          </div>
          <div style={{ borderTop: `1px solid ${HAIR}`, display: "grid", gridTemplateColumns: "repeat(3, 1fr)" }}>
            {steps.map(([title, body], i) => (
              <div key={title} style={{ padding: "2.25rem 2rem", borderRight: i < 2 ? `1px solid ${HAIR}` : "none" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: ACC }}>{String(i + 1).padStart(2, "0")}</span>
                <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", letterSpacing: "-0.015em", margin: "0.75rem 0 0", color: INK }}>{title}</h3>
                <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.625rem", lineHeight: 1.5 }}>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    );
  }

  function InstallCTA({ p, meta }) {
    return (
      <section style={{ ...wrap, paddingTop: "7rem" }}>
        <div style={{ position: "relative", borderRadius: "var(--radius-card)", overflow: "hidden", background: "#08080b", minHeight: "26rem", display: "flex", alignItems: "center" }}>
          <DotPanel seed={p.slug.length * 5 + 11} />
          <div style={{ position: "relative", padding: "0 4rem", maxWidth: "34rem" }}>
            <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", lineHeight: 1.05, letterSpacing: "-0.02em", margin: 0, color: "#fff" }}>{meta.verb === "Install" ? `Install ${p.name}` : `${meta.verb}`}</h2>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "rgba(255,255,255,0.6)", marginTop: "1rem", lineHeight: 1.5 }}>{p.sub}</p>
            <div style={{ display: "flex", gap: "0.625rem", marginTop: "2rem" }}>
              <PgButton theme="white">{meta.verb}</PgButton>
              <PgButton variant="outline" theme="white" style={{ color: "#fff", borderColor: "rgba(255,255,255,0.45)" }}>Talk to sales</PgButton>
            </div>
          </div>
        </div>
        <div style={{ display: "flex", justifyContent: "center", marginTop: "2.5rem" }}>
          <PgLink href="platform.html">Back to platform</PgLink>
        </div>
      </section>
    );
  }

  function ProductPage() {
    const p = window.HV_PRODUCT_MAP[window.HV_CURRENT_SLUG];
    if (!p) return <div style={{ ...wrap, paddingTop: "6rem" }}>Unknown product.</div>;
    const meta = INSTALL[p.slug] || { verb: "Get started", lines: ["$ hv --help"] };
    return (
      <main>
        <Hero p={p} meta={meta} />
        <Features p={p} />
        <Detail p={p} />
        <Specs p={p} />
        <Quickstart p={p} meta={meta} />
        <Related p={p} />
        <InstallCTA p={p} meta={meta} />
      </main>
    );
  }

  window.HvPage = ProductPage;
})();
