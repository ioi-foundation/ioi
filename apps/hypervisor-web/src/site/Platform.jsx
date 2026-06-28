const React = window.React;
// hypervisor.com — Platform page.
const PNS = window.IoiDesignSystem;
const { Button: PgButton, Badge: PgBadge, Card: PgCard, TextLink: PgLink, Eyebrow: PgEyebrow } = PNS;
const pwrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

function GreenCheck() {
  return <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0 }}><path d="M3 8.5l3.2 3.2L13 5" stroke="var(--color-link-green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}

function PgHero({ eyebrow, title, sub, cta = true }) {
  return (
    <section style={{ ...pwrap, paddingTop: "4rem", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
      <PgEyebrow color="var(--color-link-green)">{eyebrow}</PgEyebrow>
      <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.5rem", lineHeight: 1.05, letterSpacing: "-0.02em", margin: "1.25rem 0 0", maxWidth: "20ch", color: "var(--color-onyx-black)" }}>{title}</h1>
      <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", maxWidth: "52ch", lineHeight: 1.5 }}>{sub}</p>
      {cta && <div style={{ display: "flex", gap: "0.5rem", marginTop: "2rem" }}><PgButton iconRight={<span>→</span>}>Get started</PgButton><PgButton variant="outline">Request a demo</PgButton></div>}
    </section>
  );
}

function SectionHead({ eyebrow, title, sub }) {
  return (
    <div style={{ maxWidth: "44rem" }}>
      <PgEyebrow>{eyebrow}</PgEyebrow>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: "1rem 0 0" }}>{title}</h2>
      {sub && <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", lineHeight: 1.5 }}>{sub}</p>}
    </div>
  );
}

const HvLogoMark = PNS.Logo;

// ---- premium hero visual: nine surfaces binding to one Core ----
function CoreConstellation() {
  const ring = [
    { label: "Clients", sub: "App · Web · CLI", x: "50%", y: "13%", tx: "-50%", ty: "0" },
    { label: "Builder kits", sub: "SDK · ADK · ODK", x: "12%", y: "82%", tx: "0", ty: "-100%" },
    { label: "Gateways & substrate", sub: "MCP · OS · Embodied", x: "88%", y: "82%", tx: "-100%", ty: "-100%" },
  ];
  return (
    <div style={{ position: "relative", aspectRatio: "1.04 / 1", borderRadius: "var(--radius-card)", overflow: "hidden", background: "radial-gradient(125% 120% at 50% 42%, #161a26 0%, #0c0e17 52%, #08090f 100%)" }}>
      <div style={{ position: "absolute", inset: 0, opacity: 0.85, WebkitMaskImage: "radial-gradient(120% 110% at 50% 48%, transparent 22%, #000 64%)", maskImage: "radial-gradient(120% 110% at 50% 48%, transparent 22%, #000 64%)" }} aria-hidden="true">
        {window.HvDepthField
          ? <window.HvDepthField seed={6} />
          : <window.HvDots inverse interactive cover cols={15} rows={14} gap={30} seed={6} />}
      </div>
      {/* connectors */}
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }} aria-hidden="true">
        <line x1="50" y1="48" x2="50" y2="20" stroke="rgba(255,255,255,0.14)" strokeWidth="0.4" />
        <line x1="50" y1="48" x2="20" y2="76" stroke="rgba(255,255,255,0.14)" strokeWidth="0.4" />
        <line x1="50" y1="48" x2="80" y2="76" stroke="rgba(255,255,255,0.14)" strokeWidth="0.4" />
      </svg>
      {/* center Core — the volumetric mark */}
      <div style={{ position: "absolute", left: "50%", top: "48%", transform: "translate(-50%,-50%)", display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
        {window.HvOcta
          ? <window.HvOcta size={132} />
          : <div style={{ width: 76, height: 76, borderRadius: "50%", border: "1px solid rgba(255,255,255,0.18)", display: "grid", placeItems: "center", background: "rgba(255,255,255,0.03)" }}><span style={{ color: "#fff", display: "inline-flex" }}><HvLogoMark size={34} /></span></div>}
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-pistachio-green)" }}>Hypervisor Core</span>
      </div>
      {/* orbiting role groups */}
      {ring.map((r) => (
        <div key={r.label} style={{ position: "absolute", left: r.x, top: r.y, transform: `translate(${r.tx}, ${r.ty})`, display: "flex", flexDirection: "column", gap: 3, alignItems: "center", padding: "9px 13px", borderRadius: "var(--radius-lg)", border: "1px solid rgba(255,255,255,0.16)", background: "rgba(8,9,15,0.72)", backdropFilter: "blur(3px)", WebkitBackdropFilter: "blur(3px)", whiteSpace: "nowrap" }}>
          <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: "#fff" }}>{r.label}</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.04em", color: "rgba(255,255,255,0.5)" }}>{r.sub}</span>
        </div>
      ))}
    </div>
  );
}

// ---- soft-glow marketing visual for a platform product ----
function ProductVisual({ kind, name }) {
  const wrap = { width: "100%", aspectRatio: "1.25 / 1", borderRadius: 22, position: "relative", overflow: "hidden", display: "grid", placeItems: "center" };

  if (kind === "app") {
    return (
      <div style={{ ...wrap, background: "radial-gradient(120% 110% at 50% 0%, #1a1a20, #0c0c0f)" }}>
        <div style={{ position: "absolute", inset: "16% 12%", borderRadius: 14, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.09)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, padding: 24 }}>
          <span style={{ color: "rgba(255,255,255,0.7)" }}><HvLogoMark size={22} /></span>
          <div style={{ width: "82%", height: 52, borderRadius: 11, background: "#161619", border: "1px solid rgba(255,255,255,0.1)" }} />
          <div style={{ display: "flex", gap: 8 }}>
            {[60, 44, 84].map((w, i) => <span key={i} style={{ width: w, height: 26, borderRadius: 999, background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)" }} />)}
          </div>
        </div>
      </div>
    );
  }
  if (kind === "web") {
    return (
      <div style={{ ...wrap, background: "linear-gradient(150deg, color-mix(in srgb, var(--color-pistachio-green) 50%, var(--color-white)), var(--color-porcelain-grey))" }}>
        <div style={{ position: "absolute", inset: "15% 12%", borderRadius: 14, background: "#0c0c0f", boxShadow: "0 24px 50px rgba(0,0,0,0.25)", overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "11px 14px", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
            {["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => <span key={i} style={{ width: 9, height: 9, borderRadius: "50%", background: c }} />)}
            <span style={{ marginLeft: 8, width: "55%", height: 16, borderRadius: 6, background: "rgba(255,255,255,0.07)" }} />
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 13, height: "78%" }}>
            <span style={{ color: "rgba(255,255,255,0.7)" }}><HvLogoMark size={20} /></span>
            <div style={{ width: "70%", height: 40, borderRadius: 10, background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)" }} />
          </div>
        </div>
      </div>
    );
  }
  if (kind === "cli") {
    return (
      <div style={{ ...wrap, background: "radial-gradient(120% 110% at 50% 0%, #14181a, #0c0c0f)" }}>
        <div style={{ position: "absolute", inset: "16% 12%", borderRadius: 12, background: "#0c0c0f", border: "1px solid rgba(255,255,255,0.1)", boxShadow: "0 24px 50px rgba(0,0,0,0.3)", padding: "16px 18px", fontFamily: "var(--font-mono)", fontSize: 11.5, lineHeight: 2.1 }}>
          <div style={{ color: "rgba(255,255,255,0.85)" }}><span style={{ color: "rgba(255,255,255,0.35)" }}>$ </span>hv run "patch every CVE"</div>
          <div style={{ color: "var(--color-link-green)" }}>✓ session 9f2c1 · scoped</div>
          <div style={{ color: "rgba(255,255,255,0.5)" }}>· 210 repos · 187 PRs opened</div>
          <div style={{ color: "#ff6b6b" }}>✕ net.outbound blocked</div>
          <div style={{ color: "var(--color-link-green)" }}>✓ receipts signed</div>
        </div>
      </div>
    );
  }
  if (kind === "glow") {
    return (
      <div style={{ ...wrap, background: "radial-gradient(circle at 50% 48%, #1d2a45 0%, #10131f 45%, #0a0a0d 100%)" }}>
        <span style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "1.875rem", color: "#fff", letterSpacing: "-0.01em", textShadow: "0 0 28px rgba(120,170,255,0.55), 0 0 60px rgba(120,170,255,0.3)" }}>{name}</span>
      </div>
    );
  }
  // light gradient
  return (
    <div style={{ ...wrap, background: "linear-gradient(150deg, color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white)), color-mix(in srgb, var(--color-link-green) 18%, var(--color-white)) 60%, var(--color-porcelain-grey))" }}>
      <span style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "1.875rem", color: "var(--color-onyx-black)", letterSpacing: "-0.01em" }}>{name}</span>
    </div>
  );
}

function ProductRow({ name, role, desc, visual, flip, file }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4.5rem", alignItems: "center" }}>
      <div style={{ order: flip ? 2 : 1 }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-link-green)" }}>{role}</span>
        <h3 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.05, margin: "0.875rem 0 0", color: "var(--color-onyx-black)" }}>
          <a href={file} style={{ color: "inherit", textDecoration: "none" }}>{name}</a>
        </h3>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.55, maxWidth: "40ch" }}>{desc}</p>
        <div style={{ marginTop: "1.5rem" }}><PgLink href={file}>Explore {name}</PgLink></div>
      </div>
      <a href={file} style={{ order: flip ? 1 : 2, textDecoration: "none", color: "inherit", display: "block" }}>{visual}</a>
    </div>
  );
}

const FAMILIES = [
  ["Clients", "Operate the substrate", [
    ["Hypervisor App", "Desktop · command center", "Start governed sessions, run automations, and supervise agents across projects, tools, and models — local-first.", "hv-app.html"],
    ["Hypervisor Web", "Browser · team client", "Shared projects, remote sessions, approvals, and run history for the whole team — without changing runtime truth.", "hv-web.html"],
    ["Hypervisor CLI", "Terminal · scripting · CI", "Script and supervise autonomous work from CI, shells, and servers with the same authority and receipts as the app.", "hv-cli.html"],
  ]],
  ["Builder kits", "Extend and embed it", [
    ["Hypervisor SDK", "Protocol library", "Integrate Hypervisor into products and agents without reimplementing runtime, authority, receipt, or state.", "hv-sdk.html"],
    ["Hypervisor ADK", "Autonomous-system kit", "Compose workers, harnesses, evals, and manifests into governed, deployable autonomous-system bundles.", "hv-adk.html"],
    ["Hypervisor ODK", "Ontology-aware kit", "Compile domain ontologies and data recipes into generated surfaces, domain apps, and marketplace packs.", "hv-odk.html"],
  ]],
  ["Gateways & substrate", "Carry it outward and down to the metal", [
    ["Hypervisor MCP", "Scoped external gateway", "Expose selected capabilities to external agents through revocable, auditable MCP profiles — never a master key.", "hv-mcp.html"],
    ["HypervisorOS", "Bare-metal node profile", "Run governed private agent compute on measured nodes — containers and microVMs under kernel-level policy.", "hv-os.html"],
    ["Embodied Runtime", "Physical autonomy profile", "Operate robot fleets, devices, sensors, and command queues under safety gates with attributed operator handoff.", "hv-embodied.html"],
  ]],
];


const ENVS = [
  ["Local machines", "Your laptop or workstation, under a local daemon."],
  ["Cloud & VPC", "Hosted runtime or your own VPC — same substrate, your perimeter."],
  ["cTEE private workspace", "Plaintext-free custody; protected data never enters provider memory."],
  ["DePIN & provider nodes", "Akash compute, Filecoin storage, TEE-verified nodes — routed, receipted."],
];

// ---- Reference layout: orients rather than converts ----
function RefFamilyMap() {
  return (
    <section style={{ ...pwrap, paddingTop: "5rem" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: "0.875rem", marginBottom: "2.5rem" }}>
        <PgEyebrow>The product map</PgEyebrow>
        <span style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-700)" }}>Nine products · three roles · one Core</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "3.5rem" }}>
        {FAMILIES.map(([family, note, items], fi) => (
          <div key={family}>
            <div style={{ display: "flex", alignItems: "baseline", gap: "0.875rem", paddingBottom: "1.25rem", borderBottom: "1px solid var(--color-grey-500)" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-link-green)" }}>{family}</span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-700)" }}>{note}</span>
            </div>
            <div className="hv-pm-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem", marginTop: "1.5rem" }}>
              {items.map(([name, role, desc, file], i) => (
                <a key={name} href={file} className="hv-pmcard" style={{ position: "relative", display: "flex", flexDirection: "column", background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-card)", padding: "1.75rem", textDecoration: "none", color: "inherit" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>{role}</span>
                    <span className="hv-pmarrow" style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: "var(--color-link-green)", opacity: 0, transform: "translateX(-4px)", transition: "opacity 200ms cubic-bezier(0.22,1,0.36,1), transform 200ms cubic-bezier(0.22,1,0.36,1)" }}>→</span>
                  </div>
                  <h3 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "1.625rem", letterSpacing: "-0.02em", lineHeight: 1.1, margin: "0.75rem 0 0", color: "var(--color-onyx-black)" }}>{name}</h3>
                  <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.75rem", lineHeight: 1.5 }}>{desc}</p>
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function ChipGlyph() {
  return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none" stroke="var(--color-onyx-black)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="11" y="11" width="18" height="18" rx="2.5" />
      <rect x="16.5" y="16.5" width="7" height="7" rx="1" />
      <path d="M16 11 V7 M24 11 V7 M16 33 V29 M24 33 V29 M11 16 H7 M11 24 H7 M33 16 H29 M33 24 H29" />
    </svg>
  );
}
function StackGlyph() {
  return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none" stroke="var(--color-onyx-black)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="8" y="23" width="24" height="8" rx="2" />
      <rect x="14" y="13" width="12" height="8" rx="2" />
      <path d="M20 23 V21" />
    </svg>
  );
}
function PgLineage() {
  const foundation = [
    { tag: "Type 2", sub: "Hosted", virt: "operating systems", ex: "VMware · VirtualBox · Parallels", glyph: <StackGlyph /> },
    { tag: "Type 1", sub: "Bare metal", virt: "hardware", ex: "ESXi · Xen · KVM", glyph: <ChipGlyph /> },
  ];
  return (
    <section style={{ ...pwrap, paddingTop: "5.5rem" }}>
      <div style={{ maxWidth: "46rem" }}>
        <PgEyebrow color="var(--color-link-green)">The third hypervisor layer</PgEyebrow>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: "1rem 0 0" }}>
          A new layer in the hypervisor lineage
        </h2>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1rem", maxWidth: "60ch", lineHeight: 1.55 }}>
          Type&nbsp;1 virtualized hardware. Type&nbsp;2 virtualized operating systems. Hypervisor virtualizes autonomy — isolating, scheduling, supervising, and governing autonomous workers across machines, models, tools, and providers.
        </p>
      </div>

      {/* Stacked lineage — the third layer caps and overhangs the substrate it governs */}
      <div style={{ marginTop: "2.75rem" }}>
        {/* Cap: the third layer, full width, sitting above */}
        <div style={{ position: "relative", zIndex: 2, border: "1px solid var(--color-onyx-black)", borderRadius: "var(--radius-card)", background: "color-mix(in srgb, var(--color-pistachio-green) 24%, var(--color-white))", boxShadow: "var(--shadow-md)", padding: "1.625rem 1.875rem", display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <span style={{ width: 56, height: 56, borderRadius: 15, background: "var(--color-white)", border: "1px solid var(--color-onyx-black)", display: "grid", placeItems: "center", color: "var(--color-link-green)", flex: "none" }}><HvLogoMark size={32} /></span>
          <div style={{ flex: "none" }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--color-link-green)" }}>The third layer · Hypervisor</div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.375rem", letterSpacing: "-0.015em", color: "var(--color-onyx-black)", marginTop: 5 }}>Virtualizes <strong style={{ fontWeight: 700 }}>autonomy</strong></div>
          </div>
          <div style={{ marginLeft: "auto", textAlign: "right", maxWidth: "34ch" }}>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", margin: 0, lineHeight: 1.45 }}>Governs above any machine, model, or provider — and still provisions and isolates the layers beneath it.</p>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--color-grey-700)", marginTop: 8 }}>machines · models · tools · providers</div>
          </div>
        </div>

        {/* Connector caption */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, padding: "0.9rem 0" }}>
          <span style={{ width: 1, height: 18, background: "var(--color-grey-500)" }} />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>rests on &amp; governs the substrate below</span>
          <span style={{ width: 1, height: 18, background: "var(--color-grey-500)" }} />
        </div>

        {/* Foundation: the two classic types, inset so the cap overhangs them */}
        <div style={{ width: "90%", margin: "0 auto", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          {foundation.map((c) => (
            <div key={c.tag} style={{ display: "flex", alignItems: "center", gap: "1.25rem", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-card)", background: "var(--color-porcelain-grey)", padding: "1.125rem 1.5rem", flexWrap: "wrap" }}>
              <span style={{ width: 46, height: 46, borderRadius: 12, background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", display: "grid", placeItems: "center", flex: "none" }}>
                <span style={{ transform: "scale(0.78)" }}>{c.glyph}</span>
              </span>
              <div style={{ minWidth: 168, flex: "none" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>{c.tag} · {c.sub}</span>
              </div>
              <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.125rem", letterSpacing: "-0.015em", color: "var(--color-onyx-black)" }}>Virtualizes <strong style={{ fontWeight: 700 }}>{c.virt}</strong></div>
              <div style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--color-grey-700)" }}>{c.ex}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ marginTop: "2.5rem", paddingTop: "1.75rem", borderTop: "1px solid var(--color-onyx-black)" }}>
        <p style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "1.875rem", letterSpacing: "-0.015em", lineHeight: 1.2, margin: 0, color: "var(--color-onyx-black)", maxWidth: "32ch" }}>
          It doesn&rsquo;t replace Type&nbsp;1 or Type&nbsp;2 — it governs above them.
        </p>
      </div>
    </section>
  );
}

function LifecycleOrbit() {
  const stages = [
    ["Build", "Compose workflows, train workers in Foundry, and wire tools, models, and connectors into governed pipelines."],
    ["Run & scale", "Execute sessions across local machines, cloud, VPC, cTEE, and DePIN compute — one substrate, any provider."],
    ["Govern", "Authority is explicit. Tool calls are requests, not grants. Scope every credential; gate every consequential action."],
    ["Observe & verify", "Logs become receipts. Inspect runs, replay deterministically, and carry proof of what happened."],
    ["Optimize", "Route work through Mixture of Workers. Improve via prompts, retrieval, policy, adapters, or fine-tuning."],
    ["Package & trade", "Ship workers and services as deployable, benchmarked packages. Settle completed machine labor on IOI L1."],
  ];
  const N = stages.length;
  const ACC = "var(--color-link-green)";
  const MAXW = 760, ARH = 620 / 760;
  const geoOf = (w, h) => ({ cx: w * 0.5, cy: h * 0.5, R: w * 0.305 });
  const nodeAngle = (i) => -Math.PI / 2 + i * (2 * Math.PI / N);

  const [active, setActive] = React.useState(0);
  const [box, setBox] = React.useState({ w: MAXW, h: MAXW * ARH });
  // center copy crossfade: fade out → swap → fade in (decoupled from the canvas frame loop)
  const [disp, setDisp] = React.useState(0);
  const [vis, setVis] = React.useState(true);
  React.useEffect(() => {
    if (disp === active) return;
    setVis(false);
    const t = setTimeout(() => { setDisp(active); setVis(true); }, 280);
    return () => clearTimeout(t);
  }, [active]);
  const { cx, cy, R } = geoOf(box.w, box.h);

  const wrapRef = React.useRef(null);
  const canvasRef = React.useRef(null);
  const pausedRef = React.useRef(false);
  const activeRef = React.useRef(0);
  const stRef = React.useRef({ stepF: 0, stepTarget: 0, nextAdv: 0, last: 0, trail: [], colors: null, geo: null });

  // resolve CSS custom-prop colors to rgb triplets the canvas can blend with alpha
  React.useEffect(() => {
    const probe = (cssColor) => {
      const el = document.createElement("span");
      el.style.cssText = "position:absolute;visibility:hidden;color:" + cssColor;
      document.body.appendChild(el);
      const m = getComputedStyle(el).color.match(/[\d.]+/g) || [0, 0, 0];
      document.body.removeChild(el);
      return [Math.round(+m[0]), Math.round(+m[1]), Math.round(+m[2])];
    };
    stRef.current.colors = {
      green: probe("var(--color-link-green)"),
      pist: probe("var(--color-pistachio-green)"),
      hair: probe("var(--color-grey-500)"),
      white: probe("var(--color-white)"),
    };
  }, []);

  // fit to container
  React.useEffect(() => {
    const fit = () => { if (wrapRef.current) { const w = Math.min(wrapRef.current.clientWidth, MAXW); setBox((p) => Math.abs(p.w - w) < 0.5 ? p : { w, h: w * ARH }); } };
    fit();
    const ro = new ResizeObserver(fit); if (wrapRef.current) ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  // size the backing store + run the animation loop
  React.useEffect(() => {
    const cv = canvasRef.current; if (!cv) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.width = Math.round(box.w * dpr); cv.height = Math.round(box.h * dpr);
    const ctx = cv.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const st = stRef.current; st.geo = geoOf(box.w, box.h);
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const DWELL = 3600, TWO = Math.PI * 2, SP = TWO / N;
    const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
    const setA = (i) => { if (i !== activeRef.current) { activeRef.current = i; setActive(i); } };
    st.nextAdv = performance.now() + DWELL; st.last = 0;
    let raf;

    const draw = (ts) => {
      const C = st.colors; const { cx, cy, R } = st.geo; const w = box.w, h = box.h;
      ctx.clearRect(0, 0, w, h);
      if (!C) { raf = requestAnimationFrame(draw); return; }

      // advance + ease (clockwise, monotonic)
      if (!pausedRef.current && ts > st.nextAdv) { st.stepTarget += 1; st.nextAdv = ts + DWELL; }
      const dt = st.last ? Math.min(ts - st.last, 60) : 16; st.last = ts;
      st.stepF += (st.stepTarget - st.stepF) * (1 - Math.exp(-dt / 300));
      const headA = nodeAngle(0) + st.stepF * SP;
      const hx = cx + R * Math.cos(headA), hy = cy + R * Math.sin(headA);
      setA(((Math.round(st.stepF) % N) + N) % N);

      // faint hub spokes — everything binds to the core
      ctx.lineWidth = 1;
      for (let i = 0; i < N; i++) { const a = nodeAngle(i); ctx.strokeStyle = rgba(C.hair, 0.14); ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + R * Math.cos(a), cy + R * Math.sin(a)); ctx.stroke(); }

      // track rail + slowly drifting dotted ring (the system's dotted identity)
      ctx.strokeStyle = rgba(C.hair, 0.72); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, TWO); ctx.stroke();
      ctx.save(); ctx.setLineDash([0.5, 6]); ctx.lineCap = "round"; ctx.lineDashOffset = -(ts / 130); ctx.strokeStyle = rgba(C.hair, 0.42);
      ctx.beginPath(); ctx.arc(cx, cy, R - 11, 0, TWO); ctx.stroke(); ctx.restore();

      // tapered hairline tracer (no glow — a clean ink stroke that thins to nothing)
      st.trail.push([hx, hy]); if (st.trail.length > 22) st.trail.shift();
      ctx.lineCap = "round";
      for (let i = 1; i < st.trail.length; i++) { const t = i / st.trail.length; ctx.strokeStyle = rgba(C.green, 0.85 * t); ctx.lineWidth = 0.5 + 1.4 * t; ctx.beginPath(); ctx.moveTo(st.trail[i - 1][0], st.trail[i - 1][1]); ctx.lineTo(st.trail[i][0], st.trail[i][1]); ctx.stroke(); }

      // node marks — quiet neutral seats; the single tracer head is the only accent
      for (let i = 0; i < N; i++) {
        const a = nodeAngle(i), nx = cx + R * Math.cos(a), ny = cy + R * Math.sin(a);
        ctx.beginPath(); ctx.arc(nx, ny, 3, 0, TWO); ctx.fillStyle = rgba(C.white, 1); ctx.fill();
        ctx.lineWidth = 1; ctx.strokeStyle = rgba(C.hair, 1); ctx.stroke();
      }

      // tracer head — small, crisp, lifted off the rail with a thin ring
      ctx.beginPath(); ctx.arc(hx, hy, 5, 0, TWO); ctx.fillStyle = rgba(C.white, 1); ctx.fill();
      ctx.lineWidth = 1; ctx.strokeStyle = rgba(C.green, 0.9); ctx.stroke();
      ctx.beginPath(); ctx.arc(hx, hy, 2.8, 0, TWO); ctx.fillStyle = rgba(C.green, 1); ctx.fill();

      raf = requestAnimationFrame(draw);
    };

    if (reduce) {
      st.stepF = st.stepTarget;
      const tick = () => { if (!pausedRef.current) { st.stepTarget += 1; st.stepF = st.stepTarget; setA(((st.stepTarget % N) + N) % N); } };
      const id = setInterval(tick, DWELL);
      raf = requestAnimationFrame(draw);
      return () => { clearInterval(id); cancelAnimationFrame(raf); };
    }
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [box.w, box.h]);

  const focusStage = (i) => { pausedRef.current = true; const st = stRef.current; const cur = ((Math.round(st.stepTarget) % N) + N) % N; st.stepTarget = st.stepTarget + ((i - cur + N) % N); };
  const blurStage = () => { pausedRef.current = false; stRef.current.nextAdv = performance.now() + 1400; };
  const labelPos = (i) => { const a = nodeAngle(i), lr = R + box.w * 0.034; return { lx: cx + lr * Math.cos(a), ly: cy + lr * Math.sin(a), c: Math.cos(a), s: Math.sin(a) }; };

  return (
    <div style={{ padding: "0.5rem 2.5rem 3.25rem" }}>
      <div className="hv-lc-ring" ref={wrapRef} style={{ position: "relative", width: "100%" }}>
        <div style={{ position: "relative", width: box.w, height: box.h, margin: "0 auto" }}>
          <canvas ref={canvasRef} style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }} aria-hidden="true" />

          {/* Core medallion + active stage */}
          <div style={{ position: "absolute", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: 312, textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
            <span style={{ width: 46, height: 46, borderRadius: "50%", background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", boxShadow: "var(--shadow-sm)", display: "grid", placeItems: "center", color: ACC }}><HvLogoMark size={23} /></span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--color-grey-600)", marginTop: 10 }}>Hypervisor Core</span>
            <div style={{ marginTop: 16, transition: "opacity 300ms cubic-bezier(0.4, 0, 0.2, 1), transform 300ms cubic-bezier(0.4, 0, 0.2, 1)", opacity: vis ? 1 : 0, transform: vis ? "translateY(0)" : "translateY(3px)" }}>
              <div style={{ display: "flex", alignItems: "baseline", justifyContent: "center", gap: 11 }}>
                <span style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.625rem", lineHeight: 1, letterSpacing: "-0.02em", color: ACC, fontVariantNumeric: "tabular-nums" }}>{String(disp + 1).padStart(2, "0")}</span>
                <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.4375rem", letterSpacing: "-0.02em", margin: 0, color: "var(--color-onyx-black)", whiteSpace: "nowrap" }}>{stages[disp][0]}</h3>
              </div>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", margin: "12px auto 0", maxWidth: "30ch", lineHeight: 1.5, minHeight: "4.4em" }}>{stages[disp][1]}</p>
            </div>
          </div>

          {/* Radial labels (interactive) */}
          {stages.map(([title], i) => {
            const { lx, ly, c, s } = labelPos(i), on = i === active;
            let tx = "-50%", talign = "center";
            if (c > 0.2) { tx = "0"; talign = "left"; } else if (c < -0.2) { tx = "-100%"; talign = "right"; }
            const ty = s > 0.2 ? "0" : (s < -0.2 ? "-100%" : "-50%");
            return (
              <button key={title} type="button" onMouseEnter={() => focusStage(i)} onMouseLeave={blurStage} onFocus={() => focusStage(i)} onBlur={blurStage} aria-label={`Stage ${i + 1}: ${title}`}
                style={{ position: "absolute", left: `${(lx / box.w) * 100}%`, top: `${(ly / box.h) * 100}%`, transform: `translate(${tx}, ${ty})`, textAlign: talign, background: "none", border: "none", padding: 4, margin: -4, cursor: "pointer", font: "inherit", whiteSpace: "nowrap" }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.06em", color: on ? ACC : "var(--color-grey-500)", transition: "color 220ms" }}>{String(i + 1).padStart(2, "0")}</div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", letterSpacing: "-0.015em", marginTop: 2, fontWeight: on ? 600 : 400, color: on ? "var(--color-onyx-black)" : "var(--color-grey-700)", transition: "color 220ms" }}>{title}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Vertical timeline (mobile) */}
      <ol className="hv-lc-list" style={{ display: "none", listStyle: "none", margin: 0, padding: 0, flexDirection: "column" }}>
        {stages.map(([title, body], i) => (
          <li key={title} style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "1rem", paddingBottom: i < N - 1 ? "1.5rem" : 0 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <span style={{ width: 30, height: 30, borderRadius: "50%", display: "grid", placeItems: "center", fontFamily: "var(--font-mono)", fontSize: 12, background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", color: ACC, flex: "none" }}>{String(i + 1).padStart(2, "0")}</span>
              {i < N - 1 && <span style={{ width: 1, flex: 1, marginTop: 6, borderLeft: "1px dashed var(--color-grey-500)" }} />}
            </div>
            <div style={{ paddingTop: 3 }}>
              <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", letterSpacing: "-0.015em", margin: 0, color: "var(--color-onyx-black)" }}>{title}</h3>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", margin: "0.4rem 0 0", lineHeight: 1.45 }}>{body}</p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

function ReferenceBody() {
  return (
    <main>
      {/* Intro — orient, don't convert */}
      <section className="hv-plat-hero" style={{ ...pwrap, paddingTop: "4rem", display: "grid", gridTemplateColumns: "1.02fr 0.98fr", gap: "3.5rem", alignItems: "center" }}>
        <div>
          <PgEyebrow color="var(--color-link-green)">Platform overview</PgEyebrow>
          <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.5rem", lineHeight: 1.04, letterSpacing: "-0.02em", margin: "1.25rem 0 0", maxWidth: "14ch", color: "var(--color-onyx-black)" }}>
            Many surfaces, one truth
          </h1>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.5rem", maxWidth: "46ch", lineHeight: 1.55 }}>
            Hypervisor is one governed substrate for autonomous work. Nine products bind to a single Hypervisor Core — clients operate it, builder kits extend it, gateways carry it outward and down to the metal. None of them owns runtime truth or authority; that stays yours.
          </p>
          <div style={{ display: "flex", alignItems: "center", gap: "1.25rem", marginTop: "1.75rem", flexWrap: "wrap" }}>
            <PgButton iconRight={<span>→</span>}>Get started</PgButton>
            <PgLink href="developers.html">Read the architecture</PgLink>
          </div>
        </div>
        <CoreConstellation />
      </section>

      <PgLineage />

      <RefFamilyMap />

      {/* Run anywhere */}
      <section style={{ ...pwrap, paddingTop: "6rem" }}>
        <SectionHead eyebrow="Run anywhere" title="Edge-in, across any environment" sub="Work starts near your user, device, and data. Only the commitments that need public trust project into settlement." />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "1.25rem", marginTop: "2.5rem" }}>
          {ENVS.map(([t, d]) => (
            <PgCard key={t} tone="subtle" style={{ padding: "1.5rem 1.75rem" }}>
              <h3 style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", margin: 0 }}>{t}</h3>
              <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-800)", marginTop: "0.5rem", lineHeight: 1.45 }}>{d}</p>
            </PgCard>
          ))}
        </div>
      </section>

      {/* Lifecycle — light panel */}
      <section style={{ ...pwrap, paddingTop: "6.5rem" }}>
        <div style={{ background: "var(--color-porcelain-grey)", borderRadius: "var(--radius-card)", overflow: "hidden" }}>
          <div style={{ padding: "3rem 3rem 2.25rem" }}>
            <PgEyebrow color="var(--color-link-green)">One substrate · full lifecycle</PgEyebrow>
            <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", lineHeight: 1.1, letterSpacing: "-0.02em", margin: "1rem 0 0", color: "var(--color-onyx-black)" }}>
              Everything autonomous work needs.<br />
              <span style={{ color: "var(--color-grey-700)" }}>Behind one stable shell, owned by no single vendor.</span>
            </h2>
          </div>
          <LifecycleOrbit />
        </div>
      </section>

      {/* Quiet close */}
      <section style={{ ...pwrap, paddingTop: "6rem" }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: "2rem", flexWrap: "wrap", paddingTop: "2.5rem", borderTop: "1px solid var(--color-grey-500)" }}>
          <div style={{ maxWidth: "40ch" }}>
            <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "1.875rem", letterSpacing: "-0.02em", lineHeight: 1.1, margin: 0, color: "var(--color-onyx-black)" }}>Put autonomous work under authority</h2>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: "var(--color-grey-800)", marginTop: "0.75rem" }}>Start in minutes. Bring your own models, providers, and infrastructure.</p>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}><PgButton iconRight={<span>→</span>}>Get started</PgButton></div>
        </div>
      </section>
    </main>
  );
}

window.HvPage = ReferenceBody;
window.HvPageActive = "Platform";
