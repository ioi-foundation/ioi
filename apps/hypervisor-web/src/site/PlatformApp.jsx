const React = window.React;
// hypervisor.com — faithful recreations of Hypervisor client surfaces
// (App · Web · CLI), used as the Platform page hero showcase.
(function () {
  const NS = window.IoiDesignSystem;
  const AppLogo = NS.Logo;
  const ACC = "var(--color-link-green)";

  const ico = (d, sw) => (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={sw || 1.7} strokeLinecap="round" strokeLinejoin="round">{d}</svg>
  );
  const I = {
    plus: ico(<path d="M12 5 V19 M5 12 H19" />),
    home: ico(<path d="M4 11 L12 4 L20 11 V20 H4 Z M9 20 V14 H15 V20" />),
    projects: ico(<g><rect x="4" y="4" width="7" height="7" rx="1.4" /><rect x="13" y="4" width="7" height="7" rx="1.4" /><rect x="4" y="13" width="7" height="7" rx="1.4" /><rect x="13" y="13" width="7" height="7" rx="1.4" /></g>),
    auto: ico(<g><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M8 10 L11 12.5 L8 15" /><path d="M13 15 H16" /></g>),
    apps: ico(<g><circle cx="6.5" cy="6.5" r="2.4" /><circle cx="17.5" cy="6.5" r="2.4" /><circle cx="6.5" cy="17.5" r="2.4" /><circle cx="17.5" cy="17.5" r="2.4" /></g>),
    sessions: ico(<g><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 9 H21" /><path d="M7 14 L9.5 16.5" /></g>),
    chevR: ico(<path d="M9 6 L15 12 L9 18" />, 2),
    chevD: ico(<path d="M6 9 L12 15 L18 9" />, 2.2),
    gear: ico(<g><circle cx="12" cy="12" r="3.2" /><path d="M12 2 V5 M12 19 V22 M2 12 H5 M19 12 H22 M5 5 L7 7 M17 17 L19 19 M19 5 L17 7 M7 17 L5 19" /></g>),
    sidebar: ico(<g><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4 V20" /></g>),
    send: ico(<path d="M12 19 V5 M6 11 L12 5 L18 11" />, 2),
    target: ico(<g><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 1 V4 M12 20 V23 M1 12 H4 M20 12 H23" /></g>),
    bug: ico(<g><rect x="8" y="9" width="8" height="10" rx="4" /><path d="M12 9 V6 M9 5 L10.5 7 M15 5 L13.5 7 M8 12 H4 M16 12 H20 M8 16 H4.5 M16 16 H19.5 M8 13 L5 11 M16 13 L19 11" /></g>),
    spark: ico(<path d="M12 3 L13.4 9 L19 11 L13.4 13 L12 19 L10.6 13 L5 11 L10.6 9 Z" />, 1.4),
  };

  function useClock(period) {
    const [t, setT] = React.useState(0);
    React.useEffect(() => {
      const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (reduce) { setT(0.5); return; }
      let raf, start = null;
      const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % period) / period)); raf = requestAnimationFrame(tick); };
      raf = requestAnimationFrame(tick);
      return () => cancelAnimationFrame(raf);
    }, []);
    return t;
  }

  function NavItem({ icon, label, active, accent, badge, faint }) {
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "8px 11px", borderRadius: 8, background: active ? "rgba(255,255,255,0.07)" : "transparent", cursor: "pointer" }}>
        {badge
          ? <span style={{ width: 21, height: 21, borderRadius: 6, flex: "none", background: badge, display: "grid", placeItems: "center", fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, color: "#fff" }}>{label[0]}</span>
          : <span style={{ color: active ? "#fff" : "rgba(255,255,255,0.55)", display: "grid", placeItems: "center", flex: "none" }}>{icon}</span>}
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: faint ? "rgba(255,255,255,0.4)" : active || accent ? "#fff" : "rgba(255,255,255,0.7)", fontWeight: accent ? 600 : 400 }}>{label}</span>
      </div>
    );
  }

  // ---- shared command-center body (no outer frame) ----
  function AppBody({ t, compact }) {
    const phrase = "Audit our dependencies and open PRs for every CVE";
    const typeStart = 0.08, typeEnd = 0.4, holdEnd = 0.82;
    let typed = "";
    if (t >= typeStart && t < typeEnd) typed = phrase.slice(0, Math.round(((t - typeStart) / (typeEnd - typeStart)) * phrase.length));
    else if (t >= typeEnd && t < holdEnd) typed = phrase;
    const hasText = typed.length > 0;
    const caretOn = Math.sin(t * Math.PI * 2 * 6) > 0;

    return (
      <div style={{ display: "flex", height: compact ? 540 : 600, background: "#0c0c0f" }}>
        {/* sidebar */}
        <div style={{ width: 248, flex: "none", borderRight: "1px solid rgba(255,255,255,0.07)", display: "flex", flexDirection: "column", padding: "14px 12px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "2px 6px 14px" }}>
            <span style={{ color: "rgba(255,255,255,0.85)" }}><AppLogo size={18} /></span>
            <span style={{ color: "rgba(255,255,255,0.4)" }}>{I.sidebar}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 11px", borderRadius: 9, border: "1px solid rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.03)", cursor: "pointer", marginBottom: 10 }}>
            <span style={{ color: "rgba(255,255,255,0.8)" }}>{I.plus}</span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: "rgba(255,255,255,0.92)" }}>New Session</span>
            <span style={{ marginLeft: "auto", display: "flex", gap: 4 }}>
              {["Ctrl", "O"].map((k) => <span key={k} style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.4)", background: "rgba(255,255,255,0.06)", borderRadius: 4, padding: "2px 5px" }}>{k}</span>)}
            </span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <NavItem icon={I.home} label="Home" active />
            <NavItem icon={I.projects} label="Projects" />
            <NavItem icon={I.auto} label="Automations" />
            <NavItem icon={I.apps} label="Applications" />
          </div>
          <div style={{ height: 1, background: "rgba(255,255,255,0.07)", margin: "14px 6px" }} />
          <div style={{ padding: "2px 11px 8px", display: "flex", alignItems: "center", gap: 9 }}>
            <span style={{ color: "rgba(255,255,255,0.4)" }}>{I.apps}</span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "rgba(255,255,255,0.4)" }}>Applications</span>
          </div>
          <NavItem label="Resource Management" badge="#14a085" accent />
          <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "12px 11px 8px" }}>
            <span style={{ color: "rgba(255,255,255,0.4)" }}>{I.sessions}</span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "rgba(255,255,255,0.4)" }}>Sessions</span>
            <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 11.5, color: "rgba(255,255,255,0.35)" }}>Project</span>
              <span style={{ color: "rgba(255,255,255,0.35)", display: "flex" }}><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M7 4 V20 M7 4 L4.5 6.5 M7 4 L9.5 6.5 M17 20 V4 M17 20 L14.5 17.5 M17 20 L19.5 17.5" /></svg></span>
            </span>
          </div>
          {["lol", "From scratch"].map((label) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 11px", cursor: "pointer" }}>
              <span style={{ color: "rgba(255,255,255,0.4)" }}>{I.chevR}</span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "rgba(255,255,255,0.6)" }}>{label}</span>
            </div>
          ))}
          <div style={{ marginTop: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
            <NavItem icon={I.gear} label="Organization settings" />
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 8px", borderRadius: 9, marginTop: 4 }}>
              <span style={{ width: 28, height: 28, borderRadius: 8, flex: "none", background: "#7c5cff", display: "grid", placeItems: "center", fontFamily: "var(--font-sans)", fontSize: 13, fontWeight: 700, color: "#fff" }}>J</span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.9)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>John Doe's Workspace</div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: 11.5, color: "rgba(255,255,255,0.45)" }}>John Doe</div>
              </div>
              <span style={{ marginLeft: "auto", color: "rgba(255,255,255,0.35)" }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M8 9 L12 5 L16 9 M8 15 L12 19 L16 15" /></svg>
              </span>
            </div>
          </div>
        </div>

        {/* main */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", padding: "58px 52px 0", overflow: "hidden" }}>
          <span style={{ color: "rgba(255,255,255,0.7)", marginBottom: 20 }}><AppLogo size={26} /></span>
          <h2 style={{ fontFamily: "var(--font-sans)", fontSize: "1.9rem", fontWeight: 400, letterSpacing: "-0.02em", color: "#fff", margin: 0, textAlign: "center" }}>What do you want to get done today?</h2>
          <div style={{ width: "100%", maxWidth: 560, marginTop: 34, background: "#161619", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 14, padding: "16px 16px 12px", boxShadow: "0 12px 32px rgba(0,0,0,0.35)" }}>
            <div style={{ minHeight: 54, fontFamily: "var(--font-sans)", fontSize: 14.5, color: hasText ? "rgba(255,255,255,0.92)" : "rgba(255,255,255,0.4)", lineHeight: 1.5 }}>
              {hasText ? typed : "Describe your task or type / for commands"}
              {hasText && <span style={{ opacity: caretOn ? 0.8 : 0, color: ACC }}>▍</span>}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 7, padding: "7px 11px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.12)", fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.7)", cursor: "pointer" }}>
                {I.target}Work in a project {I.chevD}
              </span>
              <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: "rgba(255,255,255,0.5)" }}>{I.plus}</span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "7px 10px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.12)", fontFamily: "var(--font-sans)", fontSize: 12.5, color: "rgba(255,255,255,0.7)", cursor: "pointer" }}>
                  <AppLogo size={13} />5.5 Medium {I.chevD}
                </span>
                <span style={{ width: 34, height: 34, borderRadius: 9, display: "grid", placeItems: "center", background: hasText ? ACC : "rgba(255,255,255,0.1)", color: hasText ? "#fff" : "rgba(255,255,255,0.5)", transition: "background 0.3s" }}>{I.send}</span>
              </span>
            </div>
          </div>
          <div style={{ display: "flex", gap: 12, marginTop: 28, flexWrap: "wrap", justifyContent: "center" }}>
            {[["Automate env setup", null], ["Fix a bug", "#ff6b6b"], ["Boost your test coverage", "#a98bff"]].map(([label, col]) => (
              <span key={label} style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "10px 16px", borderRadius: 999, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.09)", fontFamily: "var(--font-sans)", fontSize: 13, color: "rgba(255,255,255,0.85)", cursor: "pointer" }}>
                {col ? <span style={{ color: col, display: "flex" }}>{label === "Fix a bug" ? I.bug : I.spark}</span> : null}
                {label}
              </span>
            ))}
          </div>
          <div style={{ width: "100%", maxWidth: 560, marginTop: 40 }}>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: "rgba(255,255,255,0.45)", marginBottom: 12 }}>Recent Sessions</div>
            {[["Design Post-Quantum Computing Website", "5d ago"], ["Write Parent Harness Evidence Boundary Doc", "1w ago"]].map(([title, ago]) => (
              <div key={title} style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "9px 0" }}>
                <span style={{ width: 4, height: 4, borderRadius: "50%", background: "rgba(255,255,255,0.35)", marginTop: 7, flex: "none" }} />
                <div>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "rgba(255,255,255,0.88)" }}>{title}</div>
                  <div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "rgba(255,255,255,0.4)", marginTop: 2 }}>{ago}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // ---- CLI / headless terminal view ----
  function CliView({ t }) {
    const caretOn = Math.sin(t * Math.PI * 2 * 6) > 0;
    const lines = [
      { at: 0.04, c: "cmd", s: "hv session start --scope=fs.read,shell.exec,net.none" },
      { at: 0.13, c: "ok", s: "session 9f2c1 ready · scoped credentials issued" },
      { at: 0.22, c: "cmd", s: "hv run \"audit deps and open PRs for every CVE\"" },
      { at: 0.31, c: "log", s: "scanning 210 repositories…" },
      { at: 0.41, c: "log", s: "billing-api    libfoo 1.4.2 → 1.4.7   tests ✓" },
      { at: 0.50, c: "block", s: "BLOCKED net.outbound → registry.evil.sh (net.none)" },
      { at: 0.59, c: "log", s: "web-dashboard  lodash 4.17.19 → 4.17.21 tests ✓" },
      { at: 0.68, c: "log", s: "auth-service   openssl bump          tests ✓" },
      { at: 0.78, c: "ok", s: "187 PRs opened · 1 action blocked · receipts signed" },
      { at: 0.88, c: "cmd", s: "hv session end 9f2c1" },
    ];
    const shown = lines.filter((l) => t >= l.at);
    const col = { cmd: "rgba(255,255,255,0.92)", ok: ACC, log: "rgba(255,255,255,0.58)", block: "#ff6b6b" };
    return (
      <div style={{ height: 600, background: "#0c0c0f", display: "flex", flexDirection: "column" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 18, padding: "0 18px", height: 40, borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "rgba(255,255,255,0.55)" }}>hypervisor — headless · CI runner</span>
          <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)", fontSize: 10.5, color: ACC }}><span style={{ width: 6, height: 6, borderRadius: "50%", background: ACC }} />governed</span>
        </div>
        <div style={{ flex: 1, padding: "22px 26px", fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: 2.05, overflow: "hidden" }}>
          {shown.map((l, i) => (
            <div key={i} style={{ display: "flex", gap: 11, color: col[l.c] }}>
              <span style={{ flex: "none", width: 12, color: l.c === "block" ? "#ff6b6b" : l.c === "ok" ? ACC : l.c === "cmd" ? "rgba(255,255,255,0.35)" : "rgba(255,255,255,0.18)" }}>{l.c === "block" ? "✕" : l.c === "ok" ? "✓" : l.c === "cmd" ? "$" : "·"}</span>
              <span style={{ whiteSpace: "pre-wrap" }}>{l.s}</span>
            </div>
          ))}
          {shown.length < lines.length && <span style={{ display: "inline-block", width: 8, height: 16, background: "rgba(255,255,255,0.6)", opacity: caretOn ? 0.75 : 0, marginLeft: 23 }} />}
        </div>
      </div>
    );
  }

  // ---- surface switcher (App / Web / CLI) ----
  const SURFACES = [
    ["Hypervisor App", "app", "Desktop command center"],
    ["Web", "web", "Browser & team client"],
    ["CLI / Headless", "cli", "Terminal, scripting & CI"],
  ];

  function SurfaceFrame({ kind, t }) {
    if (kind === "cli") {
      return (
        <div style={{ background: "#0c0c0f", borderRadius: 13, overflow: "hidden", boxShadow: "0 40px 90px rgba(0,0,0,0.42), 0 0 0 1px rgba(0,0,0,0.05)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "12px 15px", background: "#161a17", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
            {["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => <span key={i} style={{ width: 11, height: 11, borderRadius: "50%", background: c }} />)}
            <span style={{ margin: "0 auto", fontFamily: "var(--font-mono)", fontSize: 12, color: "rgba(255,255,255,0.3)" }}>zsh — hv</span>
          </div>
          <CliView t={t} />
        </div>
      );
    }
    if (kind === "web") {
      return (
        <div style={{ background: "#0c0c0f", borderRadius: 13, overflow: "hidden", boxShadow: "0 40px 90px rgba(0,0,0,0.42), 0 0 0 1px rgba(0,0,0,0.05)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 14px", background: "#17171c", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
            {["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => <span key={i} style={{ width: 11, height: 11, borderRadius: "50%", background: c }} />)}
            <div style={{ display: "flex", alignItems: "center", gap: 7, marginLeft: 10, background: "#0c0c0f", borderRadius: 7, padding: "5px 14px", border: "1px solid rgba(255,255,255,0.07)", flex: 1, maxWidth: 360 }}>
              <span style={{ color: ACC, display: "flex" }}><AppLogo size={12} /></span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "rgba(255,255,255,0.5)" }}>app.hypervisor.com</span>
            </div>
            <span style={{ marginLeft: "auto", display: "flex", gap: 5 }}>
              {[0, 1, 2].map((i) => <span key={i} style={{ width: 5, height: 5, borderRadius: "50%", background: "rgba(255,255,255,0.25)" }} />)}
            </span>
          </div>
          <AppBody t={t} compact />
        </div>
      );
    }
    // app — desktop window
    return (
      <div style={{ background: "#0c0c0f", borderRadius: 13, overflow: "hidden", boxShadow: "0 40px 90px rgba(0,0,0,0.42), 0 0 0 1px rgba(0,0,0,0.05)" }}>
        <AppBody t={t} />
      </div>
    );
  }

  function PlatformSurfaces() {
    const [active, setActive] = React.useState("app");
    const t = useClock(11000);
    return (
      <div style={{ width: "100%", maxWidth: 1080, margin: "0 auto", position: "relative" }}>
        <div style={{ position: "absolute", inset: "-22px -22px -34px", borderRadius: 26, background: "radial-gradient(120% 120% at 50% 0%, color-mix(in srgb, var(--color-pistachio-green) 34%, var(--color-white)), var(--color-porcelain-grey))", zIndex: 0 }} />
        <div style={{ position: "relative", zIndex: 1 }}>
          {/* segmented control */}
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 22 }}>
            <div style={{ display: "inline-flex", gap: 3, padding: 4, borderRadius: 12, background: "var(--color-white)", border: "0.5px solid var(--color-grey-500)", boxShadow: "var(--shadow-xs)" }}>
              {SURFACES.map(([label, key, sub]) => {
                const on = active === key;
                return (
                  <button key={key} onClick={() => setActive(key)} title={sub} style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 1, padding: "8px 16px", borderRadius: 9, border: "none", cursor: "pointer", background: on ? "var(--color-onyx-black)" : "transparent", transition: "background 0.2s" }}>
                    <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, fontWeight: 500, color: on ? "#fff" : "var(--color-grey-900)" }}>{label}</span>
                    <span style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: on ? "rgba(255,255,255,0.55)" : "var(--color-grey-600)" }}>{sub}</span>
                  </button>
                );
              })}
            </div>
          </div>
          <SurfaceFrame kind={active} t={t} />
        </div>
      </div>
    );
  }

  window.PlatformSurfaces = PlatformSurfaces;
  window.PlatformAppMockup = PlatformSurfaces; // back-comat
})();
