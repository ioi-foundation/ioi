const React = window.React;
// hypervisor.com — Docs (Mintlify-style, IOI copy) with search + Ask Assistant.
const DkNS = window.IoiDesignSystem;
const { Button: DkButton, Wordmark: DkWordmark } = DkNS;

const NAV = [
  ["Get Started", [["Overview", true], ["Quickstart", false], ["Architecture map", false], ["Changelog", false]]],
  ["Foundations", [["Web4 & the IOI stack", false], ["Verifiable bounded agency", false], ["Mixture of Workers", false], ["Worker training lifecycle", false], ["Domain ontologies & data recipes", false], ["Common objects & envelopes", false]]],
  ["Runtime", [["Hypervisor Daemon", false], ["Agentgres", false], ["wallet.network", false], ["HarnessProfiles", false], ["HypervisorOS", false]]],
  ["Clients & SDK", [["Hypervisor App / Web", false], ["CLI & TUI", false], ["SDK reference", false], ["ADK", false], ["Adapter targets", false]]],
  ["Domains", [["aiagent.xyz marketplace", false], ["sas.xyz services", false], ["ioi.ai outcomes", false], ["Hypervisor Foundry", false]]],
  ["Operate", [["Providers & environments", false], ["Private workspace & cTEE", false], ["Policy & approvals", false], ["Settlement on IOI L1", false]]],
  ["Conformance", [["CIRC — intent resolution", false], ["CEC — completion evidence", false], ["Events, receipts & replay", false]]],
];

const TOC = [["the-boundary", "The execution boundary"], ["not-is", "What Hypervisor is"], ["the-stack", "The stack"], ["authority", "Authority is explicit"], ["lifecycle", "The worker lifecycle"], ["whats-included", "What you get"], ["next", "Next steps"]];

const SEARCH_RESULTS = [
  ["Quickstart", "Get Started", "Install the daemon and delegate your first task"],
  ["How receipts work", "Runtime", "Logs become receipts — legible, replayable evidence"],
  ["prim:* vs scope:*", "Foundations", "Primitive execution capability vs authority scope"],
  ["Deploy in your VPC", "Operate", "Run the substrate inside your own perimeter"],
  ["Mixture of Workers", "Foundations", "Routing consequential labor across bounded workers"],
];

const SUGGESTIONS = ["How do receipts work?", "What's the difference between a prim and a scope?", "How do I deploy in my own VPC?", "Quickstart for the CLI"];

/* ---------------- Topbar ---------------- */
function DocsTopbar({ onSearch, onAssistant, assistantOpen }) {
  const [tip, setTip] = React.useState(false);
  return (
    <header style={{ position: "sticky", top: 0, zIndex: 30, background: "rgba(255,255,255,0.85)", backdropFilter: "saturate(180%) blur(12px)", WebkitBackdropFilter: "saturate(180%) blur(12px)", borderBottom: "0.5px solid var(--color-grey-500)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "1rem", height: 64, padding: "0 1.5rem" }}>
        <a href="index.html" style={{ display: "flex", color: "var(--color-onyx-black)", textDecoration: "none" }}><DkWordmark height={24} /></a>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-grey-700)", border: "0.5px solid var(--color-grey-500)", borderRadius: 6, padding: "3px 8px" }}>docs</span>
        <button onClick={onSearch} style={{ marginLeft: "0.75rem", flex: "1 1 auto", maxWidth: 540, display: "flex", alignItems: "center", gap: 8, height: 38, padding: "0 12px", borderRadius: "var(--radius-lg)", border: "1px solid var(--color-grey-500)", background: "var(--color-white)", cursor: "text", color: "var(--color-grey-700)", fontFamily: "var(--font-sans)", fontSize: 14 }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></svg>
          <span style={{ flex: 1, textAlign: "left" }}>Search or ask, e.g., 'Configure SSO'</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, border: "0.5px solid var(--color-grey-500)", borderRadius: 5, padding: "2px 6px" }}>⌘K</span>
        </button>
        <div style={{ position: "relative" }} onMouseEnter={() => setTip(true)} onMouseLeave={() => setTip(false)}>
          <button onClick={onAssistant} style={{ display: "inline-flex", alignItems: "center", gap: 7, height: 38, padding: "0 13px", borderRadius: "var(--radius-lg)", border: assistantOpen ? "1px solid var(--color-grey-600)" : "1px solid var(--color-grey-500)", background: assistantOpen ? "var(--color-grey-400)" : "var(--color-white)", cursor: "pointer", fontFamily: "var(--font-sans)", fontSize: 14, whiteSpace: "nowrap", flexShrink: 0, color: "var(--color-grey-900)" }}>
            <span style={{ color: "var(--color-link-green)", display: "inline-flex" }}><Sparkle /></span>
            Ask Assistant
          </button>
          {tip && (
            <div style={{ position: "absolute", top: "calc(100% + 8px)", left: "50%", transform: "translateX(-50%)", whiteSpace: "nowrap", background: "var(--color-onyx-black)", color: "#fff", fontFamily: "var(--font-sans)", fontSize: 12.5, padding: "7px 11px", borderRadius: 8, display: "flex", alignItems: "center", gap: 7, boxShadow: "var(--shadow-md)" }}>
              Toggle assistant panel
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, background: "rgba(255,255,255,0.15)", borderRadius: 4, padding: "2px 5px" }}>⌘ I</span>
            </div>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "1.125rem", marginLeft: "auto" }}>
          <a href="#" onClick={(e) => e.preventDefault()} style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-grey-800)", textDecoration: "none" }}>Sign in</a>
          <DkButton size="sm">Get started</DkButton>
          <button aria-label="Toggle theme" style={{ width: 30, height: 30, display: "flex", alignItems: "center", justifyContent: "center", border: "none", background: "transparent", cursor: "pointer", color: "var(--color-grey-700)" }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"><path d="M14 8.6A5.4 5.4 0 1 1 7.4 2a4.2 4.2 0 0 0 6.6 6.6Z" /></svg>
          </button>
        </div>
      </div>
    </header>
  );
}

function Sparkle({ animate }) {
  return (
    <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={animate ? "hv-sparkle-anim" : undefined} style={{ transformOrigin: "center" }}>
      <path d="M5.66 2.99L4.4 2.57L3.97 1.31C3.84 0.9 3.16 0.9 3.02 1.31L2.6 2.57L1.34 2.99C1.14 3.06 1 3.25 1 3.46C1 3.68 1.14 3.87 1.34 3.94L2.6 4.36L3.02 5.62C3.09 5.83 3.28 5.96 3.5 5.96C3.71 5.96 3.91 5.83 3.97 5.62L4.4 4.36L5.66 3.94C5.86 3.87 6 3.68 6 3.46C6 3.25 5.86 3.06 5.66 2.99Z" fill="currentColor" stroke="none" />
      <path d="M9.5 2.75L11.41 7.59L16.25 9.5L11.41 11.41L9.5 16.25L7.59 11.41L2.75 9.5L7.59 7.59L9.5 2.75Z" />
    </svg>
  );
}

/* ---------------- Search modal ---------------- */
function SearchModal({ onClose }) {
  const [q, setQ] = React.useState("");
  const ref = React.useRef(null);
  React.useEffect(() => { if (ref.current) ref.current.focus(); }, []);
  const results = SEARCH_RESULTS.filter((r) => (r[0] + r[2]).toLowerCase().includes(q.toLowerCase()));
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 60, background: "rgba(10,14,25,0.32)", display: "flex", justifyContent: "center", alignItems: "flex-start", paddingTop: "10vh" }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: "min(620px, 92vw)", background: "var(--color-white)", borderRadius: "var(--radius-card)", border: "0.5px solid var(--color-grey-500)", boxShadow: "var(--shadow-lg)", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "1rem 1.25rem", borderBottom: "0.5px solid var(--color-grey-500)" }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-grey-700)" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></svg>
          <input ref={ref} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search or ask a question…" style={{ flex: 1, border: "none", outline: "none", background: "transparent", fontFamily: "var(--font-sans)", fontSize: 16, color: "var(--color-onyx-black)" }} />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)", border: "0.5px solid var(--color-grey-500)", borderRadius: 5, padding: "2px 6px" }}>esc</span>
        </div>
        <div style={{ padding: "0.5rem", maxHeight: "48vh", overflowY: "auto" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-grey-700)", padding: "0.5rem 0.75rem" }}>{q ? "Results" : "Popular"}</div>
          {results.map((r) => (
            <a key={r[0]} href="#" onClick={(e) => e.preventDefault()} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 12px", borderRadius: "var(--radius-lg)", textDecoration: "none" }} onMouseEnter={(e) => (e.currentTarget.style.background = "var(--color-grey-400)")} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-link-green)", border: "0.5px solid var(--color-grey-500)", borderRadius: 5, padding: "3px 7px", flexShrink: 0 }}>{r[1]}</span>
              <span style={{ minWidth: 0 }}>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-onyx-black)" }}>{r[0]}</div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-grey-800)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r[2]}</div>
              </span>
            </a>
          ))}
          {!results.length && <div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-grey-700)", padding: "1.5rem 0.75rem", textAlign: "center" }}>No matches. Try Ask Assistant for a written answer.</div>}
        </div>
      </div>
    </div>
  );
}

/* ---------------- Assistant panel ---------------- */
function AssistantPanel({ onClose }) {
  const [msgs, setMsgs] = React.useState([]);
  const [draft, setDraft] = React.useState("");
  const ask = (text) => {
    const t = (text || draft).trim();
    if (!t) return;
    const answer = "Authority in Hypervisor is explicit: prim:* says what the runtime may execute, scope:* says what a wallet or tenant authorizes. Tool calls are requests, not grants — every consequential effect is brokered by wallet.network, receipted by Agentgres, and replayable. See Authority is explicit and the wallet.network doctrine.";
    setMsgs((m) => [...m, { role: "user", text: t }, { role: "assistant", text: answer }]);
    setDraft("");
  };
  return (
    <aside style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: 380, maxWidth: "92vw", zIndex: 50, background: "var(--color-white)", borderLeft: "0.5px solid var(--color-grey-500)", boxShadow: "var(--shadow-lg)", display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, height: 64, flexShrink: 0, boxSizing: "border-box", padding: "0 1.25rem", borderBottom: "0.5px solid var(--color-grey-500)" }}>
        <span style={{ color: "var(--color-link-green)" }}><Sparkle /></span>
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 15, fontWeight: 700, color: "var(--color-onyx-black)" }}>Ask Assistant</span>
        <button onClick={onClose} aria-label="Close" style={{ marginLeft: "auto", width: 28, height: 28, display: "flex", alignItems: "center", justifyContent: "center", border: "none", background: "transparent", cursor: "pointer", color: "var(--color-grey-700)", borderRadius: 6 }}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M4 4l8 8M12 4l-8 8" /></svg>
        </button>
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: "1.25rem" }}>
        {msgs.length === 0 ? (
          <>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-grey-800)", lineHeight: 1.55, margin: "0 0 1.25rem" }}>Ask anything about Hypervisor — the runtime, the authority model, the SDK, or settlement. Answers cite the docs.</p>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-grey-700)", marginBottom: "0.75rem" }}>Suggested</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => ask(s)} style={{ textAlign: "left", fontFamily: "var(--font-sans)", fontSize: 13.5, color: "var(--color-onyx-black)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-lg)", padding: "10px 12px", background: "var(--color-white)", cursor: "pointer" }}>{s}</button>
              ))}
            </div>
          </>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {msgs.map((m, i) => m.role === "user" ? (
              <div key={i} style={{ alignSelf: "flex-end", maxWidth: "85%", background: "var(--color-grey-400)", borderRadius: "12px 12px 3px 12px", padding: "8px 12px", fontFamily: "var(--font-sans)", fontSize: 13.5, color: "var(--color-onyx-black)", lineHeight: 1.45 }}>{m.text}</div>
            ) : (
              <div key={i} style={{ display: "flex", gap: 9 }}>
                <span style={{ color: "var(--color-link-green)", flexShrink: 0, marginTop: 1 }}><Sparkle /></span>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: "var(--color-grey-900)", lineHeight: 1.55 }}>{m.text}</div>
              </div>
            ))}
          </div>
        )}
      </div>
      <div style={{ padding: "0.875rem 1rem 1.125rem", borderTop: "0.5px solid var(--color-grey-500)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, border: "1px solid var(--color-grey-500)", borderRadius: "var(--radius-lg)", padding: "0 8px 0 12px", background: "var(--color-white)" }}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") ask(); }} placeholder="Ask a question…" style={{ flex: 1, height: 40, border: "none", outline: "none", background: "transparent", fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-onyx-black)" }} />
          <button onClick={() => ask()} aria-label="Send" style={{ width: 30, height: 30, display: "flex", alignItems: "center", justifyContent: "center", border: "none", borderRadius: 6, background: draft.trim() ? "var(--color-onyx-black)" : "var(--color-grey-400)", color: draft.trim() ? "#fff" : "var(--color-grey-700)", cursor: draft.trim() ? "pointer" : "default" }}>
            <svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M8 13V3M8 3l-4 4M8 3l4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </button>
        </div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", marginTop: 8, textAlign: "center" }}>Answers are generated and cite the docs.</div>
      </div>
    </aside>
  );
}

/* ---------------- Sidebar ---------------- */
function Sidebar() {
  return (
    <nav style={{ width: 280, flexShrink: 0, position: "sticky", top: 64, alignSelf: "flex-start", height: "calc(100vh - 64px)", overflowY: "auto", padding: "2rem 1rem 4rem 1.5rem" }}>
      {NAV.map(([group, items]) => (
        <div key={group} style={{ marginBottom: "1.75rem" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-grey-700)", padding: "0 0 0 0.75rem", marginBottom: "0.625rem" }}>{group}</div>
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 1 }}>
            {items.map(([label, active]) => (
              <li key={label}>
                <a href="#" onClick={(e) => e.preventDefault()} style={{ display: "block", fontFamily: "var(--font-sans)", fontSize: 14, lineHeight: 1.3, textDecoration: "none", padding: "6px 12px", borderRadius: "var(--radius-lg)", background: active ? "var(--color-pistachio-green)" : "transparent", color: active ? "var(--color-moss-green)" : "var(--color-grey-800)", fontWeight: active ? 500 : 400 }}>{label}</a>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function H2({ id, children }) {
  return <h2 id={id} style={{ fontFamily: "var(--font-sans)", fontSize: "1.5rem", letterSpacing: "-0.015em", margin: "2.75rem 0 1rem", scrollMarginTop: 84 }}>{children}</h2>;
}
function P({ children }) {
  return <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", lineHeight: 1.65, color: "var(--color-grey-900)", margin: "0 0 1.25rem" }}>{children}</p>;
}
function Code({ children }) {
  return <code style={{ fontFamily: "var(--font-mono)", fontSize: "0.9em", background: "var(--color-grey-400)", padding: "1px 6px", borderRadius: 4 }}>{children}</code>;
}

/* ---------------- Content ---------------- */
function Content() {
  const doctrine = ["Hypervisor Daemon executes.", "wallet.network authorizes.", "Agentgres remembers.", "Storage backends preserve bytes.", "MoW routes.", "IOI L1 settles.", "Clients compose.", "Evidence proves."];
  const notIs = [
    ["A chatbot", "Execution-boundary alignment & verifiable bounded agency"],
    ["A model marketplace", "Worker routing through receipts and benchmarks"],
    ["A wallet bolted to an LLM", "Authority-scoped credentials and approvals"],
    ["A workflow toy", "Canonical operational state and replay"],
    ["A chain with AI bolted on", "Settlement for completed machine labor"],
  ];
  const lifecycle = ["Intent", "Task decomposition", "Worker selection", "Capability & policy check", "Execution", "Verification", "ContributionReceipts", "Settlement"];
  const included = [
    ["Governed sessions", "Run workers across local, cloud, VPC, cTEE, and DePIN compute under one authority model."],
    ["Receipts & replay", "Every consequential action emits legible, replayable evidence — accountability by default."],
    ["Bring your own models", "Mount any model as a cognition backend. Workers are installed as accountable actors."],
    ["Workflow Compositor", "Shape directed workflows, step contracts, review points, and reusable templates."],
    ["Foundry training", "Turn workflows, traces, and corrections into deployable specialist workers."],
    ["No plaintext custody", "cTEE private workspaces keep protected data out of provider-rooted memory."],
  ];
  return (
    <article style={{ flex: 1, minWidth: 0, maxWidth: "46rem", padding: "2.5rem 3rem 6rem" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-grey-700)" }}>
        <span>Get Started</span><span>/</span><span style={{ color: "var(--color-grey-900)" }}>Overview</span>
      </div>
      <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", lineHeight: 1.05, margin: "1rem 0 0", color: "var(--color-onyx-black)" }}>What is Hypervisor</h1>
      <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.25rem", lineHeight: 1.55, color: "var(--color-grey-800)", margin: "1.25rem 0 0" }}>
        Hypervisor is the open operating environment for autonomous systems — build, run, govern, verify, improve, package, and trade autonomous work across any machine, model, or provider, without surrendering runtime truth or authority to one vendor.
      </p>

      <H2 id="the-boundary">The execution boundary</H2>
      <P>Autonomous software is beginning to operate browsers, files, APIs, wallets, credentials, models, tools, and other workers. Traditional cybersecurity protects systems from malicious software. Hypervisor protects systems from authorized-but-unbounded autonomous software.</P>
      <P>Most agent frameworks give a model tools. Hypervisor gives autonomous work a deterministic execution boundary: every consequential action is canonicalized, policy-checked, authority-scoped, approval-gated when necessary, receipted, replayable, and settleable.</P>
      <div style={{ background: "var(--color-pistachio-green)", borderRadius: "var(--radius-lg)", padding: "1rem 1.25rem", margin: "0 0 1.5rem", display: "flex", gap: 12 }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", color: "var(--color-moss-green)", paddingTop: 2 }}>NOTE</span>
        <span style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: "var(--color-moss-green)", lineHeight: 1.5 }}>The model can be fuzzy. The consequences cannot.</span>
      </div>

      <H2 id="not-is">What Hypervisor is</H2>
      <div style={{ border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-lg)", overflow: "hidden", margin: "0 0 1.5rem" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", background: "var(--color-grey-400)", borderBottom: "0.5px solid var(--color-grey-500)" }}>
          <div style={{ padding: "10px 16px", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", color: "var(--color-grey-700)" }}>NOT</div>
          <div style={{ padding: "10px 16px", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", color: "var(--color-link-green)", borderLeft: "0.5px solid var(--color-grey-500)" }}>IS</div>
        </div>
        {notIs.map((r, i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", borderBottom: i < notIs.length - 1 ? "0.5px solid var(--color-grey-500)" : "none" }}>
            <div style={{ padding: "13px 16px", fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-grey-700)" }}>{r[0]}</div>
            <div style={{ padding: "13px 16px", fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-onyx-black)", borderLeft: "0.5px solid var(--color-grey-500)" }}>{r[1]}</div>
          </div>
        ))}
      </div>

      <H2 id="the-stack">The stack</H2>
      <P>The stack is edge-in. Work starts near the user, device, data, and runtime boundary, then projects only the commitments that need public trust into settlement.</P>
      <div style={{ background: "var(--color-onyx-black)", borderRadius: "var(--radius-lg)", padding: "1.25rem 1.5rem", margin: "0 0 1.5rem" }}>
        {doctrine.map((l, i) => {
          const idx = l.lastIndexOf(" ");
          return <div key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: 1.95, color: "var(--color-grey-600)" }}><span style={{ color: "#fff" }}>{l.slice(0, idx)}</span> {l.slice(idx + 1)}</div>;
        })}
      </div>

      <H2 id="authority">Authority is explicit</H2>
      <P><Code>prim:*</Code> describes what the runtime may execute; <Code>scope:*</Code> describes what a wallet, provider, user, or tenant may authorize. Tool calls are requests, not grants — raw model output is never authority for consequential action, and credentials are never cognition.</P>
      <div style={{ background: "var(--color-onyx-black)", borderRadius: "var(--radius-lg)", padding: "1.25rem 1.5rem", margin: "0 0 1.5rem" }}>
        <pre style={{ margin: 0, fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: 1.7, color: "var(--color-grey-600)", whiteSpace: "pre-wrap" }}>{`hv run "patch CVE-2026-1188" \\
  --scope prim:fs.write,scope:repo.write \\
  --gate on-push --receipt --replay`}</pre>
      </div>

      <H2 id="lifecycle">The worker lifecycle</H2>
      <P>The Internet of Intelligence is not a single monolithic model. It is a routed supply chain of specialized, bounded workers. Mixture of Workers routes consequential labor across independently accountable actors.</P>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem 0.625rem", alignItems: "center", margin: "0 0 1.5rem" }}>
        {lifecycle.map((s, i) => (
          <React.Fragment key={s}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-grey-900)", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-md)", padding: "6px 10px" }}>{s}</span>
            {i < lifecycle.length - 1 && <span style={{ color: "var(--color-grey-600)" }}>→</span>}
          </React.Fragment>
        ))}
      </div>

      <H2 id="whats-included">What you get</H2>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", margin: "0.25rem 0 0" }}>
        {included.map(([t, d]) => (
          <div key={t} style={{ border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-lg)", padding: "1.125rem 1.25rem" }}>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", fontWeight: 700, color: "var(--color-onyx-black)" }}>{t}</div>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.875rem", color: "var(--color-grey-800)", margin: "0.5rem 0 0", lineHeight: 1.45 }}>{d}</p>
          </div>
        ))}
      </div>

      <H2 id="next">Next steps</H2>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginTop: "0.5rem" }}>
        {[["Quickstart", "Install the daemon and delegate your first task in 5 minutes."], ["Architecture map", "The source-of-truth index for every runtime subject."], ["SDK reference", "Drive runs and read receipts from your own tools."], ["Conformance", "CIRC and CEC — the invariants every runtime upholds."]].map(([t, d]) => (
          <a key={t} href="#" onClick={(e) => e.preventDefault()} style={{ display: "block", textDecoration: "none", border: "0.5px solid var(--color-grey-500)", borderRadius: "var(--radius-lg)", padding: "1.25rem 1.5rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", fontWeight: 700, color: "var(--color-onyx-black)" }}>{t}</span>
              <span style={{ color: "var(--color-link-green)" }}>→</span>
            </div>
            <p style={{ fontFamily: "var(--font-sans)", fontSize: "0.875rem", color: "var(--color-grey-800)", margin: "0.5rem 0 0", lineHeight: 1.45 }}>{d}</p>
          </a>
        ))}
      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "3.5rem", paddingTop: "1.5rem", borderTop: "0.5px solid var(--color-grey-500)" }}>
        <a href="#" onClick={(e) => e.preventDefault()} style={{ textAlign: "right", textDecoration: "none" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)", letterSpacing: "0.06em" }}>NEXT</div>
          <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-link-green)", marginTop: 4 }}>Quickstart →</div>
        </a>
      </div>
    </article>
  );
}

function Toc() {
  return (
    <aside style={{ width: 220, flexShrink: 0, position: "sticky", top: 64, alignSelf: "flex-start", height: "calc(100vh - 64px)", overflowY: "auto", padding: "2.75rem 1.5rem", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-grey-700)" }}>On this page</div>
      {TOC.map(([id, label], i) => (
        <a key={id} href={`#${id}`} style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: i === 0 ? "var(--color-link-green)" : "var(--color-grey-800)", textDecoration: "none", lineHeight: 1.4 }}>{label}</a>
      ))}
    </aside>
  );
}

function HvDocs() {
  const [search, setSearch] = React.useState(false);
  const [assistant, setAssistant] = React.useState(false);
  React.useEffect(() => {
    const onKey = (e) => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && e.key.toLowerCase() === "k") { e.preventDefault(); setSearch((s) => !s); }
      else if (meta && e.key.toLowerCase() === "i") { e.preventDefault(); setAssistant((a) => !a); }
      else if (e.key === "Escape") { setSearch(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div>
      <div style={{ paddingRight: assistant ? 380 : 0, transition: "padding-right 220ms var(--ease-out)" }}>
        <DocsTopbar onSearch={() => setSearch(true)} onAssistant={() => setAssistant((a) => !a)} assistantOpen={assistant} />
        <div style={{ display: "flex", maxWidth: "90rem", margin: "0 auto", alignItems: "flex-start" }}>
          <Sidebar />
          <div style={{ flex: 1, minWidth: 0, display: "flex", justifyContent: "center", borderLeft: "0.5px solid var(--color-grey-500)", borderRight: "0.5px solid var(--color-grey-500)" }}>
            <Content />
          </div>
          <Toc />
        </div>
      </div>
      {search && <SearchModal onClose={() => setSearch(false)} />}
      {assistant && <AssistantPanel onClose={() => setAssistant(false)} />}
    </div>
  );
}
window.HvDocs = HvDocs;
