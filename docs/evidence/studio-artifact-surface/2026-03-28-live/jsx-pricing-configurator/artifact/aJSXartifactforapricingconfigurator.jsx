import React, { useMemo, useState } from "react";

const tiers = {
  starter: { base: 1843, seat: 18, usage: 0.12 },
  growth: { base: 4243, seat: 15, usage: 0.10 },
  scale: { base: 7443, seat: 11, usage: 0.07 },
};

export default function Artifact() {
  const [tier, setTier] = useState("growth");
  const [seats, setSeats] = useState(96);
  const [usage, setUsage] = useState(18000);
  const [annual, setAnnual] = useState(true);
  const current = tiers[tier];
  const monthly = useMemo(() => current.base + seats * current.seat + usage * current.usage, [current, seats, usage]);
  const total = annual ? monthly * 0.9 : monthly;

  return (
    <main style={shell}>
      <section style={layout}>
        <article style={panel}>
          <p style={eyebrow}>JSX artifact</p>
          <h1 style={headline}>Configure a pricing configurator pricing before finance review.</h1>
          <p style={copy}>This interactive surface stays grounded in the request by exposing the variables a reviewer would actually adjust.</p>

          <label style={field}>
            <span>Tier</span>
            <select value={tier} onChange={(event) => setTier(event.target.value)} style={control}>
              <option value="starter">Starter</option>
              <option value="growth">Growth</option>
              <option value="scale">Scale</option>
            </select>
          </label>

          <label style={field}>
            <span>Seats: {seats}</span>
            <input type="range" min="20" max="400" step="5" value={seats} onChange={(event) => setSeats(Number(event.target.value))} />
          </label>

          <label style={field}>
            <span>Usage: {usage.toLocaleString()}</span>
            <input type="range" min="2000" max="52000" step="1000" value={usage} onChange={(event) => setUsage(Number(event.target.value))} />
          </label>

          <label style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <input type="checkbox" checked={annual} onChange={(event) => setAnnual(event.target.checked)} />
            <span>Apply annual commitment</span>
          </label>
        </article>

        <aside style={summaryPanel}>
          <p style={eyebrow}>Live summary</p>
          <h2 style={{ margin: 0, fontSize: 28 }}>Estimated monthly run rate</h2>
          <strong style={{ fontSize: 54, lineHeight: 1 }}>${Math.round(total).toLocaleString()}</strong>
          <Metric label="Base platform" value={current.base} />
          <Metric label="Seat extension" value={seats * current.seat} />
          <Metric label="Usage cost" value={usage * current.usage} />
          <button type="button" style={primaryButton}>Send for review</button>
          <button type="button" style={secondaryButton}>Export assumptions</button>
        </aside>
      </section>
    </main>
  );
}

function Metric({ label, value }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, color: "rgba(236,243,255,0.78)" }}>
      <span>{label}</span>
      <strong>${Math.round(value).toLocaleString()}</strong>
    </div>
  );
}

const shell = { minHeight: "100vh", padding: 32, background: "linear-gradient(180deg, #07111d, #0d1f35)", color: "#ecf3ff", fontFamily: "\"IBM Plex Sans\", \"Inter\", system-ui, sans-serif" };
const layout = { display: "grid", gridTemplateColumns: "minmax(0,1.08fr) minmax(320px,0.92fr)", gap: 24 };
const panel = { borderRadius: 24, padding: 28, background: "rgba(8, 18, 33, 0.82)", border: "1px solid rgba(139,219,255,0.14)", display: "grid", gap: 18 };
const summaryPanel = { ...panel, background: "linear-gradient(180deg, rgba(18,39,66,0.95), rgba(9,18,31,0.98))" };
const eyebrow = { margin: 0, letterSpacing: "0.22em", textTransform: "uppercase", color: "#8bdbff", fontSize: 12 };
const headline = { margin: 0, fontSize: 48, lineHeight: 0.96 };
const copy = { margin: 0, color: "rgba(236,243,255,0.72)", lineHeight: 1.7 };
const field = { display: "grid", gap: 8 };
const control = { borderRadius: 14, border: "1px solid rgba(139,219,255,0.16)", padding: "0.9rem 1rem", background: "rgba(7,15,27,0.94)", color: "#ecf3ff", font: "inherit" };
const primaryButton = { borderRadius: 999, border: 0, padding: "0.95rem 1.2rem", background: "linear-gradient(90deg, #8bdbff, #64f2c5)", color: "#07111d", fontWeight: 700, cursor: "pointer" };
const secondaryButton = { ...primaryButton, background: "transparent", border: "1px solid rgba(139,219,255,0.16)", color: "#ecf3ff" };
