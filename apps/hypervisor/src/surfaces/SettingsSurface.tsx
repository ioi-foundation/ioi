import { useEffect, useState } from "react";
import { Badge, Button, Card, Heading, Muted, Row } from "../ui";
import { listPreferences, loadSettingsOwnerProjections, putPreference, type SettingsOwnerProjection } from "../data/productSurface";
import { SurfaceStateFrame } from "./SurfaceStateFrame";

export function SettingsSurface() {
  const [preferences, setPreferences] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(true);
  const [degraded, setDegraded] = useState(false);
  const [receipt, setReceipt] = useState<Record<string, unknown> | null>(null);
  const [ownerProjections, setOwnerProjections] = useState<SettingsOwnerProjection[]>([]);
  useEffect(() => { void listPreferences().then(setPreferences).catch(() => setDegraded(true)).finally(() => setLoading(false)); }, []);
  useEffect(() => { void loadSettingsOwnerProjections().then(setOwnerProjections); }, []);
  const theme = preferences.find((record) => record.preference_id === "theme");
  const saveTheme = async (value: string) => {
    try {
      const result = await putPreference("theme", "theme", { value }, Number(theme?.revision ?? 0));
      setPreferences((current) => [...current.filter((record) => record.preference_id !== "theme"), result.preference]);
      setReceipt(result.receipt);
      document.documentElement.dataset.hypervisorTheme = value;
    } catch { setDegraded(true); }
  };
  return <div className="hv-page" data-testid="surface-settings">
    <header className="hv-page__head"><Row><Heading>Settings</Heading><Badge>core workspace</Badge></Row><Muted>Scoped personal and organization projections. Identity, connectors, providers, governance, billing, memory, and delivery retain their canonical owners.</Muted></header>
    {loading ? <SurfaceStateFrame state="loading" /> : null}{degraded ? <SurfaceStateFrame state="degraded" detail="Durable preferences are unavailable; transient UI state remains local and no successful persistence is claimed." /> : null}
    <div className="hv-settings-grid">
      <Card><h2>Appearance</h2><Muted>Durable principal and organization preference.</Muted><div className="hv-action-row"><Button disabled={loading} onClick={() => void saveTheme("dark-modern")}>Dark</Button><Button disabled={loading} onClick={() => void saveTheme("light-modern")}>Light</Button></div></Card>
      {ownerProjections.map((projection) => <Card key={projection.key}><Row><h2>{projection.label}</h2><Badge tone={projection.state === "ready" ? "success" : "warning"}>{projection.state}</Badge></Row><Muted>{projection.summary}. Canonical owner: {projection.owner}. Settings stores no copy of that owner truth.</Muted><code>{projection.endpoint}</code></Card>)}
    </div>
    {receipt ? <SurfaceStateFrame state="completed" detail={`Preference revision ${String(receipt.revision)} persisted with a state-root-bound mutation receipt.`} /> : null}
  </div>;
}
