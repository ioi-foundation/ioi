import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Modal, TextInput, Badge, Row } from "../ui";
import { FALLBACK_PROJECTION, type ProductSurfaceProjection } from "../data/productSurface";

export function ApplicationsModal({ projection, onClose }: { projection: ProductSurfaceProjection | null; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const entries = useMemo(() => (projection ?? FALLBACK_PROJECTION).application_entries.filter((entry) => entry.display_name.toLowerCase().includes(query.toLowerCase())), [projection, query]);
  const open = (route: string | null) => { if (route) navigate(route); onClose(); };
  return <Modal title="Applications and commands" onClose={onClose}>
    <TextInput autoFocus data-modal-initial-focus aria-label="Search applications and commands" placeholder="Search the compiled product surface…" value={query} onChange={(event) => setQuery(event.target.value)} />
    <div className="hv-catalog__groups">{entries.map((entry) => <button type="button" className="hv-appcard" key={entry.identity_ref} disabled={!entry.launchable} onClick={() => open(entry.resolved_launch_route)}>
      <Row><span className="hv-appcard__name">{entry.display_name}</span><Badge tone={entry.launchable ? "success" : "neutral"}>{entry.launchable ? entry.surface_capability_depth ?? "browse" : entry.disabled_reason_codes.join(", ")}</Badge></Row>
      <span className="hv-appcard__job">{entry.canonical_route} · {entry.surface_operational_state ?? "not serving"}</span>
    </button>)}</div>
  </Modal>;
}
