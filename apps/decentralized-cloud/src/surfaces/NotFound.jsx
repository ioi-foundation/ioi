import { useEffect } from "react";
import { SURFACES, hashForSurface } from "../logic/surfaces.mjs";
import { Eyebrow } from "../components/Bits.jsx";

// THE 404 — an address that is not a surface, as a composition of its own.
//
// It stays inside the shell: the rail, the search and the chips are all still there,
// because the reader's problem is one wrong address and not a broken console. It
// shows the address it was given verbatim, says it resolves to no surface on this
// branch, and offers the surfaces by name. It is not a registered surface — it has
// no rail button and no address of its own — so the gate's sweep is unchanged.
export default function NotFound({ address, announce }) {
  useEffect(() => { announce(`No surface at ${address}`); }, [address, announce]);
  return (
    <div className="stack notfound" style={{ gap: "22px" }}>
      <div className="stack" style={{ gap: "9px" }}>
        <Eyebrow>no surface at this address</Eyebrow>
        <h1>Not found</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          <span className="mono notfound-address">#/{address}</span> resolves to no surface on this
          console. Nothing was read and nothing has been shown in its place.
        </p>
      </div>
      <p className="meta">
        Addresses are the surface's name after <span className="mono">#/</span>, and the
        catalogue takes one of its four families after that. A link from an older
        build may name a surface that has since been renamed.
      </p>
      <div className="stack" style={{ gap: "10px" }}>
        <Eyebrow>the surfaces</Eyebrow>
        <ul className="notfound-list">
          {SURFACES.map((s) => (
            <li key={s.id}>
              <a className="entry-name" href={hashForSurface(s.id)}>{s.label}</a>
              <span className="meta mono"> #/{s.id}</span>
              {!s.wired && <span className="meta"> · designed, not connected</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
