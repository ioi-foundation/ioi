import { useEffect } from "react";
import { NotConnected } from "../components/Bits.jsx";

// RECEIPTS — designed, not connected.
//
// This surface renders the SHAPE of a RoutingDecisionReceipt and holds no record. It
// shows no example that could be mistaken for one: the fields below are labelled as a
// schema, not filled with plausible values, because a fabricated receipt on the one
// surface whose entire claim is auditability is the worst artifact this project could
// ship. Phase C renders receipts from real records or renders nothing.
//
// THE FEE EXISTS ONLY AS A MINTED RECEIPT, and only from two or more REAL
// (non-simulator) candidates. That is not a policy this surface enforces — the daemon
// does — but it is the sentence the surface must not contradict.

const FIELDS = [
  ["schema_version", "which version of the receipt contract this record was written against"],
  ["decision_ref", "the routing decision this receipt attests"],
  ["intent_ref", "the request it answers"],
  ["selected.provider_kind", "the venue that ran it — EVIDENCE, not an input the caller chose"],
  ["candidates_considered[]", "every candidate weighed, with its quote and its observation window"],
  ["fee", "minted only where two or more non-simulator candidates were priced"],
  ["spend", "what was actually spent, reconciled against the provider, never estimated"],
  ["offline_verifiable", "whether this record can be checked without asking us"],
];

export default function Receipts({ announce }) {
  useEffect(() => { announce("Receipts — designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <NotConnected>
        The shape of a routing receipt, with no record behind it. This surface is not
        connected to a receipt store, and it deliberately shows no filled-in example: a
        plausible receipt here would be indistinguishable from a real one, on the one
        page whose entire claim is that you can check what happened.
      </NotConnected>

      <div className="stack" style={{ gap: "9px" }}>
        <h1>Receipts</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          The fields of a RoutingDecisionReceipt, with no record behind them. A receipt
          is the only place a fee exists: no fee is charged for pricing, for looking, or
          for a decision taken between fewer than two real venues.
        </p>
      </div>

      <div className="table-scroll">
        <table className="quotes">
          <caption className="sr-only">The fields of a routing decision receipt</caption>
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">What it carries</th>
            </tr>
          </thead>
          <tbody>
            {FIELDS.map(([name, meaning]) => (
              <tr key={name} className="trow">
                <th scope="row" className="mono" style={{ fontSize: "13px" }}>{name}</th>
                <td className="basis">{meaning}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="prose">
        A simulator candidate never counts toward the two, and never counts toward a
        fee. That rule is enforced in the daemon and rendered here — it is not a
        courtesy of this page.
      </p>
    </div>
  );
}
