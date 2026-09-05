// THE RECEIPT AS AN OBJECT.
//
// A receipt is the only place a fee exists and the only thing on this surface a reader
// can take away and check — and it was rendered as a chip and a hash in a table cell,
// which is how a ledger row looks and not how a receipt does. A cold reader: "what a
// receipt IS is named on four surfaces and never displayed."
//
// So it is drawn as a thing: a ticket with a ruled edge, the kind at the top, the root
// hash set full-width in mono so it can be selected and compared, and the fee line as
// its own row. Every field is the daemon's record (job-door.mjs receiptViews); nothing
// is drawn for a record that carries no receipt — the absence is stated in words where
// the ticket would be, never as an empty ticket.

export default function Receipt({ r, compact = false }) {
  return (
    <div className={`receipt${compact ? " receipt-compact" : ""}`}>
      <div className="receipt-head">
        <span className="receipt-kind mono">{r.kind || "receipt of an unnamed kind"}</span>
        {r.at && <span className="receipt-at mono">{r.at}</span>}
      </div>
      {r.root && <div className="receipt-root mono">{r.root}</div>}
      {r.ref && !r.root && <div className="receipt-root mono">{r.ref}</div>}
      <div className="receipt-fee mono">
        {r.feeMinted === true ? "fee minted" : r.feeMinted === false ? "no fee minted" : "fee: the record does not say"}
        {r.noFee ? ` · ${r.noFee}` : ""}
      </div>
      {r.note && <div className="receipt-note">{r.note}</div>}
    </div>
  );
}
