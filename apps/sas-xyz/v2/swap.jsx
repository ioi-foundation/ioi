// Swap modal — the move SaaS lock-in never allowed.
// Shows a diff: what changes (price, SLA), what stays stable (envelope, receipt format, audit chain).
const SwapModal = ({ contract, alt, onClose, onConfirm }) => {
  if (!contract) return null;
  const from = contract.substrate;
  const to = alt || (ALTERNATIVES[contract.id] || [])[0];
  if (!to) return null;

  // Approximate current price/sla from contract
  const fromPrice = contract.id === 'ct-books' ? '$1.20 / outcome'
                  : contract.id === 'ct-hires' ? '$120 / hire'
                  : contract.id === 'ct-cves'  ? '$12 / remediation'
                  : '$48 / document';
  const fromSla = contract.slaActual;

  return (
    <div className="swap-scrim" onClick={onClose}>
      <div className="swap-modal" onClick={e => e.stopPropagation()}>
        <div className="swap-head">
          <div className="swap-eyebrow mono">Proposed substitution</div>
          <h3 className="swap-title serif">
            Substitute <em>{from.name}</em> with <em>{to.name}</em>
          </h3>
        </div>

        <div className="swap-body">
          <div className="swap-diff">
            <div className="swap-diff-head mono">
              <span></span>
              <span className="from">From · {from.name}</span>
              <span className="to">To · {to.name}</span>
            </div>
            <div className="swap-diff-row">
              <span className="k">Unit price</span>
              <span className="from">{fromPrice}</span>
              <span className="to">${to.price.toFixed(to.price % 1 ? 2 : 0)} {to.unit} <span style={{color: to.diff < 0 ? 'var(--sage-ink)' : 'var(--coral-ink)', fontFamily:'var(--mono)', fontSize:10, marginLeft:4}}>{to.diff > 0 ? '+' : ''}{to.diff}%</span></span>
            </div>
            <div className="swap-diff-row">
              <span className="k">SLA</span>
              <span className="from">{fromSla}</span>
              <span className="to">{to.sla}</span>
            </div>
            <div className="swap-diff-row">
              <span className="k">Attestations</span>
              <span className="from">SOC2 Type II · ISO 27001</span>
              <span className="to">SOC2 Type II · ISO 27001</span>
            </div>
            <div className="swap-diff-row stable">
              <span className="k">Outcome spec</span>
              <span className="from">unchanged</span>
              <span className="to">unchanged</span>
            </div>
            <div className="swap-diff-row stable">
              <span className="k">Envelope</span>
              <span className="from">unchanged</span>
              <span className="to">unchanged · {contract.envelope.name}</span>
            </div>
            <div className="swap-diff-row stable">
              <span className="k">Receipt schema</span>
              <span className="from">unchanged</span>
              <span className="to">unchanged · chain continuity preserved</span>
            </div>
            <div className="swap-diff-row stable">
              <span className="k">Audit history</span>
              <span className="from">retained</span>
              <span className="to">forward-linked to new provider</span>
            </div>
          </div>

          <div className="swap-guarantee">
            <span className="swap-guarantee-glyph">S</span>
            <span>
              <b>Guaranteed.</b> The outcome contract is the stable object. {to.name} inherits
              the same envelope, emits receipts in the same schema, and settles against the same
              audit chain. If quality degrades within 30 days, you snap back to {from.name} at the prior price.
            </span>
          </div>
        </div>

        <div className="swap-foot">
          <div className="swap-foot-note mono">
            Takes effect on the next receipt · in-flight work finishes under {from.name}
          </div>
          <div className="swap-foot-actions">
            <button className="btn ghost" onClick={onClose}>Cancel</button>
            <button className="btn accent" onClick={onConfirm}>
              Confirm swap <Icon name="arrow" size={13} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

window.SwapModal = SwapModal;
