// packages/agent-ide/src/features/Editor/Inspector/views/DnaView.tsx
import { Node } from "../../../../types/graph";

interface DnaViewProps {
  node: Node;
}

// Rename 'node' to '_node' to silence unused variable warning while keeping signature correct
export function DnaView({ node: _node }: DnaViewProps) {
  // Mock data since we don't have live evolution backend connected yet
  const generation = 12;
  const fitness = 0.89;
  
  return (
    <div className="inspector-view">
        <div className="gene-header" style={{padding: '12px', background: 'var(--surface-3)', borderRadius: '6px', marginBottom: '16px'}}>
            <div style={{fontSize: '10px', color: 'var(--text-tertiary)', textTransform: 'uppercase'}}>Current Lineage</div>
            <div style={{fontSize: '18px', fontWeight: 700, color: 'var(--accent-blue)'}}>Gen {generation}</div>
        </div>
        
        <div className="gene-stats" style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '16px'}}>
            <div className="stat-box" style={{background: 'var(--surface-2)', padding: '8px', borderRadius: '4px'}}>
                <div style={{fontSize: '10px', color: 'var(--text-tertiary)'}}>Fitness Score</div>
                <div style={{color: 'var(--status-success)', fontWeight: 600}}>{fitness}</div>
            </div>
            <div className="stat-box" style={{background: 'var(--surface-2)', padding: '8px', borderRadius: '4px'}}>
                <div style={{fontSize: '10px', color: 'var(--text-tertiary)'}}>Model Entropy</div>
                <div style={{color: 'var(--text-primary)', fontWeight: 600}}>Low (0.12)</div>
            </div>
        </div>

        <div className="section-header" style={{fontSize: '10px', fontWeight: 700, color: 'var(--text-tertiary)', marginBottom: '8px'}}>MUTATION LOG</div>
        <div className="mutation-log" style={{fontSize: '11px'}}>
            <div className="mutation-entry" style={{padding: '8px', borderLeft: '2px solid var(--status-success)', background: 'var(--surface-2)', marginBottom: '4px'}}>
                <div style={{display:'flex', justifyContent:'space-between', marginBottom:'4px'}}>
                    <span style={{fontWeight: 600}}>Gen 11 → 12</span>
                    <span style={{color: 'var(--text-tertiary)', fontSize:'10px'}}>Live</span>
                </div>
                <div style={{color: 'var(--text-secondary)'}}>Optimized prompt for lower latency (-120ms).</div>
            </div>
            <div className="mutation-entry" style={{padding: '8px', borderLeft: '2px solid var(--border-default)', background: 'var(--surface-2)', opacity: 0.7}}>
                <div style={{display:'flex', justifyContent:'space-between', marginBottom:'4px'}}>
                    <span style={{fontWeight: 600}}>Gen 10 → 11</span>
                    <span style={{color: 'var(--text-tertiary)', fontSize:'10px'}}>1h ago</span>
                </div>
                <div style={{color: 'var(--text-secondary)'}}>Adjusted parameter tolerance.</div>
            </div>
        </div>
    </div>
  );
}