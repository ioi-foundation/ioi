import { Node } from "../../../types";
import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";

interface DnaViewProps {
  node?: Node | null;
}

// [NEW] Interface for mutation events
interface MutationEvent {
  generation: number;
  reason: string;
  score_delta: number;
  // Screenshot hash that triggered this learning event
  trigger_visual_hash?: string;
  timestamp: number;
}

export function DnaView({ node }: DnaViewProps) {
  // Extract metrics or default to genesis state
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const metrics = node?.metrics as any || {};
  const generation = metrics.generation ?? 0;
  const fitness = metrics.fitness_score ?? 0.0;
  
  // Local state for live mutations
  const [mutations, setMutations] = useState<MutationEvent[]>([]);

  // Listen for evolution events
  useEffect(() => {
      const unlisten = listen<MutationEvent>("agent-mutation", (e) => {
          setMutations(prev => [e.payload, ...prev]);
      });
      return () => { unlisten.then(f => f()); };
  }, []);
  
  // Previous generation reference (Mock logic for UI demo, would normally come from history)
  const prevGen = Math.max(0, generation - 1);

  return (
    <div className="lineage-view">
        <div className="gene-header">
            <span className="gene-title">Current Lineage</span>
            <span className="gene-badge" style={{background: '#3D85C6'}}>Gen {generation}</span>
        </div>
        
        <div className="gene-stats">
            <div className="stat-box">
                <div className="stat-label">Fitness Score</div>
                <div className="stat-val" style={{color: fitness > 0.8 ? '#34D399' : '#E5E7EB'}}>
                    {fitness.toFixed(2)}
                </div>
            </div>
            <div className="stat-box">
                <div className="stat-label">Model Entropy</div>
                <div className="stat-val">Low (0.12)</div>
            </div>
        </div>

        <div className="divider" style={{margin: '16px 0', opacity: 0.3}} />
        <span className="section-title" style={{marginBottom: 8, display: 'block'}}>Mutation Log</span>

        <div className="mutation-log">
            {/* Live Mutations */}
            {mutations.map((mut, i) => (
                <div key={i} className="mutation-entry success live">
                    <div className="mutation-meta">
                        <span>Gen {mut.generation - 1} → {mut.generation}</span>
                        <span className="timestamp">Live</span>
                    </div>
                    <div className="mutation-reason">
                        {mut.reason}
                    </div>
                    {mut.trigger_visual_hash && (
                        <div className="visual-trigger" title="Learned from this screen state">
                            <span className="trigger-icon">👁️</span> Visual Context
                        </div>
                    )}
                    <div className="mutation-score positive">
                        +{mut.score_delta.toFixed(2)} Fitness
                    </div>
                </div>
            ))}

            {/* Historical State */}
            {generation > 0 ? (
                <div className="mutation-entry success">
                    <div className="mutation-meta">
                        <span>Gen {prevGen} → {generation}</span>
                        <span className="timestamp">Just now</span>
                    </div>
                    <div className="mutation-reason">
                        {node?.type === 'model' 
                            ? "Optimized prompt for lower latency (-120ms)." 
                            : "Adjusted parameter tolerance based on error rate."}
                    </div>
                    <div className="mutation-score positive">
                        Fitness {(fitness * 100).toFixed(0)}%
                    </div>
                </div>
            ) : (
                <div className="mutation-entry">
                    <div className="mutation-meta">
                        <span>Genesis</span>
                        <span className="timestamp">Initial State</span>
                    </div>
                    <div className="mutation-reason">Base configuration loaded.</div>
                </div>
            )}
            
            {/* Mock History for Flavor */}
            {generation > 1 && (
                <div className="mutation-entry success" style={{opacity: 0.6}}>
                    <div className="mutation-meta">
                        <span>Gen {prevGen-1} → {prevGen}</span>
                        <span className="timestamp">1h ago</span>
                    </div>
                    <div className="mutation-reason">Fixed JSON parsing error in `tool_call` regex.</div>
                    <div className="mutation-score positive">+15% Success Rate</div>
                </div>
            )}
        </div>
    </div>
  );
}