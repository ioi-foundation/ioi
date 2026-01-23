import React, { useState, useMemo, useCallback, useEffect, useRef } from "react";
import type { SwarmAgent } from "../types";
import "./SwarmViz.css";

// --- Icons ---
const ChevronIcon = ({ expanded }: { expanded: boolean }) => (
  <svg 
    width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    style={{ transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform 0.15s ease' }}
  >
    <polyline points="9 18 15 12 9 6" />
  </svg>
);

const PauseIcon = () => (<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>);
const PlayIcon = () => (<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>);
const XIcon = () => (<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>);
const EyeIcon = () => (<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>);
const CheckIcon = () => (<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>);
const TreeIcon = () => (<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 3v18"/><path d="M8 7l4-4 4 4"/><path d="M8 21H4a2 2 0 0 1-2-2v-4"/><path d="M16 21h4a2 2 0 0 0 2-2v-4"/></svg>);
const TimelineIcon = () => (<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/><line x1="12" y1="4" x2="12" y2="4"/></svg>);

// Role emoji mapping
const getRoleEmoji = (role: string): string => {
  const map: Record<string, string> = {
    'Planner': '🧠', 'Manager': '👔', 'Researcher': '🔍', 'Coder': '💻',
    'Python Exec': '🐍', 'Writer': '✍️', 'Analyst': '📊', 'Browser': '🌐',
    'Validator': '✅', 'Summarizer': '📝',
  };
  return map[role] || '🤖';
};

const getStatusColor = (status: string): string => {
  const map: Record<string, string> = {
    'running': '#3D85C6', 'completed': '#22C55E', 'failed': '#EF4444',
    'paused': '#F59E0B', 'requisition': '#0EA5E9', 'negotiating': '#A78BFA',
  };
  return map[status] || '#6B7280';
};

interface ActivityEvent {
  id: string;
  agentId: string;
  agentName: string;
  type: 'spawn' | 'thought' | 'action' | 'artifact' | 'complete' | 'error' | 'requisition';
  message: string;
  timestamp: Date;
}

interface SwarmVizProps {
  agents: SwarmAgent[];
  onApproveAgent?: (agentId: string) => void;
  onRejectAgent?: (agentId: string) => void;
  onPauseAgent?: (agentId: string) => void;
  onResumeAgent?: (agentId: string) => void;
  onCancelAgent?: (agentId: string) => void;
}

export function SwarmViz({ 
  agents, 
  onApproveAgent, 
  onRejectAgent,
  onPauseAgent,
  onResumeAgent,
  onCancelAgent 
}: SwarmVizProps) {
  const [viewMode, setViewMode] = useState<'tree' | 'timeline'>('tree');
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set(['root']));
  const [activityLog, setActivityLog] = useState<ActivityEvent[]>([]);
  const activityRef = useRef<HTMLDivElement>(null);

  // Track agent changes to generate activity events
  const prevAgentsRef = useRef<SwarmAgent[]>([]);
  
  useEffect(() => {
    const prevAgents = prevAgentsRef.current;
    const newEvents: ActivityEvent[] = [];

    agents.forEach(agent => {
      const prev = prevAgents.find(p => p.id === agent.id);
      
      if (!prev) {
        newEvents.push({
          id: `${agent.id}-spawn-${Date.now()}`,
          agentId: agent.id,
          agentName: agent.name,
          type: agent.status === 'requisition' ? 'requisition' : 'spawn',
          message: agent.status === 'requisition' 
            ? `${agent.role} requested`
            : `${agent.role} initialized`,
          timestamp: new Date(),
        });
      }
      
      if (prev && prev.status !== agent.status) {
        if (agent.status === 'completed') {
          newEvents.push({
            id: `${agent.id}-complete-${Date.now()}`,
            agentId: agent.id,
            agentName: agent.name,
            type: 'complete',
            message: `Task completed (${agent.artifacts_produced} artifacts)`,
            timestamp: new Date(),
          });
        } else if (agent.status === 'failed') {
          newEvents.push({
            id: `${agent.id}-error-${Date.now()}`,
            agentId: agent.id,
            agentName: agent.name,
            type: 'error',
            message: agent.current_thought || 'Execution failed',
            timestamp: new Date(),
          });
        }
      }
      
      if (prev && prev.current_thought !== agent.current_thought && agent.current_thought && agent.status === 'running') {
        newEvents.push({
          id: `${agent.id}-thought-${Date.now()}`,
          agentId: agent.id,
          agentName: agent.name,
          type: 'thought',
          message: agent.current_thought,
          timestamp: new Date(),
        });
      }
    });

    if (newEvents.length > 0) {
      setActivityLog(prev => [...newEvents, ...prev].slice(0, 50));
    }

    prevAgentsRef.current = agents;
  }, [agents]);

  // Auto-scroll timeline
  useEffect(() => {
    if (activityRef.current && viewMode === 'timeline') {
      activityRef.current.scrollTop = 0;
    }
  }, [activityLog, viewMode]);

  const { roots, getChildren } = useMemo(() => {
    const childMap = new Map<string | null, SwarmAgent[]>();
    agents.forEach(agent => {
      const parentId = agent.parentId;
      if (!childMap.has(parentId)) childMap.set(parentId, []);
      childMap.get(parentId)!.push(agent);
    });
    return { roots: childMap.get(null) || [], getChildren: (id: string) => childMap.get(id) || [] };
  }, [agents]);

  const metrics = useMemo(() => {
    const running = agents.filter(a => a.status === 'running').length;
    const completed = agents.filter(a => a.status === 'completed').length;
    const failed = agents.filter(a => a.status === 'failed').length;
    const pending = agents.filter(a => a.status === 'requisition').length;
    
    const activeBudgetUsed = agents.filter(a => a.status !== 'requisition').reduce((sum, a) => sum + (a.budget_used || 0), 0);
    const totalBudgetCap = agents.filter(a => a.status !== 'requisition').reduce((sum, a) => sum + (a.budget_cap || 0), 0);
    const pendingCost = agents.filter(a => a.status === 'requisition').reduce((sum, a) => sum + (a.estimated_cost || 0), 0);
    const totalArtifacts = agents.reduce((sum, a) => sum + (a.artifacts_produced || 0), 0);

    return { 
      running, completed, failed, pending, 
      activeBudgetUsed, totalBudgetCap, pendingCost, 
      totalArtifacts,
      total: agents.length 
    };
  }, [agents]);

  const selectedAgent = agents.find(a => a.id === selectedAgentId);

  const toggleExpand = useCallback((id: string) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const handleBatchApprove = useCallback((squadAgents: SwarmAgent[]) => {
    squadAgents.forEach(a => { if (onApproveAgent) onApproveAgent(a.id); });
  }, [onApproveAgent]);

  const handleBackgroundClick = (e: React.MouseEvent) => {
    // Only dismiss if clicking the main area directly (background), not inside a node
    if (e.target === e.currentTarget) {
      setSelectedAgentId(null);
    }
  };

  return (
    <div className="swarm-viz">
      {/* HEADER */}
      <div className="swarm-viz-header">
        <div className="swarm-viz-title">
          <div className="swarm-viz-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/>
              <path d="M7.5 17.5 10 12.5"/><path d="M16.5 17.5 14 12.5"/>
            </svg>
          </div>
          <span>Swarm Orchestration</span>
          <span className="swarm-viz-count">{metrics.total} agents</span>
        </div>

        <div className="swarm-viz-controls">
          <div className="view-toggle">
            <button className={viewMode === 'tree' ? 'active' : ''} onClick={() => setViewMode('tree')} title="Tree View"><TreeIcon /></button>
            <button className={viewMode === 'timeline' ? 'active' : ''} onClick={() => setViewMode('timeline')} title="Activity Timeline"><TimelineIcon /></button>
          </div>
          {metrics.running > 0 && <div className="live-indicator"><span className="live-dot" /><span>LIVE</span></div>}
        </div>
      </div>

      {/* METRICS BAR */}
      <div className="swarm-metrics-bar">
        <MetricChip label="Active" value={metrics.running} color="#3D85C6" pulse={metrics.running > 0} />
        <MetricChip label="Done" value={metrics.completed} color="#22C55E" />
        {metrics.failed > 0 && <MetricChip label="Failed" value={metrics.failed} color="#EF4444" />}
        {metrics.pending > 0 && <MetricChip label="Pending" value={metrics.pending} color="#0EA5E9" />}
        <MetricChip label="Artifacts" value={metrics.totalArtifacts} color="#A78BFA" />
        
        <div className="metric-budget-bar">
          <div className="budget-info">
            <span className="budget-spent">${metrics.activeBudgetUsed.toFixed(4)}</span>
            <span className="budget-separator">/</span>
            <span className="budget-cap">${metrics.totalBudgetCap.toFixed(2)}</span>
            {metrics.pendingCost > 0 && <span className="budget-pending">+${metrics.pendingCost.toFixed(2)} pending</span>}
          </div>
          <div className="budget-track">
            <div 
              className="budget-fill" 
              style={{ width: `${Math.min((metrics.activeBudgetUsed / Math.max(metrics.totalBudgetCap, 0.01)) * 100, 100)}%`, background: metrics.activeBudgetUsed > metrics.totalBudgetCap * 0.8 ? '#EF4444' : '#22C55E' }} 
            />
            {metrics.pendingCost > 0 && (
              <div 
                className="budget-pending-fill" 
                style={{ 
                  width: `${Math.min((metrics.pendingCost / Math.max(metrics.totalBudgetCap, 0.01)) * 100, 30)}%`,
                  left: `${Math.min((metrics.activeBudgetUsed / Math.max(metrics.totalBudgetCap, 0.01)) * 100, 100)}%`
                }} 
              />
            )}
          </div>
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div className="swarm-viz-content">
        {/* LEFT: Tree/Timeline */}
        <div 
            className={`swarm-viz-main ${selectedAgent ? 'has-detail' : ''}`}
            onClick={handleBackgroundClick}
        >
          {viewMode === 'tree' ? (
            <div className="swarm-tree-v2">
              {roots.length === 0 ? (
                <div className="swarm-empty"><div className="empty-icon">🔄</div><div>Initializing swarm...</div></div>
              ) : (
                roots.map(agent => (
                  <AgentNode 
                    key={agent.id} agent={agent} getChildren={getChildren} depth={0}
                    expandedNodes={expandedNodes} onToggleExpand={toggleExpand}
                    selectedAgentId={selectedAgentId} onSelect={setSelectedAgentId}
                    onApprove={onApproveAgent} onReject={onRejectAgent}
                    onPause={onPauseAgent} onResume={onResumeAgent} onCancel={onCancelAgent}
                    onBatchApprove={handleBatchApprove}
                  />
                ))
              )}
            </div>
          ) : (
            <div className="swarm-timeline" ref={activityRef}>
                {activityLog.length === 0 ? (
                    <div className="swarm-empty"><div className="empty-icon">📋</div><div>Waiting for activity...</div></div>
                ) : (
                    activityLog.map(event => <ActivityItem key={event.id} event={event} onSelectAgent={setSelectedAgentId} />)
                )}
            </div>
          )}
        </div>

        {/* RIGHT: Floating Agent Detail Panel */}
        {selectedAgent && (
          <AgentDetailPanel 
            agent={selectedAgent}
            activityLog={activityLog}
            onClose={() => setSelectedAgentId(null)}
            onApprove={onApproveAgent}
            onReject={onRejectAgent}
            onPause={onPauseAgent}
            onResume={onResumeAgent}
            onCancel={onCancelAgent}
          />
        )}
      </div>
    </div>
  );
}

// === SUBCOMPONENTS ===

function MetricChip({ label, value, color, pulse }: { label: string; value: number; color: string; pulse?: boolean }) {
  return (
    <div className="metric-chip" style={{ '--accent': color } as React.CSSProperties}>
      <span className={`metric-dot ${pulse ? 'pulse' : ''}`} style={{ background: color }} />
      <span className="metric-value">{value}</span>
      <span className="metric-label">{label}</span>
    </div>
  );
}

interface AgentNodeProps {
  agent: SwarmAgent;
  getChildren: (id: string) => SwarmAgent[];
  depth: number;
  expandedNodes: Set<string>;
  onToggleExpand: (id: string) => void;
  selectedAgentId: string | null;
  onSelect: (id: string | null) => void;
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
  onPause?: (id: string) => void;
  onResume?: (id: string) => void;
  onCancel?: (id: string) => void;
  onBatchApprove?: (agents: SwarmAgent[]) => void;
  isSquadMember?: boolean;
}

function AgentNode({ 
  agent, getChildren, depth, expandedNodes, onToggleExpand,
  selectedAgentId, onSelect, onApprove, onReject, onPause, onResume, onCancel, onBatchApprove,
  isSquadMember
}: AgentNodeProps) {
  const children = getChildren(agent.id);
  const requisitionChildren = children.filter(c => c.status === 'requisition');
  const activeChildren = children.filter(c => c.status !== 'requisition');
  const hasChildren = children.length > 0;
  const isExpanded = expandedNodes.has(agent.id);
  const isSelected = selectedAgentId === agent.id;
  const isRequisition = agent.status === 'requisition';
  const isRunning = agent.status === 'running';
  
  const budgetPercent = agent.budget_cap > 0 ? Math.min((agent.budget_used / agent.budget_cap) * 100, 100) : 0;

  return (
    <div className={`agent-node-v2 depth-${Math.min(depth, 3)}`} style={{ '--depth': isSquadMember ? 0 : depth } as React.CSSProperties}>
      {!isSquadMember && depth > 0 && <div className={`connector-line ${isRequisition ? 'dashed' : ''}`} />}
      
      <div 
        className={`agent-card-v2 ${agent.status} ${isSelected ? 'selected' : ''}`}
        onClick={(e) => { e.stopPropagation(); onSelect(isSelected ? null : agent.id); }}
      >
        <div className="agent-left">
          {hasChildren ? (
            <button className="expand-btn" onClick={(e) => { e.stopPropagation(); onToggleExpand(agent.id); }}>
              <ChevronIcon expanded={isExpanded} />
            </button>
          ) : <div className="expand-spacer" />}
          <div className={`agent-avatar ${isRunning ? 'active' : ''}`}>{getRoleEmoji(agent.role)}</div>
        </div>

        <div className="agent-center">
          <div className="agent-name-row">
            <span className="agent-name">{agent.name}</span>
            <span className="agent-role-badge">{agent.role}</span>
          </div>
          <div className="agent-status-row">
            <span className={`status-badge ${agent.status}`}>
                {isRunning && <span className="status-spinner-mini" />}
                {agent.status.toUpperCase()}
            </span>
          </div>
          {!isRequisition && (
            <div className="agent-budget-row">
              <div className="mini-budget-track">
                <div className="mini-budget-fill" style={{ width: `${budgetPercent}%`, background: budgetPercent > 80 ? '#EF4444' : getStatusColor(agent.status) }} />
              </div>
              <span className="budget-text">${agent.budget_used.toFixed(3)} / ${agent.budget_cap.toFixed(2)}</span>
            </div>
          )}
          {isRequisition && <div className="requisition-cost">Est. cost: <strong>${agent.estimated_cost?.toFixed(4)}</strong></div>}
        </div>

        <div className="agent-right">
          {isRequisition && !isSquadMember && (
            <>
              <button className="action-btn approve" onClick={(e) => { e.stopPropagation(); onApprove?.(agent.id); }}><CheckIcon /></button>
              <button className="action-btn reject" onClick={(e) => { e.stopPropagation(); onReject?.(agent.id); }}><XIcon /></button>
            </>
          )}
          {isRunning && (
            <button className="action-btn pause" onClick={(e) => { e.stopPropagation(); onPause?.(agent.id); }}><PauseIcon /></button>
          )}
          {agent.status === 'paused' && (
            <button className="action-btn resume" onClick={(e) => { e.stopPropagation(); onResume?.(agent.id); }}><PlayIcon /></button>
          )}
          {(isRunning || agent.status === 'paused') && (
            <button className="action-btn cancel" onClick={(e) => { e.stopPropagation(); onCancel?.(agent.id); }}><XIcon /></button>
          )}
          <button className="action-btn inspect" onClick={(e) => { e.stopPropagation(); onSelect(agent.id); }}><EyeIcon /></button>
        </div>
      </div>

      {(hasChildren && isExpanded) && (
        <div className="agent-children-v2">
          {activeChildren.map(c => (
            <AgentNode 
              key={c.id} agent={c} getChildren={getChildren} depth={depth + 1}
              expandedNodes={expandedNodes} onToggleExpand={onToggleExpand}
              selectedAgentId={selectedAgentId} onSelect={onSelect}
              onApprove={onApprove} onReject={onReject} onPause={onPause} onResume={onResume} onCancel={onCancel}
              onBatchApprove={onBatchApprove}
            />
          ))}
          {requisitionChildren.length > 0 && (
            <div className="squad-group">
               <div className="squad-header">
                  <div className="squad-title">
                    <span className="squad-label">PROPOSED SQUAD ({requisitionChildren.length})</span>
                    <span className="squad-meta">Total: ${requisitionChildren.reduce((s, a) => s + (a.estimated_cost||0), 0).toFixed(4)}</span>
                  </div>
                  <button className="squad-hire-btn" onClick={(e) => { e.stopPropagation(); onBatchApprove?.(requisitionChildren); }}>
                    <CheckIcon /> Sign & Hire All
                  </button>
               </div>
               <div className="squad-list">
                 {requisitionChildren.map(c => (
                    <AgentNode 
                      key={c.id} agent={c} getChildren={getChildren} depth={depth + 1}
                      expandedNodes={expandedNodes} onToggleExpand={onToggleExpand}
                      selectedAgentId={selectedAgentId} onSelect={onSelect}
                      onApprove={onApprove} onReject={onReject} isSquadMember={true}
                    />
                 ))}
               </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ActivityItem({ event, onSelectAgent }: { event: ActivityEvent; onSelectAgent: (id: string) => void }) {
  const typeStyles: Record<string, { icon: string; color: string }> = {
    'spawn': { icon: '🚀', color: '#3D85C6' },
    'thought': { icon: '💭', color: '#9CA3AF' },
    'action': { icon: '⚡', color: '#F59E0B' },
    'artifact': { icon: '📦', color: '#A78BFA' },
    'complete': { icon: '✅', color: '#22C55E' },
    'error': { icon: '❌', color: '#EF4444' },
    'requisition': { icon: '📋', color: '#0EA5E9' },
  };
  const style = typeStyles[event.type] || { icon: '•', color: '#6B7280' };
  
  return (
    <div className={`activity-item type-${event.type}`} onClick={() => onSelectAgent(event.agentId)}>
      <div className="activity-icon" style={{ background: `${style.color}20`, color: style.color }}>{style.icon}</div>
      <div className="activity-content">
        <div className="activity-header">
          <span className="activity-agent">{event.agentName}</span>
          <span className="activity-time">{event.timestamp.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})}</span>
        </div>
        <div className="activity-message">{event.message}</div>
      </div>
    </div>
  );
}

function AgentDetailPanel({ agent, activityLog, onClose, onApprove, onReject, onPause, onResume, onCancel }: any) {
  const budgetPercent = agent.budget_cap > 0 ? Math.min((agent.budget_used / agent.budget_cap) * 100, 100) : 0;
  const agentLogs = activityLog.filter((l: ActivityEvent) => l.agentId === agent.id);

  return (
    <div className="agent-detail-panel">
      <div className="detail-header">
        <div className="detail-title">
          <span className="detail-emoji">{getRoleEmoji(agent.role)}</span>
          <div><div className="detail-name">{agent.name}</div><div className="detail-role">{agent.role}</div></div>
        </div>
        <button className="detail-close" onClick={onClose}><XIcon /></button>
      </div>

      <div className="detail-body">
        <div className="detail-section">
          <div className="section-label">Status</div>
          <div className="status-chip-lg" style={{ background: `${getStatusColor(agent.status)}15`, color: getStatusColor(agent.status), borderColor: `${getStatusColor(agent.status)}40` }}>
            <span className={`status-dot-lg ${agent.status === 'running' ? 'pulse' : ''}`} style={{ background: getStatusColor(agent.status) }} />
            {agent.status.toUpperCase()}
          </div>
        </div>

        <div className="detail-section">
          <div className="section-label">Terminal Stream</div>
          <div className="terminal-box">
            {agentLogs.length === 0 ? <div className="terminal-line" style={{fontStyle: 'italic', opacity: 0.5}}>No logs available</div> : 
                agentLogs.slice(0, 5).map((log: ActivityEvent, i: number) => (
                    <div key={log.id} className={`terminal-line ${i === 0 ? 'latest' : ''}`}>
                        <span className="terminal-ts">{log.timestamp.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'})}</span>
                        <span>{log.message}</span>
                    </div>
                ))
            }
            {agent.status === 'running' && <div className="terminal-line latest"><span className="terminal-ts">Now</span><span>{agent.current_thought}<span className="terminal-cursor" /></span></div>}
          </div>
        </div>

        {agent.status !== 'requisition' && (
          <div className="detail-section">
            <div className="section-label">Budget Usage</div>
            <div className="budget-detail">
              <div className="budget-numbers"><span className="budget-used">${agent.budget_used.toFixed(4)}</span> <span className="budget-of">of</span> <span className="budget-total">${agent.budget_cap.toFixed(2)}</span></div>
              <div className="budget-track-lg"><div className="budget-fill-lg" style={{ width: `${budgetPercent}%`, background: budgetPercent > 80 ? 'linear-gradient(90deg, #F59E0B, #EF4444)' : 'linear-gradient(90deg, #22C55E, #3D85C6)' }} /></div>
            </div>
          </div>
        )}

        <div className="detail-section">
          <div className="section-label">Policy Identity</div>
          <div className="policy-row"><div className="policy-identicon" /><div className="policy-hash"><code>{agent.policy_hash}</code></div></div>
        </div>

        <div className="detail-section">
          <div className="section-label">Artifacts Produced</div>
          <div className="artifacts-count">
            <span className="artifact-number">{agent.artifacts_produced}</span>
            <span className="artifact-label">files</span>
          </div>
        </div>

        {agent.status === 'requisition' && (
          <div className="detail-section">
            <div className="section-label">Estimated Cost</div>
            <div className="estimate-box">
              <span className="estimate-value">${agent.estimated_cost?.toFixed(4)}</span>
              <span className="estimate-note">This agent requires approval before execution</span>
            </div>
          </div>
        )}
      </div>

      <div className="detail-actions">
        {agent.status === 'requisition' && <><button className="detail-btn primary" onClick={() => onApprove(agent.id)}>Approve</button><button className="detail-btn danger" onClick={() => onReject(agent.id)}>Reject</button></>}
        {agent.status === 'running' && <><button className="detail-btn secondary" onClick={() => onPause(agent.id)}>Pause</button><button className="detail-btn danger" onClick={() => onCancel(agent.id)}>Cancel</button></>}
        {agent.status === 'paused' && <><button className="detail-btn primary" onClick={() => onResume(agent.id)}>Resume</button><button className="detail-btn danger" onClick={() => onCancel(agent.id)}>Cancel</button></>}
      </div>
    </div>
  );
}