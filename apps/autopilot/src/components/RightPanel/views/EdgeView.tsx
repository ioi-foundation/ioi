import { useState, useEffect } from "react";
import { Edge } from "../../../types";

interface EdgeViewProps {
  edge: Edge;
  // Data captured from the last run (from useGraphExecution)
  throughputData?: any;
  // Callback to update the edge's "mock" data for unit testing
  onUpdateEdge: (edgeId: string, data: any) => void;
}

export function EdgeView({ edge, throughputData, onUpdateEdge }: EdgeViewProps) {
  const mockData = edge.data?.mockData as unknown;
  const [mockContent, setMockContent] = useState(mockData ? JSON.stringify(mockData, null, 2) : "");
  const [isMocking, setIsMocking] = useState(!!mockData);

  useEffect(() => {
    setMockContent(mockData ? JSON.stringify(mockData, null, 2) : "");
    setIsMocking(!!mockData);
  }, [edge.id, mockData]);

  const handleSaveMock = () => {
    try {
      const parsed = JSON.parse(mockContent);
      onUpdateEdge(edge.id, { mockData: parsed });
    } catch (e) {
      alert("Invalid JSON");
    }
  };

  const clearMock = () => {
    setIsMocking(false);
    onUpdateEdge(edge.id, { mockData: undefined });
  };

  return (
    <div className="properties-container">
      <div className="panel-section">
        <div className="section-title-row">
          <span className="section-title">Connection ID</span>
          <span className="badge">{edge.id}</span>
        </div>
        <div className="config-field">
           <label className="config-label">Source Node</label>
           <input className="input" disabled value={edge.from} />
        </div>
        <div className="config-field">
           <label className="config-label">Target Node</label>
           <input className="input" disabled value={edge.to} />
        </div>
      </div>

      <div className="panel-section">
        <div className="section-title-row">
          <span className="section-title">Data Observability</span>
          {throughputData && <span className="badge" style={{color: '#34D399'}}>Live Capture</span>}
        </div>
        
        {throughputData ? (
          <div className="output-preview" style={{maxHeight: 200, overflow: 'auto'}}>
            <code>{JSON.stringify(throughputData, null, 2)}</code>
          </div>
        ) : (
          <div className="panel-empty" style={{padding: 10}}>No data captured yet.</div>
        )}
      </div>

      <div className="panel-section">
        <div className="section-title-row">
          <span className="section-title">Simulation Override</span>
          <label className="cap-toggle">
            <input 
              type="checkbox" 
              checked={isMocking}
              onChange={(e) => {
                if (e.target.checked) {
                  setIsMocking(true);
                } else {
                  clearMock();
                }
              }}
            />
            <span className="toggle-track"><span className="toggle-thumb" /></span>
          </label>
        </div>
        
        {isMocking && (
          <div className="config-field">
            <label className="config-label">Inject Mock JSON</label>
            <textarea 
              className="input code-editor" 
              rows={8}
              value={mockContent}
              onChange={(e) => setMockContent(e.target.value)}
              placeholder='{"risk_score": 0.9}'
            />
            <div className="approval-hint" style={{marginLeft: 0, marginTop: 4}}>
              Downstream nodes will use this data instead of the actual source output during Unit Tests.
            </div>
            <button className="btn btn-primary full-width" onClick={handleSaveMock} style={{marginTop: 8}}>
              Apply Mock Data
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
