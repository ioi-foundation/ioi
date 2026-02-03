// packages/agent-ide/src/features/Editor/Inspector/views/EdgeView.tsx

interface EdgeViewProps {
  edge: any; 
}

export function EdgeView({ edge }: EdgeViewProps) {
  return (
    <div className="inspector-view">
      <div className="section-header" style={{marginBottom: 16}}>
        <span style={{fontWeight: 700}}>CONNECTION CONFIG</span>
      </div>
      
      <div className="form-group">
        <label>Connection ID</label>
        <input disabled value={edge.id} />
      </div>

      <div className="form-group">
        <label>Source → Target</label>
        <div style={{display:'flex', gap: 8}}>
            <input disabled value={edge.source} style={{flex:1}} />
            <span style={{alignSelf:'center'}}>→</span>
            <input disabled value={edge.target} style={{flex:1}} />
        </div>
      </div>

      <div className="law-card">
        <div className="cap-header">
            <span>Simulation Override</span>
            <input type="checkbox" />
        </div>
        <div className="cap-body">
            <textarea 
                className="code-editor"
                rows={5}
                placeholder='{"mock": "data"}'
            />
        </div>
      </div>
    </div>
  );
}