import { useState, useRef } from "react";
import { AgentRuntime } from "../../runtime/agent-runtime";
import { AgentConfiguration } from "../../types/graph";
import "./BuilderView.css";

interface BuilderViewProps {
  runtime: AgentRuntime;
  onAddToGraph: (config: AgentConfiguration) => void;
  onBack: () => void;
}

interface ChatMsg { role: 'agent' | 'user'; text: string; }

const DEFAULT_INSTRUCTIONS = `You are an intelligent assistant designed to answer questions about internal documentation and execute safe tools.`;

export function BuilderView({ runtime, onAddToGraph, onBack }: BuilderViewProps) {
  const [name, setName] = useState("New Agent");
  const [instructions, setInstructions] = useState(DEFAULT_INSTRUCTIONS);
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const handleSend = async () => {
    if (!input.trim()) return;
    const userMsg = input;
    setMessages(prev => [...prev, { role: 'user', text: userMsg }]);
    setInput("");
    setIsTyping(true);

    try {
        const result = await runtime.runNode("model", { 
            model: "gpt-4o", 
            systemPrompt: instructions 
        }, JSON.stringify({ input: userMsg }));

        setIsTyping(false);
        if (result.status === "success") {
            setMessages(prev => [...prev, { role: 'agent', text: result.output }]);
        } else {
            setMessages(prev => [...prev, { role: 'agent', text: `Error: ${result.output}` }]);
        }
    } catch (e) {
        setIsTyping(false);
        setMessages(prev => [...prev, { role: 'agent', text: `System Error: ${e}` }]);
    }
  };

  return (
    <div className="builder-view">
      {/* Config Panel */}
      <div className="builder-config">
         <button onClick={onBack} className="back-btn">← Back</button>
         <div className="form-group">
            <label>Name</label>
            <input value={name} onChange={e => setName(e.target.value)} />
         </div>
         <div className="form-group">
            <label>Instructions</label>
            <textarea rows={10} value={instructions} onChange={e => setInstructions(e.target.value)} />
         </div>
      </div>

      {/* Preview Panel */}
      <div className="builder-preview">
         <div className="preview-chat" ref={chatScrollRef}>
            {messages.map((m, i) => (
                <div key={i} className={`preview-msg-row ${m.role}`}>
                    <div className="preview-msg">{m.text}</div>
                </div>
            ))}
            {isTyping && <div className="thinking">Agent is thinking...</div>}
         </div>
         <div className="preview-input">
            <input 
                value={input} 
                onChange={e => setInput(e.target.value)} 
                onKeyDown={e => e.key === 'Enter' && handleSend()}
                placeholder="Test your agent..."
            />
            <button 
                onClick={() => onAddToGraph({ name, description: "Generated", instructions, model: "gpt-4o", temperature: 0.7, tools: [] })}
                className="add-btn"
            >
                Add to Graph
            </button>
         </div>
      </div>
    </div>
  );
}