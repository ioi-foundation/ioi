// Home cockpit — source-owned, source-derived from the product-ui home route (intent composer
// + quick actions + Recent Sessions). Data boundary: /v1/threads (recent sessions, create).
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Folder, Sparkles, Bug, FlaskConical, ArrowUp, Plus } from "lucide-react";
import "./Home.css";
import { createSession, listSessions, relativeTime, type Session } from "../../data/threads";

const QUICK = [
  { icon: Sparkles, label: "Automate env setup" },
  { icon: Bug, label: "Fix a bug" },
  { icon: FlaskConical, label: "Boost your test coverage" },
];

export function HomeView() {
  const [task, setTask] = useState("");
  const [recent, setRecent] = useState<Session[] | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let live = true;
    listSessions().then((s) => live && setRecent(s)).catch(() => live && setRecent([]));
    return () => {
      live = false;
    };
  }, []);

  async function submit() {
    try {
      const { id } = await createSession(task.trim() || undefined);
      if (id) navigate(`/sessions/${id}`);
    } catch {
      /* daemon down */
    }
  }

  return (
    <div className="hm">
      <div className="hm-cockpit">
        <div className="hm-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="26" height="26">
            <path d="M12 2 22 12 12 22 2 12Z" fill="none" stroke="currentColor" strokeWidth="1.4" />
            <circle cx="12" cy="12" r="2.6" fill="currentColor" />
          </svg>
        </div>
        <h1 className="hm-title">What do you want to get done today?</h1>

        <div className="hm-composer" data-testid="composer">
          <textarea
            className="hm-input"
            placeholder="Describe your task or type / for commands"
            value={task}
            onChange={(e) => setTask(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit();
            }}
            rows={3}
          />
          <div className="hm-comprow">
            <button className="hm-chip"><Folder size={15} /> Work in a project</button>
            <div className="hm-spacer" />
            <button className="hm-iconbtn" title="Attach"><Plus size={16} /></button>
            <button className="hm-agent">Agent</button>
            <button className="hm-send" onClick={submit} title="Send" data-testid="composer-send"><ArrowUp size={16} /></button>
          </div>
        </div>

        <div className="hm-quick">
          {QUICK.map((q) => (
            <button key={q.label} className="hm-quickbtn" onClick={() => setTask(q.label)}>
              <q.icon size={15} /> {q.label}
            </button>
          ))}
        </div>

        <div className="hm-recent" data-testid="recent-sessions">
          <div className="hm-recenthead">Recent Sessions</div>
          {recent === null && <div className="hm-recentempty">Loading…</div>}
          {recent !== null && recent.length === 0 && <div className="hm-recentempty">No sessions yet.</div>}
          {(recent || []).slice(0, 8).map((s) => (
            <button
              key={s.id}
              className="hm-recentrow"
              onClick={() => navigate(`/sessions/${s.id}`)}
              data-testid="recent-row"
            >
              <span className={"hm-dot" + (s.running ? " is-running" : "")} />
              <span className="hm-recenttitle">{s.title}</span>
              <span className="hm-recentage">{relativeTime(s.updatedAt)}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
