import { Link } from "react-router-dom";
import { Badge, Card, Heading, Muted, Row } from "../ui";

export function HomeSurface() {
  return <div className="hv-page hv-home" data-testid="surface-home">
    <header className="hv-page__head"><Row><Heading>Operate bounded intelligence</Heading><Badge>source-owned</Badge></Row><Muted>Move from intent to governed work, durable result, evidence, and recovery without moving truth into the client.</Muted></header>
    <div className="hv-home__hero"><p>What do you want to get done?</p><Link className="hv-primary-link" to="/work/new-session">Start a governed session →</Link></div>
    <div className="hv-app-grid"><Card><h2>Systems</h2><Muted>Inspect autonomous institutions and their desired-versus-observed topology.</Muted><Link className="hv-link" to="/systems">Open Systems</Link></Card><Card><h2>Work</h2><Muted>One typed projection over sessions, runs, queues, rooms, reviews, and history.</Muted><Link className="hv-link" to="/work">Open Work</Link></Card><Card><h2>Applications</h2><Muted>Launch from the policy-filtered product-surface compiler.</Muted><Link className="hv-link" to="/applications">Browse Applications</Link></Card></div>
  </div>;
}
