import type { ReactNode } from "react";
import type { AssistantTurnProcess } from "../utils/assistantTurnProcessModel";
import { AssistantProcessDisclosure } from "./AssistantProcessDisclosure";
import { SourcePill } from "./SourcePill";

type AssistantTurnProps = {
  process: AssistantTurnProcess;
  children?: ReactNode;
};

export function AssistantTurn({
  process,
  children,
}: AssistantTurnProps) {
  return (
    <section className="assistant-turn" aria-label="Assistant turn">
      <AssistantProcessDisclosure process={process} />
      {children}
      {process.sources.length > 0 ? (
        <div className="assistant-turn__sources" aria-label="Sources and evidence">
          <span className="assistant-turn__sources-label">Sources</span>
          <div className="assistant-turn__source-list">
            {process.sources.map((source) => (
              <SourcePill key={source.id} source={source} />
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
