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
  const chatVisibleSources = process.sources.filter(
    (source) => source.kind !== "receipt" && source.kind !== "trace",
  );
  return (
    <section className="assistant-turn" aria-label="Assistant turn">
      <AssistantProcessDisclosure process={process} />
      {children}
      {chatVisibleSources.length > 0 ? (
        <div className="assistant-turn__sources" aria-label="Sources">
          <span className="assistant-turn__sources-label">Sources</span>
          <div className="assistant-turn__source-list">
            {chatVisibleSources.map((source) => (
              <SourcePill key={source.id} source={source} />
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
