import { AgentInstallModal } from "../../components/AgentInstallModal";
import { CommandPalette } from "../../components/CommandPalette";
import { TauriRuntime } from "../../services/TauriRuntime";
import { StudioWindowMainContent } from "./components/StudioWindowMainContent";
import { useStudioWindowController } from "./useStudioWindowController";

import "@ioi/agent-ide/dist/style.css";
import "./StudioWindow.css";

const runtime = new TauriRuntime();

export function StudioWindow() {
  const controller = useStudioWindowController();

  return (
    <div className="studio-window">
      <StudioWindowMainContent controller={controller} runtime={runtime} />

      {controller.modals.commandPaletteOpen ? (
        <CommandPalette onClose={controller.modals.closeCommandPalette} />
      ) : null}

      {controller.modals.installModalOpen && controller.agents.selectedAgent ? (
        <AgentInstallModal
          isOpen={controller.modals.installModalOpen}
          onClose={controller.modals.closeInstallModal}
          agent={controller.agents.selectedAgent}
        />
      ) : null}
    </div>
  );
}
