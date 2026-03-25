import { Suspense, lazy } from "react";
import type { StudioEditorTab } from "./StudioCodeWorkbench";

const StudioCodeWorkbench = lazy(async () => {
  const module = await import("./StudioCodeWorkbench");
  return { default: module.StudioCodeWorkbench };
});

interface StudioExplorerViewProps {
  editorTabs: StudioEditorTab[];
  activeEditorPath: string | null;
  onSelectEditorTab: (path: string) => void;
  onCloseEditorTab: (path: string) => void;
  onChangeEditorTabContent: (path: string, content: string) => void;
  onSaveEditorTab: (path: string) => void;
}

export function StudioExplorerView({
  editorTabs,
  activeEditorPath,
  onSelectEditorTab,
  onCloseEditorTab,
  onChangeEditorTabContent,
  onSaveEditorTab,
}: StudioExplorerViewProps) {
  return (
    <div className="mission-control-view mission-control-view--workflows">
      <div className="mission-control-stage mission-control-stage--workflow">
        <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
          <Suspense
            fallback={
              <section className="studio-code-workbench studio-code-workbench--empty">
                <div className="studio-code-message">
                  <strong>Loading explorer</strong>
                  <p>
                    Studio loads the editor surface on demand so the shell stays
                    lighter until you open the explorer.
                  </p>
                </div>
              </section>
            }
          >
            <StudioCodeWorkbench
              tabs={editorTabs}
              activePath={activeEditorPath}
              onSelectTab={onSelectEditorTab}
              onCloseTab={onCloseEditorTab}
              onChangeTabContent={onChangeEditorTabContent}
              onSaveTab={onSaveEditorTab}
            />
          </Suspense>
        </div>
      </div>
    </div>
  );
}
