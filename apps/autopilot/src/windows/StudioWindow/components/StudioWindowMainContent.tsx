import { buildConnectorPolicySummary } from "../policyCenter";
import { WORKSPACE_NAME } from "../studioWindowModel";
import { useStudioWindowController } from "../useStudioWindowController";
import { type TauriRuntime } from "../../../services/TauriRuntime";
import { StatusBar } from "../../../components/StatusBar";
import { LocalActivityBar } from "./LocalActivityBar";
import { CapabilitiesView } from "./CapabilitiesView";
import { MissionControlControlView } from "./MissionControlControlView";
import { MissionControlRunsView } from "./MissionControlRunsView";
import { MissionControlWorkflowsView } from "./MissionControlWorkflowsView";
import { NotificationsView } from "./NotificationsView";
import { StudioExplorerPane } from "./StudioExplorerPane";
import { StudioExplorerView } from "./StudioExplorerView";
import { StudioIdeHeader } from "./StudioIdeHeader";
import { StudioLeftUtilityPane } from "./StudioLeftUtilityPane";
import { StudioUtilityDrawer } from "./StudioUtilityDrawer";

interface StudioWindowMainContentProps {
  controller: ReturnType<typeof useStudioWindowController>;
  runtime: TauriRuntime;
}

export function StudioWindowMainContent({
  controller,
  runtime,
}: StudioWindowMainContentProps) {
  const { activeView, currentProject, projects, notificationBadgeCount } =
    controller;

  return (
    <>
      <LocalActivityBar
        activeView={activeView}
        onViewChange={controller.changePrimaryView}
        notificationCount={notificationBadgeCount}
        currentProject={currentProject}
      />

      <div className="studio-main">
        <StudioIdeHeader
          workspaceName={WORKSPACE_NAME}
          currentProject={currentProject}
          projects={projects}
          activeView={activeView}
          workflowSurface={controller.workflow.surface}
          chatVisible={controller.chat.paneVisible}
          notificationCount={notificationBadgeCount}
          onSelectProject={controller.workflow.selectProject}
          onToggleChat={controller.chat.togglePaneVisibility}
          onOpenCommandPalette={controller.modals.openCommandPalette}
        />

        <div
          className={`studio-content ${controller.chatFullscreen ? "is-chat-fullscreen" : ""}`}
        >
          {activeView === "explorer" ? (
            <StudioExplorerPane
              currentProject={currentProject}
              activeFilePath={controller.workflow.activeEditorPath}
              onOpenFile={controller.workflow.openProjectFile}
            />
          ) : null}

          <div className="studio-center-area">
            <div className="studio-content-main">
              {activeView === "explorer" ? (
                <StudioExplorerView
                  editorTabs={controller.workflow.editorTabs}
                  activeEditorPath={controller.workflow.activeEditorPath}
                  onSelectEditorTab={controller.workflow.selectEditorTab}
                  onCloseEditorTab={controller.workflow.closeEditorTab}
                  onChangeEditorTabContent={
                    controller.workflow.updateEditorTabContent
                  }
                  onSaveEditorTab={controller.workflow.saveEditorTab}
                />
              ) : null}

              {activeView === "workflows" ? (
                <MissionControlWorkflowsView
                  runtime={runtime}
                  surface={controller.workflow.surface}
                  currentProject={currentProject}
                  projects={projects}
                  notificationCount={notificationBadgeCount}
                  editingAgent={controller.agents.editingAgent}
                  onSurfaceChange={controller.workflow.setSurface}
                  onSelectProject={controller.workflow.selectProject}
                  onOpenInbox={() => controller.changePrimaryView("inbox")}
                  onOpenCapabilities={() =>
                    controller.changePrimaryView("capabilities")
                  }
                  onOpenPolicy={() =>
                    controller.policy.openPolicyCenter(null)
                  }
                  onOpenAgent={controller.agents.openBuilder}
                  onCloseAgent={controller.agents.closeBuilder}
                  onInstallAgent={controller.agents.openInstallModalForAgent}
                  onAddBuilderConfigToCanvas={(config) => {
                    void runtime.loadBuilderConfigToCompose(config).catch((error) => {
                      console.error("Builder->Compose handoff unavailable:", error);
                    });
                  }}
                />
              ) : null}

              {activeView === "runs" ? (
                <MissionControlRunsView runtime={runtime} />
              ) : null}

              {activeView === "inbox" ? (
                <NotificationsView
                  onOpenAutopilot={() => {
                    controller.chat.setSurface("chat");
                    controller.chat.showPane();
                  }}
                  onOpenIntegrations={() =>
                    controller.changePrimaryView("capabilities")
                  }
                  onOpenShield={(connectorId) =>
                    controller.policy.openPolicyCenter(connectorId)
                  }
                  onOpenSettings={() =>
                    controller.changePrimaryView("settings")
                  }
                  onOpenReplyComposer={controller.chat.openReplyComposer}
                  onOpenMeetingPrep={controller.chat.openMeetingPrep}
                />
              ) : null}

              {activeView === "capabilities" ? (
                <CapabilitiesView
                  runtime={runtime}
                  getConnectorPolicySummary={(connector) =>
                    buildConnectorPolicySummary(
                      controller.policy.shieldPolicy,
                      connector.id,
                    )
                  }
                  onOpenPolicyCenter={(connector) =>
                    controller.policy.openPolicyCenter(connector.id)
                  }
                />
              ) : null}

              {activeView === "policy" || activeView === "settings" ? (
                <MissionControlControlView
                  runtime={runtime}
                  surface={activeView === "settings" ? "system" : "policy"}
                  policyState={controller.policy.shieldPolicy}
                  profile={controller.profile.value}
                  profileDraft={controller.profile.draft}
                  profileSaving={controller.profile.saving}
                  profileError={controller.profile.error}
                  focusedConnectorId={controller.policy.focusedConnectorId}
                  onSurfaceChange={(surface) =>
                    controller.changePrimaryView(
                      surface === "policy" ? "policy" : "settings",
                    )
                  }
                  onPolicyChange={controller.policy.setShieldPolicy}
                  onProfileDraftChange={controller.profile.updateDraft}
                  onResetProfileDraft={controller.profile.resetDraft}
                  onSaveProfile={controller.profile.saveDraft}
                  onFocusConnector={controller.policy.focusConnector}
                  onOpenConnections={() =>
                    controller.changePrimaryView("capabilities")
                  }
                />
              ) : null}
            </div>

            <StudioUtilityDrawer
              runtime={runtime}
              activeView={activeView}
              chatSurface={controller.chat.surface}
              operatorPaneOpen={controller.chat.paneVisible}
              workflowSurface={controller.workflow.surface}
              notificationCount={notificationBadgeCount}
              shieldPolicy={controller.policy.shieldPolicy}
              currentProject={currentProject}
              focusedPolicyConnectorId={controller.policy.focusedConnectorId}
              assistantWorkbench={controller.chat.assistantWorkbench}
              profile={controller.profile.value}
            />
          </div>

          {controller.chat.paneVisible ? (
            <StudioLeftUtilityPane
              surface={controller.chat.surface}
              session={controller.chat.assistantWorkbench}
              runtime={runtime}
              maximized={controller.chat.paneMaximized}
              seedIntent={controller.chat.seedIntent}
              onConsumeSeedIntent={controller.chat.consumeSeedIntent}
              onClose={controller.chat.hidePane}
              onToggleMaximize={controller.chat.toggleMaximize}
              onBackToInbox={() => {
                controller.chat.setSurface("chat");
                controller.changePrimaryView("inbox");
              }}
              onOpenInbox={() => controller.changePrimaryView("inbox")}
              onOpenAutopilot={controller.chat.openAutopilotWithIntent}
            />
          ) : null}
        </div>

        {controller.showStatusBar ? (
          <StatusBar
            metrics={{ cost: 0.0, privacy: 0.0, risk: 0.0 }}
            status="Ready"
            onOpenShield={() =>
              controller.policy.openPolicyCenter(
                controller.policy.focusedConnectorId,
              )
            }
          />
        ) : null}
      </div>
    </>
  );
}
