import { useCallback } from "react";
import { buildConnectorPolicySummary } from "../chatPolicyCenter";
import { WORKSPACE_NAME } from "../chatWindowModel";
import { useChatWindowController } from "../useChatWindowController";
import { type TauriRuntime } from "../../../services/TauriRuntime";
import { StatusBar } from "../../../components/StatusBar";
import { buildConnectorTrustProfile } from "./capabilities/model";
import { ChatLocalActivityBar } from "./ChatLocalActivityBar";
import { ChatCapabilitiesView } from "./ChatCapabilitiesView";
import { ChatMissionControlControlView } from "./ChatMissionControlControlView";
import { ChatMissionControlRunsView } from "./ChatMissionControlRunsView";
import { ChatMissionControlWorkflowsView } from "./ChatMissionControlWorkflowsView";
import { ChatNotificationsView } from "./ChatNotificationsView";
import { ChatIdeHeader } from "./ChatIdeHeader";
import { ChatCopilotView } from "./ChatCopilot";
import { ChatLeftUtilityPane } from "./ChatLeftUtilityPane";
import { ChatUtilityDrawer } from "./ChatUtilityDrawer";

interface ChatWindowMainContentProps {
  controller: ReturnType<typeof useChatWindowController>;
  runtime: TauriRuntime;
}

export function ChatWindowMainContent({
  controller,
  runtime,
}: ChatWindowMainContentProps) {
  const { activeView, currentProject, projects, notificationBadgeCount } =
    controller;
  const auxiliaryChatVisible =
    activeView !== "studio" && controller.chat.paneVisible;
  const auxiliaryChatFullscreen =
    auxiliaryChatVisible && controller.chat.paneMaximized;
  const openNewTerminal = useCallback(() => {
    controller.chat.openAutopilotWithIntent(
      "Open the active artifact's workspace terminal lens if a workspace renderer is available.",
    );
    controller.changePrimaryView("studio");
  }, [controller]);

  return (
    <div className="studio-shell">
      <ChatIdeHeader
        workspaceName={WORKSPACE_NAME}
        currentProject={currentProject}
        projects={projects}
        activeView={activeView}
        workflowSurface={controller.workflow.surface}
        chatVisible={auxiliaryChatVisible}
        notificationCount={notificationBadgeCount}
        onSelectProject={controller.workflow.selectProject}
        onToggleChat={controller.chat.togglePaneVisibility}
        onOpenCommandPalette={controller.modals.openCommandPalette}
        onOpenNewTerminal={openNewTerminal}
      />

      <div className="studio-workspace">
        <ChatLocalActivityBar
          activeView={activeView}
          onViewChange={controller.changePrimaryView}
          notificationCount={notificationBadgeCount}
          currentProject={currentProject}
        />

        <div className="studio-main">
          <div
            className={`studio-content ${auxiliaryChatFullscreen ? "is-chat-fullscreen" : ""}`}
          >
            <div className="studio-center-area">
              <div className="studio-content-main">
                {activeView === "studio" ? (
                  <ChatCopilotView
                    seedIntent={controller.chat.seedIntent}
                    onConsumeSeedIntent={controller.chat.consumeSeedIntent}
                    sessionRuntime={runtime}
                  />
                ) : null}

                {activeView === "workflows" ? (
                  <ChatMissionControlWorkflowsView
                    runtime={runtime}
                    surface={controller.workflow.surface}
                    currentProject={currentProject}
                    projects={projects}
                    notificationCount={notificationBadgeCount}
                    editingAgent={controller.agents.editingAgent}
                    onSurfaceChange={controller.workflow.setSurface}
                    onSelectProject={controller.workflow.selectProject}
                    onOpenStudio={() => controller.changePrimaryView("studio")}
                    onOpenInbox={() => controller.changePrimaryView("inbox")}
                    onOpenCapabilities={() =>
                      controller.changePrimaryView("capabilities")
                    }
                    onOpenPolicy={() =>
                      controller.policy.openPolicyCenter(null)
                    }
                    onOpenSettings={() =>
                      controller.changePrimaryView("settings")
                    }
                    onOpenAgent={controller.agents.openBuilder}
                    onCloseAgent={controller.agents.closeBuilder}
                    onStageCatalogEntry={controller.catalog.openStageModalForEntry}
                    composeSeedProject={controller.workflow.composeSeedProject}
                    onConsumeComposeSeedProject={
                      controller.workflow.consumeComposeSeedProject
                    }
                    onAddBuilderConfigToCanvas={(config) => {
                      controller.workflow.queueBuilderConfigToCanvas(config);
                    }}
                  />
                ) : null}

                {activeView === "runs" ? (
                  <ChatMissionControlRunsView runtime={runtime} />
                ) : null}

                {activeView === "inbox" ? (
                  <ChatNotificationsView
                    onOpenAutopilot={() => {
                      controller.chat.setSurface("chat");
                      controller.chat.showPane();
                    }}
                    onOpenIntegrations={() =>
                      controller.capabilities.openSurface(null)
                    }
                    onOpenLocalEngine={() =>
                      controller.capabilities.openSurface("engine")
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
                  <ChatCapabilitiesView
                    runtime={runtime}
                    getConnectorPolicySummary={(connector) =>
                      buildConnectorPolicySummary(
                        controller.policy.shieldPolicy,
                        connector.id,
                      )
                    }
                    getConnectorTrustProfile={(connector, options) =>
                      buildConnectorTrustProfile(
                        connector,
                        controller.policy.shieldPolicy,
                        options,
                      )
                    }
                    onOpenPolicyCenter={(connector) =>
                      controller.policy.openPolicyCenter(connector?.id ?? null)
                    }
                    onOpenInbox={() => controller.changePrimaryView("inbox")}
                    onOpenSettings={() => controller.changePrimaryView("settings")}
                    onOpenSkillSources={() =>
                      controller.settings.openSection("skill_sources")
                    }
                    seedSurface={controller.capabilities.seedSurface}
                    seedConnectorId={controller.capabilities.targetConnectorId}
                    seedConnectionDetailSection={
                      controller.capabilities.targetDetailSection
                    }
                    onConsumeSeedSurface={
                      controller.capabilities.consumeSeedSurface
                    }
                    onConsumeSeedConnector={controller.capabilities.consumeTarget}
                  />
                ) : null}

                {activeView === "policy" || activeView === "settings" ? (
                  <ChatMissionControlControlView
                    runtime={runtime}
                    surface={activeView === "settings" ? "system" : "policy"}
                    policyState={controller.policy.shieldPolicy}
                    profile={controller.profile.value}
                    profileDraft={controller.profile.draft}
                    profileSaving={controller.profile.saving}
                    profileError={controller.profile.error}
                    governanceRequest={controller.policy.governanceRequest}
                    focusedConnectorId={controller.policy.focusedConnectorId}
                    onSurfaceChange={(surface) =>
                      controller.changePrimaryView(
                        surface === "policy" ? "policy" : "settings",
                      )
                    }
                    settingsSeedSection={controller.settings.seedSection}
                    onConsumeSettingsSeedSection={
                      controller.settings.consumeSeedSection
                    }
                    onPolicyChange={controller.policy.setShieldPolicy}
                    onProfileDraftChange={controller.profile.updateDraft}
                    onResetProfileDraft={controller.profile.resetDraft}
                    onSaveProfile={controller.profile.saveDraft}
                    onFocusConnector={controller.policy.focusConnector}
                    onApplyGovernanceRequest={
                      controller.policy.applyGovernanceRequest
                    }
                    onDismissGovernanceRequest={
                      controller.policy.dismissGovernanceRequest
                    }
                    onOpenConnections={() =>
                      controller.changePrimaryView("capabilities")
                    }
                  />
                ) : null}
              </div>

              {activeView !== "studio" ? (
                <ChatUtilityDrawer
                  runtime={runtime}
                  activeView={activeView}
                  chatSurface={controller.chat.surface}
                  operatorPaneOpen={controller.chat.paneVisible}
                  notificationCount={notificationBadgeCount}
                  shieldPolicy={controller.policy.shieldPolicy}
                  currentProject={currentProject}
                  focusedPolicyConnectorId={controller.policy.focusedConnectorId}
                  assistantWorkbench={controller.chat.assistantWorkbench}
                  onOpenChatConversation={() => controller.changePrimaryView("studio")}
                />
              ) : null}
            </div>

            {auxiliaryChatVisible ? (
              <ChatLeftUtilityPane
                surface={controller.chat.surface}
                session={controller.chat.assistantWorkbench}
                runtime={runtime}
                maximized={controller.chat.paneMaximized}
                seedIntent={null}
                onConsumeSeedIntent={undefined}
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
      </div>
    </div>
  );
}
