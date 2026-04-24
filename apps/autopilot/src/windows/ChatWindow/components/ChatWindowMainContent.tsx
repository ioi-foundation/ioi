import { buildConnectorPolicySummary } from "../chatPolicyCenter";
import { useChatWindowController } from "../useChatWindowController";
import { type TauriRuntime } from "../../../services/TauriRuntime";
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
import { WorkspaceShell } from "../../../services/WorkspaceShell";
import { getDefaultWorkspaceWorkbenchHost } from "../../../services/workspaceWorkbenchHostRegistry";

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
  const workspaceHost = getDefaultWorkspaceWorkbenchHost();

  if (activeView === "workspace") {
    return (
      <div className="chat-shell chat-shell--workspace-mode">
        <ChatIdeHeader
          activeView={activeView}
          workflowSurface={controller.workflow.surface}
        />

        <div className="chat-workspace chat-workspace--workspace-mode">
          <ChatLocalActivityBar
            activeView={activeView}
            onViewChange={controller.changePrimaryView}
            notificationCount={notificationBadgeCount}
            currentProject={currentProject}
          />

          <div className="chat-main chat-main--workspace-mode">
            <WorkspaceShell
              active
              currentProject={currentProject}
              runtime={runtime}
              host={workspaceHost}
            />
          </div>
        </div>
      </div>
    );
  }

  const auxiliaryChatVisible =
    activeView !== "chat" && controller.chat.paneVisible;
  const auxiliaryChatFullscreen =
    auxiliaryChatVisible && controller.chat.paneMaximized;

  return (
    <div className="chat-shell">
      <ChatIdeHeader
        activeView={activeView}
        workflowSurface={controller.workflow.surface}
      />

      <div className="chat-workspace">
        <ChatLocalActivityBar
          activeView={activeView}
          onViewChange={controller.changePrimaryView}
          notificationCount={notificationBadgeCount}
          currentProject={currentProject}
        />

        <div className="chat-main">
          <div
            className={`chat-content ${auxiliaryChatFullscreen ? "is-chat-fullscreen" : ""}`}
          >
            <div className="chat-center-area">
              <div className="chat-content-main">
                {activeView === "chat" ? (
                  <ChatCopilotView
                    seedIntent={controller.chat.seedIntent}
                    onConsumeSeedIntent={controller.chat.consumeSeedIntent}
                    sessionRuntime={runtime}
                    workspaceRootHint={currentProject.rootPath}
                    workspaceNameHint={currentProject.name}
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
                    onOpenChat={() => controller.changePrimaryView("chat")}
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

              {activeView !== "chat" ? (
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
                  onOpenChatConversation={() => controller.changePrimaryView("chat")}
                />
              ) : null}
            </div>

            {auxiliaryChatVisible ? (
              <ChatLeftUtilityPane
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
        </div>
      </div>
    </div>
  );
}
