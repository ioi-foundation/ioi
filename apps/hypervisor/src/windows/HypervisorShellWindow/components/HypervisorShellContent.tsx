import clsx from "clsx";
import { useEffect, useState } from "react";

import { buildConnectorPolicySummary } from "../../../surfaces/Policy";
import { useHypervisorShellController } from "../useHypervisorShellController";
import { type HypervisorClientRuntime } from "../../../services/HypervisorClientRuntime";
import { buildConnectorTrustProfile } from "../../../surfaces/Capabilities";
import { ChatLocalActivityBar } from "./ChatLocalActivityBar";
import { CapabilitiesView } from "../../../surfaces/Capabilities";
import { InboxView } from "../../../surfaces/Inbox";
import {
  MissionControlControlView,
  MissionControlMountsView,
  MissionControlRunsView,
  MissionControlWorkflowsView,
} from "../../../surfaces/MissionControl";
import { HypervisorClientHeader } from "./HypervisorClientHeader";
import { ChatCopilotView } from "./ChatCopilot";
import { HomeView } from "../../../surfaces/Home";
import { ChatLeftUtilityPane } from "./ChatLeftUtilityPane";
import { ChatUtilityDrawer } from "./ChatUtilityDrawer";
import { WorkspaceShell } from "../../../surfaces/Workspace";
import {
  directWorkspaceWorkbenchHost,
  getDefaultWorkspaceWorkbenchHost,
  openVsCodeWorkbenchHost,
} from "../../../services/workspaceWorkbenchHostRegistry";
import { buildOperatorCommandCenterModel } from "../operatorSubstrateModel";
import { materializeWorkflowProject } from "../../../services/workflowProjectMaterialization";
import type { PrimaryView } from "../hypervisorShellModel";

interface HypervisorShellContentProps {
  controller: ReturnType<typeof useHypervisorShellController>;
  runtime: HypervisorClientRuntime;
}

const PLACEHOLDER_SURFACE_COPY: Partial<
  Record<PrimaryView, { eyebrow: string; title: string; body: string; tags: string[] }>
> = {
  projects: {
    eyebrow: "Project state",
    title: "Projects will bind repos, workspace state, and restore posture.",
    body:
      "This surface is where Hypervisor will group local folders, remote workspaces, Agentgres state refs, encrypted artifact refs, and zero-to-idle restore material without making any editor the parent product.",
    tags: ["Workspace refs", "Restore posture", "Artifact refs"],
  },
  privacy: {
    eyebrow: "Private workspace",
    title: "Privacy will expose cTEE custody state and declassification gates.",
    body:
      "This surface tracks public trunks, redacted projections, encrypted refs, private handles, model-mount posture, and explicit unsafe mounts before a provider or adapter sees sensitive state.",
    tags: ["cTEE", "No plaintext custody", "Declassification"],
  },
  fleet: {
    eyebrow: "Provider estate",
    title: "Fleet will manage direct provider integrations.",
    body:
      "This surface is for local machines, customer clouds, DePIN providers, VMs, containers, HypervisorOS nodes, ports, services, spend leases, and provider receipts.",
    tags: ["Local", "Cloud", "DePIN"],
  },
  foundry: {
    eyebrow: "Evals and promotion",
    title: "Foundry will govern evals, distillation, benchmarks, and package promotion.",
    body:
      "This is not the meta harness. It is the application surface for training, evaluation, scorecards, promotion candidates, and artifact-backed release evidence.",
    tags: ["Evals", "Benchmarks", "Promotion"],
  },
  receipts: {
    eyebrow: "Operational evidence",
    title: "Receipts will become the audit and replay console.",
    body:
      "This surface will index action receipts, Agentgres operation refs, artifact refs, trace refs, state roots, delivery evidence, and restore/import proof chains.",
    tags: ["Agentgres", "Replay", "State roots"],
  },
};

function isPlaceholderSurface(view: PrimaryView): boolean {
  return Boolean(PLACEHOLDER_SURFACE_COPY[view]);
}

function HypervisorSurfacePlaceholder({
  activeView,
}: {
  activeView: PrimaryView;
}) {
  const copy = PLACEHOLDER_SURFACE_COPY[activeView];
  if (!copy) {
    return null;
  }

  return (
    <section
      className="hypervisor-surface-placeholder"
      data-testid={`hypervisor-surface-placeholder-${activeView}`}
      data-hypervisor-surface={activeView}
      aria-label={copy.title}
    >
      <div className="hypervisor-surface-placeholder-eyebrow">
        {copy.eyebrow}
      </div>
      <h2>{copy.title}</h2>
      <p>{copy.body}</p>
      <div className="hypervisor-surface-placeholder-tags" aria-label="Surface primitives">
        {copy.tags.map((tag) => (
          <span key={tag}>{tag}</span>
        ))}
      </div>
    </section>
  );
}

export function HypervisorShellContent({
  controller,
  runtime,
}: HypervisorShellContentProps) {
  const { activeView, currentProject, projects, notificationBadgeCount } =
    controller;
  const workspaceHost = getDefaultWorkspaceWorkbenchHost();
  const workspaceUsesNativeWorkbenchChat =
    workspaceHost === directWorkspaceWorkbenchHost ||
    workspaceHost === openVsCodeWorkbenchHost;
  const workspaceActive = activeView === "workbench";
  const workflowActive = activeView === "automations";
  const mountsActive = activeView === "models";
  const dedicatedWorkbenchActive = workflowActive || mountsActive;

  const auxiliaryChatVisible =
    !workspaceActive &&
    !dedicatedWorkbenchActive &&
    activeView !== "sessions" &&
    activeView !== "home" &&
    controller.chat.paneVisible;
  const utilityDrawerVisible =
    activeView !== "sessions" && activeView !== "home" && !dedicatedWorkbenchActive;
  const auxiliaryChatFullscreen =
    auxiliaryChatVisible && controller.chat.paneMaximized;
  const commandCenterModel = buildOperatorCommandCenterModel({
    activeView,
    workflowSurface: controller.workflow.surface,
    currentProject,
    notificationCount: notificationBadgeCount,
  });
  const [workspaceChatDismissed, setWorkspaceChatDismissed] = useState(false);

  useEffect(() => {
    if (!workspaceActive) {
      setWorkspaceChatDismissed(false);
    }
  }, [workspaceActive]);

  const workspaceOperatorChatPaneWidthPx = controller.chat.paneMaximized
    ? 560
    : 360;
  const workspaceOperatorChatPane =
    workspaceActive &&
    !workspaceUsesNativeWorkbenchChat &&
    !workspaceChatDismissed ? (
      <ChatLeftUtilityPane
        surface={controller.chat.surface}
        session={controller.chat.assistantWorkbench}
        runtime={runtime}
        maximized={controller.chat.paneMaximized}
        seedIntent={null}
        onConsumeSeedIntent={undefined}
        onClose={() => {
          setWorkspaceChatDismissed(true);
          controller.chat.hidePane();
        }}
        onToggleMaximize={controller.chat.toggleMaximize}
        onBackToInbox={() => {
          controller.chat.setSurface("chat");
          controller.changePrimaryView("missions");
        }}
        onOpenInbox={() => controller.changePrimaryView("missions")}
        onOpenAutopilot={controller.chat.openAutopilotWithIntent}
      />
    ) : null;

  return (
    <div
      className={clsx(
        "chat-shell",
        workspaceActive && "chat-shell--workspace-mode",
      )}
    >
      <HypervisorClientHeader
        activeView={activeView}
        workflowSurface={controller.workflow.surface}
        commandCenter={commandCenterModel}
        onOpenCommandPalette={controller.modals.openCommandPalette}
      />

      <div
        className={clsx(
          "chat-workspace",
          workspaceActive && "chat-workspace--workspace-mode",
        )}
      >
        <ChatLocalActivityBar
          activeView={activeView}
          onViewChange={controller.changePrimaryView}
          onOpenCommandPalette={controller.modals.openCommandPalette}
          notificationCount={notificationBadgeCount}
          profile={controller.profile.value}
        />

        <div
          className={clsx(
            "chat-main",
            workspaceActive && "chat-main--workspace-mode",
          )}
        >
          <WorkspaceShell
            active={workspaceActive}
            currentProject={currentProject}
            projects={projects}
            runtime={runtime}
            host={workspaceHost}
            operatorChatPane={workspaceOperatorChatPane}
            operatorChatPaneWidthPx={workspaceOperatorChatPaneWidthPx}
            commandPaletteOpen={controller.modals.commandPaletteOpen}
            onOpenCommandPalette={controller.modals.openCommandPalette}
          />

          {!workspaceActive ? (
            <div
              className={clsx(
                "chat-content",
                auxiliaryChatFullscreen && "is-chat-fullscreen",
                dedicatedWorkbenchActive && "is-dedicated-workbench",
              )}
            >
              <div className="chat-center-area">
                <div
                  className={clsx(
                    "chat-content-main",
                    dedicatedWorkbenchActive &&
                      "chat-content-main--dedicated-workbench",
                  )}
                >
                  {activeView === "home" ? (
                    <HomeView
                      currentProject={currentProject}
                      projects={projects}
                      notificationCount={notificationBadgeCount}
                      onOpenChat={() => controller.changePrimaryView("sessions")}
                      onOpenWorkspace={() =>
                        controller.changePrimaryView("workbench")
                      }
                      onOpenRuns={() => controller.changePrimaryView("insights")}
                      onOpenModels={() =>
                        controller.changePrimaryView("models")
                      }
                      onOpenInbox={() => controller.changePrimaryView("missions")}
                      onOpenCapabilities={() =>
                        controller.changePrimaryView("agents")
                      }
                      onOpenPolicy={() =>
                        controller.policy.openPolicyCenter(null)
                      }
                      onOpenSettings={controller.settings.openSection}
                      onOpenCommandPalette={
                        controller.modals.openCommandPalette
                      }
                      onSelectProject={controller.workflow.selectProject}
                    />
                  ) : null}

                  {activeView === "sessions" ? (
                    <ChatCopilotView
                      seedIntent={controller.chat.seedIntent}
                      onConsumeSeedIntent={controller.chat.consumeSeedIntent}
                      sessionRuntime={runtime}
                      workspaceRootHint={currentProject.rootPath}
                      workspaceNameHint={currentProject.name}
                    />
                  ) : null}

                  {activeView === "automations" ? (
                    <MissionControlWorkflowsView
                      runtime={runtime}
                      surface={controller.workflow.surface}
                      currentProject={currentProject}
                      projects={projects}
                      notificationCount={notificationBadgeCount}
                      editingAgent={controller.agents.editingAgent}
                      onSurfaceChange={controller.workflow.setSurface}
                      onSelectProject={controller.workflow.selectProject}
                      onOpenChat={() => controller.changePrimaryView("sessions")}
                      onOpenInbox={() => controller.changePrimaryView("missions")}
                      onOpenCapabilities={() =>
                        controller.changePrimaryView("agents")
                      }
                      onOpenPolicy={() =>
                        controller.policy.openPolicyCenter(null)
                      }
                      onOpenSettings={() =>
                        controller.changePrimaryView("settings")
                      }
                      onOpenAgent={controller.agents.openBuilder}
                      onCloseAgent={controller.agents.closeBuilder}
                      onStageCatalogEntry={
                        controller.catalog.openStageModalForEntry
                      }
                      composeSeedProject={
                        controller.workflow.composeSeedProject
                      }
                      onConsumeComposeSeedProject={
                        controller.workflow.consumeComposeSeedProject
                      }
                      workflowPreflightSeed={controller.workflow.preflightSeed}
                      onConsumeWorkflowPreflightSeed={
                        controller.workflow.consumePreflightSeed
                      }
                      onMaterializeWorkflowProject={async (request) => {
                        const result =
                          await materializeWorkflowProject(request);
                        controller.changePrimaryView("workbench");
                        return result;
                      }}
                      onAddBuilderConfigToCanvas={(config) => {
                        controller.workflow.queueBuilderConfigToCanvas(config);
                      }}
                    />
                  ) : null}

                  {activeView === "insights" ? (
                    <MissionControlRunsView runtime={runtime} />
                  ) : null}

                  {activeView === "models" ? (
                    <MissionControlMountsView />
                  ) : null}

                  {activeView === "missions" ? (
                    <InboxView
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

                  {activeView === "agents" ? (
                    <CapabilitiesView
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
                        controller.policy.openPolicyCenter(
                          connector?.id ?? null,
                        )
                      }
                      onOpenInbox={() => controller.changePrimaryView("missions")}
                      onOpenSettings={() =>
                        controller.changePrimaryView("settings")
                      }
                      onOpenSkillSources={() =>
                        controller.settings.openSection("skill_sources")
                      }
                      seedSurface={controller.capabilities.seedSurface}
                      seedConnectorId={
                        controller.capabilities.targetConnectorId
                      }
                      seedConnectionDetailSection={
                        controller.capabilities.targetDetailSection
                      }
                      onConsumeSeedSurface={
                        controller.capabilities.consumeSeedSurface
                      }
                      onConsumeSeedConnector={
                        controller.capabilities.consumeTarget
                      }
                    />
                  ) : null}

                  {activeView === "authority" || activeView === "settings" ? (
                    <MissionControlControlView
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
                          surface === "policy" ? "authority" : "settings",
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
                        controller.changePrimaryView("agents")
                      }
                      onOpenModelRoutes={() =>
                        controller.changePrimaryView("models")
                      }
                      onOpenWorkflowPreflight={(seed) =>
                        controller.workflow.openPreflight(
                          seed ?? {
                            panel: "readiness",
                            source: "authority-center",
                          },
                        )
                      }
                    />
                  ) : null}

                  {isPlaceholderSurface(activeView) ? (
                    <HypervisorSurfacePlaceholder activeView={activeView} />
                  ) : null}
                </div>

                {utilityDrawerVisible ? (
                  <ChatUtilityDrawer
                    runtime={runtime}
                    activeView={activeView}
                    chatSurface={controller.chat.surface}
                    operatorPaneOpen={controller.chat.paneVisible}
                    notificationCount={notificationBadgeCount}
                    shieldPolicy={controller.policy.shieldPolicy}
                    currentProject={currentProject}
                    focusedPolicyConnectorId={
                      controller.policy.focusedConnectorId
                    }
                    assistantWorkbench={controller.chat.assistantWorkbench}
                    onOpenChatConversation={() =>
                      controller.changePrimaryView("sessions")
                    }
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
                    controller.changePrimaryView("missions");
                  }}
                  onOpenInbox={() => controller.changePrimaryView("missions")}
                  onOpenAutopilot={controller.chat.openAutopilotWithIntent}
                />
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
