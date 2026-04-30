import type { Node, WorkflowWorkbenchTab } from "../types/graph";
import type { useWorkflowComposerController } from "./controller";

export type WorkflowComposerViewModel = ReturnType<typeof useWorkflowComposerController>;

export function WorkflowComposerView(model: WorkflowComposerViewModel) {
  const {
    activeRightPanelMeta,
    activeTab,
    bindingManifest,
    BOTTOM_TABS,
    bottomPanel,
    Brain,
    Cable,
    CheckCircle2,
    GitCompare,
    Canvas,
    canvasSearchOpen,
    canvasSearchQuery,
    canvasSearchResults,
    checkpoints,
    closeCanvasSearch,
    closeLeftDrawer,
    compareRunId,
    compareRunResult,
    compatibleNodeHints,
    compatiblePortFocusLabel,
    connectFromNodeId,
    ConnectorBindingModal,
    connectorBindingOpen,
    counts,
    createKind,
    createMode,
    createName,
    createOpen,
    CreateWorkflowModal,
    currentProject,
    currentProjectFile,
    DeployModal,
    deployOpen,
    displayEdges,
    displayNodes,
    dogfoodRun,
    emptyCanvasStartItems,
    execution,
    executionCheckpointCount,
    executionCompareRun,
    executionStatusCounts,
    filteredNodeLibrary,
    fitView,
    FlaskConical,
    functionDryRunResult,
    GitPullRequest,
    globalConfig,
    guardedCanvasDrop,
    guardedOnConnect,
    guardedOnEdgesChange,
    guardedOnNodesChange,
    handleAddCompatibleNode,
    handleAddNodeFromLibrary,
    handleAddTest,
    handleAddTestFromOutput,
    handleApplyProposal,
    handleCaptureNodeFixture,
    handleCheckReadiness,
    handleCheckWorkflowBinding,
    handleCompareRun,
    handleConnectSelectedNodes,
    handleCreateProposal,
    handleCreateWorkflow,
    handleDragStart,
    handleDryRunFunction,
    handleDryRunNodeFromFixture,
    handleExportPortablePackage,
    handleForkDefaultHarness,
    handleGenerateBindingManifest,
    handleImportNodeFixture,
    handleImportPortablePackage,
    handleInsertAgentLoopMacro,
    handleInspectExecutionNode,
    handleOpenDefaultHarness,
    handleOpenDeploy,
    handlePinNodeFixture,
    handleResolveWorkflowIssue,
    handleResumeRun,
    handleRun,
    handleRunTests,
    handleRunWorkflowNode,
    handleRunWorkflowUpstream,
    handleSave,
    handleSelectRun,
    handleUpdateEnvironmentProfile,
    handleUpdateProductionProfile,
    handleValidate,
    handleWorkflowNodeSelect,
    harnessWorkerBinding,
    ImportPackageModal,
    importPackageName,
    importPackageOpen,
    importPackagePath,
    isBlessedHarnessWorkflow,
    isReadOnlyWorkflow,
    isSearchingNodeLibrary,
    lastRunResult,
    leftDrawerOpen,
    lifecycleState,
    missingReasoningBinding,
    ModelBindingModal,
    modelBindingOpen,
    newTestExpected,
    newTestExpression,
    newTestKind,
    newTestName,
    newTestTargets,
    NODE_GROUP_FILTERS,
    nodeConfigInitialSection,
    nodeConfigOpen,
    nodeGroupCounts,
    nodeGroupFilter,
    nodeRunStatusById,
    nodes,
    nodeSearch,
    openLeftDrawer,
    PanelLeftOpen,
    PanelRightClose,
    PanelRightOpen,
    Play,
    Plus,
    portablePackage,
    proposalBoundedTargetCount,
    ProposalPreviewModal,
    proposals,
    proposalStatusCounts,
    proposalToReview,
    readinessResult,
    recentNodeLibrary,
    RIGHT_PANELS,
    rightPanel,
    rightPanelBadgeCounts,
    rightRailCollapsed,
    rightRailWidth,
    Rocket,
    Search,
    Settings,
    runDetailLoading,
    runEvents,
    runs,
    Save,
    SCAFFOLD_GROUPS,
    WORKFLOW_SCAFFOLDS,
    selectedDefinition,
    selectedExecutionRun,
    selectedExecutionRunResult,
    selectedFixtures,
    selectedNode,
    selectedNodeId,
    selectedRunId,
    selectedUpstreamReferences,
    setActiveTab,
    setBottomPanel,
    setCanvasSearchQuery,
    setCompatiblePortFocus,
    setConnectFromNodeId,
    setConnectorBindingOpen,
    setCreateKind,
    setCreateMode,
    setCreateName,
    setCreateOpen,
    setDeployOpen,
    setGlobalConfig,
    setImportPackageName,
    setImportPackageOpen,
    setImportPackagePath,
    setModelBindingOpen,
    setNewTestExpected,
    setNewTestExpression,
    setNewTestKind,
    setNewTestName,
    setNewTestTargets,
    setNodeConfigInitialSection,
    setNodeConfigOpen,
    setNodeGroupFilter,
    setNodeSearch,
    setProposalToReview,
    setRightPanel,
    setRightRailCollapsed,
    setRightRailWidth,
    setStatusMessage,
    setTestEditorOpen,
    slugify,
    statusMessage,
    TestEditorModal,
    testEditorOpen,
    testResult,
    tests,
    testsPath,
    toggleCanvasSearch,
    toggleLeftDrawer,
    updateNode,
    validationResult,
    visibleCompatibleNodeHints,
    workflow,
    workflowActionMetadataLabel,
    WorkflowBottomShelf,
    workflowConfigSectionForNodeKind,
    workflowCreatorItemId,
    workflowDurationLabel,
    workflowEventLabel,
    WorkflowHeaderAction,
    WorkflowInlineIcon,
    WorkflowNodeConfigModal,
    workflowNodeCreatorBadge,
    workflowNodeName,
    workflowNodeRunChildLineage,
    workflowPath,
    WorkflowRailPanel,
    workflowTimeLabel,
    zoomIn,
    zoomOut
  } = model;

    return (
    <div
      className="workflow-composer"
      data-testid="workflow-composer"
      data-selected-node-id={selectedNodeId ?? ""}
    >
      <header
        className="workflow-composer-header"
        data-testid="workflow-header"
      >
        <div className="workflow-composer-breadcrumbs">
          <span>{currentProject?.name || "Workspace"}</span>
          <span>Workflows</span>
          <strong>{globalConfig.meta.name}</strong>
        </div>
        <div className="workflow-composer-title-row">
          <input
            aria-label="Workflow name"
            value={globalConfig.meta.name}
            disabled={isReadOnlyWorkflow}
            onChange={(event) =>
              setGlobalConfig((current) => ({
                ...current,
                meta: { ...current.meta, name: event.target.value },
              }))
            }
          />
          <span className="workflow-composer-path">{workflowPath}</span>
          <span className="workflow-composer-branch">
            {workflow.metadata.branch || "main"}
          </span>
          <span
            className={`workflow-composer-save-state ${workflow.metadata.dirty ? "is-dirty" : ""}`}
          >
            {workflow.metadata.dirty ? "Unsaved" : "Saved"}
          </span>
          {isReadOnlyWorkflow ? (
            <span
              className="workflow-composer-readonly-badge"
              data-testid="workflow-readonly-badge"
            >
              Read-only
            </span>
          ) : null}
          {harnessWorkerBinding ? (
            <span
              className="workflow-composer-harness-badge"
              data-testid="workflow-harness-worker-binding"
              title={`${harnessWorkerBinding.harnessWorkflowId} · ${harnessWorkerBinding.harnessHash}`}
            >
              Harness {harnessWorkerBinding.source} · {harnessWorkerBinding.harnessWorkflowId}
            </span>
          ) : null}
          <span
            className={`workflow-composer-lifecycle is-${lifecycleState.status}`}
            data-testid="workflow-lifecycle-state"
            data-lifecycle-state={lifecycleState.id}
            title={lifecycleState.detail}
          >
            {lifecycleState.label}
          </span>
        </div>
        <div className="workflow-composer-actions">
          <div
            className="workflow-action-cluster"
            aria-label="Workflow library"
          >
            <span className="workflow-action-cluster-label">Create</span>
            <WorkflowHeaderAction
              label="Add"
              icon={PanelLeftOpen}
              testId="workflow-open-node-drawer"
              onClick={toggleLeftDrawer}
              title="Add nodes"
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Harness"
              icon={GitCompare}
              testId="workflow-open-default-harness"
              onClick={handleOpenDefaultHarness}
              title="Open the read-only Default Agent Harness graph"
            />
            <WorkflowHeaderAction
              label="New"
              icon={Plus}
              testId="workflow-create-button"
              onClick={() => setCreateOpen(true)}
              variant="primary"
              showLabel
              title="Create workflow"
            />
          </div>
          <div
            className="workflow-action-cluster"
            aria-label="Workflow bindings"
          >
            <span className="workflow-action-cluster-label">Bind</span>
            <WorkflowHeaderAction
              label="Models"
              icon={Brain}
              testId="workflow-model-bindings-button"
              onClick={() => setModelBindingOpen(true)}
            />
            <WorkflowHeaderAction
              label="Connectors"
              icon={Cable}
              testId="workflow-connector-bindings-button"
              onClick={() => setConnectorBindingOpen(true)}
            />
          </div>
          <div
            className="workflow-action-cluster"
            aria-label="Workflow run controls"
          >
            <span className="workflow-action-cluster-label">Run</span>
            <WorkflowHeaderAction
              label="Validate"
              icon={CheckCircle2}
              testId="workflow-validate-button"
              onClick={handleValidate}
            />
            <WorkflowHeaderAction
              label="Run tests"
              icon={FlaskConical}
              testId="workflow-run-tests-button"
              onClick={handleRunTests}
              title={`Run tests: ${testsPath}`}
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Run"
              icon={Play}
              testId="workflow-run-button"
              onClick={handleRun}
              variant="primary"
              showLabel
              disabled={isReadOnlyWorkflow}
            />
          </div>
          <div
            className="workflow-action-cluster"
            aria-label="Workflow release controls"
          >
            <span className="workflow-action-cluster-label">Ship</span>
            <WorkflowHeaderAction
              label="Propose"
              icon={GitPullRequest}
              testId="workflow-propose-button"
              onClick={handleCreateProposal}
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Fork harness"
              icon={GitCompare}
              testId="workflow-fork-harness-button"
              onClick={handleForkDefaultHarness}
              disabled={!isBlessedHarnessWorkflow}
              title={
                isBlessedHarnessWorkflow
                  ? "Fork the Default Agent Harness into an editable package"
                  : "Open the Default Agent Harness first"
              }
            />
            <WorkflowHeaderAction
              label="Deploy"
              icon={Rocket}
              testId="workflow-deploy-button"
              onClick={() => {
                void handleOpenDeploy();
              }}
              disabled={isReadOnlyWorkflow}
            />
            <WorkflowHeaderAction
              label="Save"
              icon={Save}
              testId="workflow-save-button"
              onClick={handleSave}
              disabled={isReadOnlyWorkflow}
            />
          </div>
        </div>
      </header>

      <div
        className="workflow-composer-tabs"
        role="tablist"
        aria-label="Workflow views"
      >
        {(["graph", "proposals", "executions"] as WorkflowWorkbenchTab[]).map(
          (tab) => (
            <button
              key={tab}
              type="button"
              className={activeTab === tab ? "is-active" : ""}
              onClick={() => setActiveTab(tab)}
            >
              {tab === "graph"
                ? "Graph"
                : tab === "proposals"
                  ? "Proposals"
                  : "Executions"}
            </button>
          ),
        )}
      </div>

      {missingReasoningBinding ? (
        <div className="workflow-composer-banner">
          <span>
            A model node needs a model binding. Configure a default model or
            attach a Model Binding node.
          </span>
          <button
            type="button"
            data-testid="workflow-banner-configure-models"
            onClick={() => setModelBindingOpen(true)}
          >
            Configure models
          </button>
        </div>
      ) : null}

      <main className="workflow-composer-body">
        {activeTab === "graph" ? (
          <section
            className={`workflow-composer-graph ${leftDrawerOpen ? "has-left-drawer" : ""}`}
            style={{
              gridTemplateColumns: leftDrawerOpen
                ? `260px minmax(0, 1fr) ${rightRailCollapsed ? "48px" : `${rightRailWidth}px`}`
                : `minmax(0, 1fr) ${rightRailCollapsed ? "48px" : `${rightRailWidth}px`}`,
            }}
          >
            {leftDrawerOpen ? (
              <aside
                className="workflow-composer-left-drawer"
                aria-label="Workflow node library"
                data-testid="workflow-left-drawer"
              >
                <header>
                  <h3>Add node</h3>
                  <button type="button" onClick={closeLeftDrawer}>
                    Close
                  </button>
                </header>
                <label className="workflow-node-search">
                  <span>Search primitives</span>
                  <input
                    data-testid="workflow-node-library-search"
                    value={nodeSearch}
                    onChange={(event) => setNodeSearch(event.target.value)}
                    placeholder="Search sources, models, tools..."
                  />
                </label>
                <nav
                  className="workflow-node-group-filter"
                  data-testid="workflow-node-group-filter"
                  aria-label="Primitive groups"
                >
                  {NODE_GROUP_FILTERS.map((filter) => {
                    const count = nodeGroupCounts.get(filter) ?? 0;
                    const disabled = filter === "Compatible" && count === 0;
                    return (
                      <button
                        key={filter}
                        type="button"
                        className={
                          nodeGroupFilter === filter ? "is-active" : ""
                        }
                        data-testid={`workflow-node-group-filter-${slugify(filter)}`}
                        disabled={disabled}
                        title={
                          filter === "Compatible"
                            ? "Show primitives compatible with the selected node"
                            : `Show ${filter}`
                        }
                        onClick={() => {
                          setNodeGroupFilter(filter);
                          if (filter !== "Compatible") {
                            setCompatiblePortFocus(null);
                          }
                        }}
                      >
                        <span>{filter}</span>
                        <small>{count}</small>
                      </button>
                    );
                  })}
                </nav>
                <p
                  className="workflow-node-drawer-summary"
                  data-testid="workflow-node-drawer-summary"
                >
                  {filteredNodeLibrary.length} primitive
                  {filteredNodeLibrary.length === 1 ? "" : "s"}
                  {nodeGroupFilter === "Compatible" && selectedNode
                    ? ` compatible with ${compatiblePortFocusLabel ?? selectedNode.name}`
                    : ""}
                </p>
                {!isSearchingNodeLibrary && recentNodeLibrary.length > 0 ? (
                  <section
                    className="workflow-recent-primitives"
                    data-testid="workflow-recent-primitives"
                  >
                    <h5>Recently used</h5>
                    <div>
                      {recentNodeLibrary.map((item) => {
                        const badge = workflowNodeCreatorBadge(
                          item,
                          globalConfig,
                        );
                        const itemId = workflowCreatorItemId(item);
                        return (
                          <button
                            key={`recent-${itemId}`}
                            type="button"
                            data-testid={`workflow-recent-primitive-${itemId}`}
                            onClick={() =>
                              handleAddNodeFromLibrary(
                                item.type,
                                item.label,
                                undefined,
                                {
                                  openConfig: true,
                                  closeDrawer: true,
                                  creatorId: itemId,
                                  defaultLogic: item.defaultLogic,
                                  defaultLaw: item.defaultLaw,
                                  metricLabel: item.metricLabel,
                                  metricValue: item.metricValue,
                                },
                              )
                            }
                            title={`Add ${item.label}`}
                          >
                            <strong>{item.label}</strong>
                            <span>{item.group}</span>
                            <small
                              className="workflow-action-metadata"
                              data-testid={`workflow-recent-action-${itemId}`}
                            >
                              {workflowActionMetadataLabel(item)}
                            </small>
                            <em data-readiness={badge.status}>{badge.label}</em>
                          </button>
                        );
                      })}
                    </div>
                  </section>
                ) : null}
                {selectedNode &&
                visibleCompatibleNodeHints.length > 0 &&
                !isSearchingNodeLibrary ? (
                  <section
                    className="workflow-related-nodes"
                    data-testid="workflow-related-node-hints"
                  >
                    <div className="workflow-related-header">
                      <h5>
                        Works with{" "}
                        {compatiblePortFocusLabel ?? selectedNode.name}
                      </h5>
                      {compatiblePortFocusLabel ? (
                        <button
                          type="button"
                          data-testid="workflow-clear-compatible-port-filter"
                          onClick={() => setCompatiblePortFocus(null)}
                        >
                          All ports
                        </button>
                      ) : null}
                    </div>
                    <div>
                      {visibleCompatibleNodeHints.slice(0, 8).map((hint) => {
                        const item = hint.definition;
                        const badge = workflowNodeCreatorBadge(
                          item,
                          globalConfig,
                        );
                        const itemId = workflowCreatorItemId(item);
                        return (
                          <button
                            key={`related-${hint.direction}-${itemId}-${hint.sourcePort.id}-${hint.targetPort.id}`}
                            type="button"
                            data-testid={`workflow-add-compatible-${itemId}`}
                            data-connection-class={hint.connectionClass}
                            data-connection-direction={hint.direction}
                            className={hint.recommended ? "is-recommended" : ""}
                            onClick={() =>
                              handleAddCompatibleNode(selectedNode, item, hint)
                            }
                            title={`Add ${item.label}: ${hint.sourcePort.label} to ${hint.targetPort.label}`}
                          >
                            <strong>{item.label}</strong>
                            <span data-testid="workflow-compatible-port-path">
                              {hint.direction === "attachment"
                                ? "Attach"
                                : "After"}{" "}
                              · {hint.sourcePort.label}
                              {" -> "}
                              {hint.targetPort.label} · {hint.connectionClass}
                            </span>
                            <small
                              className="workflow-action-metadata"
                              data-testid={`workflow-compatible-action-${itemId}`}
                            >
                              {workflowActionMetadataLabel(item)}
                            </small>
                            <em data-readiness={badge.status}>{badge.label}</em>
                          </button>
                        );
                      })}
                    </div>
                  </section>
                ) : selectedDefinition ? (
                  <p className="workflow-related-empty">
                    {compatiblePortFocusLabel ? (
                      <>
                        No primitives match {compatiblePortFocusLabel}.{" "}
                        <button
                          type="button"
                          data-testid="workflow-clear-compatible-port-filter-empty"
                          onClick={() => setCompatiblePortFocus(null)}
                        >
                          Show all compatible ports
                        </button>
                      </>
                    ) : (
                      <>
                        Select a node with compatible ports to add downstream or
                        attached primitives.
                      </>
                    )}
                  </p>
                ) : null}
                {!isSearchingNodeLibrary ? (
                  <section
                    className="workflow-macro-library"
                    data-testid="workflow-macro-library"
                  >
                    <h5>Composition helpers</h5>
                    <button
                      type="button"
                      data-testid="workflow-add-agent-loop-macro"
                      onClick={handleInsertAgentLoopMacro}
                      title="Expand a generic agent loop into explicit source, model, memory, tool, decision, and output nodes"
                    >
                      <strong>Agent loop</strong>
                      <span>
                        Expands into typed primitives with visible tool and
                        memory attachments.
                      </span>
                    </button>
                  </section>
                ) : null}
                <section
                  className="workflow-component-library"
                  data-testid="workflow-component-library"
                >
                  {filteredNodeLibrary.length === 0 ? (
                    <p
                      className="workflow-node-library-empty"
                      data-testid="workflow-node-library-empty"
                    >
                      No primitives match the current search and group filter.
                    </p>
                  ) : null}
                  {SCAFFOLD_GROUPS.map((group) => {
                    const groupItems = filteredNodeLibrary.filter(
                      (item) => item.group === group,
                    );
                    if (groupItems.length === 0) return null;
                    return (
                      <div
                        className="workflow-scaffold-group"
                        key={group}
                        data-testid={`workflow-scaffold-group-${slugify(group)}`}
                      >
                        <h5>{group}</h5>
                        {groupItems.map((item) => {
                          const scaffold = WORKFLOW_SCAFFOLDS.find(
                            (entry) => entry.nodeType === item.type,
                          );
                          const classList =
                            scaffold?.connectionClasses?.join(", ") || "data";
                          const badge = workflowNodeCreatorBadge(
                            item,
                            globalConfig,
                          );
                          const itemId = workflowCreatorItemId(item);
                          const compatibleHint =
                            selectedNode && isSearchingNodeLibrary
                              ? compatibleNodeHints.find(
                                  (hint) =>
                                    workflowCreatorItemId(hint.definition) ===
                                    itemId,
                                )
                              : undefined;
                          return (
                            <button
                              key={`drawer-${itemId}`}
                              type="button"
                              data-testid={`workflow-component-${itemId}`}
                              data-node-type={item.type}
                              draggable
                              onDragStart={(event) =>
                                handleDragStart(event, item.type, item.label)
                              }
                              onClick={() =>
                                selectedNode && compatibleHint
                                  ? handleAddCompatibleNode(
                                      selectedNode,
                                      item,
                                      compatibleHint,
                                    )
                                  : handleAddNodeFromLibrary(
                                      item.type,
                                      item.label,
                                      undefined,
                                      {
                                        openConfig: true,
                                        closeDrawer: true,
                                        creatorId: itemId,
                                        defaultLogic: item.defaultLogic,
                                        defaultLaw: item.defaultLaw,
                                        metricLabel: item.metricLabel,
                                        metricValue: item.metricValue,
                                      },
                                    )
                              }
                              title={
                                ("creatorDescription" in item
                                  ? item.creatorDescription
                                  : undefined) ??
                                scaffold?.description ??
                                `Add ${item.label}`
                              }
                            >
                              <strong>{item.label}</strong>
                              <span>
                                {item.familyLabel} · {classList}
                              </span>
                              <small
                                className="workflow-action-metadata"
                                data-testid={`workflow-component-action-${itemId}`}
                              >
                                {workflowActionMetadataLabel(item)}
                              </small>
                              <em
                                data-testid={`workflow-component-readiness-${itemId}`}
                                data-readiness={badge.status}
                              >
                                {badge.label}
                              </em>
                            </button>
                          );
                        })}
                      </div>
                    );
                  })}
                </section>
              </aside>
            ) : null}
            <div className="workflow-composer-canvas-stage">
              <div
                className="workflow-composer-toolbar workflow-composer-toolbar--compact"
                aria-label="Workflow canvas tools"
              >
                <button
                  type="button"
                  className="workflow-toolbar-action"
                  data-testid="workflow-open-node-library"
                  onClick={openLeftDrawer}
                  title="Open node library"
                  aria-label="Open node library"
                >
                  <WorkflowInlineIcon icon={PanelLeftOpen} />
                  <span>Add</span>
                </button>
              </div>

              <div className="workflow-composer-canvas-controls">
                <button
                  type="button"
                  className={`workflow-icon-button ${canvasSearchOpen ? "is-active" : ""}`}
                  aria-label="Search workflow"
                  title="Search workflow"
                  data-testid="workflow-canvas-search-toggle"
                  onClick={toggleCanvasSearch}
                >
                  <WorkflowInlineIcon icon={Search} />
                </button>
                {canvasSearchOpen ? (
                  <section
                    className="workflow-canvas-search-panel"
                    data-testid="workflow-canvas-search-panel"
                    aria-label="Search workflow nodes"
                  >
                    <label>
                      <span>Find node</span>
                      <input
                        autoFocus
                        data-testid="workflow-canvas-search-input"
                        value={canvasSearchQuery}
                        onChange={(event) =>
                          setCanvasSearchQuery(event.target.value)
                        }
                        placeholder="Name, type, status, field..."
                      />
                    </label>
                    <div
                      className="workflow-canvas-search-results"
                      data-testid="workflow-canvas-search-results"
                    >
                      {canvasSearchResults.length > 0 ? (
                        canvasSearchResults.map((result) => {
                          const nodeItem = result.node;
                          return (
                            <article
                              key={nodeItem.id}
                              className={`workflow-canvas-search-result-row ${
                                selectedNodeId === nodeItem.id
                                  ? "is-selected"
                                  : ""
                              }`}
                              data-testid="workflow-canvas-search-result"
                            >
                              <button
                                type="button"
                                className="workflow-canvas-search-result-main"
                                onClick={() => {
                                  handleWorkflowNodeSelect(nodeItem.id);
                                  setBottomPanel("selection");
                                }}
                              >
                                <strong>{nodeItem.name}</strong>
                                <span>
                                  {nodeItem.type}
                                  {result.status ? ` · ${result.status}` : ""}
                                </span>
                                <small>
                                  {result.configuredFields.length > 0
                                    ? result.configuredFields
                                        .slice(0, 4)
                                        .join(", ")
                                    : nodeItem.id}
                                </small>
                              </button>
                              <button
                                type="button"
                                className="workflow-canvas-search-compatible"
                                data-testid="workflow-canvas-search-compatible"
                                title={`Show compatible nodes for ${nodeItem.name}`}
                                onClick={() => {
                                  handleWorkflowNodeSelect(nodeItem.id);
                                  setCompatiblePortFocus(null);
                                  openLeftDrawer();
                                  setNodeGroupFilter("Compatible");
                                  setNodeSearch("");
                                  setBottomPanel("selection");
                                }}
                              >
                                Add next
                              </button>
                              <button
                                type="button"
                                className="workflow-canvas-search-configure"
                                data-testid="workflow-canvas-search-configure"
                                title={`Configure ${nodeItem.name}`}
                                onClick={() => {
                                  handleWorkflowNodeSelect(nodeItem.id);
                                  closeCanvasSearch();
                                  setNodeConfigInitialSection(
                                    workflowConfigSectionForNodeKind(
                                      nodeItem.type,
                                    ),
                                  );
                                  setNodeConfigOpen(true);
                                }}
                              >
                                Configure
                              </button>
                            </article>
                          );
                        })
                      ) : (
                        <p data-testid="workflow-canvas-search-empty">
                          No nodes match this search.
                        </p>
                      )}
                    </div>
                  </section>
                ) : null}
                <div className="workflow-legend">
                  {counts.map((item) => (
                    <span key={item.family}>
                      <i data-family={item.family} />
                      {item.family} ({item.count})
                    </span>
                  ))}
                </div>
              </div>

              <Canvas
                nodes={displayNodes}
                edges={displayEdges}
                onNodesChange={guardedOnNodesChange}
                onEdgesChange={guardedOnEdgesChange}
                onConnect={guardedOnConnect}
                onNodeSelect={handleWorkflowNodeSelect}
                onNodeActivate={(nodeId) => {
                  if (isReadOnlyWorkflow) return;
                  const nodeItem = nodes.find((node) => node.id === nodeId)
                    ?.data as Node | undefined;
                  handleWorkflowNodeSelect(nodeId);
                  setNodeConfigInitialSection(
                    workflowConfigSectionForNodeKind(nodeItem?.type ?? ""),
                  );
                  setNodeConfigOpen(true);
                }}
                onDrop={guardedCanvasDrop}
                readOnly={isReadOnlyWorkflow}
              />

              {nodes.length === 0 ? (
                <section
                  className="workflow-start-overlay"
                  data-testid="workflow-empty-start-overlay"
                  aria-label="Choose what starts this workflow"
                >
                  <header>
                    <div>
                      <h3>What starts this workflow?</h3>
                      <p>
                        Start with a trigger or input, then grow the graph from
                        typed ports.
                      </p>
                    </div>
                    <button
                      type="button"
                      data-testid="workflow-empty-browse-primitives"
                      onClick={() => {
                        setNodeGroupFilter("All");
                        setNodeSearch("");
                        openLeftDrawer();
                      }}
                    >
                      Browse all primitives
                    </button>
                  </header>
                  <div className="workflow-start-card-grid">
                    {emptyCanvasStartItems.map((item) => {
                      const itemId = workflowCreatorItemId(item);
                      const badge = workflowNodeCreatorBadge(
                        item,
                        globalConfig,
                      );
                      return (
                        <button
                          key={itemId}
                          type="button"
                          className="workflow-start-card"
                          data-testid={`workflow-empty-start-${itemId}`}
                          onClick={() =>
                            handleAddNodeFromLibrary(
                              item.type,
                              item.label,
                              undefined,
                              {
                                openConfig: true,
                                closeDrawer: true,
                                creatorId: itemId,
                                defaultLogic: item.defaultLogic,
                                defaultLaw: item.defaultLaw,
                                metricLabel: item.metricLabel,
                                metricValue: item.metricValue,
                              },
                            )
                          }
                          title={item.creatorDescription}
                        >
                          <strong>{item.label}</strong>
                          <span>{item.creatorDescription}</span>
                          <small>
                            {item.group} · {workflowActionMetadataLabel(item)}
                          </small>
                          <em data-readiness={badge.status}>{badge.label}</em>
                        </button>
                      );
                    })}
                  </div>
                </section>
              ) : null}

              <div className="workflow-zoom-controls">
                <button type="button" onClick={() => zoomIn({ duration: 160 })}>
                  +
                </button>
                <button
                  type="button"
                  onClick={() => zoomOut({ duration: 160 })}
                >
                  -
                </button>
                <button type="button" onClick={() => fitView({ padding: 0.2 })}>
                  Fit
                </button>
              </div>
              {selectedNode ? (
                <div className="workflow-selection-actions">
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-configure-node"
                    aria-label="Configure node"
                    title="Configure node"
                    onClick={() => {
                      setNodeConfigInitialSection(
                        workflowConfigSectionForNodeKind(selectedNode.type),
                      );
                      setNodeConfigOpen(true);
                    }}
                  >
                    <WorkflowInlineIcon icon={Settings} />
                    <span className="workflow-action-tooltip">
                      Configure node
                    </span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-show-compatible-nodes"
                    aria-label="Show compatible nodes"
                    title="Show compatible nodes"
                    disabled={compatibleNodeHints.length === 0}
                    onClick={() => {
                      setCompatiblePortFocus(null);
                      openLeftDrawer();
                      setNodeGroupFilter("Compatible");
                      setNodeSearch("");
                      setStatusMessage(
                        compatibleNodeHints.length > 0
                          ? `${compatibleNodeHints.length} compatible node option${compatibleNodeHints.length === 1 ? "" : "s"} for ${selectedNode.name}`
                          : `No compatible nodes found for ${selectedNode.name}`,
                      );
                    }}
                  >
                    <WorkflowInlineIcon icon={Plus} />
                    <span className="workflow-action-tooltip">
                      Show compatible nodes
                    </span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-connect-from-node"
                    aria-label="Connect from"
                    title="Connect from"
                    onClick={() => {
                      setConnectFromNodeId(selectedNode.id);
                      setStatusMessage(`Connecting from ${selectedNode.name}`);
                    }}
                  >
                    <WorkflowInlineIcon icon={Cable} />
                    <span className="workflow-action-tooltip">
                      Connect from
                    </span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-connect-to-node"
                    aria-label="Connect to"
                    title="Connect to"
                    disabled={
                      !connectFromNodeId ||
                      connectFromNodeId === selectedNode.id
                    }
                    onClick={handleConnectSelectedNodes}
                  >
                    <WorkflowInlineIcon icon={GitPullRequest} />
                    <span className="workflow-action-tooltip">Connect to</span>
                  </button>
                  <button
                    type="button"
                    className="workflow-selection-action"
                    data-testid="workflow-add-node-test"
                    aria-label="Add test"
                    title="Add test"
                    onClick={() => {
                      setNewTestTargets(selectedNode.id);
                      setNewTestKind("node_exists");
                      setNewTestExpected("");
                      setNewTestExpression("");
                      setTestEditorOpen(true);
                    }}
                  >
                    <WorkflowInlineIcon icon={FlaskConical} />
                    <span className="workflow-action-tooltip">Add test</span>
                  </button>
                </div>
              ) : null}
            </div>

            <aside
              className={`workflow-composer-rail ${rightRailCollapsed ? "is-collapsed" : ""}`}
              data-testid={`workflow-right-rail-${rightPanel}`}
            >
              {!rightRailCollapsed ? (
                <div className="workflow-composer-rail-panel">
                  <div className="workflow-rail-controls">
                    <div className="workflow-rail-active-header">
                      <button
                        type="button"
                        className="workflow-icon-button"
                        data-testid="workflow-rail-collapse"
                        aria-label="Collapse rail"
                        title="Collapse rail"
                        onClick={() => setRightRailCollapsed(true)}
                      >
                        <WorkflowInlineIcon icon={PanelRightClose} />
                      </button>
                      <div>
                        <strong>{activeRightPanelMeta.label}</strong>
                        <span>{activeRightPanelMeta.description}</span>
                      </div>
                    </div>
                    <label>
                      Width
                      <input
                        type="range"
                        min={280}
                        max={460}
                        value={rightRailWidth}
                        onChange={(event) =>
                          setRightRailWidth(Number(event.target.value))
                        }
                      />
                    </label>
                  </div>
                  <WorkflowRailPanel
                    panel={rightPanel}
                    selectedNode={selectedNode}
                    tests={tests}
                    proposals={proposals}
                    runs={runs}
                    validationResult={validationResult}
                    readinessResult={readinessResult}
                    testResult={testResult}
                    workflow={currentProjectFile}
                    lastRunResult={lastRunResult}
                    selectedRunId={selectedRunId}
                    compareRunResult={compareRunResult}
                    compareRunId={compareRunId}
                    runEvents={runEvents}
                    dogfoodRun={dogfoodRun}
                    portablePackage={portablePackage}
                    bindingManifest={bindingManifest}
                    selectedNodeFixtures={selectedFixtures}
                    checkpoints={checkpoints}
                    onSelectRun={handleSelectRun}
                    onCompareRun={handleCompareRun}
                    onOpenExecutions={() => setActiveTab("executions")}
                    onInspectNode={(nodeId) => handleWorkflowNodeSelect(nodeId)}
                    onConfigureNode={() => {
                      if (selectedNode) {
                        setNodeConfigInitialSection(
                          workflowConfigSectionForNodeKind(selectedNode.type),
                        );
                      }
                      setNodeConfigOpen(true);
                    }}
                    onSelectProposal={(proposal) =>
                      setProposalToReview(proposal)
                    }
                    onExportPackage={handleExportPortablePackage}
                    onOpenImportPackage={() => setImportPackageOpen(true)}
                    onGenerateBindingManifest={handleGenerateBindingManifest}
                    onUpdateEnvironmentProfile={handleUpdateEnvironmentProfile}
                    onUpdateProductionProfile={handleUpdateProductionProfile}
                    onCheckBinding={handleCheckWorkflowBinding}
                    onResolveIssue={handleResolveWorkflowIssue}
                    onRunNode={(node, fixture) => {
                      void handleRunWorkflowNode(node, fixture);
                    }}
                    onRunUpstream={(node) => {
                      void handleRunWorkflowUpstream(node);
                    }}
                    onCaptureFixtureForNode={(node) => {
                      void handleCaptureNodeFixture(node);
                    }}
                    onDryRunFixtureForNode={(node, fixture) => {
                      void handleDryRunNodeFromFixture(node, fixture);
                    }}
                    onPinFixtureForNode={(node, fixture) => {
                      void handlePinNodeFixture(node, fixture);
                    }}
                    onAddTestFromOutput={handleAddTestFromOutput}
                  />
                </div>
              ) : null}
              <nav
                className="workflow-composer-rail-strip"
                aria-label="Workflow panels"
              >
                <button
                  type="button"
                  data-testid="workflow-rail-toggle"
                  className={rightRailCollapsed ? "is-active" : ""}
                  title={rightRailCollapsed ? "Expand rail" : "Collapse rail"}
                  aria-label={
                    rightRailCollapsed ? "Expand rail" : "Collapse rail"
                  }
                  onClick={() =>
                    setRightRailCollapsed((collapsed) => !collapsed)
                  }
                >
                  {rightRailCollapsed ? (
                    <WorkflowInlineIcon icon={PanelRightOpen} />
                  ) : (
                    <WorkflowInlineIcon icon={PanelRightClose} />
                  )}
                </button>
                {RIGHT_PANELS.map((panel) => {
                  const PanelIcon = panel.icon;
                  const badgeCount = rightPanelBadgeCounts[panel.id];
                  return (
                    <button
                      key={panel.id}
                      type="button"
                      data-testid={`workflow-rail-panel-${panel.id}`}
                      className={rightPanel === panel.id ? "is-active" : ""}
                      title={`${panel.label}: ${panel.description}`}
                      aria-label={panel.label}
                      data-panel-badge={badgeCount > 0 ? badgeCount : undefined}
                      onClick={() => {
                        setRightPanel(panel.id);
                        setRightRailCollapsed(false);
                      }}
                    >
                      <WorkflowInlineIcon icon={PanelIcon} />
                      <span className="workflow-rail-panel-label">
                        <strong>{panel.label}</strong>
                        <small>{panel.description}</small>
                      </span>
                      {badgeCount > 0 ? (
                        <em
                          className="workflow-rail-panel-badge"
                          data-testid={`workflow-rail-panel-badge-${panel.id}`}
                        >
                          {badgeCount > 99 ? "99+" : badgeCount}
                        </em>
                      ) : null}
                    </button>
                  );
                })}
              </nav>
            </aside>
          </section>
        ) : null}

        {activeTab === "proposals" ? (
          <section
            className="workflow-composer-empty workflow-proposals-workbench"
            data-testid="workflow-proposals-workbench"
          >
            <header className="workflow-workbench-tab-header">
              <div>
                <h3>Proposals</h3>
                <p>
                  Review bounded graph, test, and code changes before anything
                  is applied.
                </p>
              </div>
              <button
                type="button"
                onClick={handleCreateProposal}
                data-testid="workflow-proposals-create"
              >
                Create proposal
              </button>
            </header>
            <dl
              className="workflow-tab-stats"
              data-testid="workflow-proposals-summary"
            >
              <div>
                <dt>Open</dt>
                <dd>{proposalStatusCounts.open}</dd>
              </div>
              <div>
                <dt>Applied</dt>
                <dd>{proposalStatusCounts.applied}</dd>
              </div>
              <div>
                <dt>Rejected</dt>
                <dd>{proposalStatusCounts.rejected}</dd>
              </div>
              <div>
                <dt>Bounded targets</dt>
                <dd>{proposalBoundedTargetCount}</dd>
              </div>
            </dl>
            {proposals.length === 0 ? (
              <section
                className="workflow-tab-empty"
                data-testid="workflow-proposals-empty"
              >
                <strong>No proposals</strong>
                <span>
                  Use proposals for self-mutation, generated repair, or
                  reviewable workflow changes.
                </span>
              </section>
            ) : (
              <div
                className="workflow-proposal-workbench-list"
                data-testid="workflow-proposal-workbench-list"
              >
                {proposals.map((proposal) => {
                  const changedNodeIds = [
                    ...(proposal.graphDiff?.addedNodeIds ?? []),
                    ...(proposal.graphDiff?.changedNodeIds ?? []),
                    ...(proposal.graphDiff?.removedNodeIds ?? []),
                  ];
                  return (
                    <article
                      key={proposal.id}
                      className={`workflow-proposal-review-card is-${proposal.status}`}
                      data-testid={`workflow-proposals-card-${proposal.id}`}
                    >
                      <header>
                        <div>
                          <strong>{proposal.title}</strong>
                          <span>{proposal.summary}</span>
                        </div>
                        <em>{proposal.status}</em>
                      </header>
                      <dl>
                        <div>
                          <dt>Targets</dt>
                          <dd>{proposal.boundedTargets.length}</dd>
                        </div>
                        <div>
                          <dt>Changed nodes</dt>
                          <dd>{changedNodeIds.length}</dd>
                        </div>
                        <div>
                          <dt>Created</dt>
                          <dd>{workflowTimeLabel(proposal.createdAtMs)}</dd>
                        </div>
                      </dl>
                      <div
                        className="workflow-proposal-targets"
                        data-testid={`workflow-proposals-targets-${proposal.id}`}
                      >
                        {proposal.boundedTargets.slice(0, 6).map((target) => (
                          <code key={target}>{target}</code>
                        ))}
                        {proposal.boundedTargets.length > 6 ? (
                          <code>+{proposal.boundedTargets.length - 6}</code>
                        ) : null}
                      </div>
                      <footer>
                        <span>
                          {changedNodeIds.length > 0
                            ? changedNodeIds
                                .map((nodeId) =>
                                  workflowNodeName(currentProjectFile, nodeId),
                                )
                                .join(", ")
                            : "No graph node changes recorded"}
                        </span>
                        <button
                          type="button"
                          onClick={() => setProposalToReview(proposal)}
                        >
                          Preview
                        </button>
                      </footer>
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        ) : null}

        {activeTab === "executions" ? (
          <section
            className="workflow-composer-empty workflow-executions-workbench"
            data-testid="workflow-executions-workbench"
          >
            <header className="workflow-workbench-tab-header">
              <div>
                <h3>Executions</h3>
                <p>
                  Inspect run lifecycle, attempts, checkpoints, interrupts, and
                  output status.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRun}
                data-testid="workflow-executions-run-now"
              >
                Run workflow
              </button>
            </header>
            <dl
              className="workflow-tab-stats"
              data-testid="workflow-executions-summary"
            >
              <div>
                <dt>Runs</dt>
                <dd>{runs.length}</dd>
              </div>
              <div>
                <dt>Passed</dt>
                <dd>{executionStatusCounts.passed ?? 0}</dd>
              </div>
              <div>
                <dt>Blocked</dt>
                <dd>
                  {(executionStatusCounts.blocked ?? 0) +
                    (executionStatusCounts.failed ?? 0)}
                </dd>
              </div>
              <div>
                <dt>Checkpoints</dt>
                <dd>{executionCheckpointCount}</dd>
              </div>
            </dl>
            {runs.length === 0 ? (
              <section
                className="workflow-tab-empty"
                data-testid="workflow-executions-empty"
              >
                <strong>No runs</strong>
                <span>
                  Run the workflow to create executions, node attempts, and
                  checkpoint records.
                </span>
              </section>
            ) : (
              <div className="workflow-executions-layout">
                <div
                  className="workflow-executions-run-list"
                  data-testid="workflow-executions-run-list"
                >
                  {runs.map((run) => (
                    <article
                      key={run.id}
                      className={`workflow-executions-run-card is-${run.status} ${selectedExecutionRun?.id === run.id ? "is-active" : ""}`}
                      data-testid={`workflow-executions-run-${run.id}`}
                    >
                      <button
                        type="button"
                        onClick={() => void handleSelectRun(run)}
                      >
                        <strong>{run.status}</strong>
                        <span>{run.summary}</span>
                        <small>
                          {workflowDurationLabel(
                            run.startedAtMs,
                            run.finishedAtMs,
                          )}{" "}
                          · {run.checkpointCount ?? 0} checkpoints
                        </small>
                      </button>
                      {lastRunResult && run.id !== lastRunResult.summary.id ? (
                        <button
                          type="button"
                          className="workflow-inline-link"
                          onClick={() => void handleCompareRun(run)}
                        >
                          Compare
                        </button>
                      ) : null}
                    </article>
                  ))}
                </div>
                <section
                  className="workflow-executions-detail"
                  data-testid="workflow-executions-run-detail"
                >
                  {selectedExecutionRun ? (
                    <>
                      <header>
                        <div>
                          <strong>{selectedExecutionRun.status}</strong>
                          <span>{selectedExecutionRun.summary}</span>
                        </div>
                        {executionCompareRun ? (
                          <button
                            type="button"
                            onClick={() =>
                              void handleCompareRun(executionCompareRun)
                            }
                          >
                            Compare latest
                          </button>
                        ) : null}
                      </header>
                      <dl className="workflow-tab-stats">
                        <div>
                          <dt>Nodes</dt>
                          <dd>{selectedExecutionRun.nodeCount}</dd>
                        </div>
                        <div>
                          <dt>Tests</dt>
                          <dd>{selectedExecutionRun.testCount}</dd>
                        </div>
                        <div>
                          <dt>Checkpoints</dt>
                          <dd>{selectedExecutionRun.checkpointCount ?? 0}</dd>
                        </div>
                        <div>
                          <dt>Duration</dt>
                          <dd>
                            {workflowDurationLabel(
                              selectedExecutionRun.startedAtMs,
                              selectedExecutionRun.finishedAtMs,
                            )}
                          </dd>
                        </div>
                      </dl>
                      {selectedExecutionRunResult ? (
                        <>
                          <div
                            className="workflow-run-attempt-grid"
                            data-testid="workflow-executions-node-attempts"
                          >
                            {selectedExecutionRunResult.nodeRuns.map(
                              (nodeRun) => {
                                const childLineage =
                                  workflowNodeRunChildLineage(nodeRun);
                                return (
                                  <button
                                    key={`${nodeRun.nodeId}-${nodeRun.attempt}-${nodeRun.startedAtMs}`}
                                    type="button"
                                    className={`workflow-run-attempt is-${nodeRun.status}`}
                                    onClick={() =>
                                      handleInspectExecutionNode(nodeRun.nodeId)
                                    }
                                  >
                                    <strong>
                                      {workflowNodeName(
                                        currentProjectFile,
                                        nodeRun.nodeId,
                                      )}
                                    </strong>
                                    <span>
                                      {nodeRun.status} · attempt{" "}
                                      {nodeRun.attempt}
                                    </span>
                                    <small>
                                      {nodeRun.error ??
                                        workflowDurationLabel(
                                          nodeRun.startedAtMs,
                                          nodeRun.finishedAtMs,
                                        )}
                                      {" · "}
                                      {nodeRun.input === undefined
                                        ? "input not captured"
                                        : "input captured"}
                                    </small>
                                    <small
                                      className="workflow-run-lifecycle"
                                      data-testid="workflow-executions-node-lifecycle"
                                    >
                                      {(nodeRun.lifecycle?.length ?? 0) > 0
                                        ? `${nodeRun.lifecycle?.length} run steps`
                                        : "run steps pending"}
                                      {nodeRun.checkpointId
                                        ? " · checkpoint saved"
                                        : ""}
                                    </small>
                                    {childLineage ? (
                                      <small
                                        className="workflow-run-child-lineage"
                                        data-testid="workflow-executions-child-lineage"
                                        data-node-id={nodeRun.nodeId}
                                      >
                                        Child run {childLineage.childRunStatus}{" "}
                                        · {childLineage.childRunId}
                                      </small>
                                    ) : null}
                                  </button>
                                );
                              },
                            )}
                          </div>
                          <ol
                            className="workflow-run-timeline"
                            data-testid="workflow-executions-timeline"
                          >
                            {selectedExecutionRunResult.events
                              .slice(0, 12)
                              .map((event) => (
                                <li
                                  key={event.id}
                                  className={`is-${event.status ?? event.kind}`}
                                >
                                  <strong>{workflowEventLabel(event)}</strong>
                                  <span>
                                    {event.message ??
                                      workflowNodeName(
                                        currentProjectFile,
                                        event.nodeId,
                                      )}
                                  </span>
                                  <small>
                                    {workflowTimeLabel(event.createdAtMs)}
                                  </small>
                                </li>
                              ))}
                          </ol>
                        </>
                      ) : (
                        <p>
                          Load a run to inspect node attempts and timeline
                          events.
                        </p>
                      )}
                    </>
                  ) : null}
                </section>
              </div>
            )}
          </section>
        ) : null}
      </main>

      <section
        className="workflow-composer-bottom"
        aria-label="Workflow details"
        data-testid={`workflow-bottom-${bottomPanel}`}
      >
        <div className="workflow-composer-bottom-tabs">
          {BOTTOM_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              data-testid={`workflow-bottom-tab-${tab.id}`}
              className={bottomPanel === tab.id ? "is-active" : ""}
              onClick={() => setBottomPanel(tab.id)}
            >
              {tab.label}
            </button>
          ))}
          <span>{statusMessage}</span>
        </div>
        <WorkflowBottomShelf
          panel={bottomPanel}
          selectedNode={selectedNode}
          selectedNodeRun={
            selectedNode ? (nodeRunStatusById[selectedNode.id] ?? null) : null
          }
          tests={tests}
          proposals={proposals}
          testResult={testResult}
          validationResult={validationResult}
          runs={runs}
          lastRunResult={lastRunResult}
          runDetailLoading={runDetailLoading}
          compareRunResult={compareRunResult}
          workflow={currentProjectFile}
          functionDryRunResult={functionDryRunResult}
          dogfoodRun={dogfoodRun}
          fixtures={selectedFixtures}
          runEvents={runEvents}
          checkpoints={checkpoints}
          logs={execution.logs}
          onCaptureFixture={() => {
            if (selectedNode) void handleCaptureNodeFixture(selectedNode);
          }}
          onPinFixture={(fixture) => {
            if (selectedNode) void handlePinNodeFixture(selectedNode, fixture);
          }}
          onDryRunFixture={(fixture) => {
            if (selectedNode)
              void handleDryRunNodeFromFixture(selectedNode, fixture);
          }}
          onResumeRun={handleResumeRun}
          onInspectNode={(nodeId) => handleWorkflowNodeSelect(nodeId)}
        />
      </section>

      {createOpen ? (
        <CreateWorkflowModal
          name={createName}
          projectRoot={currentProject?.rootPath || "."}
          workflowKind={createKind}
          executionMode={createMode}
          onNameChange={setCreateName}
          onWorkflowKindChange={setCreateKind}
          onExecutionModeChange={setCreateMode}
          onClose={() => setCreateOpen(false)}
          onCreate={() => {
            void handleCreateWorkflow();
          }}
        />
      ) : null}

      {nodeConfigOpen && selectedNode ? (
        <WorkflowNodeConfigModal
          node={selectedNode}
          workflow={currentProjectFile}
          dryRunResult={functionDryRunResult}
          fixtures={selectedFixtures}
          selectedNodeRun={nodeRunStatusById[selectedNode.id] ?? null}
          upstreamReferences={selectedUpstreamReferences}
          compatibleNodeHints={compatibleNodeHints}
          tests={tests}
          testResult={testResult}
          validationResult={validationResult}
          readinessResult={readinessResult}
          initialSection={nodeConfigInitialSection}
          onClose={() => setNodeConfigOpen(false)}
          onUpdate={(updates) => updateNode(selectedNode.id, updates)}
          onInspectNode={(nodeId) => {
            const nodeItem = nodes.find((node) => node.id === nodeId)
              ?.data as Node | undefined;
            handleWorkflowNodeSelect(nodeId);
            setNodeConfigInitialSection(
              workflowConfigSectionForNodeKind(nodeItem?.type ?? ""),
            );
            setNodeConfigOpen(true);
          }}
          onDryRun={() => {
            void handleDryRunFunction(selectedNode);
          }}
          onCaptureFixture={() => {
            void handleCaptureNodeFixture(selectedNode);
          }}
          onImportFixture={(rawText) => {
            void handleImportNodeFixture(selectedNode, rawText);
          }}
          onPinFixture={(fixture) => {
            void handlePinNodeFixture(selectedNode, fixture);
          }}
          onDryRunFixture={(fixture) => {
            void handleDryRunNodeFromFixture(selectedNode, fixture);
          }}
        />
      ) : null}

      {modelBindingOpen ? (
        <ModelBindingModal
          globalConfig={globalConfig}
          onClose={() => setModelBindingOpen(false)}
          onUpdate={setGlobalConfig}
        />
      ) : null}

      {connectorBindingOpen ? (
        <ConnectorBindingModal
          workflow={currentProjectFile}
          onClose={() => setConnectorBindingOpen(false)}
          onInspectNode={(nodeId) => {
            const nodeItem = nodes.find((node) => node.id === nodeId)
              ?.data as Node | undefined;
            handleWorkflowNodeSelect(nodeId);
            setNodeConfigInitialSection(
              workflowConfigSectionForNodeKind(nodeItem?.type ?? ""),
            );
            setNodeConfigOpen(true);
            setConnectorBindingOpen(false);
          }}
          onOpenNodeLibrary={() => {
            openLeftDrawer();
            setConnectorBindingOpen(false);
          }}
        />
      ) : null}

      {testEditorOpen ? (
        <TestEditorModal
          workflow={currentProjectFile}
          existingTests={tests}
          name={newTestName}
          targets={newTestTargets}
          selectedNode={selectedNode}
          onNameChange={setNewTestName}
          onTargetsChange={setNewTestTargets}
          kind={newTestKind}
          expected={newTestExpected}
          expression={newTestExpression}
          onKindChange={setNewTestKind}
          onExpectedChange={setNewTestExpected}
          onExpressionChange={setNewTestExpression}
          onClose={() => setTestEditorOpen(false)}
          onSubmit={handleAddTest}
        />
      ) : null}

      {proposalToReview ? (
        <ProposalPreviewModal
          proposal={proposalToReview}
          onClose={() => setProposalToReview(null)}
          onApply={() => handleApplyProposal(proposalToReview.id)}
        />
      ) : null}

      {deployOpen ? (
        <DeployModal
          workflow={currentProjectFile}
          validationResult={validationResult}
          readinessResult={readinessResult}
          onCheckReadiness={() => {
            void handleCheckReadiness();
          }}
          onInspectNode={(nodeId) => {
            handleWorkflowNodeSelect(nodeId);
            setRightPanel("readiness");
          }}
          onClose={() => setDeployOpen(false)}
          onDeploy={async () => {
            const readiness = readinessResult ?? (await handleCheckReadiness());
            if (readiness.status !== "passed") {
              setRightPanel("readiness");
              setStatusMessage("Activation blocked");
              return;
            }
            await handleSave();
            setDeployOpen(false);
            setStatusMessage("Activation checkpoint saved");
          }}
        />
      ) : null}

      {importPackageOpen ? (
        <ImportPackageModal
          projectRoot={currentProject?.rootPath || "."}
          packagePath={importPackagePath}
          packageName={importPackageName}
          onPackagePathChange={setImportPackagePath}
          onPackageNameChange={setImportPackageName}
          onClose={() => setImportPackageOpen(false)}
          onImport={handleImportPortablePackage}
        />
      ) : null}
    </div>
  );
}
