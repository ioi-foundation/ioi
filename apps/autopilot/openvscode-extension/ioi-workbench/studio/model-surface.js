function createModelSurfaceRenderer(deps) {
  const {
    commandPayloadAttr,
    daemonEndpoint,
    escapeHtml,
    formatBytes,
    modelSnapshotFromState,
    renderCommandButton,
  } = deps;

function modelReceiptKind(receipt) {
  return receipt?.details?.operation || receipt?.kind || "receipt";
}

function modelStatusPill(value) {
  const normalized = String(value || "unknown").toLowerCase();
  const tone = /loaded|ready|available|running|mounted|connected|pass|active/.test(normalized)
    ? "ready"
    : /blocked|failed|error|absent|denied/.test(normalized)
      ? "blocked"
      : /loading|starting|degraded|warning|stopped/.test(normalized)
        ? "warn"
        : "muted";
  return `<span class="model-status is-${tone}">${escapeHtml(value || "unknown")}</span>`;
}

function modelEndpointForArtifact(snapshot, artifact) {
  if (!artifact) {
    return undefined;
  }
  return (
    snapshot.endpoints.find((endpoint) => endpoint.artifactId === artifact.id) ||
    snapshot.endpoints.find((endpoint) => endpoint.modelId === artifact.modelId)
  );
}

function modelInstanceForEndpoint(snapshot, endpoint) {
  return snapshot.instances.find(
    (instance) => instance.endpointId === endpoint?.id && instance.status === "loaded",
  );
}

function modelDisplayName(artifact = {}) {
  return artifact.displayName || artifact.name || artifact.modelId || artifact.id || "Model";
}

function modelPublisher(artifact = {}) {
  const modelId = String(artifact.modelId || artifact.id || "");
  return (
    artifact.publisher ||
    artifact.providerId ||
    artifact.registry ||
    (modelId.includes("/") ? modelId.split("/")[0] : "") ||
    "local"
  );
}

function modelArch(artifact = {}) {
  return artifact.arch || artifact.architecture || artifact.family || artifact.metadata?.arch || "llama";
}

function modelParams(artifact = {}) {
  const explicit = artifact.params || artifact.parameterCount || artifact.metadata?.params;
  if (explicit) {
    return String(explicit);
  }
  const source = `${artifact.modelId || ""} ${artifact.name || ""}`;
  const match = source.match(/\b\d+(?:\.\d+)?\s?[bBmM]\b/);
  return match ? match[0].replace(/\s+/g, "").toUpperCase() : "local";
}

function modelDomain(artifact = {}) {
  const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
  if (capabilities.some((capability) => /embed/i.test(String(capability)))) {
    return "embedding";
  }
  if (capabilities.some((capability) => /vision|image|video/i.test(String(capability)))) {
    return "vlm";
  }
  return artifact.domain || "llm";
}

function modelIsEmbeddingOnly(record = {}) {
  const capabilities = Array.isArray(record.capabilities) ? record.capabilities : [];
  return capabilities.length > 0 &&
    capabilities.some((capability) => /embed/i.test(String(capability || ""))) &&
    !capabilities.some((capability) => /chat|responses/i.test(String(capability || "")));
}

function modelLooksHiddenFromProductChat(record = {}) {
  const haystack = [
    record.id,
    record.modelId,
    record.model_id,
    record.providerId,
    record.provider_id,
    record.backendId,
    record.backend_id,
    record.artifactId,
    record.artifact_id,
    record.name,
    record.label,
    record.displayName,
    record.source,
    record.driver,
    record.status,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  return (
    /\bfixture\b/.test(haystack) ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("stories260k") ||
    haystack.includes("provider.lmstudio") ||
    haystack.includes("lmstudio:detected") ||
    haystack.includes("detected model slot") ||
    haystack.includes("provider_stopped")
  );
}

function modelLooksProductChatSelectable(snapshot, artifact = {}) {
  const endpoint = modelEndpointForArtifact(snapshot, artifact) || {};
  if (modelIsEmbeddingOnly(artifact) || modelIsEmbeddingOnly(endpoint)) {
    return false;
  }
  const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
  const supportsChat = capabilities.length === 0 ||
    capabilities.some((capability) => /chat|responses/i.test(String(capability || "")));
  return supportsChat && ![artifact, endpoint].some(modelLooksHiddenFromProductChat);
}

function renderRecommendedModelSetup(snapshot) {
  if (snapshot.artifacts.some((artifact) => modelLooksProductChatSelectable(snapshot, artifact))) {
    return "";
  }
  return `
    <section class="model-onboarding" data-testid="model-recommended-setup">
      <div>
        <span class="model-chip">Recommended setup</span>
        <h3>Set up product local models</h3>
        <p>No product chat model is mounted. Autopilot should guide first-run setup from hardware survey to recommended downloads instead of exposing fixtures or detected-provider internals.</p>
      </div>
      <ul>
        <li><strong>Qwen 3.5</strong><span>Primary local chat, reasoning, and artifact generation route.</span></li>
        <li><strong>Story model</strong><span>Optional creative-writing lane when intentionally installed.</span></li>
        <li><strong>Text embedding</strong><span>Optional retrieval/indexing lane, not a chat route.</span></li>
      </ul>
      <div class="model-onboarding__actions">
        ${renderCommandButton({
          label: "Find recommended models",
          command: "ioi.models.open",
          payload: { phase: "recommended-setup", source: "model-onboarding-empty-state" },
        })}
      </div>
    </section>
  `;
}

function renderModelTags(values, { max = 4 } = {}) {
  const tags = Array.from(new Set(values.filter(Boolean).map((value) => String(value))));
  if (!tags.length) {
    return `<span class="model-chip is-muted">chat</span>`;
  }
  return tags
    .slice(0, max)
    .map((value) => `<span class="model-chip">${escapeHtml(value)}</span>`)
    .join("");
}

function modelCapabilityText(artifact = {}) {
  const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
  return Array.from(new Set(capabilities.filter(Boolean).map((value) => String(value)))).join(", ") || "chat";
}

function modelSelectedLoadOptions(instance = {}, engine = {}) {
  const defaults = engine.defaultLoadOptions || {};
  const instanceLoadOptions = instance.loadOptions || {};
  return {
    identifier: instance.identifier || instance.modelId || "local-model",
    contextLength: instance.contextLength || instanceLoadOptions.contextLength || defaults.contextLength || 2048,
    gpuOffload:
      instance.gpuOffload ??
      instanceLoadOptions.gpuOffload ??
      instanceLoadOptions.gpu ??
      defaults.gpuOffload ??
      defaults.gpu ??
      "auto",
    parallelism: instance.parallelism || instanceLoadOptions.parallel || defaults.parallel || 1,
    idleTtlSeconds: instance.loadPolicy?.idleTtlSeconds || defaults.idleTtlSeconds || 900,
  };
}

function renderModelLibraryRows(snapshot) {
  if (!snapshot.artifacts.length) {
    return `
      <tr>
        <td colspan="7">
          <div class="model-empty" data-testid="model-empty-state">No daemon model artifacts are projected yet.</div>
        </td>
      </tr>
    `;
  }
  const loadedModelIds = new Set(
    snapshot.instances
      .filter((instance) => instance.status === "loaded")
      .map((instance) => instance.modelId)
      .filter(Boolean),
  );
  const selectedId =
    snapshot.artifacts.find((artifact) => loadedModelIds.has(artifact.modelId))?.id ||
    snapshot.artifacts[0]?.id ||
    snapshot.artifacts[0]?.modelId;
  return snapshot.artifacts
    .map((artifact, index) => {
      const endpoint = modelEndpointForArtifact(snapshot, artifact);
      const instance = modelInstanceForEndpoint(snapshot, endpoint);
      const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
      const modelId = artifact.modelId || artifact.id;
      const rowStatus = instance?.status || endpoint?.status || artifact.status || "installed";
      const actionPayload = {
        modelId,
        endpointId: endpoint?.id,
      };
      const isSelected =
        artifact.id === selectedId ||
        artifact.modelId === selectedId ||
        (index === 0 && !selectedId);
      return `
        <tr
          class="${isSelected ? "is-selected" : ""}"
          data-model-row="${escapeHtml(artifact.modelId || artifact.id)}"
          data-model-label="${escapeHtml(modelDisplayName(artifact))}"
          data-model-publisher="${escapeHtml(modelPublisher(artifact))}"
          data-model-domain="${escapeHtml(modelDomain(artifact))}"
          data-model-status="${escapeHtml(rowStatus)}"
          data-model-file="${escapeHtml(artifact.fileName || artifact.path || "daemon artifact")}"
          data-model-format="${escapeHtml(artifact.format || "GGUF")}"
          data-model-quantization="${escapeHtml(artifact.quantization || "unknown")}"
          data-model-arch="${escapeHtml(modelArch(artifact))}"
          data-model-params="${escapeHtml(modelParams(artifact))}"
          data-model-capabilities="${escapeHtml(modelCapabilityText(artifact))}"
          data-model-size="${escapeHtml(formatBytes(artifact.sizeBytes ?? artifact.size_bytes))}"
          data-model-endpoint-id="${escapeHtml(endpoint?.id || "")}"
          data-model-instance-id="${escapeHtml(instance?.id || "")}"
          data-model-backend-id="${escapeHtml(instance?.backendId || endpoint?.backendId || "")}"
          tabindex="0"
          role="button"
          data-testid="${isSelected ? "model-library-row-selected" : "model-library-row"}"
        >
          <td class="model-table__name">
            <strong>${escapeHtml(modelDisplayName(artifact))}</strong>
            <small>${escapeHtml(artifact.modelId || artifact.id)}</small>
          </td>
          <td>${renderModelTags([modelArch(artifact)])}</td>
          <td>${renderModelTags([modelParams(artifact)])}</td>
          <td>${escapeHtml(modelPublisher(artifact))}</td>
          <td>${renderModelTags([modelDomain(artifact), artifact.format || "GGUF"])}</td>
          <td>${modelStatusPill(rowStatus)}</td>
          <td class="model-actions-cell">
            <button class="model-icon-button" type="button" data-command="ioi.models.openLoader"${commandPayloadAttr(actionPayload)} title="Open loader" aria-label="Open loader">Load</button>
            <button class="model-icon-button" type="button" data-command="ioi.models.estimateNative"${commandPayloadAttr(actionPayload)} title="Estimate load" aria-label="Estimate load">Estimate</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderModelQuickLoaderRows(snapshot) {
  if (!snapshot.artifacts.length) {
    return `<div class="model-empty">Open the daemon model catalog to populate the loader.</div>`;
  }
  return snapshot.artifacts
    .slice(0, 5)
    .map((artifact, index) => {
      const endpoint = modelEndpointForArtifact(snapshot, artifact);
      const instance = modelInstanceForEndpoint(snapshot, endpoint);
      const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
      return `
        <button
          class="model-loader-row ${index === 0 ? "is-selected" : ""}"
          type="button"
          data-model-label="${escapeHtml(modelDisplayName(artifact))}"
          data-model-publisher="${escapeHtml(modelPublisher(artifact))}"
          data-model-domain="${escapeHtml(modelDomain(artifact))}"
          data-testid="${index === 0 ? "model-quick-loader-selected-row" : "model-quick-loader-row"}"
          data-command="ioi.models.openLoader"
          ${commandPayloadAttr({ modelId: artifact.modelId || artifact.id, endpointId: endpoint?.id })}
        >
          <span>
            <strong>${escapeHtml(modelDisplayName(artifact))}</strong>
            <small>${escapeHtml(modelPublisher(artifact))}</small>
          </span>
          <span>${renderModelTags([modelArch(artifact), artifact.format || "GGUF", ...capabilities], { max: 3 })}</span>
          <span>${escapeHtml(formatBytes(artifact.sizeBytes ?? artifact.size_bytes))}</span>
          <span>${modelStatusPill(instance?.status || endpoint?.status || artifact.status || "installed")}</span>
        </button>
      `;
    })
    .join("");
}

function renderModelReceiptRows(snapshot, limit = 7) {
  const receipts = snapshot.receipts.slice(-limit).reverse();
  if (!receipts.length) {
    return `<div class="model-empty">No model receipts have been emitted yet.</div>`;
  }
  return receipts
    .map(
      (receipt) => `
        <article class="model-log-row">
          <strong>${escapeHtml(modelReceiptKind(receipt))}</strong>
          <span>${escapeHtml(receipt.id || receipt.receiptId || "receipt")}</span>
          <small>${escapeHtml(receipt.summary || receipt.details?.summary || "daemon receipt")}</small>
        </article>
      `,
    )
    .join("");
}

function modelCatalogFallbackEntries(snapshot) {
  return snapshot.artifacts.slice(0, 8).map((artifact) => ({
    id: `local.${artifact.id || artifact.modelId}`,
    providerId: artifact.providerId || "provider.local-folder",
    catalogProviderId: "catalog.local-installed",
    modelId: artifact.modelId || artifact.id,
    family: artifact.family || artifact.arch || modelDomain(artifact),
    architecture: modelArch(artifact),
    parameterCount: modelParams(artifact),
    format: String(artifact.format || "gguf").toLowerCase(),
    quantization: artifact.quantization || "installed",
    sizeBytes: artifact.sizeBytes ?? artifact.size_bytes,
    contextWindow: artifact.contextWindow ?? artifact.context_window ?? null,
    sourceLabel: `Installed artifact / ${modelDisplayName(artifact)}`,
    license: artifact.license || "local",
    compatibility: ["installed", modelDomain(artifact), artifact.format || "gguf"],
    tags: Array.isArray(artifact.capabilities) ? artifact.capabilities : [modelDomain(artifact)],
    variantPath: artifact.path || artifact.fileName || null,
    description:
      artifact.description ||
      "This model is already projected by the daemon. Run a catalog search to discover remote or provider-backed variants.",
    downloadRisk: { status: "already_installed" },
  }));
}

function modelCatalogReferenceEntries() {
  return [
    {
      id: "reference.nvidia.nemotron-3-nano-omni",
      catalogProviderId: "catalog.huggingface",
      modelId: "nvidia/nemotron-3-nano-omni",
      displayName: "Nemotron 3 Nano Omni",
      publisher: "NVIDIA",
      family: "Nemotron Nano V3 Omni",
      architecture: "nemotron_h_moe",
      parameterCount: "30B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 26.1 * 1024 * 1024 * 1024,
      downloads: 149_861,
      stars: 22,
      updatedLabel: "23 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/nvidia/nemotron-3-nano-omni",
      license: "model card",
      staffPick: true,
      verified: true,
      compatibility: ["vision", "tool use", "reasoning"],
      tags: ["vision", "tool use", "reasoning", "llm", "gguf"],
      description:
        "Nemotron Nano V3 Omni is a multi-modal large language model designed to integrate image and text understanding, enabling workflows such as Q&A, summarization, and document intelligence.",
      readme:
        "Nemotron 3 Nano Omni by NVIDIA supports long-context, multi-modal workflows with reasoning, tool use, and partial GPU offload options surfaced through the daemon catalog.",
      moreFromPublisher: [
        { label: "nemotron-3-nano-4b", downloads: 155_000, stars: 14 },
        { label: "nemotron-3-super", downloads: 169_000, stars: 45 },
        { label: "nemotron-3-nano", downloads: 148_000, stars: 59 },
      ],
    },
    {
      id: "reference.qwen.qwen3.6-27b",
      catalogProviderId: "catalog.huggingface",
      modelId: "qwen/qwen3.6-27b",
      displayName: "Qwen3.6 27B",
      publisher: "Qwen",
      family: "Qwen3.6",
      architecture: "qwen3",
      parameterCount: "27B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 16.4 * 1024 * 1024 * 1024,
      downloads: 94_820,
      stars: 18,
      updatedLabel: "29 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/qwen/qwen3.6-27b",
      license: "model card",
      staffPick: true,
      verified: true,
      compatibility: ["reasoning", "tool use", "llm"],
      tags: ["reasoning", "tool use", "llm", "gguf"],
      description:
        "Dense Qwen reasoning model for local planning, tool use, and workflow-backed coding tasks.",
      readme:
        "Qwen3.6 27B is a practical local reasoning candidate for Autopilot routes where the daemon needs predictable model lifecycle, receipts, and replay.",
      moreFromPublisher: [
        { label: "qwen3.6-35b-a3b", downloads: 86_000, stars: 33 },
        { label: "qwen3-coder-next", downloads: 71_000, stars: 31 },
        { label: "qwen3.5-9b", downloads: 64_000, stars: 21 },
      ],
    },
    {
      id: "reference.google.gemma-4-31b",
      catalogProviderId: "catalog.huggingface",
      modelId: "google/gemma-4-31b",
      displayName: "Gemma 4 31B",
      publisher: "Google",
      family: "Gemma 4",
      architecture: "gemma4",
      parameterCount: "31B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 18.7 * 1024 * 1024 * 1024,
      downloads: 88_630,
      stars: 27,
      updatedLabel: "40 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/google/gemma-4-31b",
      license: "model card",
      verified: true,
      compatibility: ["vision", "tool use", "llm"],
      tags: ["vision", "tool use", "llm", "gguf"],
      description:
        "General-purpose model family candidate for on-device assistants and document workflows.",
      readme:
        "Gemma 4 31B is shown as a discovery candidate so Autopilot can route users from model selection into daemon-owned estimate, download, and load flows.",
      moreFromPublisher: [
        { label: "gemma-4-e4b", downloads: 73_000, stars: 19 },
        { label: "gemma-4-e2b", downloads: 67_000, stars: 15 },
        { label: "gemma-4-26b-a4b", downloads: 61_000, stars: 17 },
      ],
    },
    {
      id: "reference.mistral.devstral-small-2-2512",
      catalogProviderId: "catalog.huggingface",
      modelId: "mistral/devstral-small-2-2512",
      displayName: "Devstral Small 2 2512",
      publisher: "Mistral",
      family: "Devstral",
      architecture: "mistral",
      parameterCount: "24B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 14.9 * 1024 * 1024 * 1024,
      downloads: 57_430,
      stars: 16,
      updatedLabel: "161 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/mistral/devstral-small-2-2512",
      license: "model card",
      verified: true,
      compatibility: ["tool use", "coding", "llm"],
      tags: ["tool use", "coding", "llm", "gguf"],
      description:
        "Second-generation coding model candidate for local repository work and agentic code proposal loops.",
      readme:
        "Devstral is a coding-focused local model candidate for Workflow Composer dry-runs and code proposal routes once daemon download/load APIs are enabled.",
      moreFromPublisher: [
        { label: "ministral-3-14b-reasoning", downloads: 42_000, stars: 11 },
        { label: "mistral-small-instruct", downloads: 98_000, stars: 39 },
      ],
    },
    {
      id: "reference.ollama.nomic-embed-text",
      catalogProviderId: "catalog.custom_http",
      modelId: "nomic-ai/nomic-embed-text-v1.5",
      displayName: "Nomic Embed Text v1.5",
      publisher: "Nomic AI",
      family: "Nomic Embed",
      architecture: "nomic-bert",
      parameterCount: "local",
      domain: "embedding",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 80.2 * 1024 * 1024,
      downloads: 214_000,
      stars: 52,
      updatedLabel: "local registry",
      sourceLabel: "Embedding pick / configurable endpoint",
      sourceUrl: "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5",
      license: "model card",
      verified: true,
      compatibility: ["embedding", "retrieval"],
      tags: ["embedding", "retrieval", "gguf"],
      description:
        "Small text embedding model candidate for retrieval, memory, and workflow evidence search.",
      readme:
        "Nomic Embed Text is useful when Autopilot needs local retrieval indexes without giving the model direct authority over files or receipts.",
      moreFromPublisher: [
        { label: "nomic-embed-code", downloads: 76_000, stars: 18 },
        { label: "nomic-bert", downloads: 112_000, stars: 29 },
      ],
    },
  ];
}

function modelCatalogResults(snapshot) {
  const results = Array.isArray(snapshot.catalog?.results) ? snapshot.catalog.results : [];
  const remoteResults = results.filter((entry) => {
    const provider = `${entry.catalogProviderId || ""} ${entry.providerId || ""} ${entry.sourceLabel || ""}`;
    const summary = `${entry.description || ""} ${entry.summary || ""}`;
    return (
      !/local-installed|local-folder|provider\.local|daemon catalog/i.test(provider) &&
      !/already projected by the daemon/i.test(summary)
    );
  });
  return remoteResults.length ? remoteResults : modelCatalogReferenceEntries();
}

function modelCatalogLocalProjectionEntries(snapshot) {
  return modelCatalogFallbackEntries(snapshot);
}

function formatCatalogMetric(value, fallback = "unknown") {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return fallback;
  }
  return numeric.toLocaleString("en-US");
}

function catalogSizeLabel(entry = {}) {
  return entry.sizeLabel || formatBytes(entry.sizeBytes ?? entry.size_bytes);
}

function catalogUpdatedLabel(entry = {}) {
  if (entry.updatedLabel) {
    return String(entry.updatedLabel);
  }
  const timestamp =
    entry.updatedAt ||
    entry.updated_at ||
    entry.modifiedAt ||
    entry.modified_at ||
    entry.discoveredAt ||
    entry.discovered_at;
  return timestamp ? formatRelativeTime(Date.parse(timestamp)) : "registry";
}

function catalogReadme(entry = {}) {
  return entry.readme || entry.card || catalogSummary(entry);
}

function catalogPublisherLogo(entry = {}) {
  const publisher = catalogPublisher(entry);
  if (/nvidia/i.test(publisher)) return "NV";
  if (/google/i.test(publisher)) return "G";
  if (/qwen/i.test(publisher)) return "Q";
  if (/mistral/i.test(publisher)) return "MI";
  if (/nomic/i.test(publisher)) return "NO";
  return publisher.slice(0, 2).toUpperCase();
}

function catalogMoreFromPublisher(results, selected) {
  if (Array.isArray(selected.moreFromPublisher) && selected.moreFromPublisher.length) {
    return selected.moreFromPublisher.slice(0, 4);
  }
  return results
    .filter((entry) => catalogPublisher(entry) === catalogPublisher(selected) && entry.id !== selected.id)
    .slice(0, 4)
    .map((entry) => ({
      label: entry.modelId || entry.id,
      downloads: entry.downloads,
      stars: entry.stars,
      sizeBytes: entry.sizeBytes ?? entry.size_bytes,
    }));
}

function catalogDisplayName(entry = {}) {
  const raw = entry.displayName || entry.name || entry.modelId || entry.id || "Catalog model";
  return String(raw).split("/").pop() || raw;
}

function catalogPublisher(entry = {}) {
  const explicit = entry.publisher || entry.author || entry.providerLabel || entry.catalogProviderId || entry.providerId;
  if (explicit) {
    return String(explicit).replace(/^catalog\./, "").replace(/^provider\./, "");
  }
  const modelId = String(entry.modelId || "");
  return modelId.includes("/") ? modelId.split("/")[0] : "daemon catalog";
}

function catalogSummary(entry = {}) {
  return (
    entry.description ||
    entry.summary ||
    `${entry.family || "Model"} ${entry.parameterCount || ""} ${entry.format || ""} candidate discovered through ${catalogPublisher(entry)}.`
  )
    .replace(/\s+/g, " ")
    .trim();
}

function catalogCapabilities(entry = {}) {
  return Array.from(
    new Set(
      [
        ...(Array.isArray(entry.tags) ? entry.tags : []),
        ...(Array.isArray(entry.compatibility) ? entry.compatibility : []),
        entry.format,
        entry.quantization,
      ]
        .filter(Boolean)
        .map((value) => String(value)),
    ),
  );
}

function catalogDownloadBlocked(snapshot, entry = {}) {
  const providers = Array.isArray(snapshot.catalog?.providers) ? snapshot.catalog.providers : [];
  const provider = providers.find(
    (candidate) => candidate.id === entry.catalogProviderId || candidate.providerId === entry.providerId,
  );
  const liveDownloadConfigured = providers.some((candidate) =>
    /configured|available|enabled/i.test(String(candidate.liveDownloadStatus || candidate.downloadStatus || "")),
  );
  const isInstalled = String(entry.catalogProviderId || "").includes("local-installed");
  return {
    blocked: isInstalled || !liveDownloadConfigured,
    reason: isInstalled
      ? "Already installed"
      : provider?.downloadGate
        ? "Download gated"
        : "Daemon gated",
  };
}

function renderModelDiscoveryRows(snapshot) {
  const results = modelCatalogResults(snapshot);
  if (!results.length) {
    return `<div class="model-empty" data-testid="model-discover-empty-state">Search the daemon catalog to discover models.</div>`;
  }
  return results
    .map((entry, index) => {
      const capabilities = catalogCapabilities(entry);
      const isSelected = index === 0;
      const badges = [entry.parameterCount, entry.architecture || entry.arch, entry.format, ...capabilities]
        .filter(Boolean)
        .slice(0, 4);
      return `
        <button
          class="model-discover-result ${isSelected ? "is-selected" : ""}"
          type="button"
          data-catalog-row="${escapeHtml(entry.id || entry.modelId || `catalog-${index}`)}"
          data-catalog-label="${escapeHtml(catalogDisplayName(entry))}"
          data-catalog-model-id="${escapeHtml(entry.modelId || entry.id || "")}"
          data-catalog-publisher="${escapeHtml(catalogPublisher(entry))}"
          data-catalog-summary="${escapeHtml(catalogSummary(entry))}"
          data-catalog-params="${escapeHtml(entry.parameterCount || "local")}"
          data-catalog-arch="${escapeHtml(entry.architecture || entry.arch || "unknown")}"
          data-catalog-domain="${escapeHtml(entry.domain || "llm")}"
          data-catalog-format="${escapeHtml(entry.format || "gguf")}"
          data-catalog-quantization="${escapeHtml(entry.quantization || "unknown")}"
          data-catalog-size="${escapeHtml(catalogSizeLabel(entry))}"
          data-catalog-license="${escapeHtml(entry.license || "unknown")}"
          data-catalog-downloads="${escapeHtml(formatCatalogMetric(entry.downloads, "registry"))}"
          data-catalog-stars="${escapeHtml(formatCatalogMetric(entry.stars, "score"))}"
          data-catalog-updated="${escapeHtml(catalogUpdatedLabel(entry))}"
          data-catalog-capabilities="${escapeHtml(catalogCapabilities(entry).slice(0, 5).join(" / "))}"
          data-catalog-source-label="${escapeHtml(entry.sourceLabel || catalogPublisher(entry))}"
          data-catalog-source-url="${escapeHtml(entry.sourceUrl || "")}"
          data-catalog-download-label="${escapeHtml(entry.downloadRisk?.status === "already_installed" ? "Already installed" : "Download")}"
          data-catalog-readme-title="${escapeHtml(`${catalogDisplayName(entry)} by ${catalogPublisher(entry)}`)}"
          data-catalog-readme="${escapeHtml(catalogReadme(entry))}"
          data-testid="${isSelected ? "model-discover-result-selected" : "model-discover-result-row"}"
        >
          <span class="model-discover-result__logo">${escapeHtml(catalogPublisherLogo(entry))}</span>
          <span class="model-discover-result__body">
            <strong>${escapeHtml(catalogDisplayName(entry))}${entry.verified ? `<span class="model-discover-result__verified">verified</span>` : ""}</strong>
            <small>${escapeHtml(catalogSummary(entry))}</small>
            <span class="model-discover-result__age">${escapeHtml(catalogUpdatedLabel(entry))}</span>
          </span>
          <span class="model-discover-result__tags">${renderModelTags(badges, { max: 4 })}</span>
        </button>
      `;
    })
    .join("");
}

function renderModelDiscoverySurface(snapshot) {
  const results = modelCatalogResults(snapshot);
  const localProjectionCount = modelCatalogLocalProjectionEntries(snapshot).length;
  const selected = results[0] || {};
  const providers = Array.isArray(snapshot.catalog?.providers) ? snapshot.catalog.providers : [];
  const lastSearch = snapshot.catalog?.lastSearch || null;
  const downloadState = catalogDownloadBlocked(snapshot, selected);
  const moreFromPublisher = catalogMoreFromPublisher(results, selected);
  const selectedCapabilities = catalogCapabilities(selected).slice(0, 5);
  return `
    <section class="models-lmstudio__discover" data-model-surface-panel="discover" data-testid="model-discovery-surface" data-catalog-needs-search="${lastSearch ? "false" : "true"}" hidden>
      <section class="model-discovery-list" data-testid="model-discover-list">
        <header class="model-discovery-toolbar">
          <label class="models-lmstudio__search">
            <span aria-hidden="true">Find</span>
            <input data-testid="model-discover-search-input" type="search" placeholder="Search registry models by name or author..." value="${escapeHtml(lastSearch?.query || "")}" />
          </label>
          <button class="model-icon-button" type="button" data-testid="model-discover-search-button">Search</button>
        </header>
        <div class="model-discovery-meta" data-testid="model-discover-staff-picks">
          <span>Staff picks</span>
          <button class="model-icon-button" type="button" data-testid="model-discover-refresh-button" title="Refresh catalog search">Refresh</button>
          <label class="model-discovery-sort" data-testid="model-discover-sort">
            <span>Sort</span>
            <select aria-label="Sort registry models">
              <option>Best Match</option>
              <option>Recently Updated</option>
              <option>Downloads</option>
              <option>Smallest</option>
            </select>
          </label>
        </div>
        <div class="model-discovery-results">${renderModelDiscoveryRows(snapshot)}</div>
        <footer class="model-discovery-provider-strip" data-testid="model-catalog-provider-strip">
          <span>${escapeHtml(lastSearch ? `${lastSearch.resultCount ?? results.length} daemon results` : "reference staff picks")}</span>
          <span>${escapeHtml(String(localProjectionCount))} local artifacts available in My Models</span>
          ${providers
            .slice(0, 3)
            .map((provider) => `<span>${escapeHtml(provider.label || provider.id)} · ${escapeHtml(provider.status || "unknown")}</span>`)
            .join("") || "<span>Default endpoint: Hugging Face-compatible</span>"}
        </footer>
      </section>
      <section class="model-discovery-detail" data-testid="model-discover-detail">
        <header>
          <div>
            <span class="model-icon-label" aria-hidden="true">AI</span>
            <h2 data-catalog-field="title">${escapeHtml(catalogDisplayName(selected))}</h2>
            <small data-catalog-field="modelId">${escapeHtml(selected.modelId || selected.id || "daemon catalog")}</small>
          </div>
          <button class="model-icon-button model-discovery-close" type="button" data-model-surface-tab="library" data-testid="model-discover-close-button" title="Close discovery">X</button>
        </header>
        <section class="model-discovery-stats" data-testid="model-discover-stats">
          <span><strong data-catalog-field="downloads">${escapeHtml(formatCatalogMetric(selected.downloads, "registry"))}</strong> downloads</span>
          <span><strong data-catalog-field="stars">${escapeHtml(formatCatalogMetric(selected.stars, "score"))}</strong> stars</span>
          <span>Updated <strong data-catalog-field="updated">${escapeHtml(catalogUpdatedLabel(selected))}</strong></span>
          ${selected.staffPick ? "<span>Staff Pick</span>" : ""}
        </section>
        <p class="model-discovery-summary" data-catalog-field="summary">${escapeHtml(catalogSummary(selected))}</p>
        <dl class="model-discovery-facts">
          <div><dt>Params</dt><dd data-catalog-field="params">${escapeHtml(selected.parameterCount || "local")}</dd></div>
          <div><dt>Arch</dt><dd data-catalog-field="arch">${escapeHtml(selected.architecture || selected.arch || "unknown")}</dd></div>
          <div><dt>Domain</dt><dd data-catalog-field="domain">${escapeHtml(selected.domain || "llm")}</dd></div>
          <div><dt>Format</dt><dd data-catalog-field="format">${escapeHtml(selected.format || "gguf")}</dd></div>
        </dl>
        <section class="model-download-options model-discovery-download" data-testid="model-download-options">
          <header>
            <strong>Download Options</strong>
            <small data-catalog-field="sourceLabel">${escapeHtml(selected.sourceLabel || catalogPublisher(selected))}</small>
          </header>
          <div>
            <span>GGUF</span>
            <span data-catalog-field="downloadTitle">${escapeHtml(`${catalogDisplayName(selected)} ${selected.parameterCount || ""} ${selected.quantization || "Q4_K_M"}`.trim())}</span>
            <span data-catalog-field="quantization">${escapeHtml(selected.quantization || "Q4_K_M")}</span>
            <span data-catalog-field="size">${escapeHtml(catalogSizeLabel(selected))}</span>
            <button
              class="action"
              type="button"
              data-testid="model-download-button"
              data-command="ioi.models.downloadCatalog"
              ${commandPayloadAttr({ catalogEntryId: selected.id, sourceUrl: selected.sourceUrl, modelId: selected.modelId })}
              ${downloadState.blocked ? "disabled" : ""}
            >${downloadState.blocked ? escapeHtml(downloadState.reason) : "Download"}</button>
          </div>
          <small>Partial GPU offload possible when the daemon exposes a compatible backend estimate.</small>
        </section>
        <section class="model-discovery-capabilities" data-testid="model-discover-capabilities">
          <strong>Capabilities</strong>
          <span data-catalog-field="capabilities">${escapeHtml(selectedCapabilities.join(" / ") || "metadata pending")}</span>
        </section>
        <section class="model-readme-panel" data-testid="model-readme-panel">
          <h3 data-testid="model-discover-readme-title" data-catalog-field="readmeTitle">${escapeHtml(`${catalogDisplayName(selected)} by ${catalogPublisher(selected)}`)}</h3>
          <p data-catalog-field="readme">${escapeHtml(catalogReadme(selected))}</p>
        </section>
        <section class="model-more-from" data-testid="model-more-from-publisher">
          <h3>More from <span data-catalog-field="publisher">${escapeHtml(catalogPublisher(selected))}</span></h3>
          ${
            moreFromPublisher.length
              ? moreFromPublisher
                  .map((entry) => `<span>${escapeHtml(entry.label || entry.modelId || entry.id)} · ${escapeHtml(entry.sizeBytes ? formatBytes(entry.sizeBytes) : formatCatalogMetric(entry.downloads, "registry"))} · ${escapeHtml(formatCatalogMetric(entry.stars, "score"))}</span>`)
                  .join("")
              : "<span>No additional daemon-projected variants yet.</span>"
          }
        </section>
      </section>
    </section>
  `;
}

function catalogProviderById(snapshot, providerId) {
  const providers = [
    ...(Array.isArray(snapshot.catalog?.providers) ? snapshot.catalog.providers : []),
    ...(Array.isArray(snapshot.providers) ? snapshot.providers : []),
  ];
  const configs = Array.isArray(snapshot.catalogProviderConfigs) ? snapshot.catalogProviderConfigs : [];
  return {
    provider: providers.find((candidate) => candidate.id === providerId) || {},
    config: configs.find((candidate) => candidate.id === providerId) || {},
  };
}

function renderCatalogSourceRow(snapshot, providerId, label, description, testId) {
  const { provider, config } = catalogProviderById(snapshot, providerId);
  const status = provider.status || config.runtimeMaterialStatus || (config.materialConfigured ? "configured" : "unconfigured");
  const configured = Boolean(config.materialConfigured || provider.materialConfigured || provider.baseUrlHash || provider.manifestPathHash);
  return `
    <article class="model-source-row" data-testid="${escapeHtml(testId)}">
      <div>
        <strong>${escapeHtml(label)}</strong>
        <span>${escapeHtml(description)}</span>
      </div>
      <dl>
        <div><dt>Status</dt><dd>${escapeHtml(status)}</dd></div>
        <div><dt>Configured</dt><dd>${configured ? "yes" : "default"}</dd></div>
        <div><dt>Boundary</dt><dd>${escapeHtml(provider.gate || "daemon provider config")}</dd></div>
      </dl>
    </article>
  `;
}

function renderModelSourcesSurface(snapshot) {
  const providers = Array.isArray(snapshot.providers) ? snapshot.providers : [];
  const lmStudio = providers.find((provider) => provider.id === "provider.lmstudio" || provider.providerId === "provider.lmstudio") || {};
  const ollama = providers.find((provider) => provider.id === "provider.ollama" || provider.providerId === "provider.ollama") || {};
  return `
    <section class="models-lmstudio__sources" data-model-surface-panel="sources" data-testid="model-catalog-sources-surface" hidden>
      <section class="model-sources-grid">
        <header class="model-sources-header">
          <div>
            <h2>Catalog Sources</h2>
            <p>Local autodiscovery plus configurable daemon-owned remote registries. The webview only submits source configuration requests.</p>
          </div>
          <button class="model-icon-button" type="button" data-model-surface-tab="discover" data-testid="model-sources-open-discover-button">Open Discover</button>
        </header>
        <section class="model-sources-card" data-testid="model-local-autodiscovery-sources">
          <h3>Local Autodiscovery</h3>
          ${renderCatalogSourceRow({ catalog: {}, catalogProviderConfigs: [], providers: [lmStudio] }, "provider.lmstudio", "LM Studio", "Find local LM Studio models and mounted local server routes.", "model-source-lmstudio")}
          ${renderCatalogSourceRow({ catalog: {}, catalogProviderConfigs: [], providers: [ollama] }, "provider.ollama", "Ollama", "Find local Ollama models without copying artifacts into Autopilot.", "model-source-ollama")}
          <p class="model-source-note">Local providers are discovered on startup and remain daemon-owned; Autopilot mounts routes as projections.</p>
        </section>
        <section class="model-sources-card" data-testid="model-remote-registry-sources">
          <h3>Remote Registries</h3>
          ${renderCatalogSourceRow(snapshot, "catalog.huggingface", "Hugging Face-compatible", "Default public registry, or a sovereign HF-compatible endpoint.", "model-source-huggingface")}
          ${renderCatalogSourceRow(snapshot, "catalog.custom_http", "Custom HTTP catalog", "Private or ecosystem catalogs exposing /catalog/search.", "model-source-custom-http")}
          ${renderCatalogSourceRow(snapshot, "catalog.local_manifest", "Local manifest", "Offline JSON catalog for internal or air-gapped model indexes.", "model-source-local-manifest")}
        </section>
        <section class="model-sources-card model-source-config" data-testid="model-catalog-source-config">
          <h3>Configure Source</h3>
          <label>
            <span>Provider</span>
            <select data-testid="model-catalog-provider-select">
              <option value="catalog.huggingface">Hugging Face-compatible</option>
              <option value="catalog.custom_http">Custom HTTP catalog</option>
              <option value="catalog.local_manifest">Local manifest</option>
            </select>
          </label>
          <label data-model-source-field="baseUrl">
            <span>Endpoint</span>
            <input data-testid="model-catalog-source-url-input" type="url" placeholder="https://huggingface.co" value="https://huggingface.co" />
          </label>
          <label data-model-source-field="manifestPath" hidden>
            <span>Manifest path</span>
            <input data-testid="model-catalog-manifest-path-input" type="text" placeholder="/path/to/model-catalog.json" />
          </label>
          <label>
            <span>Search after configure</span>
            <input data-testid="model-catalog-source-search-input" type="search" placeholder="qwen, llama, embedding..." value="qwen" />
          </label>
          <div class="model-source-actions">
            <button class="action" type="button" data-testid="model-catalog-source-configure-button">Save source</button>
            <button class="model-icon-button" type="button" data-model-surface-tab="discover">Skip to Discover</button>
          </div>
          <p class="model-source-note">Credentials stay out of the webview. Auth and OAuth remain daemon/vault concerns.</p>
        </section>
      </section>
    </section>
  `;
}

function renderModelsPanelBody(state, { compact = false } = {}) {
  const snapshot = modelSnapshotFromState(state);
  const modelStatus = state.modelMountingStatus || {};
  const loadedModelIds = new Set(
    snapshot.instances
      .filter((instance) => instance.status === "loaded")
      .map((instance) => instance.modelId)
      .filter(Boolean),
  );
  const selectedArtifact =
    snapshot.artifacts.find((artifact) => loadedModelIds.has(artifact.modelId)) ||
    snapshot.artifacts[0] ||
    {};
  const selectedEndpoint = modelEndpointForArtifact(snapshot, selectedArtifact) || snapshot.endpoints[0] || {};
  const selectedInstance =
    modelInstanceForEndpoint(snapshot, selectedEndpoint) || snapshot.instances.find((item) => item.status === "loaded") || {};
  const selectedRoute =
    snapshot.routes.find((route) => route.id === "route.native-local") || snapshot.routes[0] || {};
  const selectedBackend =
    snapshot.backends.find((backend) => backend.id === selectedInstance.backendId) ||
    snapshot.backends[0] ||
    {};
  const selectedEngine =
    snapshot.runtimeEngines.find(
      (engine) =>
        engine.id === selectedBackend.id ||
        engine.kind === selectedBackend.kind ||
        engine.kind === `${selectedBackend.kind}_runtime`,
    ) ||
    snapshot.runtimeEngines.find((engine) => engine.selected) ||
    snapshot.runtimeEngines[0] ||
    {};
  const loadReceipt = snapshot.receipts
    .slice()
    .reverse()
    .find((receipt) => modelReceiptKind(receipt) === "model_load_estimate");
  const invokeReceipt = snapshot.receipts
    .slice()
    .reverse()
    .find((receipt) => receipt.kind === "model_invocation");
  const routeReceipt = snapshot.receipts
    .slice()
    .reverse()
    .find((receipt) => receipt.kind === "model_route_selection");
  const loadedCount = snapshot.instances.filter((instance) => instance.status === "loaded").length;
  const loadOptions = modelSelectedLoadOptions(selectedInstance, selectedEngine);
  const localSizeBytes = snapshot.artifacts.reduce(
    (total, artifact) => total + Number(artifact.sizeBytes ?? artifact.size_bytes ?? 0),
    0,
  );
  const artifactCapabilities = Array.isArray(selectedArtifact.capabilities)
    ? selectedArtifact.capabilities
    : [];
      const serverBaseUrl =
    snapshot.server.openAiCompatibleBaseUrl ||
      snapshot.server.openAiCompatibleApi ||
      snapshot.server.nativeBaseUrl ||
      snapshot.server.nativeApi ||
      "/v1";

  return `
      <section
        class="model-workbench models-lmstudio ${compact ? "is-compact" : ""}"
      data-testid="autopilot-models-mode"
      data-inspection-target="autopilot-models-mode"
      data-daemon-backed="${modelStatus.status === "connected" ? "true" : "false"}"
      data-active-model-surface="library"
      >
      ${
        modelStatus.status === "degraded"
          ? `<section class="model-state-banner is-error" data-testid="model-error-state"><strong>Daemon model runtime degraded</strong><span>${escapeHtml(modelStatus.error || "The model daemon is configured but not reachable.")}</span></section>`
          : ""
      }
      <section class="models-lmstudio__primary" data-testid="models-lmstudio-shell">
        <aside class="models-lmstudio__rail" data-testid="models-left-rail" aria-label="Model categories">
          <strong>My Models</strong>
          <button class="is-active" type="button" data-model-surface-tab="library">View All</button>
          <button type="button">LLMs <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "llm").length))}</span></button>
          <button type="button">Text Embedding <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "embedding").length))}</span></button>
          <button type="button">Vision / Tools <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "vlm").length))}</span></button>
          <strong>Discover</strong>
          <button type="button" data-model-surface-tab="discover" data-testid="model-discover-open-button">Catalog <span>${escapeHtml(String(modelCatalogResults(snapshot).length))}</span></button>
          <button type="button" data-model-surface-tab="sources" data-testid="model-sources-open-button">Sources <span>${escapeHtml(String(snapshot.catalogProviderConfigs.length || 3))}</span></button>
          <div class="models-lmstudio__rail-status">
            <span>Daemon</span>
            ${modelStatusPill(modelStatus.status || "not_configured")}
          </div>
          <div class="models-lmstudio__rail-status">
            <span>Loaded</span>
            <strong>${escapeHtml(String(loadedCount))}</strong>
          </div>
        </aside>

        <main class="models-lmstudio__library model-surface" data-testid="model-library">
          <section class="models-lmstudio__local is-active" data-model-surface-panel="library" data-testid="model-local-library-surface">
            <header class="models-lmstudio__library-header">
              <h2>My Models</h2>
              <label class="models-lmstudio__search">
                <span aria-hidden="true">Find</span>
                <input data-testid="model-library-filter" type="search" placeholder="Filter models... (Ctrl + F)" />
              </label>
            </header>
            ${renderRecommendedModelSetup(snapshot)}
            <div class="models-lmstudio__table-wrap" data-testid="model-library-table">
              <table class="model-table">
                <thead>
                  <tr>
                    <th>Model</th>
                    <th>Arch</th>
                    <th>Params</th>
                    <th>Publisher</th>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>${renderModelLibraryRows(snapshot)}</tbody>
              </table>
            </div>
            <footer class="models-lmstudio__status-strip" data-testid="model-library-footer" data-role="model-bottom-status-strip">
              <span>You have ${escapeHtml(String(snapshot.artifacts.length))} local models, taking up ${escapeHtml(formatBytes(localSizeBytes))} of disk space</span>
              <code>${escapeHtml(snapshot.server.modelRoot || "~/.ioi/models")}</code>
            </footer>
          </section>
          ${renderModelDiscoverySurface(snapshot)}
          ${renderModelSourcesSurface(snapshot)}
        </main>

        <aside class="models-lmstudio__inspector model-surface" data-testid="model-selected-inspector">
          <header class="models-lmstudio__inspector-header">
            <div>
              <span class="model-icon-label" aria-hidden="true">AI</span>
              <h2 data-testid="model-inspector-title">${escapeHtml(modelDisplayName(selectedArtifact))}</h2>
              <small data-testid="model-inspector-subtitle">${escapeHtml(selectedArtifact.modelId || selectedEndpoint.modelId || "Select a model")}</small>
            </div>
            ${modelStatusPill(selectedInstance.status || selectedEndpoint.status || selectedArtifact.status || "installed")}
          </header>
          <div class="models-lmstudio__inspector-actions">
            <button
              class="action"
              type="button"
              data-model-action="workflow"
              data-command="ioi.models.selectForWorkflow"
              ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedEndpoint.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id })}
            >Use in Workflow</button>
            <button
              class="action"
              type="button"
              data-model-action="load"
              data-command="ioi.models.openLoader"
              ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedEndpoint.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id })}
            >Load Model</button>
          </div>
          <nav class="models-lmstudio__tabs" aria-label="Model inspector tabs">
            <button class="is-active" type="button" data-model-inspector-tab="info" data-testid="model-inspector-info-tab">Info</button>
            <button type="button" data-model-inspector-tab="load" data-testid="model-inspector-load-tab">Load</button>
            <button type="button" data-model-inspector-tab="inference" data-testid="model-inspector-inference-tab">Inference</button>
            <button type="button" data-model-inspector-tab="policy" data-testid="model-inspector-policy-tab">Policy</button>
            <button type="button" data-model-inspector-tab="routes" data-testid="model-inspector-routes-tab">Routes</button>
            <button type="button" data-model-inspector-tab="receipts" data-testid="model-inspector-receipts-tab">Receipts</button>
          </nav>
          <section class="models-lmstudio__tab-panel is-active" data-model-inspector-panel="info" data-testid="model-inspector-info-panel">
            <h3>Model Information</h3>
            <dl>
              <div><dt>Model</dt><dd data-model-field="model">${escapeHtml(selectedArtifact.modelId || selectedArtifact.id || "none")}</dd></div>
              <div><dt>File</dt><dd data-model-field="file">${escapeHtml(selectedArtifact.fileName || selectedArtifact.path || "daemon artifact")}</dd></div>
              <div><dt>Format</dt><dd data-model-field="format">${escapeHtml(selectedArtifact.format || "GGUF")}</dd></div>
              <div><dt>Quantization</dt><dd data-model-field="quantization">${escapeHtml(selectedArtifact.quantization || "unknown")}</dd></div>
              <div><dt>Arch</dt><dd data-model-field="arch">${escapeHtml(modelArch(selectedArtifact))}</dd></div>
              <div><dt>Capabilities</dt><dd data-model-field="capabilities">${renderModelTags(artifactCapabilities)}</dd></div>
              <div><dt>Size on disk</dt><dd data-model-field="size">${escapeHtml(formatBytes(selectedArtifact.sizeBytes ?? selectedArtifact.size_bytes))}</dd></div>
            </dl>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="load" data-testid="model-inspector-load-panel">
            <details class="model-side-section model-quick-loader" data-testid="model-mount-drawer">
              <summary>Quick Loader</summary>
              <p class="model-muted">Search mounted daemon catalog entries without leaving the selected model context.</p>
              <label class="models-lmstudio__search">
                <span aria-hidden="true">Find</span>
                <input data-testid="model-quick-loader-filter" type="search" placeholder="Type to filter models..." />
              </label>
              <div data-testid="model-quick-loader-popover">
                <div class="model-loader-list" data-testid="model-quick-loader-list">
                  ${renderModelQuickLoaderRows(snapshot)}
                </div>
              </div>
              <label class="model-toggle-row">
                <input type="checkbox" data-testid="model-loader-manual-toggle" />
                <span>Manually choose model load parameters</span>
              </label>
            </details>

            <section class="model-side-section model-load-dialog" data-testid="model-load-dialog">
              <header class="models-lmstudio__dialog-title">
                <h3>${escapeHtml(modelDisplayName(selectedArtifact))}</h3>
              </header>
              <section class="models-lmstudio__estimate" data-testid="model-load-estimate">
                <strong>Estimated Memory Usage</strong>
                <span data-testid="model-load-estimated-memory">GPU ${escapeHtml(formatBytes(loadReceipt?.details?.estimate?.estimatedVramBytes))}</span>
                <span>Total ${escapeHtml(formatBytes(loadReceipt?.details?.estimate?.estimatedSizeBytes || selectedArtifact.sizeBytes || selectedArtifact.size_bytes))}</span>
              </section>
              <label class="model-field">
                <span>API Identifier</span>
                <input data-testid="model-api-identifier-input" type="text" value="${escapeHtml(loadOptions.identifier)}" />
              </label>
              <label class="model-toggle-row">
                <input data-testid="model-auto-unload-toggle" type="checkbox" />
                <span>Auto Unload If Idle (TTL)</span>
              </label>
              <label class="model-range-row">
                <span>Context Length</span>
                <input data-testid="model-context-length-slider" type="range" min="1024" max="131072" value="${escapeHtml(String(loadOptions.contextLength))}" />
                <output>${escapeHtml(String(loadOptions.contextLength))}</output>
              </label>
              <label class="model-range-row">
                <span>GPU Offload</span>
                <input data-testid="model-gpu-offload-slider" type="range" min="0" max="99" value="${escapeHtml(String(Number(loadOptions.gpuOffload) || 0))}" />
                <output>${escapeHtml(String(loadOptions.gpuOffload))}</output>
              </label>
              <div class="model-dialog-options">
                <label><input data-testid="model-remember-settings-toggle" type="checkbox" /> Remember settings for ${escapeHtml(modelDisplayName(selectedArtifact))}</label>
                <label><input data-testid="model-advanced-settings-toggle" type="checkbox" /> Show advanced settings</label>
              </div>
              <section class="model-advanced-panel" data-testid="model-advanced-settings-panel" hidden>
                <dl>
                  <div><dt>Parallelism</dt><dd>${escapeHtml(String(loadOptions.parallelism))}</dd></div>
                  <div><dt>Idle TTL</dt><dd>${escapeHtml(String(loadOptions.idleTtlSeconds))}s</dd></div>
                  <div><dt>Engine</dt><dd>${escapeHtml(selectedEngine.id || "daemon-selected")}</dd></div>
                </dl>
              </section>
              <div class="model-workbench__actions">
                <button
                  class="action"
                  type="button"
                  data-testid="model-estimate-button"
                  data-model-action="estimate"
                  data-command="ioi.models.estimateNative"
                  ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id, contextLength: loadOptions.contextLength, gpuOffload: loadOptions.gpuOffload })}
                >Estimate</button>
                <button
                  class="action"
                  type="button"
                  data-testid="model-load-confirm-button"
                  data-model-action="loadNative"
                  data-command="ioi.models.loadNative"
                  ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id, contextLength: loadOptions.contextLength, gpuOffload: loadOptions.gpuOffload })}
                >Load Model</button>
              </div>
            </section>

            <section class="model-side-section" data-testid="model-instance-ready">
              <div class="model-surface__head">
                <div>
                  <span>Running Models</span>
                  <strong data-model-field="running-model">${escapeHtml(selectedInstance.modelId || selectedEndpoint.modelId || "No loaded instance")}</strong>
                </div>
                ${modelStatusPill(selectedInstance.status || "empty")}
              </div>
              <div class="model-progress" data-testid="model-load-progress"><span style="width: ${selectedInstance.status === "loaded" ? "100" : "18"}%"></span></div>
              <dl>
                <div><dt>Instance</dt><dd data-model-field="instance">${escapeHtml(selectedInstance.id || "none")}</dd></div>
                <div><dt>Identifier</dt><dd>${escapeHtml(selectedInstance.identifier || "none")}</dd></div>
                <div><dt>Backend</dt><dd data-model-field="backend">${escapeHtml(selectedInstance.backendId || selectedBackend.id || "none")}</dd></div>
                <div><dt>Receipt evidence</dt><dd>${escapeHtml(selectedInstance.providerEvidenceRefs?.join(", ") || "pending")}</dd></div>
              </dl>
              <button
                class="action"
                type="button"
                data-testid="model-running-unload-button"
                data-model-action="unload"
                data-command="ioi.models.unloadNative"
                ${commandPayloadAttr({ instanceId: selectedInstance.id })}
                ${selectedInstance.id ? "" : "disabled"}
              >Unload</button>
            </section>

          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="inference" data-testid="model-inspector-inference-panel">
            <h3>Inference</h3>
            <details class="model-accordion" open>
              <summary>System Prompt</summary>
              <p class="model-muted">Prompt policy and defaults are projected from the daemon route. The webview never executes inference directly.</p>
            </details>
            <details class="model-accordion" open>
              <summary>Settings</summary>
              <label class="model-range-row">
                <span>Temperature</span>
                <input type="range" min="0" max="2" step="0.1" value="0.8" />
                <output>0.8</output>
              </label>
              <label class="model-toggle-row"><input type="checkbox" /> Limit Response Length</label>
              <label class="model-field"><span>Stop Strings</span><input type="text" placeholder="Enter a string and press Enter" /></label>
            </details>
            <details class="model-accordion">
              <summary>Reasoning Parsing</summary>
              <label class="model-toggle-row"><input type="checkbox" checked /> Reasoning section parsing</label>
              <label class="model-field"><span>Start String</span><input type="text" value="&lt;think&gt;" /></label>
              <label class="model-field"><span>End String</span><input type="text" value="&lt;/think&gt;" /></label>
            </details>
            <details class="model-accordion">
              <summary>Sampling</summary>
              <label class="model-range-row"><span>Top K Sampling</span><input type="range" min="1" max="100" value="40" /><output>40</output></label>
              <label class="model-range-row"><span>Top P Sampling</span><input type="range" min="0" max="1" step="0.01" value="0.95" /><output>0.95</output></label>
            </details>
            <details class="model-accordion">
              <summary>Structured Output</summary>
              <label class="model-toggle-row"><input type="checkbox" /> Structured output</label>
            </details>
            <details class="model-accordion">
              <summary>Speculative Decoding</summary>
              <label class="model-field"><span>Draft Model</span><input type="text" placeholder="Select a compatible draft model" /></label>
            </details>
            <details class="model-accordion">
              <summary>Prompt Template</summary>
              <label class="model-field"><span>Template</span><input type="text" value="Alpaca" /></label>
            </details>
            <section class="model-side-section" data-testid="model-server-api">
              <div data-testid="model-server-view">
                <div class="model-surface__head">
                  <div>
                    <span>Developer / Local Server</span>
                    <strong data-testid="model-server-status">${escapeHtml(snapshot.server.status || "unknown")}</strong>
                  </div>
                  ${modelStatusPill(snapshot.server.gatewayStatus || snapshot.server.status || "unknown")}
                </div>
                <dl data-testid="model-server-endpoints">
                  <div><dt>Native API</dt><dd>${escapeHtml(snapshot.server.nativeApi || snapshot.server.nativeBaseUrl || "/api/v1")}</dd></div>
                  <div><dt>OpenAI API</dt><dd>${escapeHtml(serverBaseUrl)}</dd></div>
                  <div><dt>Loaded</dt><dd data-testid="model-server-loaded-models">${escapeHtml(String(snapshot.server.loadedInstances ?? loadedCount))}</dd></div>
                  <div><dt>Daemon</dt><dd>${escapeHtml(modelStatus.endpoint || daemonEndpoint() || "not configured")}</dd></div>
                </dl>
                <div class="model-log-list" data-testid="model-server-logs">
                  <article class="model-log-row" data-testid="model-server-backend-logs"><strong>gateway</strong><span>${escapeHtml(snapshot.server.gatewayStatus || "pending")}</span><small>Server/API state is projected from daemon model runtime state.</small></article>
                  <article class="model-log-row" data-testid="model-server-request-log"><strong>requests</strong><span>${escapeHtml(invokeReceipt?.id || "no invocation receipt yet")}</span><small>No webview or extension-host model execution.</small></article>
                  <article class="model-log-row" data-testid="model-server-receipts"><strong>receipts</strong><span>${escapeHtml(routeReceipt?.id || invokeReceipt?.id || "pending")}</span><small>Server activity links to daemon receipt/replay state.</small></article>
                </div>
              </div>
            </section>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="policy" data-testid="model-inspector-policy-panel">
            <h3>Policy</h3>
            <dl>
              <div><dt>Authority</dt><dd>daemon-owned</dd></div>
              <div><dt>Privacy</dt><dd>${escapeHtml(selectedRoute.privacy || selectedEndpoint.privacyClass || "local_first")}</dd></div>
              <div><dt>Approvals</dt><dd>${escapeHtml(selectedRoute.approvalPolicy || "route policy")}</dd></div>
              <div><dt>Mutation path</dt><dd>receipted daemon request</dd></div>
            </dl>
            <section class="model-side-section" data-testid="model-runtime-backend">
              <div class="model-surface__head">
                <div>
                  <span>Runtime / Backend</span>
                  <strong>${escapeHtml(selectedBackend.label || selectedBackend.id || selectedEngine.id || "Backend")}</strong>
                </div>
                ${modelStatusPill(selectedBackend.status || selectedEngine.status || "unknown")}
              </div>
              <dl>
                <div><dt>Kind</dt><dd>${escapeHtml(selectedBackend.kind || selectedEngine.kind || "unknown")}</dd></div>
                <div><dt>Process</dt><dd>${escapeHtml(selectedBackend.processStatus || selectedBackend.process?.status || "stateless")}</dd></div>
                <div><dt>Selected engine</dt><dd>${escapeHtml(selectedEngine.id || snapshot.runtimePreference.selectedEngineId || "none")}</dd></div>
                <div><dt>Evidence</dt><dd>${escapeHtml(selectedBackend.evidenceRefs?.join(", ") || "daemon backend registry")}</dd></div>
              </dl>
            </section>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="routes" data-testid="model-inspector-routes-panel">
            <h3>Routes</h3>
            <dl>
              <div><dt>Route</dt><dd>${escapeHtml(selectedRoute.id || "none")}</dd></div>
              <div><dt>Selected model</dt><dd data-model-field="route-model">${escapeHtml(routeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "none")}</dd></div>
              <div><dt>Backend</dt><dd>${escapeHtml(selectedBackend.id || selectedEngine.id || "pending")}</dd></div>
              <div><dt>Receipt</dt><dd>${escapeHtml(routeReceipt?.id || "pending")}</dd></div>
            </dl>
            <section class="model-side-section" data-testid="workflow-node-live-model-binding">
              <div class="model-surface__head">
                <div>
                  <span>Workflow Binding</span>
                  <strong>${escapeHtml(selectedRoute.id || "route pending")}</strong>
                </div>
                ${modelStatusPill(routeReceipt ? "route receipted" : "ready")}
              </div>
              <dl>
                <div><dt>Route</dt><dd>${escapeHtml(selectedRoute.id || "none")}</dd></div>
                <div><dt>Selected model</dt><dd data-model-field="workflow-model">${escapeHtml(routeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "none")}</dd></div>
                <div><dt>Policy</dt><dd>${escapeHtml(selectedRoute.privacy || "local_first")}</dd></div>
                <div><dt>Receipt</dt><dd>${escapeHtml(routeReceipt?.id || "pending")}</dd></div>
              </dl>
              ${renderCommandButton({ label: "Bind in Composer", command: "ioi.workflow.openComposer", payload: { scenarioId: "model-backed-dry-run", phase: "model-binding" } })}
            </section>
            <section class="model-side-section" data-testid="workflow-live-model-dry-run-timeline">
              <div class="model-surface__head">
                <div>
                  <span>Workflow Dry-run Timeline</span>
                  <strong>${escapeHtml(invokeReceipt ? "model invocation complete" : "ready for daemon dry-run")}</strong>
                </div>
                ${modelStatusPill(invokeReceipt ? "receipted" : "pending")}
              </div>
              <ol class="model-timeline">
                <li>route selected: ${escapeHtml(routeReceipt?.details?.routeId || selectedRoute.id || "route")}</li>
                <li>model invoked: <span data-model-field="timeline-model">${escapeHtml(invokeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "model")}</span></li>
                <li>runtime evidence: ${escapeHtml(invokeReceipt?.details?.backendId || selectedBackend.id || selectedEngine.id || "backend")}</li>
              </ol>
            </section>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="receipts" data-testid="model-inspector-receipts-panel">
            <h3>Receipts</h3>
            <section class="model-side-section model-surface--wide" data-testid="model-invocation-receipts-replay">
              <div class="model-surface__head">
                <div>
                  <span>Receipts / Replay</span>
                  <strong>${escapeHtml(snapshot.receipts.length)} daemon receipts</strong>
                </div>
                ${modelStatusPill("daemon-owned")}
              </div>
              <div class="model-log-list">${renderModelReceiptRows(snapshot)}</div>
            </section>
          </section>
        </aside>
      </section>
    </section>
  `;
}


  return {
    modelDisplayName,
    modelEndpointForArtifact,
    modelInstanceForEndpoint,
    renderModelsPanelBody,
  };
}

module.exports = {
  createModelSurfaceRenderer,
};
