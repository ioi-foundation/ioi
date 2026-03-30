import type { SettingsViewBodyView } from "./SettingsView.types";

export function SettingsRuntimeSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const { controlPlane, updateEngineDraft } = view;
  if (!controlPlane) return null;

  return (
    <div className="studio-settings-stack">
      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Runtime</span>
            <h2>Runtime posture</h2>
          </div>
          <span className="studio-settings-pill">Kernel-backed</span>
        </div>
        <p className="studio-settings-body">
          This absorbs the LocalAI-style runtime settings into a first-party
          settings plane while keeping the kernel as planner, policy, and
          receipt authority.
        </p>
        <div className="studio-settings-profile-grid">
          <label className="studio-settings-field">
            <span>Runtime mode</span>
            <select
              value={controlPlane.runtime.mode}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  runtime: {
                    ...current.runtime,
                    mode: event.target.value,
                  },
                }))
              }
            >
              <option value="openai_baseline">OpenAI baseline</option>
              <option value="http_local">HTTP local bridge</option>
              <option value="mock">Mock substrate</option>
            </select>
          </label>
          <label className="studio-settings-field">
            <span>Endpoint</span>
            <input
              value={controlPlane.runtime.endpoint}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  runtime: {
                    ...current.runtime,
                    endpoint: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Default model</span>
            <input
              value={controlPlane.runtime.defaultModel}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  runtime: {
                    ...current.runtime,
                    defaultModel: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field studio-settings-field--wide">
            <span>Baseline role</span>
            <textarea
              value={controlPlane.runtime.baselineRole}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  runtime: {
                    ...current.runtime,
                    baselineRole: event.target.value,
                  },
                }))
              }
            />
          </label>
        </div>
      </article>

      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Launcher</span>
            <h2>Shell and launch behavior</h2>
          </div>
          <span className="studio-settings-pill">Settings plane</span>
        </div>
        <div className="studio-settings-form-grid">
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.launcher.autoStartOnBoot}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  launcher: {
                    ...current.launcher,
                    autoStartOnBoot: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Start local engine on boot</strong>
              <span>Use Settings as the launcher-parity control surface.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.launcher.reopenStudioOnLaunch}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  launcher: {
                    ...current.launcher,
                    reopenStudioOnLaunch: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Reopen Studio on launch</strong>
              <span>Return operators to the same shell after relaunch.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.launcher.autoCheckUpdates}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  launcher: {
                    ...current.launcher,
                    autoCheckUpdates: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Check updates automatically</strong>
              <span>Keep runtime and launcher parity visible to the operator.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.launcher.showKernelConsole}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  launcher: {
                    ...current.launcher,
                    showKernelConsole: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Show kernel console</strong>
              <span>Expose low-level runtime stdout and stderr when debugging.</span>
            </div>
          </label>
          <label className="studio-settings-field">
            <span>Release channel</span>
            <select
              value={controlPlane.launcher.releaseChannel}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  launcher: {
                    ...current.launcher,
                    releaseChannel: event.target.value,
                  },
                }))
              }
            >
              <option value="stable">Stable</option>
              <option value="preview">Preview</option>
              <option value="nightly">Nightly</option>
            </select>
          </label>
        </div>
      </article>

      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Execution</span>
            <h2>Watchdog, memory, and throughput</h2>
          </div>
          <span className="studio-settings-pill">Runtime policy</span>
        </div>
        <div className="studio-settings-form-grid">
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.watchdog.enabled}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    enabled: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Enable watchdog</strong>
              <span>Keep idle and busy eviction semantics under kernel control.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.memory.reclaimerEnabled}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  memory: {
                    ...current.memory,
                    reclaimerEnabled: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Enable memory reclaimer</strong>
              <span>Evict aggressively before local workloads overrun capacity.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.watchdog.idleCheckEnabled}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    idleCheckEnabled: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Enable idle check</strong>
              <span>Stop backends that stay loaded after the operator has gone quiet.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.watchdog.busyCheckEnabled}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    busyCheckEnabled: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Enable busy check</strong>
              <span>Let the kernel recover from stuck backend work that exceeds the budget.</span>
            </div>
          </label>
          <label className="studio-settings-field">
            <span>Idle timeout</span>
            <input
              value={controlPlane.watchdog.idleTimeout}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    idleTimeout: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Busy timeout</span>
            <input
              value={controlPlane.watchdog.busyTimeout}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    busyTimeout: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Check interval</span>
            <input
              value={controlPlane.watchdog.checkInterval}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    checkInterval: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Eviction retries</span>
            <input
              type="number"
              min={0}
              value={controlPlane.watchdog.lruEvictionMaxRetries}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    lruEvictionMaxRetries: Number(event.target.value || 0),
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Retry interval</span>
            <input
              value={controlPlane.watchdog.lruEvictionRetryInterval}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    lruEvictionRetryInterval: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Memory threshold (%)</span>
            <input
              type="number"
              min={50}
              max={100}
              value={controlPlane.memory.thresholdPercent}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  memory: {
                    ...current.memory,
                    thresholdPercent: Number(event.target.value || 80),
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Target resource</span>
            <input
              value={controlPlane.memory.targetResource}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  memory: {
                    ...current.memory,
                    targetResource: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Max concurrency</span>
            <input
              type="number"
              min={1}
              value={controlPlane.backendPolicy.maxConcurrency}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  backendPolicy: {
                    ...current.backendPolicy,
                    maxConcurrency: Number(event.target.value || 1),
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Queued requests</span>
            <input
              type="number"
              min={1}
              value={controlPlane.backendPolicy.maxQueuedRequests}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  backendPolicy: {
                    ...current.backendPolicy,
                    maxQueuedRequests: Number(event.target.value || 1),
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Parallel backend loads</span>
            <input
              type="number"
              min={1}
              value={controlPlane.backendPolicy.parallelBackendLoads}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  backendPolicy: {
                    ...current.backendPolicy,
                    parallelBackendLoads: Number(event.target.value || 1),
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Health probe interval</span>
            <input
              value={controlPlane.backendPolicy.healthProbeInterval}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  backendPolicy: {
                    ...current.backendPolicy,
                    healthProbeInterval: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Log level</span>
            <input
              value={controlPlane.backendPolicy.logLevel}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  backendPolicy: {
                    ...current.backendPolicy,
                    logLevel: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-field">
            <span>Retention days</span>
            <input
              type="number"
              min={1}
              value={controlPlane.responses.retainReceiptsDays}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  responses: {
                    ...current.responses,
                    retainReceiptsDays: Number(event.target.value || 1),
                  },
                }))
              }
            />
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.backendPolicy.allowParallelRequests}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  backendPolicy: {
                    ...current.backendPolicy,
                    allowParallelRequests: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Allow parallel requests</strong>
              <span>Keep concurrent local workloads inside the runtime budget.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.watchdog.forceEvictionWhenBusy}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  watchdog: {
                    ...current.watchdog,
                    forceEvictionWhenBusy: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Force eviction when busy</strong>
              <span>Allow the kernel to reclaim residency even during active API pressure.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.memory.preferGpu}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  memory: {
                    ...current.memory,
                    preferGpu: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Prefer GPU memory</strong>
              <span>Bias reclaimed workloads toward GPU residency when hardware is available.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.backendPolicy.autoShutdownOnIdle}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  backendPolicy: {
                    ...current.backendPolicy,
                    autoShutdownOnIdle: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Shutdown idle backends</strong>
              <span>Collapse residency back to zero when local demand disappears.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.responses.persistArtifacts}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  responses: {
                    ...current.responses,
                    persistArtifacts: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Persist response artifacts</strong>
              <span>Keep output artifacts and receipts available for later review.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.responses.allowStreaming}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  responses: {
                    ...current.responses,
                    allowStreaming: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Allow streaming</strong>
              <span>Keep partial local responses visible while workloads are still running.</span>
            </div>
          </label>
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.responses.storeRequestPreviews}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  responses: {
                    ...current.responses,
                    storeRequestPreviews: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Store request previews</strong>
              <span>Retain sanitized request previews alongside receipts for later audit.</span>
            </div>
          </label>
        </div>
      </article>
    </div>
  );
}
