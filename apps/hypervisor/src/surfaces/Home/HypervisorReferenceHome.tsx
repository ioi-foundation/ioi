// Parity Phase C — Home cockpit ported from the IOI demo reference's harvested
// DOM (internal-docs/reverse-engineering/ioi/public/index.html, <main> region),
// using the vendored reference utility classes. Additive: mounted on its own
// /parity-home route so it does not touch the live shell. Validate against
// http://localhost:9228/ with scripts/internal/parity-shot.mjs, then iterate.
// First cut: on-load-visible cockpit (heading + task input + quick actions +
// recent sessions); hidden selector menus are not rendered.

const QUICK_ACTIONS = [
  { title: "Automate env setup", body: "Create a fully working dev environment as code configuration." },
  { title: "Fix a bug", body: "Find a bug in the codebase that looks important and fix it." },
  { title: "Boost your test coverage", body: "Find key areas to cover with new and smarter tests." },
];

function FocusIcon() {
  return (
    <svg className="lucide lucide-focus shrink-0" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="3" /><path d="M3 7V5a2 2 0 0 1 2-2h2" /><path d="M17 3h2a2 2 0 0 1 2 2v2" /><path d="M21 17v2a2 2 0 0 1-2 2h-2" /><path d="M7 21H5a2 2 0 0 1-2-2v-2" />
    </svg>
  );
}
function ChevronDown() {
  return (
    <svg className="size-4" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg>
  );
}

export function HypervisorReferenceHome() {
  return (
    <main className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div className="size-full max-w-full flex min-h-0 flex-col p-0">
        <div className="flex size-full">
          <div className="relative flex size-full flex-col overflow-y-auto">
            <div className="mx-auto flex min-h-[calc(100dvh-4rem)] w-full max-w-[46rem] flex-col overflow-x-hidden pb-2 md:min-h-0 md:gap-12 md:px-1 md:pb-0">
              <div className="flex flex-1 flex-col items-center justify-center gap-2 pb-2 md:flex-none md:gap-4 md:pb-0 md:pt-20">
                <div className="relative size-12" aria-label="Ona waiting">
                  <div className="size-full" />
                </div>
                <h1 className="truncate text-2xl font-semibold tracking-[-0.2px] text-content-primary hidden md:block" />
                <p className="text-center text-xl text-content-primary md:text-2xl">
                  What do you want to get done today?
                </p>

                <div className="w-full">
                  <div className="flex flex-col gap-1 md:gap-0">
                    <div className="flex flex-col gap-0.5 rounded-xl bg-surface-muted p-1.5 transition-opacity">
                      <div className="flex flex-col overflow-clip rounded-lg border border-border-base bg-surface-secondary">
                        <div className="p-2">
                          <div className="relative">
                            <div className="mx-[1px]">
                              <textarea
                                placeholder="Describe your task or type / for commands"
                                className="placeholder:text-content-muted text-content-primary text-base h-auto resize-none overflow-y-auto leading-[18px] w-full rounded-none border-0 bg-transparent outline-none focus-within:ring-0 focus-visible:ring-0 max-w-full p-2"
                                rows={2}
                              />
                            </div>
                          </div>
                        </div>
                        <div className="flex h-full min-w-0 flex-col gap-2 p-2 pt-0 sm:flex-row sm:items-center sm:justify-between">
                          <div className="flex min-w-0 flex-1 flex-row items-center gap-2">
                            <button
                              type="button"
                              className="h-10 rounded-lg border border-border-base px-3 py-1.5 text-base opacity-80 outline-none hover:bg-surface-hover focus:border-border-brand active:border-border-brand md:h-8 md:py-1 flex items-center space-x-2"
                            >
                              <FocusIcon />
                              <span className="flex-1 text-start">Work in a project</span>
                            </button>
                          </div>
                          <div className="ml-auto flex min-w-0 flex-row flex-wrap items-center gap-2">
                            <button
                              type="button"
                              aria-label="Change agent mode"
                              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border-base px-2 text-sm font-normal text-content-primary hover:opacity-80 focus:outline-none"
                            >
                              <div className="flex min-w-0 items-center gap-1.5">
                                <span className="truncate">5.5 Medium</span>
                              </div>
                              <ChevronDown />
                            </button>
                            <button
                              type="button"
                              aria-label="Submit"
                              className="select-none inline-flex items-center justify-center rounded-lg bg-surface-button-primary text-content-always-white size-8 shrink-0"
                            >
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m5 12 7-7 7 7" /><path d="M12 19V5" /></svg>
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex w-full flex-row flex-wrap items-stretch justify-center gap-2 pt-2">
                  {QUICK_ACTIONS.map((a) => (
                    <button
                      key={a.title}
                      type="button"
                      title={a.body}
                      className="flex flex-1 min-w-[12rem] flex-col gap-1 rounded-lg border border-border-base bg-surface-secondary p-3 text-start hover:bg-surface-hover"
                    >
                      <span className="text-sm font-medium text-content-primary">{a.title}</span>
                      <span className="text-xs text-content-muted">{a.body}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex w-full flex-col gap-2 pt-4">
                <div className="px-1 text-sm font-medium text-content-muted">Recent Sessions</div>
                <div className="flex flex-col">
                  {["Recent session", "Recent session"].map((label, i) => (
                    <button
                      key={i}
                      type="button"
                      className="flex flex-col gap-0.5 rounded-md px-2 py-2 text-start hover:bg-surface-hover"
                    >
                      <span className="text-base text-content-primary">{label}</span>
                      <span className="text-xs text-content-muted">—</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

export default HypervisorReferenceHome;
