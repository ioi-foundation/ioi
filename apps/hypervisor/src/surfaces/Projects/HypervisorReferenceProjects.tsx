// Parity Phase C — Projects surface ported bit-for-bit from the IOI demo
// reference's LIVE <main> DOM (http://localhost:9228/projects): exact element tree,
// classes, verbatim SVG paths and copy. Additive on /parity-projects. The project
// card mirrors the reference's single mock project (ioi / teamioitest/ioi).

const PlusGlyph = () => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M10.25 5V10.25M10.25 10.25V15.5M10.25 10.25H5M10.25 10.25H15.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);
const SearchGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 20L16.1265 16.1265M16.1265 16.1265C17.4385 14.8145 18.25 13.002 18.25 11C18.25 6.99594 15.0041 3.75 11 3.75C6.99594 3.75 3.75 6.99594 3.75 11C3.75 15.0041 6.99594 18.25 11 18.25C13.002 18.25 14.8145 17.4385 16.1265 16.1265Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const GithubGlyph = () => (
  <svg className="shrink-0" width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg"><g clipPath="url(#parity_gh_0)"><g clipPath="url(#parity_gh_1)"><path fillRule="evenodd" clipRule="evenodd" d="M6.97914 0.142853C3.11986 0.142853 0 3.28571 0 7.17385C0 10.2819 1.999 12.9127 4.77214 13.8439C5.11886 13.9139 5.24586 13.6926 5.24586 13.5064C5.24586 13.3434 5.23443 12.7847 5.23443 12.2026C3.293 12.6217 2.88871 11.3644 2.88871 11.3644C2.57671 10.5496 2.11443 10.3401 2.11443 10.3401C1.479 9.90942 2.16071 9.90942 2.16071 9.90942C2.86557 9.95599 3.23543 10.6311 3.23543 10.6311C3.85929 11.702 4.86457 11.3994 5.269 11.2131C5.32671 10.7591 5.51171 10.4449 5.70814 10.2703C4.15971 10.1073 2.53057 9.502 2.53057 6.80128C2.53057 6.033 2.80771 5.40442 3.24686 4.91557C3.17757 4.741 2.93486 4.01914 3.31629 3.053C3.31629 3.053 3.90557 2.86671 5.23429 3.77471C5.80315 3.6208 6.38982 3.54251 6.97914 3.54185C7.56843 3.54185 8.16914 3.62342 8.72386 3.77471C10.0527 2.86671 10.642 3.053 10.642 3.053C11.0234 4.01914 10.7806 4.741 10.7113 4.91557C11.162 5.40442 11.4277 6.033 11.4277 6.80128C11.4277 9.502 9.79857 10.0956 8.23857 10.2703C8.49286 10.4914 8.71229 10.9104 8.71229 11.574C8.71229 12.5169 8.70086 13.2736 8.70086 13.5063C8.70086 13.6926 8.828 13.9139 9.17457 13.844C11.9477 12.9126 13.9467 10.2819 13.9467 7.17385C13.9581 3.28571 10.8269 0.142853 6.97914 0.142853Z" fill="currentColor" /></g></g><defs><clipPath id="parity_gh_0"><rect width="14" height="14" fill="white" /></clipPath><clipPath id="parity_gh_1"><rect width="14" height="13.7143" fill="white" transform="translate(0 0.142853)" /></clipPath></defs></svg>
);
const BranchGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-git-branch size-3 flex-shrink-0"><line x1="6" x2="6" y1="3" y2="15" /><circle cx="18" cy="6" r="3" /><circle cx="6" cy="18" r="3" /><path d="M18 9a9 9 0 0 1-9 9" /></svg>
);
const DotsGlyph = () => (
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M4.5 8C4.5 8.72488 3.91238 9.3125 3.1875 9.3125C2.46262 9.3125 1.875 8.72488 1.875 8C1.875 7.27512 2.46262 6.6875 3.1875 6.6875C3.91238 6.6875 4.5 7.27512 4.5 8ZM9.3125 8C9.3125 8.72488 8.72488 9.3125 8 9.3125C7.27512 9.3125 6.6875 8.72488 6.6875 8C6.6875 7.27512 7.27512 6.6875 8 6.6875C8.72488 6.6875 9.3125 7.27512 9.3125 8ZM12.8125 9.3125C13.5373 9.3125 14.125 8.72488 14.125 8C14.125 7.27512 13.5373 6.6875 12.8125 6.6875C12.0877 6.6875 11.5 7.27512 11.5 8C11.5 8.72488 12.0877 9.3125 12.8125 9.3125Z" fill="currentColor" /></svg>
);

export function HypervisorReferenceProjects() {
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div className="relative [scrollbar-gutter:stable] overflow-x-auto overflow-y-auto size-full max-w-full p-6" data-orientation="both">
        <div data-testid="projects-page" className="h-full">
          <div className="flex size-full flex-col gap-4">
            <div className="flex items-center">
              <h1 className="truncate text-2xl font-semibold tracking-[-0.2px] my-0.5 flex grow flex-row align-middle text-content-primary">Projects</h1>
              <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 disabled:bg-surface-primary-inverted disabled:text-content-primary-inverted focus-visible:outline-border-brand gap-2 px-4 py-2 h-9 text-base" data-tracking-id="new-project-projects-page">
                <PlusGlyph />
                <span className="truncate">New project</span>
              </button>
            </div>

            <div className="flex flex-row items-center gap-2">
              <div className="relative flex flex-1">
                <div className="relative [&>div]:max-w-none w-full">
                  <div className="flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base disabled:cursor-text focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit bg-surface-input [&[readonly]]:border-border-subtle [&[readonly]]:bg-transparent data-[readonly]:border-border-subtle data-[readonly]:bg-transparent">
                    <span className="flex-shrink-0 text-content-secondary"><SearchGlyph /></span>
                    <input className="flex h-full w-full focus-visible:ring-0 text-base p-0 border-0 outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-text placeholder:text-content-muted border-border-base disabled:bg-surface-input text-content-primary bg-transparent [&[readonly]]:bg-transparent transition-all duration-150 ease-out max-w-none" type="text" placeholder="Search projects" defaultValue="" />
                  </div>
                </div>
              </div>
            </div>

            <div className="flex w-full flex-col gap-4 pb-6" data-testid="projects-list">
              <ul className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3">
                <li>
                  <a data-testid="project-019ee100-f64f-7554-946f-405f46528c91" className="@container group flex h-full min-h-[180px] flex-col justify-between gap-3 rounded-lg border border-solid border-border-light bg-surface-glass p-5 text-left transition-all duration-200 hover:border-border-medium hover:shadow-md" href="/projects/019ee100-f64f-7554-946f-405f46528c91">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1">
                          <h3 className="flex min-w-0 flex-1 items-baseline justify-between gap-2 text-xl font-semibold leading-tight text-content-primary">ioi
                            <ul className="group/avatars max-w-[140px] items-center whitespace-nowrap rounded-lg p-0.5 hidden @xs:flex" tabIndex={0} aria-label="Shared with groups and used by users">
                              <li className="relative flex-shrink-0 transition-all ease-out" style={{ zIndex: 1 }}>
                                <span data-slot="avatar" className="relative flex shrink-0 overflow-hidden size-6 flex-shrink-0 border-2 border-surface-glass bg-surface-glass ring-1 ring-border-light transition-shadow group-focus-within/avatars:shadow-sm group-hover/avatars:shadow-sm rounded-md" data-state="closed">
                                  <span data-slot="avatar-fallback" className="flex size-full items-center justify-center rounded-full">
                                    <div className="inline-flex size-full select-none items-center justify-center font-medium text-xs leading-6 bg-surface-brand-accent-09 text-content-brand-accent-07" role="img" aria-label="Levi Josman's Workspace 320's avatar"><span className="inline-block text-center">LJ</span></div>
                                  </span>
                                </span>
                              </li>
                            </ul>
                          </h3>
                        </div>
                        <div className="grid grid-cols-[auto,1fr] items-center gap-x-2 gap-y-1 text-sm text-content-secondary" title="https://github.com/teamioitest/ioi.git">
                          <div className="flex justify-center"><GithubGlyph /></div>
                          <span className="truncate font-mono text-xs">teamioitest/ioi</span>
                          <div className="flex justify-center"><BranchGlyph /></div>
                          <span className="font-mono text-xs">master</span>
                        </div>
                      </div>
                      <div data-tracking-id-none="true">
                        <div className="flex items-center" data-tracking-id-none="true">
                          <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-8 text-base aspect-square p-0" aria-label="More actions" aria-haspopup="menu" aria-expanded="false" data-state="closed" data-testid="project-actions-dropdown-trigger"><DotsGlyph /></button>
                        </div>
                      </div>
                    </div>
                    <div className="relative flex justify-between flex-col items-start gap-2 @xs:flex-row @xs:items-center">
                      <div data-tracking-id-none="true">
                        <ul className="group/avatars flex max-w-[140px] items-center whitespace-nowrap rounded-lg p-0.5" tabIndex={0} aria-label="Shared with groups and used by users">
                          <li className="relative flex-shrink-0 transition-all ease-out" style={{ zIndex: 1 }}>
                            <span data-slot="avatar" className="relative flex shrink-0 overflow-hidden size-6 flex-shrink-0 border-2 border-surface-glass bg-surface-glass ring-1 ring-border-light transition-shadow group-focus-within/avatars:shadow-sm group-hover/avatars:shadow-sm rounded-full" data-state="closed">
                              <img data-slot="avatar-image" data-testid="avatar-image" className="aspect-square size-full object-cover" referrerPolicy="no-referrer" loading="lazy" alt="Levi Josman's avatar" src="https://lh3.googleusercontent.com/a/ACg8ocIBE-yWc_g6QMTLx_fI4gV6NkJ6Q1ERKa4YxbkEy2U9RsS3DCHb=s96-c" />
                            </span>
                          </li>
                        </ul>
                      </div>
                      <div className="inline-flex rounded-lg border border-border-base opacity-0 group-focus-within:opacity-100 group-hover:opacity-100" role="group" data-tracking-id-none="true">
                        <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base rounded-r-none border-none focus-visible:bg-surface-accent focus-visible:ring-0 focus-visible:ring-offset-0" aria-busy="false" aria-label="Create environment" data-testid="create-environment-from-project-button-019ee100-f64f-7554-946f-405f46528c91" data-tracking-id="create-environment-button" data-state="closed"><span className="truncate">Create Environment</span></button>
                      </div>
                    </div>
                  </a>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

export default HypervisorReferenceProjects;
