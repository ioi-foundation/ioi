// Reference 404 — ported from the IOI demo reference's not-found page (e.g.
// :9228/workspaces): a standalone "4 <glyph> 4" page with "Back to dashboard". Used as
// the catch-all for routes the parity UX does not own (sessions, workbench, agents,
// models, etc.) now that the legacy shell is removed from the app. The reference's
// animated "waiting" lottie glyph is rendered as the static brand hexagon mark.
import { useReferenceTheme } from "../Home/HypervisorReferenceShell";

const BIG_DIGIT = "text-8xl font-light tracking-tight text-content-tertiary sm:text-9xl";

export function HypervisorReferenceNotFound() {
  useReferenceTheme();
  return (
    <div className="app-background flex size-full overflow-hidden">
      <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0">
        <div className="relative [scrollbar-gutter:stable] overflow-x-auto overflow-y-auto size-full max-w-full p-6" data-orientation="both">
          <div className="flex h-full flex-col items-center justify-center gap-6 px-4">
            <div className="flex items-center gap-3" role="img" aria-label="404 — page not found">
              <span className={BIG_DIGIT}>4</span>
              <div className="relative size-20 text-content-tertiary sm:size-24" aria-hidden="true">
                <svg className="size-full" viewBox="108.97 89.47 781.56 706.06" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" strokeWidth="12" strokeLinejoin="round" strokeLinecap="round"><path d="M295.299 434.631L295.299 654.116 485.379 544.373z" /><path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" /><path d="M514.621 544.373L704.701 654.115 704.701 434.631z" /><path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" /><path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" /><path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" /><path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" /><path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" /><path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" /><path d="M302.61 666.778L500 780.741 500 552.815z" /><path d="M500 552.815L500 780.741 697.39 666.778z" /></g></svg>
              </div>
              <span className={BIG_DIGIT}>4</span>
            </div>
            <p className="text-base text-content-secondary">Hypervisor looked everywhere. This page doesn't exist.</p>
            <a className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 active:outline-0 focus:ring-0 bg-surface-button-secondary text-content-primary hover:bg-surface-button-secondary-accent disabled:opacity-50 gap-2 px-4 py-2 h-9 text-base" href="/">
              <span className="flex items-center gap-1">Back to dashboard</span>
            </a>
          </div>
        </div>
      </main>
    </div>
  );
}

export default HypervisorReferenceNotFound;
