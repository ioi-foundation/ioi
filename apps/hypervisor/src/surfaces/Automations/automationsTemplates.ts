// Parity Phase C — suggested-automation templates, data extracted verbatim from
// the reference live /automations DOM (:9228). Icon SVGs are kept as raw markup and
// injected via dangerouslySetInnerHTML to preserve the exact reference glyphs.
export interface SuggestedTemplate {
  testid: string;
  tracking: string;
  iconBoxClass: string;
  iconSvg: string;
  title: string;
  desc: string;
}

export const SUGGESTED_TEMPLATES: SuggestedTemplate[] = [
  {
    "testid": "suggested-template-scan-recent-commits",
    "tracking": "suggested-template-select-scan-recent-commits",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-warning-subtle text-content-warning",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M20 20L16.1265 16.1265M16.1265 16.1265C17.4385 14.8145 18.25 13.002 18.25 11C18.25 6.99594 15.0041 3.75 11 3.75C6.99594 3.75 3.75 6.99594 3.75 11C3.75 15.0041 6.99594 18.25 11 18.25C13.002 18.25 14.8145 17.4385 16.1265 16.1265Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "Scan recent commits for bugs",
    "desc": "Finds likely bugs in recent commits and opens a draft PR with proposed fixes."
  },
  {
    "testid": "suggested-template-draft-weekly-release-notes",
    "tracking": "suggested-template-select-draft-weekly-release-notes",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-brand-subtle text-content-brand",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M18.2461 2.75H18.9961V1.7335L18.0248 2.03338L18.2461 2.75ZM18.2461 19.25L18.0248 19.9666L18.9961 20.2665V19.25H18.2461ZM2.74609 14.4643H1.99609V15.0177L2.52483 15.1809L2.74609 14.4643ZM2.74609 7.53571L2.52483 6.81909L1.99609 6.98235V7.53571H2.74609ZM13.2825 18.4999L13.5325 17.7928L12.1182 17.2929L11.8683 18.0001L13.2825 18.4999ZM18.2461 14.75C20.3172 14.75 21.9961 13.0711 21.9961 11H20.4961C20.4961 12.2426 19.4887 13.25 18.2461 13.25V14.75ZM18.2461 8.75C19.4887 8.75 20.4961 9.75736 20.4961 11H21.9961C21.9961 8.92893 20.3172 7.25 18.2461 7.25V8.75ZM17.4961 2.75V19.25H18.9961V2.75H17.4961ZM18.4674 18.5334L2.96735 13.7477L2.52483 15.1809L18.0248 19.9666L18.4674 18.5334ZM18.0248 2.03338L2.52483 6.81909L2.96735 8.25233L18.4674 3.46662L18.0248 2.03338ZM3.49609 14.4643V7.53571H1.99609V14.4643H3.49609ZM9.74609 19.5C8.50345 19.5 7.49609 18.4926 7.49609 17.25H5.99609C5.99609 19.3211 7.67503 21 9.74609 21V19.5ZM11.8683 18.0001C11.559 18.875 10.7246 19.5 9.74609 19.5V21C11.38 21 12.7681 19.9554 13.2825 18.4999L11.8683 18.0001ZM7.49609 17.25V15.75H5.99609V17.25H7.49609ZM5.99829 6.25V15.75H7.49829V6.25H5.99829Z\" fill=\"currentColor\"></path></svg>",
    "title": "Draft weekly release notes",
    "desc": "Turns merged PRs into categorized release notes with concise summaries."
  },
  {
    "testid": "suggested-template-generate-agents-md",
    "tracking": "suggested-template-select-generate-agents-md",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-base text-content-primary",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M9.75 14.75H14.25M12 2.75V4.75M2.25 8.75V11.25M21.75 8.75V11.25M9.25 10C9.25 10.4142 8.91421 10.75 8.5 10.75C8.08579 10.75 7.75 10.4142 7.75 10C7.75 9.58579 8.08579 9.25 8.5 9.25C8.91421 9.25 9.25 9.58579 9.25 10ZM16.25 10C16.25 10.4142 15.9142 10.75 15.5 10.75C15.0858 10.75 14.75 10.4142 14.75 10C14.75 9.58579 15.0858 9.25 15.5 9.25C15.9142 9.25 16.25 9.58579 16.25 10ZM3.25 4.75H20.75V16.25C20.75 17.9069 19.4069 19.25 17.75 19.25H6.25C4.59315 19.25 3.25 17.9069 3.25 16.25V4.75Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "Add optimized AGENTS.md",
    "desc": "Creates or updates AGENTS.md with project-specific guidance for coding agents."
  },
  {
    "testid": "suggested-template-10x-engineer",
    "tracking": "suggested-template-select-10x-engineer",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-brand-subtle text-content-brand",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M21.25 12C21.25 17.1086 17.1086 21.25 12 21.25C6.89137 21.25 2.75 17.1086 2.75 12C2.75 6.89137 6.89137 2.75 12 2.75C17.1086 2.75 21.25 6.89137 21.25 12Z\" stroke=\"currentColor\" stroke-width=\"1.5\"></path><path d=\"M17 12C17 14.7614 14.7614 17 12 17C9.23858 17 7 14.7614 7 12C7 9.23858 9.23858 7 12 7C14.7614 7 17 9.23858 17 12Z\" stroke=\"currentColor\" stroke-width=\"1.5\"></path><path d=\"M12.75 12C12.75 12.4142 12.4142 12.75 12 12.75C11.5858 12.75 11.25 12.4142 11.25 12C11.25 11.5858 11.5858 11.25 12 11.25C12.4142 11.25 12.75 11.5858 12.75 12Z\" stroke=\"currentColor\" stroke-width=\"1.5\"></path></svg>",
    "title": "10x engineer",
    "desc": "Picks your highest-priority Linear issue, implements it, runs tests, and opens a draft PR."
  },
  {
    "testid": "suggested-template-linear-sprint-standup",
    "tracking": "suggested-template-select-linear-sprint-standup",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-success-subtle text-content-success",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M3.75 4.75V4H3V4.75H3.75ZM20.25 4.75H21V4H20.25V4.75ZM11.25 21H12V19.5H11.25V21ZM3.75 20.25H3V21H3.75V20.25ZM8.5 2.75V2H7V2.75H8.5ZM17 2.75V2H15.5V2.75H17ZM19.5 12.25V13H21V12.25H19.5ZM16.9167 21.25L16.3823 21.7763L16.9793 22.3824L17.5058 21.7142L16.9167 21.25ZM21.8391 16.2142L22.3033 15.625L21.125 14.6967L20.6609 15.2858L21.8391 16.2142ZM15.2844 18.5237L14.7581 17.9894L13.6894 19.0419L14.2156 19.5763L15.2844 18.5237ZM3.75 5.5H7.75V4H3.75V5.5ZM7.75 5.5H16.25V4H7.75V5.5ZM16.25 5.5H20.25V4H16.25V5.5ZM11.25 19.5H3.75V21H11.25V19.5ZM4.5 20.25V9.25H3V20.25H4.5ZM4.5 9.25V4.75H3V9.25H4.5ZM3.75 10H20.25V8.5H3.75V10ZM8.5 4.75V2.75H7V4.75H8.5ZM17 4.75V2.75H15.5V4.75H17ZM19.5 4.75V9.25H21V4.75H19.5ZM19.5 9.25V12.25H21V9.25H19.5ZM17.5058 21.7142L21.8391 16.2142L20.6609 15.2858L16.3275 20.7858L17.5058 21.7142ZM14.2156 19.5763L16.3823 21.7763L17.451 20.7237L15.2844 18.5237L14.2156 19.5763Z\" fill=\"currentColor\"></path></svg>",
    "title": "Daily standup generator",
    "desc": "Combines Linear and Git activity into a daily standup update."
  },
  {
    "testid": "suggested-template-notion-tech-spec-from-issue",
    "tracking": "suggested-template-select-notion-tech-spec-from-issue",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-brand-subtle text-content-brand",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M19.25 2.75H20V2H19.25V2.75ZM19.25 21.25V22H20V21.25H19.25ZM19.25 16.75V17.5H20V16.75H19.25ZM8.75 6.25H8V7.75H8.75V6.25ZM15.25 7.75H16V6.25H15.25V7.75ZM8.75 10.25H8V11.75H8.75V10.25ZM12.25 11.75H13V10.25H12.25V11.75ZM6.75 3.5H19.25V2H6.75V3.5ZM18.5 2.75V21.25H20V2.75H18.5ZM19.25 20.5H6.75V22H19.25V20.5ZM5.5 19.25V4.75H4V19.25H5.5ZM6.75 20.5C6.05964 20.5 5.5 19.9404 5.5 19.25H4C4 20.7688 5.23122 22 6.75 22V20.5ZM6.75 2C5.23122 2 4 3.23122 4 4.75H5.5C5.5 4.05964 6.05964 3.5 6.75 3.5V2ZM18.5 12V16.75H20V12H18.5ZM19.25 16H7V17.5H19.25V16ZM7 22H10V20.5H7V22ZM4 19C4 20.6569 5.34315 22 7 22V20.5C6.17157 20.5 5.5 19.8284 5.5 19H4ZM7 16C5.34315 16 4 17.3431 4 19H5.5C5.5 18.1716 6.17157 17.5 7 17.5V16ZM8.75 7.75H15.25V6.25H8.75V7.75ZM8.75 11.75H12.25V10.25H8.75V11.75Z\" fill=\"currentColor\"></path></svg>",
    "title": "Tech spec from Linear issue",
    "desc": "Turns a Linear issue into an implementation-ready spec with technical design and execution details."
  },
  {
    "testid": "suggested-template-automated-dev-environment-setup",
    "tracking": "suggested-template-select-automated-dev-environment-setup",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-success-subtle text-content-success",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M3.75 8V3.75H8M3.75 16V20.25H8M16 3.75H20.25V8M20.25 16V20.25H16\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M11.0259 8L8 16H9.70708L10.1768 14.7582H13.8232L14.2929 16H16L12.9741 8H11.0259ZM13.1249 12.9121L12 9.93791L10.8751 12.9121H13.1249Z\" fill=\"currentColor\"></path></svg>",
    "title": "Automated dev environment setup",
    "desc": "Standardizes your development environment and opens a PR with the required updates."
  },
  {
    "testid": "suggested-template-cve-mitigation-and-version-updates",
    "tracking": "suggested-template-select-cve-mitigation-and-version-updates",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-brand-accent-01-subtle text-content-brand-accent-01",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M8.75 12L10.9167 14.25L15.25 9.75M12 2.25L3.75 5.75V13C3.75 17.5563 7.44365 21.25 12 21.25C16.5563 21.25 20.25 17.5563 20.25 13V5.75L12 2.25Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "CVE mitigation & dependency updates",
    "desc": "Fixes vulnerable or outdated dependencies, validates changes, and opens a PR."
  },
  {
    "testid": "suggested-template-add-and-maintain-readmes-and-backstage-yaml",
    "tracking": "suggested-template-select-add-and-maintain-readmes-and-backstage-yaml",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-warning-subtle text-content-warning",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M8.75 13.25H12.25M8.75 17.25H15.25M12.75 3.25309V9.25H18.7461M4.75 2.75H12.75L19.25 9.25V21.25H4.75V2.75Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "Backstage catalog standardization",
    "desc": "Updates catalog-info.yaml to match your Backstage standards and opens a PR."
  },
  {
    "testid": "suggested-template-migrate-deprecated-api",
    "tracking": "suggested-template-select-migrate-deprecated-api",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-warning-subtle text-content-warning",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M7.25 18.25H2.75V3.75H21.25V18.25H12.25M15 15L11.75 18.25L15 21.25\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "Migrate deprecated API usage",
    "desc": "Replaces deprecated APIs, validates the migration, and opens a PR."
  },
  {
    "testid": "suggested-template-ci-failure-summary",
    "tracking": "suggested-template-select-ci-failure-summary",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-destructive-subtle text-content-destructive",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M12 11.9998L11.3569 12.3857C11.4924 12.6116 11.7366 12.7498 12 12.7498C12.2634 12.7498 12.5076 12.6116 12.6431 12.3857L12 11.9998ZM17.25 11.9644H18H17.25ZM12.6431 12.3857L17.4029 4.45285L16.1166 3.6811L11.3569 11.614L12.6431 12.3857ZM6.59715 4.45282L11.3569 12.3857L12.6431 11.614L7.88339 3.68108L6.59715 4.45282ZM12 20.5C7.30558 20.5 3.5 16.6944 3.5 12H2C2 17.5228 6.47715 22 12 22V20.5ZM3.5 12C3.5 7.30558 7.30558 3.5 12 3.5V2C6.47715 2 2 6.47715 2 12H3.5ZM12 3.5C16.6944 3.5 20.5 7.30558 20.5 12H22C22 6.47715 17.5228 2 12 2V3.5ZM20.5 12C20.5 16.6944 16.6944 20.5 12 20.5V22C17.5228 22 22 17.5228 22 12H20.5ZM12 16.4644C9.51472 16.4644 7.5 14.4497 7.5 11.9644H6C6 15.2781 8.68629 17.9644 12 17.9644V16.4644ZM16.5 11.9644C16.5 14.4497 14.4853 16.4644 12 16.4644V17.9644C15.3137 17.9644 18 15.2781 18 11.9644H16.5ZM14.315 8.10467C15.6258 8.89282 16.5 10.3269 16.5 11.9644H18C18 9.77898 16.8311 7.86728 15.088 6.81916L14.315 8.10467ZM7.5 11.9644C7.5 10.3269 8.37421 8.89282 9.68497 8.10467L8.91201 6.81916C7.16889 7.86728 6 9.77898 6 11.9644H7.5ZM12 12H10.5C10.5 12.8284 11.1716 13.5 12 13.5V12ZM12 12V10.5C11.1716 10.5 10.5 11.1716 10.5 12H12ZM12 12H13.5C13.5 11.1716 12.8284 10.5 12 10.5V12ZM12 12V13.5C12.8284 13.5 13.5 12.8284 13.5 12H12Z\" fill=\"currentColor\"></path></svg>",
    "title": "CI failure & flaky test summary",
    "desc": "Highlights recurring CI failures and flaky tests, ranked by impact."
  },
  {
    "testid": "suggested-template-sentry-error-triage-and-fix",
    "tracking": "suggested-template-select-sentry-error-triage-and-fix",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-destructive-subtle text-content-destructive",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M5.37036 9.80627L3 9M5.37036 13.75H2.75M5.37036 17.4437L3 18.25M18.63 9.80627L21 9M18.63 13.75H21.2504M18.63 17.4437L21 18.25M12 13.75V20.75M7.75 7.5V7C7.75 4.65279 9.65279 2.75 12 2.75C14.3472 2.75 16.25 4.65279 16.25 7V7.5M18.25 7.75H5.75V15C5.75 18.4518 8.54822 21.25 12 21.25C15.4518 21.25 18.25 18.4518 18.25 15V7.75Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "Sentry error triage & fix",
    "desc": "Fixes the highest-impact unresolved Sentry error and opens a PR."
  },
  {
    "testid": "suggested-template-sentry-to-linear-issues",
    "tracking": "suggested-template-select-sentry-to-linear-issues",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-destructive-subtle text-content-destructive",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M20.25 13.5C20.25 17.7802 16.5563 21.25 12 21.25C7.44365 21.25 3.75 17.7802 3.75 13.5C3.75 9.21979 7.44365 5.75 12 5.75C16.5563 5.75 20.25 9.21979 20.25 13.5Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\" stroke-linejoin=\"round\"></path><path d=\"M20.25 4.64584C20.25 4.64584 19.75 2.75 18 2.75C15.25 2.75 14.25 7.08336 13.75 9.25\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\" stroke-linejoin=\"round\"></path><path d=\"M3.75 4.64584C3.75 4.64584 4.25 2.75 6 2.75C8.74996 2.75 9.74999 7.08336 10.25 9.25\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\" stroke-linejoin=\"round\"></path><path d=\"M10.5 13.75C10.5 14.7165 9.82843 15.5 9 15.5C8.17157 15.5 7.5 14.7165 7.5 13.75C7.5 12.7835 8.17157 12 9 12C9.82843 12 10.5 12.7835 10.5 13.75Z\" fill=\"currentColor\"></path><path d=\"M13.5 17C13.5 17.5523 12.8284 18 12 18C11.1716 18 10.5 17.5523 10.5 17C10.5 16.4477 11.1716 16 12 16C12.8284 16 13.5 16.4477 13.5 17Z\" fill=\"currentColor\"></path><path d=\"M16.5 13.75C16.5 14.7165 15.8284 15.5 15 15.5C14.1716 15.5 13.5 14.7165 13.5 13.75C13.5 12.7835 14.1716 12 15 12C15.8284 12 16.5 12.7835 16.5 13.75Z\" fill=\"currentColor\"></path></svg>",
    "title": "Sentry to Linear issues",
    "desc": "Turns new Sentry errors into prioritized Linear issues with relevant context."
  },
  {
    "testid": "suggested-template-weekly-sentry-report",
    "tracking": "suggested-template-select-weekly-sentry-report",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-warning-subtle text-content-warning",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M2 5.25L5 2.25M22 5.25L19 2.25M12 8V12L14.5 14.5M21.25 12C21.25 17.1086 17.1086 21.25 12 21.25C6.89137 21.25 2.75 17.1086 2.75 12C2.75 6.89137 6.89137 2.75 12 2.75C17.1086 2.75 21.25 6.89137 21.25 12Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "Weekly Sentry error report",
    "desc": "Publishes a weekly summary of new errors, regressions, and top offenders."
  },
  {
    "testid": "suggested-template-linear-bug-to-fix",
    "tracking": "suggested-template-select-linear-bug-to-fix",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-warning-subtle text-content-warning",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M20.25 13.5C20.25 17.7802 16.5563 21.25 12 21.25C7.44365 21.25 3.75 17.7802 3.75 13.5C3.75 9.21979 7.44365 5.75 12 5.75C16.5563 5.75 20.25 9.21979 20.25 13.5Z\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\" stroke-linejoin=\"round\"></path><path d=\"M20.25 4.64584C20.25 4.64584 19.75 2.75 18 2.75C15.25 2.75 14.25 7.08336 13.75 9.25\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\" stroke-linejoin=\"round\"></path><path d=\"M3.75 4.64584C3.75 4.64584 4.25 2.75 6 2.75C8.74996 2.75 9.74999 7.08336 10.25 9.25\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\" stroke-linejoin=\"round\"></path><path d=\"M10.5 13.75C10.5 14.7165 9.82843 15.5 9 15.5C8.17157 15.5 7.5 14.7165 7.5 13.75C7.5 12.7835 8.17157 12 9 12C9.82843 12 10.5 12.7835 10.5 13.75Z\" fill=\"currentColor\"></path><path d=\"M13.5 17C13.5 17.5523 12.8284 18 12 18C11.1716 18 10.5 17.5523 10.5 17C10.5 16.4477 11.1716 16 12 16C12.8284 16 13.5 16.4477 13.5 17Z\" fill=\"currentColor\"></path><path d=\"M16.5 13.75C16.5 14.7165 15.8284 15.5 15 15.5C14.1716 15.5 13.5 14.7165 13.5 13.75C13.5 12.7835 14.1716 12 15 12C15.8284 12 16.5 12.7835 16.5 13.75Z\" fill=\"currentColor\"></path></svg>",
    "title": "Linear bug to fix PR",
    "desc": "Converts a Linear bug report into a tested fix and draft PR."
  },
  {
    "testid": "suggested-template-notion-weekly-digest",
    "tracking": "suggested-template-select-notion-weekly-digest",
    "iconBoxClass": "shrink-0 rounded-[4px] p-1 bg-surface-brand-subtle text-content-brand",
    "iconSvg": "<svg aria-hidden=\"true\" width=\"16px\" height=\"16px\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M8.75 3.25H4.25V20.75H8.75M8.75 3.25H19.75V20.75H8.75M8.75 3.25V20.75M12.75 7.75H15.75M12.75 11.75H15.75\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"square\"></path></svg>",
    "title": "Weekly team digest to Notion",
    "desc": "Publishes a weekly digest of team activity, merged PRs, and open work."
  }
];
