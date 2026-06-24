// Parity Phase C — Project detail surface ported bit-for-bit from the IOI demo
// reference's LIVE <main> DOM (http://localhost:9228/projects/019ee100-f64f-7554-946f-405f46528c91):
// exact element tree, classes, verbatim SVG paths and copy. The shared chrome
// (header + breadcrumb + tab bar) wraps the active tab's content; the four tabs
// (Home/Settings/Secrets/Prebuilds) are real sub-routes like the reference, so the
// tab bar navigates between /projects/:id[/settings|/secrets|/prebuilds]. The
// non-home panels live in HypervisorReferenceProjectTabs. Content mirrors the
// reference's single mock project (ioi / teamioitest/ioi).
import { useRef, useState } from "react";
import type { MouseEventHandler } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  SettingsTabContent,
  SecretsTabContent,
  PrebuildsTabContent,
} from "./HypervisorReferenceProjectTabs";
import { ReferenceModal, AnchoredPopover } from "../parityOverlays";
import { ToggleSwitch } from "../parityControls";
import {
  ShareProjectDialog,
  CreateEnvironmentDialog,
  ProjectActionsMenu,
} from "./HypervisorReferenceProjectDialogs";

export type ProjectDetailTab = "home" | "settings" | "secrets" | "prebuilds";

const FIXTURE_PROJECT_ID = "019ee100-f64f-7554-946f-405f46528c91";

const PROJECT_TABS: { key: ProjectDetailTab; label: string; path: string }[] = [
  { key: "home", label: "Home", path: "" },
  { key: "settings", label: "Settings", path: "/settings" },
  { key: "secrets", label: "Secrets", path: "/secrets" },
  { key: "prebuilds", label: "Prebuilds", path: "/prebuilds" },
];

const ChevronGlyph = () => (
  <svg className="shrink-0 mx-0.5" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8.733 13L10.9375 10.7955C11.3768 10.3562 11.3768 9.64382 10.9375 9.20447L8.733 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const ChevronInactiveGlyph = () => (
  <svg className="shrink-0 text-content-inactive" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8.733 13L10.9375 10.7955C11.3768 10.3562 11.3768 9.64382 10.9375 9.20447L8.733 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const ShareGlyph = () => (
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M15 7.99967L8.33333 2.33301V5.66634C2.66667 5.66634 1 7.99967 1 13.6663C2 11.6663 2.66667 10.333 8.33333 10.333V13.6663L15 7.99967Z" stroke="currentColor" strokeLinejoin="round" /></svg>
);
const DotsGlyph = () => (
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M4.5 8C4.5 8.72488 3.91238 9.3125 3.1875 9.3125C2.46262 9.3125 1.875 8.72488 1.875 8C1.875 7.27512 2.46262 6.6875 3.1875 6.6875C3.91238 6.6875 4.5 7.27512 4.5 8ZM9.3125 8C9.3125 8.72488 8.72488 9.3125 8 9.3125C7.27512 9.3125 6.6875 8.72488 6.6875 8C6.6875 7.27512 7.27512 6.6875 8 6.6875C8.72488 6.6875 9.3125 7.27512 9.3125 8ZM12.8125 9.3125C13.5373 9.3125 14.125 8.72488 14.125 8C14.125 7.27512 13.5373 6.6875 12.8125 6.6875C12.0877 6.6875 11.5 7.27512 11.5 8C11.5 8.72488 12.0877 9.3125 12.8125 9.3125Z" fill="currentColor" /></svg>
);
const ChevronTabGlyph = () => (
  <svg className="rotate-180" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M7.15533 10L8.62498 8.53035C8.91788 8.23745 8.91788 7.76255 8.62498 7.46965L7.15533 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const ChevronTabRightGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M7.15533 10L8.62498 8.53035C8.91788 8.23745 8.91788 7.76255 8.62498 7.46965L7.15533 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const EditPencilGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><g clipPath="url(#clip0_467_866)"><path d="M12.587 5.40601C12.8514 5.14172 12.9999 4.78324 12.9999 4.40943C13 4.03563 12.8515 3.67711 12.5872 3.41276C12.323 3.1484 11.9645 2.99986 11.5907 2.99982C11.2169 2.99977 10.8584 3.14822 10.594 3.41251L3.921 10.087C3.80491 10.2028 3.71905 10.3453 3.671 10.502L3.0105 12.678C2.99758 12.7212 2.9966 12.7672 3.00767 12.8109C3.01875 12.8547 3.04146 12.8946 3.0734 12.9265C3.10533 12.9584 3.14531 12.981 3.18908 12.992C3.23285 13.003 3.27878 13.002 3.322 12.989L5.4985 12.329C5.65508 12.2814 5.79758 12.1961 5.9135 12.0805L12.587 5.40601Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M9.5 4.5L11.5 6.5" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></g><defs><clipPath id="clip0_467_866"><rect width="12" height="12" fill="white" transform="translate(2 2)" /></clipPath></defs></svg>
);
const GithubGlyph = () => (
  <svg className="shrink-0" width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg"><g clipPath="url(#clip0_347_348)"><g clipPath="url(#clip1_347_348)"><path fillRule="evenodd" clipRule="evenodd" d="M6.97914 0.142853C3.11986 0.142853 0 3.28571 0 7.17385C0 10.2819 1.999 12.9127 4.77214 13.8439C5.11886 13.9139 5.24586 13.6926 5.24586 13.5064C5.24586 13.3434 5.23443 12.7847 5.23443 12.2026C3.293 12.6217 2.88871 11.3644 2.88871 11.3644C2.57671 10.5496 2.11443 10.3401 2.11443 10.3401C1.479 9.90942 2.16071 9.90942 2.16071 9.90942C2.86557 9.95599 3.23543 10.6311 3.23543 10.6311C3.85929 11.702 4.86457 11.3994 5.269 11.2131C5.32671 10.7591 5.51171 10.4449 5.70814 10.2703C4.15971 10.1073 2.53057 9.502 2.53057 6.80128C2.53057 6.033 2.80771 5.40442 3.24686 4.91557C3.17757 4.741 2.93486 4.01914 3.31629 3.053C3.31629 3.053 3.90557 2.86671 5.23429 3.77471C5.80315 3.6208 6.38982 3.54251 6.97914 3.54185C7.56843 3.54185 8.16914 3.62342 8.72386 3.77471C10.0527 2.86671 10.642 3.053 10.642 3.053C11.0234 4.01914 10.7806 4.741 10.7113 4.91557C11.162 5.40442 11.4277 6.033 11.4277 6.80128C11.4277 9.502 9.79857 10.0956 8.23857 10.2703C8.49286 10.4914 8.71229 10.9104 8.71229 11.574C8.71229 12.5169 8.70086 13.2736 8.70086 13.5063C8.70086 13.6926 8.828 13.9139 9.17457 13.844C11.9477 12.9126 13.9467 10.2819 13.9467 7.17385C13.9581 3.28571 10.8269 0.142853 6.97914 0.142853Z" fill="currentColor" /></g></g><defs><clipPath id="clip0_347_348"><rect width="14" height="14" fill="white" /></clipPath><clipPath id="clip1_347_348"><rect width="14" height="13.7143" fill="white" transform="translate(0 0.142853)" /></clipPath></defs></svg>
);
const BranchGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-git-branch size-3"><line x1="6" x2="6" y1="3" y2="15" /><circle cx="18" cy="6" r="3" /><circle cx="6" cy="18" r="3" /><path d="M18 9a9 9 0 0 1-9 9" /></svg>
);
const EnvSetupGlyph = () => (
  <svg className="flex-shrink-0 text-content-primary" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><g clipPath="url(#clip0_7_572)"><path d="M5.94563 2.78885L5.72542 2.23073L5.94563 2.78885ZM5.7684 2.86234L5.52907 2.31213L5.7684 2.86234ZM2.86245 5.76815L2.31225 5.5288L2.86245 5.76815ZM2.86239 10.2318L2.31219 10.4711L2.86239 10.2318ZM2.68837 12.5879L2.26411 13.0122L2.68837 12.5879ZM3.41215 13.3117L2.98788 13.7359L3.41215 13.3117ZM5.76826 13.1377L6.0076 12.5875L5.76826 13.1377ZM10.0544 13.2112L10.2746 13.7694L10.0544 13.2112ZM10.2318 13.1377L9.99247 12.5875L10.2318 13.1377ZM13.1377 10.2318L12.5875 9.99246L13.1377 10.2318ZM13.2112 10.0544L13.7694 10.2746L13.2112 10.0544ZM13.2112 5.94566L12.6531 6.16587L13.2112 5.94566ZM13.1377 5.76833L13.6879 5.52901L13.1377 5.76833ZM13.3117 3.41215L12.8875 3.83641L13.3117 3.41215ZM10.0544 2.78883L9.83417 3.34696L10.0544 2.78883ZM8.51198 0.4H7.48804V1.6H8.51198V0.4ZM10.4712 2.31222C10.4062 2.28396 10.3407 2.25678 10.2746 2.2307L9.83417 3.34696C9.88739 3.36796 9.94017 3.38985 9.99249 3.41261L10.4712 2.31222ZM13.736 2.98788L13.0122 2.26413L12.1637 3.11266L12.8875 3.83641L13.736 2.98788ZM13.7693 5.72546C13.7433 5.65941 13.7161 5.59392 13.6879 5.52901L12.5875 6.00766C12.6102 6.05994 12.6321 6.11269 12.6531 6.16587L13.7693 5.72546ZM15.6 8.51202V7.48801H14.4V8.51202H15.6ZM13.6879 10.4711C13.7161 10.4062 13.7433 10.3406 13.7694 10.2746L12.6531 9.83415C12.6321 9.88737 12.6102 9.94015 12.5875 9.99246L13.6879 10.4711ZM13.0121 13.7359L13.7359 13.0121L12.8874 12.1636L12.1636 12.8874L13.0121 13.7359ZM10.2746 13.7694C10.3407 13.7433 10.4062 13.7161 10.4711 13.6879L9.99247 12.5875C9.94016 12.6102 9.88739 12.6321 9.83417 12.6531L10.2746 13.7694ZM7.48802 15.6H8.51203V14.4H7.48802V15.6ZM5.52893 13.6879C5.59387 13.7161 5.6594 13.7433 5.72548 13.7694L6.16589 12.6531C6.11268 12.6321 6.05991 12.6102 6.0076 12.5875L5.52893 13.6879ZM2.26411 13.0122L2.98788 13.7359L3.83641 12.8874L3.11264 12.1636L2.26411 13.0122ZM2.23071 10.2746C2.25678 10.3407 2.28395 10.4062 2.31219 10.4711L3.41259 9.99245C3.38984 9.94016 3.36796 9.88739 3.34697 9.83419L2.23071 10.2746ZM0.4 7.48806V8.512H1.6V7.48806H0.4ZM2.31225 5.5288C2.28399 5.59378 2.2568 5.65934 2.23071 5.72545L3.34697 6.16587C3.36798 6.11263 3.38987 6.05983 3.41264 6.0075L2.31225 5.5288ZM3.1127 3.83633L3.83647 3.11257L2.98794 2.26404L2.26418 2.98781L3.1127 3.83633ZM5.72542 2.23073C5.65941 2.25677 5.59395 2.28392 5.52907 2.31213L6.00772 3.41254C6.05997 3.38982 6.11268 3.36796 6.16584 3.34698L5.72542 2.23073ZM6.16584 3.34698C6.73111 3.12396 7.2 2.58076 7.2 1.88804H6C6 2.00571 5.91399 2.15632 5.72542 2.23073L6.16584 3.34698ZM4.24412 3.11257C4.73409 3.60254 5.45007 3.6551 6.00772 3.41254L5.52907 2.31213C5.34328 2.39295 5.17594 2.34733 5.09265 2.26404L4.24412 3.11257ZM3.83647 3.11257C3.94904 3 4.13155 3 4.24412 3.11257L5.09265 2.26404C4.51145 1.68284 3.56914 1.68284 2.98794 2.26404L3.83647 3.11257ZM3.1127 4.2439C3.00016 4.13136 3.00016 3.94888 3.1127 3.83633L2.26418 2.98781C1.683 3.56898 1.683 4.51126 2.26418 5.09243L3.1127 4.2439ZM3.41264 6.0075C3.65522 5.44987 3.60268 4.73388 3.1127 4.2439L2.26418 5.09243C2.34746 5.17571 2.39307 5.34304 2.31225 5.5288L3.41264 6.0075ZM1.88803 7.20003C2.58075 7.20003 3.12395 6.73113 3.34697 6.16587L2.23071 5.72545C2.15631 5.91402 2.0057 6.00003 1.88803 6.00003V7.20003ZM1.6 7.48806C1.6 7.32898 1.72896 7.20003 1.88803 7.20003V6.00003C1.06622 6.00003 0.4 6.66624 0.4 7.48806H1.6ZM1.88803 8.80003C1.72896 8.80003 1.6 8.67107 1.6 8.512H0.4C0.4 9.33382 1.06621 10 1.88803 10V8.80003ZM3.34697 9.83419C3.12395 9.26892 2.58075 8.80003 1.88803 8.80003V10C2.0057 10 2.15631 10.086 2.23071 10.2746L3.34697 9.83419ZM3.11264 11.756C3.60261 11.2661 3.65516 10.5501 3.41259 9.99245L2.31219 10.4711C2.39301 10.6569 2.34739 10.8242 2.26411 10.9075L3.11264 11.756ZM3.11264 12.1636C3.00008 12.0511 3.00008 11.8686 3.11264 11.756L2.26411 10.9075C1.68292 11.4887 1.68292 12.431 2.26411 13.0122L3.11264 12.1636ZM4.24401 12.8874C4.13146 13 3.94897 13 3.83641 12.8874L2.98788 13.7359C3.56907 14.3171 4.51135 14.3171 5.09254 13.7359L4.24401 12.8874ZM6.0076 12.5875C5.44997 12.3449 4.73398 12.3975 4.24401 12.8874L5.09254 13.7359C5.17582 13.6527 5.34315 13.6071 5.52893 13.6879L6.0076 12.5875ZM7.20002 14.112C7.20002 13.4193 6.73114 12.8761 6.16589 12.6531L5.72548 13.7694C5.91403 13.8437 6.00002 13.9943 6.00002 14.112H7.20002ZM7.48802 14.4C7.32896 14.4 7.20002 14.2711 7.20002 14.112H6.00002C6.00002 14.9338 6.66622 15.6 7.48802 15.6V14.4ZM8.80003 14.112C8.80003 14.2711 8.67109 14.4 8.51203 14.4V15.6C9.33383 15.6 10 14.9338 10 14.112H8.80003ZM9.83417 12.6531C9.26891 12.8761 8.80003 13.4193 8.80003 14.112H10C10 13.9943 10.086 13.8438 10.2746 13.7694L9.83417 12.6531ZM11.756 12.8874C11.2661 12.3974 10.5501 12.3449 9.99247 12.5875L10.4711 13.6879C10.6569 13.607 10.8242 13.6527 10.9075 13.7359L11.756 12.8874ZM12.1636 12.8874C12.0511 13 11.8686 13 11.756 12.8874L10.9075 13.7359C11.4887 14.3171 12.431 14.3171 13.0121 13.7359L12.1636 12.8874ZM12.8874 11.756C13 11.8686 13 12.0511 12.8874 12.1636L13.7359 13.0121C14.3171 12.431 14.3171 11.4887 13.7359 10.9075L12.8874 11.756ZM12.5875 9.99246C12.3449 10.5501 12.3975 11.2661 12.8874 11.756L13.7359 10.9075C13.6527 10.8242 13.6071 10.6569 13.6879 10.4711L12.5875 9.99246ZM14.112 8.80001C13.4193 8.80001 12.8761 9.2689 12.6531 9.83415L13.7694 10.2746C13.8438 10.086 13.9944 10 14.112 10V8.80001ZM14.4 8.51202C14.4 8.67107 14.2711 8.80001 14.112 8.80001V10C14.9338 10 15.6 9.33382 15.6 8.51202H14.4ZM14.112 7.20001C14.2711 7.20001 14.4 7.32895 14.4 7.48801H15.6C15.6 6.66621 14.9338 6.00001 14.112 6.00001V7.20001ZM12.6531 6.16587C12.8761 6.73113 13.4193 7.20001 14.112 7.20001V6.00001C13.9943 6.00001 13.8437 5.91401 13.7693 5.72546L12.6531 6.16587ZM12.8875 4.24405C12.3975 4.73403 12.3449 5.45002 12.5875 6.00766L13.6879 5.52901C13.6071 5.34322 13.6527 5.17587 13.736 5.09258L12.8875 4.24405ZM12.8875 3.83641C13 3.94898 13 4.13148 12.8875 4.24405L13.736 5.09258C14.3172 4.51138 14.3172 3.56908 13.736 2.98788L12.8875 3.83641ZM11.7561 3.11266C11.8687 3.0001 12.0512 3.0001 12.1637 3.11266L13.0122 2.26413C12.4311 1.68295 11.4888 1.68294 10.9076 2.26413L11.7561 3.11266ZM9.99249 3.41261C10.5501 3.65519 11.2661 3.60263 11.7561 3.11266L10.9076 2.26413C10.8243 2.34742 10.657 2.39303 10.4712 2.31222L9.99249 3.41261ZM8.8 1.88803C8.8 2.58074 9.2689 3.12394 9.83417 3.34696L10.2746 2.2307C10.086 2.1563 10 2.00569 10 1.88803H8.8ZM7.48804 0.4C6.66622 0.4 6 1.06622 6 1.88804H7.2C7.2 1.72896 7.32896 1.6 7.48804 1.6V0.4ZM8.51198 1.6C8.67105 1.6 8.8 1.72895 8.8 1.88803H10C10 1.06621 9.33379 0.4 8.51198 0.4V1.6Z" fill="currentColor" /><circle cx="8.00002" cy="7.99996" r="2.33334" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" /></g><defs><clipPath id="clip0_7_572"><rect width="16" height="16" fill="white" /></clipPath></defs></svg>
);
const SecretsGlyph = () => (
  <svg className="flex-shrink-0 text-content-primary" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><g clipPath="url(#clip0_41_813)"><path d="M2.5085 11.1582C2.28969 11.3769 2.16673 11.6736 2.16667 11.983V13.25C2.16667 13.4047 2.22813 13.5531 2.33752 13.6625C2.44692 13.7719 2.59529 13.8333 2.75 13.8333H4.5C4.65471 13.8333 4.80308 13.7719 4.91248 13.6625C5.02188 13.5531 5.08333 13.4047 5.08333 13.25V12.6667C5.08333 12.5119 5.14479 12.3636 5.25419 12.2542C5.36359 12.1448 5.51196 12.0833 5.66667 12.0833H6.25C6.40471 12.0833 6.55308 12.0219 6.66248 11.9125C6.77188 11.8031 6.83333 11.6547 6.83333 11.5V10.9167C6.83333 10.7619 6.89479 10.6136 7.00419 10.5042C7.11359 10.3948 7.26196 10.3333 7.41667 10.3333H7.517C7.82639 10.3333 8.12309 10.2103 8.34183 9.99149L8.81667 9.51666C9.6274 9.79908 10.51 9.798 11.32 9.5136C12.1301 9.2292 12.8196 8.67831 13.2759 7.95106C13.7321 7.22382 13.9281 6.36326 13.8316 5.51017C13.7352 4.65708 13.3521 3.86197 12.7451 3.25491C12.138 2.64784 11.3429 2.26477 10.4898 2.16834C9.63673 2.07192 8.77618 2.26786 8.04893 2.72412C7.32168 3.18037 6.7708 3.86992 6.4864 4.67996C6.202 5.49001 6.20092 6.37259 6.48333 7.18333L2.5085 11.1582Z" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" /><path d="M10.625 5.66665C10.7861 5.66665 10.9167 5.53606 10.9167 5.37498C10.9167 5.2139 10.7861 5.08331 10.625 5.08331C10.4639 5.08331 10.3333 5.2139 10.3333 5.37498C10.3333 5.53606 10.4639 5.66665 10.625 5.66665Z" fill="currentColor" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></g><defs><clipPath id="clip0_41_813"><rect width="14" height="14" fill="white" transform="translate(1 1)" /></clipPath></defs></svg>
);
const PrebuildsGlyph = () => (
  <svg className="flex-shrink-0 text-content-primary" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13.5 5V2.5H2.5V13.5H5.25H6.625M13.5 11.5V13.5H12.125" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M14 7.41463H10.6061V4L6 10.4865H9.39394V14L14 7.41463Z" stroke="currentColor" strokeLinejoin="round" /></svg>
);
const ExternalLinkGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M18.25 14V20.25H3.75V5.75H9.25M13.75 3.75H20.25V10.25M11 13L19.5 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);

export function HypervisorReferenceProjectDetail({ tab = "home" }: { tab?: ProjectDetailTab } = {}) {
  const navigate = useNavigate();
  const { projectId = FIXTURE_PROJECT_ID } = useParams();
  const [overlay, setOverlay] = useState<null | "share" | "create" | "actions">(null);
  const actionsRef = useRef<HTMLButtonElement>(null);
  const closeOverlay = () => setOverlay(null);
  // Project-actions menu items close the menu; anchor items keep their navigation.
  const onActionsItemClick: MouseEventHandler = (e) => {
    if ((e.target as HTMLElement).closest('[role="menuitem"], a, button')) closeOverlay();
  };
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div {...{ orientation: "both" }} className="size-full max-w-full flex min-h-0 flex-col p-0">
        <div data-testid="project-details-layout" className="flex min-h-0 max-h-full grow flex-col overflow-hidden">
          <header className="@container/page-header flex items-center justify-between gap-4 bg-surface-primary border-b border-border-base px-6 py-3 min-h-[57px]">
            <div className="min-w-[min(67%,200px)]">
              <div className="relative min-w-0">
                <ol className="flex min-w-0 flex-row items-center h-6 gap-0.5 text-base invisible absolute inset-0 overflow-hidden" aria-hidden="true">
                  <li className="flex shrink-0 flex-row items-center whitespace-nowrap"><span className="max-w-[200px] truncate">Projects</span><ChevronGlyph /></li>
                  <li className="flex shrink-0 flex-row items-center whitespace-nowrap"><span>ioi</span></li>
                </ol>
                <ol className="flex min-w-0 flex-row items-center h-6 gap-0.5 text-base">
                  <li className="flex min-w-0 shrink-0 flex-row items-center text-content-strong gap-0.5 text-base font-normal"><a className="max-w-[200px] truncate hover:text-content-primary" title="Projects" data-tracking-id="breadcrumb-link" href="/projects">Projects</a><ChevronInactiveGlyph /></li>
                  <li className="flex min-w-0 shrink items-center text-content-primary gap-1.5 text-base font-medium"><span className="truncate">ioi</span></li>
                </ol>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <div className="flex items-center gap-2">
                <div className="hidden items-center gap-2 @[660px]/page-header:flex">
                  <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:text-content-tertiary disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent data-[state=open]:bg-surface-button-clear-accent border border-border-base text-content-primary hover:text-content-accent data-[state=open]:text-content-accent disabled:border-opacity-1 focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base" data-testid="share-project-button" data-tracking-id="share-project-button" type="button" onClick={() => setOverlay("share")}><ShareGlyph /><span className="truncate">Share</span></button>
                  <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-secondary text-content-primary hover:bg-surface-button-secondary-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base" aria-busy="false" data-testid="trigger-prebuild-button" data-tracking-id="trigger-prebuild-button"><span className="truncate">Run prebuild</span></button>
                  <div className="h-4 w-px bg-border-subtle"></div>
                </div>
                <div className="flex items-center" data-tracking-id-none="true">
                  <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-8 text-base aspect-square p-0" aria-label="More actions" type="button" ref={actionsRef} id="radix-:r2r:" aria-haspopup="menu" aria-expanded={overlay === "actions"} data-state={overlay === "actions" ? "open" : "closed"} data-testid="project-actions-dropdown-trigger" onClick={() => setOverlay((o) => (o === "actions" ? null : "actions"))}><DotsGlyph /></button>
                </div>
                <div className="inline-flex rounded-lg border border-border-base" role="group">
                  <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 disabled:bg-surface-primary-inverted disabled:text-content-primary-inverted focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base border-none focus-visible:ring-0 focus-visible:ring-offset-0" aria-busy="false" type="button" aria-label="Create environment" data-testid="create-environment-from-project-button-019ee100-f64f-7554-946f-405f46528c91" data-tracking-id="create-environment-button" data-state="closed" onClick={() => setOverlay("create")}><span className="truncate">Create Environment</span></button>
                </div>
              </div>
            </div>
          </header>
          <div className="relative [scrollbar-gutter:stable] overflow-y-auto overflow-x-hidden flex min-h-0 grow flex-col p-6 mx-[1px] mb-[3px] mt-[1px] overscroll-contain gap-4" data-orientation="vertical">
            <div dir="ltr" data-orientation="horizontal" className="@container">
              <div className="relative min-w-0 max-w-full">
                <div role="tablist" aria-orientation="horizontal" className="scrollbar-hide flex min-h-9 flex-row items-stretch gap-0.5 overflow-x-auto rounded-lg border border-transparent bg-surface-button-tab-base p-[3px] dark:border-border-subtle [&>*]:shrink-0 [&>*]:grow-0 [&>*]:whitespace-nowrap w-fit" tabIndex={0} data-orientation="horizontal" style={{ outline: "none" }}>
                  {PROJECT_TABS.map((t) => {
                    const active = t.key === tab;
                    return (
                      <button key={t.key} type="button" role="tab" aria-selected={active} aria-controls={`radix-:r27:-content-${t.key}`} data-state={active ? "active" : "inactive"} id={`radix-:r27:-trigger-${t.key}`} className="inline-flex flex-row h-7 items-center @md:justify-center gap-2 overflow-hidden rounded-md border-transparent px-1.5 py-1 text-base text-content-strong text-left @md:text-center min-w-0 flex-shrink flex-grow hover:text-content-primary data-[state=active]:bg-surface-button-tab-primary data-[state=active]:border-transparent data-[state=active]:text-content-primary disabled:opacity-50 disabled:hover:text-content-strong" tabIndex={-1} data-orientation="horizontal" data-radix-collection-item="" onClick={() => navigate(`/projects/${projectId}${t.path}`)}><span className="truncate">{t.label}</span></button>
                    );
                  })}
                </div>
                <div className="absolute inset-y-px left-px z-10 flex w-10 items-center rounded-l-lg bg-gradient-to-r from-surface-button-tab-base from-70% to-transparent" style={{ display: "none" }}>
                  <button type="button" tabIndex={-1} aria-label="Scroll tabs left" data-tracking-id="scroll-tabs-left" className="ml-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface-button-tab-base text-content-secondary shadow-sm ring-1 ring-border-base transition-colors hover:bg-surface-glass hover:text-content-primary"><ChevronTabGlyph /></button>
                </div>
                <div className="absolute inset-y-px right-px z-10 flex w-10 items-center justify-end rounded-r-lg bg-gradient-to-l from-surface-button-tab-base from-70% to-transparent" style={{ display: "none" }}>
                  <button type="button" tabIndex={-1} aria-label="Scroll tabs right" data-tracking-id="scroll-tabs-right" className="mr-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface-button-tab-base text-content-secondary shadow-sm ring-1 ring-border-base transition-colors hover:bg-surface-glass hover:text-content-primary"><ChevronTabRightGlyph /></button>
                </div>
              </div>
            </div>
            {tab === "home" ? (
              <HomeTabContent />
            ) : tab === "settings" ? (
              <SettingsTabContent />
            ) : tab === "secrets" ? (
              <SecretsTabContent />
            ) : (
              <PrebuildsTabContent />
            )}
          </div>
        </div>
      </div>
      <ReferenceModal open={overlay === "share"} onClose={closeOverlay}><ShareProjectDialog /></ReferenceModal>
      <ReferenceModal open={overlay === "create"} onClose={closeOverlay} maxWidth="520px"><CreateEnvironmentDialog /></ReferenceModal>
      <AnchoredPopover open={overlay === "actions"} onClose={closeOverlay} anchorRef={actionsRef} side="bottom" align="end"><div onClick={onActionsItemClick}><ProjectActionsMenu /></div></AnchoredPopover>
    </main>
  );
}

function HomeTabContent() {
  const [prebuild, setPrebuild] = useState(false);
  return (
    <div className="flex flex-col gap-8" data-testid="project-home-page">
              <div className="flex flex-col gap-1">
                <div className="flex items-center gap-1">
                  <h2 className="text-xl font-bold tracking-[-0.2px] text-content-primary">ioi</h2>
                  <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 px-2 py-1.5 h-6 text-sm" data-tracking-id="project-home-edit-settings" aria-label="Edit project settings" data-state="closed"><EditPencilGlyph /></button>
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-content-secondary">
                  <span className="flex items-center gap-1.5"><GithubGlyph /><span className="font-mono text-xs">teamioitest/ioi</span></span>
                  <span className="text-content-tertiary">·</span>
                  <span className="flex items-center gap-1"><BranchGlyph /><span className="font-mono text-xs">master</span></span>
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-content-secondary">
                  <span>Created Jun 19, 2026 by Levi Josman</span>
                  <span className="text-content-tertiary">·</span>
                  <span className="flex items-center gap-2">
                    <span className="text-xs text-content-tertiary">Used by</span>
                    <ul className="group/avatars flex max-w-[140px] items-center whitespace-nowrap rounded-lg p-0.5" tabIndex={0} aria-label="Shared with groups and used by users">
                      <li className="relative flex-shrink-0 transition-all ease-out" style={{ zIndex: 1 }}>
                        <span data-slot="avatar" className="relative flex shrink-0 overflow-hidden size-6 flex-shrink-0 border-2 border-surface-glass bg-surface-glass ring-1 ring-border-light transition-shadow group-focus-within/avatars:shadow-sm group-hover/avatars:shadow-sm rounded-full" data-state="closed">
                          <img data-slot="avatar-image" data-testid="avatar-image" className="aspect-square size-full object-cover" referrerPolicy="no-referrer" loading="lazy" alt="Levi Josman's avatar" src="https://lh3.googleusercontent.com/a/ACg8ocIBE-yWc_g6QMTLx_fI4gV6NkJ6Q1ERKa4YxbkEy2U9RsS3DCHb=s96-c" />
                        </span>
                      </li>
                    </ul>
                    <span className="text-xs text-content-tertiary">1 user</span>
                  </span>
                </div>
              </div>
              <div className="relative">
                <div className="flex gap-4 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
                  <a className="hover:border-border-medium min-w-[160px] flex-1 rounded-xl border border-border-light p-4 transition-colors hover:bg-surface-secondary/50" data-tracking-id="project-home-env-setup" href="/projects/019ee100-f64f-7554-946f-405f46528c91/settings#environment-classes">
                    <div className="flex flex-col gap-2" data-testid="project-home-env-setup">
                      <div className="flex items-center gap-1.5"><EnvSetupGlyph /><p className="text-sm font-semibold text-content-primary">Environment Setup</p></div>
                      <div className="flex flex-col gap-1 pl-[22px]">
                        <p className="text-sm text-content-primary" data-state="closed"><span className="font-semibold">1 </span>environment class</p>
                        <p className="text-sm text-content-primary" data-state="closed">All editors</p>
                      </div>
                    </div>
                  </a>
                  <a className="hover:border-border-medium min-w-[160px] flex-1 rounded-xl border border-border-light p-4 transition-colors hover:bg-surface-secondary/50" data-tracking-id="project-home-secrets" href="/projects/019ee100-f64f-7554-946f-405f46528c91/secrets">
                    <div className="flex flex-col gap-2" data-testid="project-home-secrets">
                      <div className="flex items-center gap-1.5"><SecretsGlyph /><p className="text-sm font-semibold text-content-primary">Secrets</p></div>
                      <div className="flex flex-col gap-1 pl-[22px]">
                        <p className="text-sm text-content-primary" data-state="closed"><span className="font-semibold">0 </span>configured</p>
                      </div>
                    </div>
                  </a>
                  <a className="hover:border-border-medium min-w-[160px] flex-1 rounded-xl border border-border-light p-4 transition-colors hover:bg-surface-secondary/50" data-tracking-id="project-home-prebuilds" href="/projects/019ee100-f64f-7554-946f-405f46528c91/prebuilds">
                    <div className="flex flex-col gap-2" data-testid="project-home-prebuilds">
                      <div className="flex items-center gap-1.5"><PrebuildsGlyph /><p className="text-sm font-semibold text-content-primary">Prebuilds</p></div>
                      <div className="flex flex-col gap-1 pl-[22px]">
                        <div className="flex items-center gap-2" data-tracking-id="project-home-prebuilds-toggle-wrapper-0">
                          <div className="flex w-9 justify-center pointer-coarse:w-10">
                            <ToggleSwitch checked={prebuild} onChange={setPrebuild} value="on" ariaLabel={prebuild ? "Enabled" : "Disabled"} testid="project-home-prebuilds-toggle-0" trackingId="project-home-prebuilds-toggle-0" className="h-5 w-9 cursor-pointer rounded-full bg-black/10 dark:bg-white/10 disabled:cursor-default pointer-coarse:h-[22px] pointer-coarse:w-10 data-[state=checked]:bg-content-success dark:data-[state=checked]:bg-content-success disabled:data-[state=checked]:bg-content-success" knobClassName="flex size-5 items-center justify-center data-[state=checked]:translate-x-[16px] pointer-coarse:size-[22px] pointer-coarse:data-[state=checked]:translate-x-[18px]" />
                          </div>
                          <p className="text-sm text-content-primary">{prebuild ? "Enabled" : "Disabled"}</p>
                        </div>
                      </div>
                    </div>
                  </a>
                </div>
              </div>
              <div className="flex flex-col gap-4" data-testid="insights-upsell">
                <div className="flex items-baseline gap-2"><h3 className="text-lg font-bold text-content-primary">Insights</h3></div>
                <div className="rounded-xl border border-border-light flex flex-col items-center gap-3 p-6 text-center">
                  <p className="text-content-primary text-sm font-medium">Available on Enterprise ✨</p>
                  <p className="text-sm text-content-secondary">Insights surfaces speed, AI adoption, and platform usage trends for this project.</p>
                  <a className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:text-content-tertiary disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent data-[state=open]:bg-surface-button-clear-accent border border-border-base text-content-primary hover:text-content-accent data-[state=open]:text-content-accent disabled:border-opacity-1 focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base" target="_blank" rel="noreferrer" href="https://ona.com/docs/ona/organizations/insights"><span className="flex items-center gap-1">Learn more</span><ExternalLinkGlyph /></a>
                </div>
              </div>
            </div>
  );
}

export default HypervisorReferenceProjectDetail;
