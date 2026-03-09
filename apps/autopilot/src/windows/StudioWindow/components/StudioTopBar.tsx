import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useRef, useState } from "react";
import type { AssistantUserProfile } from "../../../types";
import { NotificationsIcon } from "./ActivityBarIcons";

interface StudioTopBarProps {
  activeView: string;
  notificationCount: number;
  onOpenNotifications: () => void;
  onOpenSettings: () => void;
}

const DEFAULT_PROFILE: AssistantUserProfile = {
  version: 1,
  displayName: "Operator",
  preferredName: null,
  roleLabel: "Private Operator",
  timezone: "UTC",
  locale: "en-US",
  primaryEmail: null,
  avatarSeed: "OP",
  groundingAllowed: false,
};

function topBarCopy(activeView: string): { eyebrow: string; title: string; subtitle: string } {
  switch (activeView) {
    case "autopilot":
      return {
        eyebrow: "Autopilot",
        title: "Private Assistant",
        subtitle: "Task execution, intervention handling, and assistant-guided work.",
      };
    case "notifications":
      return {
        eyebrow: "Operator Console",
        title: "Notifications",
        subtitle: "Persistent interventions and ranked assistant prompts in one queue.",
      };
    case "reply-composer":
      return {
        eyebrow: "Assistant Workbench",
        title: "Reply Composer",
        subtitle: "Draft and send Gmail replies with thread context still visible.",
      };
    case "meeting-prep":
      return {
        eyebrow: "Assistant Workbench",
        title: "Meeting Prep",
        subtitle: "Review event context and shape a prep brief before the meeting starts.",
      };
    case "compose":
      return {
        eyebrow: "Studio",
        title: "Compose",
        subtitle: "Build and edit automations without losing shell-level awareness.",
      };
    case "atlas":
      return {
        eyebrow: "Context Atlas",
        title: "Live Context",
        subtitle: "Inspect the active graph, evidence, and focus state behind the assistant.",
      };
    case "agents":
      return {
        eyebrow: "Agent Workspace",
        title: "Agents",
        subtitle: "Manage builders, draft new agents, and stage them for execution.",
      };
    case "fleet":
      return {
        eyebrow: "Fleet",
        title: "Runtime Fleet",
        subtitle: "Monitor deployed agents and shared execution surfaces.",
      };
    case "marketplace":
      return {
        eyebrow: "Marketplace",
        title: "Agent Catalog",
        subtitle: "Install and evaluate premade assistants without leaving Studio.",
      };
    case "integrations":
      return {
        eyebrow: "Integrations",
        title: "Connector Control",
        subtitle: "Review connected services, policies, and wallet-backed auth state.",
      };
    case "shield":
      return {
        eyebrow: "Shield",
        title: "Policy Center",
        subtitle: "Inspect enforcement posture, privacy thresholds, and connector policy.",
      };
    case "settings":
      return {
        eyebrow: "Studio",
        title: "Settings",
        subtitle: "Reset, troubleshoot, and manage shell-wide Autopilot behavior.",
      };
    default:
      return {
        eyebrow: "Studio",
        title: "Autopilot",
        subtitle: "Operate workflows, interventions, and assistant signals from one shell.",
      };
  }
}

function initialsForProfile(profile: AssistantUserProfile): string {
  const source = (profile.preferredName || profile.displayName || "Operator").trim();
  const initials = source
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  return initials || profile.avatarSeed || "OP";
}

export function StudioTopBar({
  activeView,
  notificationCount,
  onOpenNotifications,
  onOpenSettings,
}: StudioTopBarProps) {
  const [profile, setProfile] = useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [draft, setDraft] = useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [profileOpen, setProfileOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const profileShellRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;

    void invoke<AssistantUserProfile>("assistant_user_profile_get")
      .then((loadedProfile) => {
        if (cancelled) return;
        setProfile(loadedProfile);
        setDraft(loadedProfile);
      })
      .catch(() => {
        // Best-effort bootstrap only.
      });

    const unlistenPromise = listen<AssistantUserProfile>(
      "assistant-user-profile-updated",
      (event) => {
        if (cancelled) return;
        setProfile(event.payload);
        setDraft(event.payload);
      },
    );

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    if (!profileOpen) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (!profileShellRef.current?.contains(event.target as Node)) {
        setProfileOpen(false);
        setDraft(profile);
        setError(null);
      }
    };

    window.addEventListener("mousedown", handlePointerDown);
    return () => window.removeEventListener("mousedown", handlePointerDown);
  }, [profileOpen, profile]);

  const copy = topBarCopy(activeView);
  const visibleName = profile.preferredName || profile.displayName;

  const updateDraft = <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => {
    setDraft((current) => ({
      ...current,
      [key]: value,
    }));
  };

  const saveProfile = async () => {
    setSaving(true);
    setError(null);
    try {
      const savedProfile = await invoke<AssistantUserProfile>("assistant_user_profile_set", {
        profile: {
          ...draft,
          groundingAllowed: false,
        },
      });
      setProfile(savedProfile);
      setDraft(savedProfile);
      setProfileOpen(false);
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setSaving(false);
    }
  };

  return (
    <header className="studio-topbar">
      <div className="studio-topbar-head">
        <span className="studio-topbar-eyebrow">{copy.eyebrow}</span>
        <div className="studio-topbar-title-row">
          <h1>{copy.title}</h1>
          <p>{copy.subtitle}</p>
        </div>
      </div>

      <div className="studio-topbar-actions">
        <button
          type="button"
          className={`studio-topbar-bell${activeView === "notifications" ? " is-active" : ""}`}
          onClick={onOpenNotifications}
          aria-label={
            notificationCount > 0
              ? `Open notifications (${notificationCount} unresolved)`
              : "Open notifications"
          }
        >
          <NotificationsIcon />
          {notificationCount > 0 ? (
            <span className="studio-topbar-bell-badge">
              {notificationCount > 9 ? "9+" : notificationCount}
            </span>
          ) : null}
        </button>

        <div className="studio-profile-shell" ref={profileShellRef}>
          <button
            type="button"
            className={`studio-topbar-profile-trigger${profileOpen ? " is-open" : ""}`}
            onClick={() => {
              if (!profileOpen) {
                setDraft(profile);
                setError(null);
              }
              setProfileOpen((current) => !current);
            }}
            aria-label="Open profile"
          >
            <span className="studio-topbar-avatar">{initialsForProfile(profile)}</span>
            <span className="studio-topbar-profile-meta">
              <strong>{visibleName}</strong>
              <small>{profile.roleLabel || "Local shell profile"}</small>
            </span>
          </button>

          {profileOpen ? (
            <div className="studio-profile-popover">
              <div className="studio-profile-popover-head">
                <div>
                  <span className="studio-topbar-eyebrow">Profile</span>
                  <h2>Shell identity</h2>
                </div>
                <button
                  type="button"
                  className="studio-profile-link"
                  onClick={() => {
                    setProfileOpen(false);
                    onOpenSettings();
                  }}
                >
                  Open settings
                </button>
              </div>

              <p className="studio-profile-note">
                Local-only shell profile. Not used for assistant grounding, discovery, or PII
                inference.
              </p>

              <div className="studio-profile-grid">
                <label>
                  <span>Display name</span>
                  <input
                    value={draft.displayName}
                    onChange={(event) => updateDraft("displayName", event.target.value)}
                    placeholder="Operator"
                  />
                </label>
                <label>
                  <span>Preferred name</span>
                  <input
                    value={draft.preferredName ?? ""}
                    onChange={(event) => updateDraft("preferredName", event.target.value)}
                    placeholder="Optional"
                  />
                </label>
                <label>
                  <span>Role label</span>
                  <input
                    value={draft.roleLabel ?? ""}
                    onChange={(event) => updateDraft("roleLabel", event.target.value)}
                    placeholder="Private Operator"
                  />
                </label>
                <label>
                  <span>Primary email</span>
                  <input
                    value={draft.primaryEmail ?? ""}
                    onChange={(event) => updateDraft("primaryEmail", event.target.value)}
                    placeholder="Optional"
                  />
                </label>
                <label>
                  <span>Timezone</span>
                  <input
                    value={draft.timezone}
                    onChange={(event) => updateDraft("timezone", event.target.value)}
                    placeholder="America/New_York"
                  />
                </label>
                <label>
                  <span>Locale</span>
                  <input
                    value={draft.locale}
                    onChange={(event) => updateDraft("locale", event.target.value)}
                    placeholder="en-US"
                  />
                </label>
              </div>

              {error ? <div className="studio-profile-error">{error}</div> : null}

              <div className="studio-profile-actions">
                <button
                  type="button"
                  className="studio-profile-button studio-profile-button-secondary"
                  onClick={() => {
                    setDraft(profile);
                    setProfileOpen(false);
                    setError(null);
                  }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="studio-profile-button studio-profile-button-primary"
                  onClick={saveProfile}
                  disabled={saving}
                >
                  {saving ? "Saving…" : "Save profile"}
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
