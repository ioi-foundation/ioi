import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import type {
  CapabilityRegistryEntry,
  CapabilityRegistrySnapshot,
  ExtensionManifestRecord,
  SkillCatalogEntry,
  SkillDetailView,
  SkillSourceRecord,
  StudioArtifactSelectedSkill,
} from "../../../types";

export type SpotlightCapabilityRegistryStatus =
  | "idle"
  | "loading"
  | "ready"
  | "error";

let cachedCapabilityRegistrySnapshot: CapabilityRegistrySnapshot | null = null;
let inflightCapabilityRegistrySnapshot:
  | Promise<CapabilityRegistrySnapshot>
  | null = null;

function sourceRegistryKey(
  kind: string | null | undefined,
  uri: string | null | undefined,
) {
  const normalizedKind = (kind ?? "").trim().toLowerCase();
  const normalizedUri = (uri ?? "").trim().replace(/\\/g, "/");
  return `${normalizedKind}:${normalizedUri}`;
}

async function loadCapabilityRegistrySnapshot(
  forceRefresh = false,
): Promise<CapabilityRegistrySnapshot> {
  if (cachedCapabilityRegistrySnapshot && !forceRefresh) {
    return cachedCapabilityRegistrySnapshot;
  }

  if (!inflightCapabilityRegistrySnapshot) {
    inflightCapabilityRegistrySnapshot = invoke<CapabilityRegistrySnapshot>(
      "get_capability_registry_snapshot",
    )
      .then((snapshot) => {
        cachedCapabilityRegistrySnapshot = snapshot;
        return snapshot;
      })
      .finally(() => {
        inflightCapabilityRegistrySnapshot = null;
      });
  }

  return inflightCapabilityRegistrySnapshot;
}

function resolveSkillSourceRecordForDetail(
  snapshot: CapabilityRegistrySnapshot,
  detail: SkillDetailView | null,
): SkillSourceRecord | null {
  if (!detail) {
    return null;
  }

  if (detail.source_registry_id) {
    return (
      snapshot.skillSources.find(
        (source) => source.sourceId === detail.source_registry_id,
      ) ?? null
    );
  }

  if (detail.source_registry_kind && detail.source_registry_uri) {
    const registryKey = sourceRegistryKey(
      detail.source_registry_kind,
      detail.source_registry_uri,
    );
    return (
      snapshot.skillSources.find(
        (source) => sourceRegistryKey(source.kind, source.uri) === registryKey,
      ) ?? null
    );
  }

  return null;
}

export function resolveCapabilityRegistryEntryForCatalogSkill(
  entryLookup: Map<string, CapabilityRegistryEntry>,
  skill: SkillCatalogEntry,
): CapabilityRegistryEntry | null {
  return entryLookup.get(`skill:${skill.skill_hash}`) ?? null;
}

export function resolveExtensionManifestForSelectedSkill(
  skill: StudioArtifactSelectedSkill,
  detail: SkillDetailView | null,
  manifests: ExtensionManifestRecord[],
): ExtensionManifestRecord | null {
  const candidatePaths = [
    detail?.source_registry_relative_path,
    detail?.relative_path,
    skill.relativePath,
  ].filter((value): value is string => Boolean(value));

  if (candidatePaths.length === 0) {
    return null;
  }

  const sourceUri = detail?.source_registry_uri ?? null;
  const sourceKind = detail?.source_registry_kind ?? null;

  return (
    manifests.find((manifest) => {
      if (sourceUri && manifest.sourceUri !== sourceUri) {
        return false;
      }
      if (sourceKind && manifest.sourceKind !== sourceKind) {
        return false;
      }
      return manifest.filesystemSkills.some((filesystemSkill) =>
        candidatePaths.includes(filesystemSkill.relativePath),
      );
    }) ?? null
  );
}

export function resolveCapabilityRegistryEntryForSelectedArtifactSkill(
  snapshot: CapabilityRegistrySnapshot | null,
  entryLookup: Map<string, CapabilityRegistryEntry>,
  skill: StudioArtifactSelectedSkill,
  detail: SkillDetailView | null,
  extension: ExtensionManifestRecord | null,
): CapabilityRegistryEntry | null {
  const runtimeSkillEntry = entryLookup.get(`skill:${skill.skillHash}`);
  if (runtimeSkillEntry) {
    return runtimeSkillEntry;
  }

  if (extension) {
    const extensionEntry =
      entryLookup.get(`extension:${extension.extensionId}`) ?? null;
    if (extensionEntry) {
      return extensionEntry;
    }
  }

  if (snapshot) {
    const sourceRecord = resolveSkillSourceRecordForDetail(snapshot, detail);
    if (sourceRecord) {
      return entryLookup.get(`skill_source:${sourceRecord.sourceId}`) ?? null;
    }
  }

  return null;
}

export function useSpotlightCapabilityRegistry(enabled = true) {
  const [snapshot, setSnapshot] = useState<CapabilityRegistrySnapshot | null>(
    () => cachedCapabilityRegistrySnapshot,
  );
  const [status, setStatus] = useState<SpotlightCapabilityRegistryStatus>(() =>
    cachedCapabilityRegistrySnapshot ? "ready" : "idle",
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;

    if (cachedCapabilityRegistrySnapshot) {
      setSnapshot(cachedCapabilityRegistrySnapshot);
      setStatus("ready");
    } else {
      setStatus("loading");
    }

    setError(null);

    void loadCapabilityRegistrySnapshot(Boolean(cachedCapabilityRegistrySnapshot))
      .then((nextSnapshot) => {
        if (cancelled) {
          return;
        }
        setSnapshot(nextSnapshot);
        setStatus("ready");
      })
      .catch((nextError) => {
        if (cancelled) {
          return;
        }
        setStatus("error");
        setError(
          nextError instanceof Error ? nextError.message : String(nextError ?? ""),
        );
      });

    return () => {
      cancelled = true;
    };
  }, [enabled]);

  const entryLookup = useMemo(() => {
    const lookup = new Map<string, CapabilityRegistryEntry>();
    snapshot?.entries.forEach((entry) => {
      lookup.set(entry.entryId, entry);
    });
    return lookup;
  }, [snapshot]);

  return {
    snapshot,
    status,
    error,
    entryLookup,
  };
}
