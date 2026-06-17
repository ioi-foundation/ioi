import type { Artifact as GeneratedArtifact } from "../generated/autopilot-contracts";
import type { JsonRecord } from "./base";

export type { ArtifactRef, ArtifactType } from "./generated";

export type Artifact = Omit<GeneratedArtifact, "metadata"> & {
  metadata: JsonRecord;
};

export interface ArtifactContentPayload {
  artifact_id: string;
  encoding: "utf-8" | "base64" | string;
  content: string;
}

export type {
  ChatArtifactManifest,
  ChatArtifactManifestFile,
  ChatArtifactManifestStorage,
  ChatArtifactManifestTab,
  ChatArtifactManifestVerification,
  ChatArtifactNavigatorNode,
  ChatArtifactRevision,
  ChatArtifactSession,
  ChatArtifactTabKind,
} from "./chat-artifacts";
