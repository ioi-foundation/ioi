import { useCallback } from "react";

export interface UseSessionInspectionSurfaceOptions<TView> {
  setInspectionView: (view: TView | null) => void;
  setInspectionTargetId: (targetId: string | null) => void;
  setSelectedArtifactId: (artifactId: string | null) => void;
  toggleInspectionVisible: (visible?: boolean) => Promise<void>;
}

export function useSessionInspectionSurface<TView>({
  setInspectionView,
  setInspectionTargetId,
  setSelectedArtifactId,
  toggleInspectionVisible,
}: UseSessionInspectionSurfaceOptions<TView>) {
  const openArtifactById = useCallback(
    async (artifactId: string) => {
      setInspectionView(null);
      setInspectionTargetId(null);
      setSelectedArtifactId(artifactId);
      await toggleInspectionVisible(true);
    },
    [
      setInspectionTargetId,
      setInspectionView,
      setSelectedArtifactId,
      toggleInspectionVisible,
    ],
  );

  const openInspectionHub = useCallback(
    async (preferredView?: TView | null, preferredTargetId?: string | null) => {
      setInspectionView(preferredView ?? null);
      setInspectionTargetId(preferredTargetId ?? null);
      setSelectedArtifactId(null);
      await toggleInspectionVisible(true);
    },
    [
      setInspectionTargetId,
      setInspectionView,
      setSelectedArtifactId,
      toggleInspectionVisible,
    ],
  );

  const closeInspectionSurface = useCallback(async () => {
    setInspectionView(null);
    setInspectionTargetId(null);
    await toggleInspectionVisible(false);
  }, [setInspectionTargetId, setInspectionView, toggleInspectionVisible]);

  const resetInspectionSurface = useCallback(async () => {
    setInspectionView(null);
    setInspectionTargetId(null);
    setSelectedArtifactId(null);
    await toggleInspectionVisible(false);
  }, [
    setInspectionTargetId,
    setInspectionView,
    setSelectedArtifactId,
    toggleInspectionVisible,
  ]);

  return {
    openArtifactById,
    openInspectionHub,
    closeInspectionSurface,
    resetInspectionSurface,
  };
}
