import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

export interface SpotlightLayout {
  sidebarVisible: boolean;
  artifactPanelVisible: boolean;
}

interface UseSpotlightLayoutOptions {
  persistToBackend?: boolean;
  initialSidebarVisible?: boolean;
  initialArtifactPanelVisible?: boolean;
}

export function useSpotlightLayout({
  persistToBackend = true,
  initialSidebarVisible = false,
  initialArtifactPanelVisible = false,
}: UseSpotlightLayoutOptions = {}) {
  const [layout, setLayout] = useState<SpotlightLayout>({
    sidebarVisible: initialSidebarVisible,
    artifactPanelVisible: initialArtifactPanelVisible,
  });

  const [isLoading, setIsLoading] = useState(persistToBackend);

  // Sync layout from backend on mount
  useEffect(() => {
    if (!persistToBackend) {
      setLayout({
        sidebarVisible: initialSidebarVisible,
        artifactPanelVisible: initialArtifactPanelVisible,
      });
      setIsLoading(false);
      return;
    }

    const syncLayout = async () => {
      try {
        const [sidebarVisible, artifactPanelVisible] = await invoke<
          [boolean, boolean]
        >("get_spotlight_layout");

        setLayout({
          sidebarVisible,
          artifactPanelVisible,
        });
      } catch (e) {
        console.error("Failed to sync layout:", e);
      } finally {
        setIsLoading(false);
      }
    };

    syncLayout();
  }, [
    initialArtifactPanelVisible,
    initialSidebarVisible,
    persistToBackend,
  ]);

  const toggleSidebar = useCallback(
    async (visible?: boolean) => {
      const newVisible = visible ?? !layout.sidebarVisible;

      if (!persistToBackend) {
        setLayout((prev) => ({ ...prev, sidebarVisible: newVisible }));
        return;
      }

      try {
        await invoke("toggle_spotlight_sidebar", { visible: newVisible });
        setLayout((prev) => ({ ...prev, sidebarVisible: newVisible }));
      } catch (e) {
        console.error("Failed to toggle sidebar:", e);
      }
    },
    [layout.sidebarVisible, persistToBackend],
  );

  const toggleArtifactPanel = useCallback(
    async (visible?: boolean) => {
      const newVisible = visible ?? !layout.artifactPanelVisible;

      if (!persistToBackend) {
        setLayout((prev) => ({ ...prev, artifactPanelVisible: newVisible }));
        return;
      }

      try {
        await invoke("toggle_spotlight_artifact_panel", {
          visible: newVisible,
        });
        setLayout((prev) => ({ ...prev, artifactPanelVisible: newVisible }));
      } catch (e) {
        console.error("Failed to toggle artifact panel:", e);
      }
    },
    [layout.artifactPanelVisible, persistToBackend],
  );

  return {
    layout,
    isLoading,
    toggleSidebar,
    toggleArtifactPanel,
  };
}
