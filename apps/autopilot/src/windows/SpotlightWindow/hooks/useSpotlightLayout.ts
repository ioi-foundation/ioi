import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

export interface SpotlightLayout {
  sidebarVisible: boolean;
  artifactPanelVisible: boolean;
}

export function useSpotlightLayout() {
  const [layout, setLayout] = useState<SpotlightLayout>({
    sidebarVisible: false,
    artifactPanelVisible: false,
  });

  const [isLoading, setIsLoading] = useState(true);

  // Sync layout from backend on mount
  useEffect(() => {
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
  }, []);

  const toggleSidebar = useCallback(
    async (visible?: boolean) => {
      const newVisible = visible ?? !layout.sidebarVisible;

      try {
        await invoke("toggle_spotlight_sidebar", { visible: newVisible });
        setLayout((prev) => ({ ...prev, sidebarVisible: newVisible }));
      } catch (e) {
        console.error("Failed to toggle sidebar:", e);
      }
    },
    [layout.sidebarVisible],
  );

  const toggleArtifactPanel = useCallback(
    async (visible?: boolean) => {
      const newVisible = visible ?? !layout.artifactPanelVisible;

      try {
        await invoke("toggle_spotlight_artifact_panel", {
          visible: newVisible,
        });
        setLayout((prev) => ({ ...prev, artifactPanelVisible: newVisible }));
      } catch (e) {
        console.error("Failed to toggle artifact panel:", e);
      }
    },
    [layout.artifactPanelVisible],
  );

  return {
    layout,
    isLoading,
    toggleSidebar,
    toggleArtifactPanel,
  };
}
