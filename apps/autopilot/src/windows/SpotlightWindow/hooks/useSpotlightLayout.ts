// apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightLayout.ts

import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

export type DockPosition = "right" | "center" | "float";

export interface SpotlightLayout {
  dockPosition: DockPosition;
  sidebarVisible: boolean;
  artifactPanelVisible: boolean;
}

export function useSpotlightLayout() {
  const [layout, setLayout] = useState<SpotlightLayout>({
    dockPosition: "right",
    sidebarVisible: false,
    artifactPanelVisible: false,
  });

  const [isLoading, setIsLoading] = useState(true);

  // Sync layout from backend on mount
  useEffect(() => {
    const syncLayout = async () => {
      try {
        const [dockPosition, sidebarVisible, artifactPanelVisible] = 
          await invoke<[string, boolean, boolean]>("get_spotlight_layout");
        
        setLayout({
          dockPosition: dockPosition as DockPosition,
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

  // Toggle sidebar visibility
  const toggleSidebar = useCallback(async (visible?: boolean) => {
    const newVisible = visible ?? !layout.sidebarVisible;
    
    try {
      await invoke("toggle_spotlight_sidebar", { visible: newVisible });
      setLayout(prev => ({ ...prev, sidebarVisible: newVisible }));
    } catch (e) {
      console.error("Failed to toggle sidebar:", e);
    }
  }, [layout.sidebarVisible]);

  // Toggle artifact panel visibility
  const toggleArtifactPanel = useCallback(async (visible?: boolean) => {
    const newVisible = visible ?? !layout.artifactPanelVisible;
    
    try {
      await invoke("toggle_spotlight_artifact_panel", { visible: newVisible });
      setLayout(prev => ({ ...prev, artifactPanelVisible: newVisible }));
    } catch (e) {
      console.error("Failed to toggle artifact panel:", e);
    }
  }, [layout.artifactPanelVisible]);

  // Set dock position
  const setDockPosition = useCallback(async (position: DockPosition) => {
    try {
      const mode = position === "center" ? "spotlight" : position;
      await invoke("set_spotlight_mode", { mode });
      setLayout(prev => ({ ...prev, dockPosition: position }));
    } catch (e) {
      console.error("Failed to set dock position:", e);
    }
  }, []);

  // Re-dock to right edge
  const dockRight = useCallback(async () => {
    try {
      await invoke("dock_spotlight_right");
      setLayout(prev => ({ ...prev, dockPosition: "right" }));
    } catch (e) {
      console.error("Failed to dock right:", e);
    }
  }, []);

  return {
    layout,
    isLoading,
    toggleSidebar,
    toggleArtifactPanel,
    setDockPosition,
    dockRight,
  };
}