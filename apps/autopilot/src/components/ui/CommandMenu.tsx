import {
  useEffect,
  useRef,
  type ChangeEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { icons } from "./icons";
import "./CommandMenus.css";

export type CommandMenuItem = {
  id: string;
  title: string;
  description?: string;
  meta?: string;
  icon?: ReactNode;
  active?: boolean;
  disabled?: boolean;
  onSelect?: () => void;
};

export type CommandMenuSection = {
  id: string;
  title?: string;
  items: CommandMenuItem[];
};

type CommandMenuProps = {
  sections: CommandMenuSection[];
  emptyState?: string;
  mode?: "slash" | "palette";
  selectedItemId?: string | null;
  onHighlightItem?: (itemId: string) => void;
  searchPlaceholder?: string;
  searchQuery?: string;
  onSearchQueryChange?: (value: string) => void;
  onSearchKeyDown?: (event: KeyboardEvent<HTMLInputElement>) => void;
};

export function CommandMenu({
  sections,
  emptyState = "No commands match that filter.",
  mode = "slash",
  selectedItemId = null,
  onHighlightItem,
  searchPlaceholder = "Search commands, sessions, tools, and skills",
  searchQuery = "",
  onSearchQueryChange,
  onSearchKeyDown,
}: CommandMenuProps) {
  const visibleSections = sections.filter((section) => section.items.length > 0);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const commandPaletteMode = mode === "palette";

  useEffect(() => {
    if (!selectedItemId || !menuRef.current) {
      return;
    }

    const selectedItem = menuRef.current.querySelector<HTMLElement>(
      `[data-slash-item-id="${selectedItemId}"]`,
    );
    selectedItem?.scrollIntoView({ block: "nearest" });
  }, [selectedItemId]);

  return (
    <div
      ref={menuRef}
      className={`spot-slash-menu ${
        commandPaletteMode ? "spot-slash-menu--palette" : ""
      }`}
      onClick={(event) => event.stopPropagation()}
      role="menu"
      aria-label={commandPaletteMode ? "Command palette" : "Slash commands"}
    >
      {commandPaletteMode ? (
        <div className="spot-slash-menu-header">
          <div className="spot-slash-menu-header-topline">
            <span className="spot-slash-menu-title">Command Palette</span>
            <span className="spot-slash-menu-hint">Esc</span>
          </div>

          <label className="spot-slash-menu-search" aria-label="Search commands">
            <span className="spot-slash-menu-search-icon">{icons.search}</span>
            <input
              autoFocus
              className="spot-slash-menu-search-input"
              onChange={(event: ChangeEvent<HTMLInputElement>) =>
                onSearchQueryChange?.(event.target.value)
              }
              onKeyDown={onSearchKeyDown}
              placeholder={searchPlaceholder}
              type="text"
              value={searchQuery}
            />
          </label>
        </div>
      ) : null}

      <div className="spot-slash-menu-scroll">
        {visibleSections.length > 0 ? (
          visibleSections.map((section) => (
            <section className="spot-slash-section" key={section.id}>
              {section.title ? (
                <div className="spot-slash-section-label">{section.title}</div>
              ) : null}

              <div className="spot-slash-items">
                {section.items.map((item) =>
                  item.onSelect && !item.disabled ? (
                    <button
                      key={item.id}
                      className={`spot-slash-item ${
                        item.active ? "active" : ""
                      } ${selectedItemId === item.id ? "selected" : ""}`}
                      data-slash-item-id={item.id}
                      onClick={(event) => {
                        event.stopPropagation();
                        item.onSelect?.();
                      }}
                      onMouseEnter={() => onHighlightItem?.(item.id)}
                      type="button"
                      role="menuitem"
                    >
                      {item.icon ? (
                        <span className="spot-slash-item-icon">{item.icon}</span>
                      ) : null}

                      <span className="spot-slash-item-copy">
                        <span className="spot-slash-item-title">{item.title}</span>
                        {item.description ? (
                          <span className="spot-slash-item-description">
                            {item.description}
                          </span>
                        ) : null}
                      </span>

                      {item.meta ? (
                        <span className="spot-slash-item-meta">{item.meta}</span>
                      ) : null}

                      {item.active ? (
                        <span className="spot-slash-item-check">{icons.check}</span>
                      ) : null}
                    </button>
                  ) : (
                    <div
                      key={item.id}
                      className="spot-slash-item spot-slash-item--static"
                      role="presentation"
                    >
                      {item.icon ? (
                        <span className="spot-slash-item-icon">{item.icon}</span>
                      ) : null}

                      <span className="spot-slash-item-copy">
                        <span className="spot-slash-item-title">{item.title}</span>
                        {item.description ? (
                          <span className="spot-slash-item-description">
                            {item.description}
                          </span>
                        ) : null}
                      </span>

                      {item.meta ? (
                        <span className="spot-slash-item-meta">{item.meta}</span>
                      ) : null}
                    </div>
                  ),
                )}
              </div>
            </section>
          ))
        ) : (
          <div className="spot-slash-empty">{emptyState}</div>
        )}
      </div>
    </div>
  );
}
