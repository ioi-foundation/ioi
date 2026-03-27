import type { ReactNode } from "react";
import { icons } from "./Icons";
import "../styles/Components.css";

export type SlashMenuItem = {
  id: string;
  title: string;
  description?: string;
  meta?: string;
  icon?: ReactNode;
  active?: boolean;
  disabled?: boolean;
  onSelect?: () => void;
};

export type SlashMenuSection = {
  id: string;
  title?: string;
  items: SlashMenuItem[];
};

type SpotlightSlashMenuProps = {
  sections: SlashMenuSection[];
  emptyState?: string;
};

export function SpotlightSlashMenu({
  sections,
  emptyState = "No commands match that filter.",
}: SpotlightSlashMenuProps) {
  const visibleSections = sections.filter((section) => section.items.length > 0);

  return (
    <div
      className="spot-slash-menu"
      onClick={(event) => event.stopPropagation()}
      role="menu"
      aria-label="Slash commands"
    >
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
                      className={`spot-slash-item ${item.active ? "active" : ""}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        item.onSelect?.();
                      }}
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
