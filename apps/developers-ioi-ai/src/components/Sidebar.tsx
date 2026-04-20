import { ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { DocPage, DocSectionMeta } from '../content/docs';

interface SidebarSection extends DocSectionMeta {
  pages: DocPage[];
}

interface SidebarProps {
  activePageId: string;
  isDark: boolean;
  isOpen: boolean;
  onNavigate: (pageId: string) => void;
  searchQuery: string;
  sections: SidebarSection[];
}

export default function Sidebar({
  activePageId,
  isDark,
  isOpen,
  onNavigate,
  searchQuery,
  sections,
}: SidebarProps) {
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});

  const visibleSections = useMemo(
    () => sections.filter((section) => section.pages.length > 0),
    [sections],
  );

  return (
    <aside
      className={`fixed bottom-0 left-0 top-16 z-40 w-[18.5rem] shrink-0 overflow-y-auto border-r transition-[transform,background-color,border-color,color] duration-300 md:sticky md:h-[calc(100vh-4rem)] md:translate-x-0 ${
        isDark
          ? 'border-stone-800/80 bg-[rgba(10,9,8,0.97)]'
          : 'border-stone-200/80 bg-[rgba(247,242,232,0.96)]'
      } ${isOpen ? 'translate-x-0' : '-translate-x-full'}`}
    >
      <div className="space-y-10 px-4 py-7 pb-24">
        {searchQuery.trim() ? (
          <div
            className={`mx-2 rounded-xl border px-3 py-2 text-xs transition-colors duration-300 ${
              isDark
                ? 'border-[#5a8cec]/20 bg-[#5a8cec]/8 text-[#c8dcfd]'
                : 'border-[#3b5eda]/15 bg-[#edf2fd] text-[#2740a8]'
            }`}
          >
            Filtering pages for <span className="font-semibold">{searchQuery}</span>
          </div>
        ) : null}

        <div className="space-y-9">
          {visibleSections.length === 0 ? (
            <div
              className={`px-2 text-sm text-stone-500 transition-colors duration-300`}
            >
              No pages match the current search.
            </div>
          ) : null}

          {visibleSections.map((section) => {
            const isCollapsed = collapsedSections[section.id] ?? false;

            return (
              <div key={section.id} className="space-y-3.5">
                <button
                  onClick={() =>
                    setCollapsedSections((current) => ({
                      ...current,
                      [section.id]: !isCollapsed,
                    }))
                  }
                  className={`flex w-full items-start justify-between gap-3 px-2 text-left transition-colors duration-300 ${
                    isDark ? 'text-stone-200' : 'text-stone-900'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-[1.05rem] font-semibold tracking-[-0.01em]">
                      {section.label}
                    </div>
                  </div>
                  {isCollapsed ? (
                    <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-stone-500" />
                  ) : (
                    <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-stone-500" />
                  )}
                </button>

                {!isCollapsed ? (
                  <div className="space-y-1.5">
                    {section.pages.map((page) => {
                      const isActive = page.id === activePageId;
                      return (
                        <button
                          key={page.id}
                          onClick={() => onNavigate(page.id)}
                          className={`w-full rounded-xl px-3 py-2.5 text-left transition-colors duration-300 ${
                            isActive
                              ? isDark
                                ? 'bg-[rgba(250,248,244,0.11)] text-stone-50 shadow-[inset_0_1px_0_rgba(250,248,244,0.03)]'
                                : 'bg-[rgba(47,39,32,0.08)] text-stone-950'
                              : isDark
                                ? 'text-stone-300 hover:bg-[rgba(250,248,244,0.05)] hover:text-stone-100'
                                : 'text-stone-700 hover:bg-[rgba(47,39,32,0.04)] hover:text-stone-950'
                          }`}
                        >
                          <div className="min-w-0">
                            <div
                              className={`text-[15px] leading-6 tracking-[-0.01em] ${
                                isActive
                                  ? isDark
                                    ? 'text-stone-50'
                                    : 'text-stone-950'
                                  : isDark
                                    ? 'text-stone-300'
                                    : 'text-stone-800'
                              }`}
                            >
                              {page.title}
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>

        <a
          href="https://docs.ioi.network"
          target="_blank"
          rel="noreferrer"
          className={`flex items-center justify-between rounded-2xl border px-3 py-3 text-sm transition-colors duration-300 ${
            isDark
              ? 'border-stone-800 bg-stone-950/70 text-stone-300 hover:border-stone-700 hover:text-stone-100'
              : 'border-stone-200 bg-white/70 text-stone-700 hover:border-stone-300 hover:text-stone-900'
          }`}
        >
          <span>Need canonical protocol docs?</span>
          <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </div>
    </aside>
  );
}
