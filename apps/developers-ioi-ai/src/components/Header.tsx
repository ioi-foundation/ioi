import { ChevronDown, ExternalLink, Menu, Moon, Search, Sun } from 'lucide-react';
import { useState } from 'react';
import type { DocPage, DocSectionMeta } from '../content/docs';

interface HeaderSection extends DocSectionMeta {
  firstPageId: string;
  pages: Array<Pick<DocPage, 'id' | 'summary' | 'title'>>;
}

interface HeaderProps {
  activeSectionId: string;
  isDark: boolean;
  onMenuToggle: () => void;
  onSearchChange: (value: string) => void;
  onSelectPage: (pageId: string) => void;
  searchQuery: string;
  searchResults: DocPage[];
  sections: HeaderSection[];
  toggleTheme: () => void;
}

export default function Header({
  activeSectionId,
  isDark,
  onMenuToggle,
  onSearchChange,
  onSelectPage,
  searchQuery,
  searchResults,
  sections,
  toggleTheme,
}: HeaderProps) {
  const searchHasResults = searchQuery.trim().length > 0 && searchResults.length > 0;
  const searchHasNoResults = searchQuery.trim().length > 0 && searchResults.length === 0;
  const [openSectionId, setOpenSectionId] = useState<string | null>(null);

  const closeSectionMenu = () => setOpenSectionId(null);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 border-b backdrop-blur-xl transition-colors duration-300 ${
        isDark
          ? 'border-stone-800/80 bg-[rgba(10,9,8,0.82)]'
          : 'border-stone-200/80 bg-[rgba(247,242,232,0.82)]'
      }`}
    >
      <div className="relative flex h-16 items-center gap-4 px-4 md:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <button
            className={`rounded-full p-2 md:hidden ${
              isDark ? 'text-stone-300 hover:bg-stone-900' : 'text-stone-700 hover:bg-white'
            }`}
            onClick={onMenuToggle}
          >
            <Menu className="h-5 w-5" />
          </button>
          <button
            onClick={() => onSelectPage('choose-the-right-surface')}
            className="min-w-0 text-left"
          >
            <div
              className={`truncate text-[1.08rem] font-semibold tracking-[-0.03em] ${
                isDark ? 'text-stone-100' : 'text-stone-900'
              }`}
            >
              developers.ioi.ai
            </div>
          </button>
        </div>

        <div className="pointer-events-none absolute inset-y-0 left-1/2 hidden -translate-x-1/2 items-center lg:flex">
          <nav className="pointer-events-auto flex min-w-0 items-center gap-1">
            {sections.map((section) => {
              const isActive = section.id === activeSectionId;
              const isOpen = section.id === openSectionId;
              const featuredPages = section.pages.slice(0, 3);

              return (
                <div
                  key={section.id}
                  className="relative -mb-3 pb-3"
                  onMouseEnter={() => setOpenSectionId(section.id)}
                  onMouseLeave={closeSectionMenu}
                >
                  <button
                    onClick={() => {
                      closeSectionMenu();
                      onSelectPage(section.firstPageId);
                    }}
                    onFocus={() => setOpenSectionId(section.id)}
                    className={`inline-flex items-center gap-1 rounded-[0.95rem] px-3 py-1.5 text-[14px] leading-5 tracking-[-0.01em] transition-colors ${
                      isActive
                        ? isDark
                          ? 'bg-[rgba(250,248,244,0.11)] text-stone-100 shadow-[inset_0_1px_0_rgba(250,248,244,0.03)]'
                          : 'bg-[rgba(47,39,32,0.08)] text-stone-900 shadow-sm'
                        : isOpen
                          ? isDark
                            ? 'bg-[rgba(250,248,244,0.05)] text-stone-100'
                            : 'bg-[rgba(47,39,32,0.04)] text-stone-900'
                          : isDark
                            ? 'text-stone-400 hover:bg-[rgba(250,248,244,0.05)] hover:text-stone-200'
                            : 'text-stone-600 hover:bg-[rgba(47,39,32,0.04)] hover:text-stone-900'
                    }`}
                  >
                    <span>{section.label}</span>
                    <ChevronDown
                      className={`h-3.25 w-3.25 ${
                        isActive
                          ? isDark
                            ? 'text-stone-300'
                            : 'text-stone-700'
                          : isOpen
                            ? isDark
                              ? 'text-stone-300'
                              : 'text-stone-700'
                          : isDark
                            ? 'text-stone-500'
                            : 'text-stone-500'
                      }`}
                    />
                  </button>

                  {isOpen ? (
                    <div
                      className="absolute left-1/2 top-full z-30 w-[24rem] -translate-x-1/2 pt-2"
                    >
                      <div
                        className={`overflow-hidden rounded-[1.2rem] border shadow-2xl ${
                          isDark
                            ? 'border-stone-800 bg-stone-900'
                            : 'border-stone-200 bg-[#fffaf2]'
                        }`}
                      >
                        <button
                          onClick={() => {
                            closeSectionMenu();
                            onSelectPage(section.firstPageId);
                          }}
                          className={`block w-full px-4 py-3 text-left transition-colors ${
                            isDark
                              ? 'bg-[rgba(250,248,244,0.06)] hover:bg-[rgba(250,248,244,0.10)]'
                              : 'bg-[rgba(47,39,32,0.05)] hover:bg-[rgba(47,39,32,0.08)]'
                          }`}
                        >
                          <div
                            className={`text-[14px] font-medium leading-5 tracking-[-0.01em] ${
                              isDark ? 'text-stone-100' : 'text-stone-900'
                            }`}
                          >
                            {section.label}
                          </div>
                          <div
                            className={`mt-1 text-[12px] leading-5 ${
                              isDark ? 'text-stone-400' : 'text-stone-600'
                            }`}
                          >
                            {section.description}
                          </div>
                        </button>

                        <div className={isDark ? 'divide-y divide-stone-800' : 'divide-y divide-stone-200'}>
                          {featuredPages.map((page) => (
                            <button
                              key={page.id}
                              onClick={() => {
                                closeSectionMenu();
                                onSelectPage(page.id);
                              }}
                              className={`block w-full px-4 py-3 text-left transition-colors ${
                                isDark
                                  ? 'hover:bg-[rgba(250,248,244,0.07)]'
                                  : 'hover:bg-[rgba(47,39,32,0.05)]'
                              }`}
                            >
                              <div
                                className={`text-[14px] font-medium leading-5 tracking-[-0.01em] ${
                                  isDark ? 'text-stone-100' : 'text-stone-900'
                                }`}
                              >
                                {page.title}
                              </div>
                              <div
                                className={`mt-1 text-[12px] leading-5 ${
                                  isDark ? 'text-stone-400' : 'text-stone-600'
                                }`}
                              >
                                {truncateSummary(page.summary)}
                              </div>
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </nav>
        </div>

        <div className="ml-auto flex items-center gap-3">
          <div className="relative hidden md:block">
            <Search
              className={`pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 ${
                isDark ? 'text-stone-500' : 'text-stone-400'
              }`}
            />
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => onSearchChange(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && searchResults[0]) {
                  onSelectPage(searchResults[0].id);
                }
              }}
              placeholder="Search pages"
              className={`w-[260px] rounded-full border py-2 pl-9 pr-4 text-[14px] leading-5 tracking-[-0.01em] outline-none transition-all xl:w-[340px] ${
                isDark
                  ? 'border-stone-800 bg-stone-950/80 text-stone-200 placeholder:text-stone-500 focus:border-[#5a8cec]/40'
                  : 'border-stone-200 bg-white/85 text-stone-900 placeholder:text-stone-400 focus:border-[#3b5eda]/35'
              }`}
            />
            {searchHasResults ? (
              <div
                className={`absolute right-0 top-[calc(100%+0.5rem)] w-80 overflow-hidden rounded-3xl border shadow-2xl ${
                  isDark
                    ? 'border-stone-800 bg-stone-950/95'
                    : 'border-stone-200 bg-[rgba(255,255,255,0.96)]'
                }`}
              >
                {searchResults.map((page) => (
                  <button
                    key={page.id}
                    onClick={() => onSelectPage(page.id)}
                    className={`block w-full border-b px-4 py-3 text-left transition-colors last:border-b-0 ${
                      isDark
                        ? 'border-stone-800 text-stone-200 hover:bg-stone-900'
                        : 'border-stone-100 text-stone-800 hover:bg-stone-50'
                    }`}
                  >
                    <div className="text-[14px] font-medium leading-5 tracking-[-0.01em]">{page.title}</div>
                    <div className={isDark ? 'mt-1 text-xs text-stone-500' : 'mt-1 text-xs text-stone-500'}>
                      {page.eyebrow} • {page.section.replace('-', ' ')}
                    </div>
                  </button>
                ))}
              </div>
            ) : null}
            {searchHasNoResults ? (
              <div
                className={`absolute right-0 top-[calc(100%+0.5rem)] w-72 rounded-3xl border px-4 py-3 text-sm ${
                  isDark
                    ? 'border-stone-800 bg-stone-950/95 text-stone-400'
                    : 'border-stone-200 bg-white/95 text-stone-600'
                }`}
              >
                No matching pages yet.
              </div>
            ) : null}
          </div>

          <a
            href="https://docs.ioi.network"
            target="_blank"
            rel="noreferrer"
            className={`hidden items-center gap-2 rounded-full px-4 py-2 text-[14px] font-medium leading-5 tracking-[-0.01em] transition-colors md:inline-flex ${
              isDark
                ? 'border border-stone-800 bg-stone-950/80 text-stone-200 hover:border-stone-700 hover:bg-stone-950 hover:text-stone-50'
                : 'border border-stone-200 bg-white/85 text-stone-900 hover:border-stone-300 hover:bg-white'
            }`}
          >
            Canonical docs
            <ExternalLink className="h-3.5 w-3.5" />
          </a>

          <button
            onClick={toggleTheme}
            className={`rounded-full p-2 transition-colors ${
              isDark ? 'text-stone-300 hover:bg-stone-900' : 'text-stone-700 hover:bg-white'
            }`}
          >
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
        </div>
      </div>
    </header>
  );
}

function truncateSummary(summary: string) {
  if (summary.length <= 92) {
    return summary;
  }

  return `${summary.slice(0, 89).trimEnd()}...`;
}
