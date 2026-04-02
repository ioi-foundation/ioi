import {
  startTransition,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
} from 'react';
import Header from './components/Header';
import MainContent from './components/MainContent';
import Sidebar from './components/Sidebar';
import {
  DEFAULT_PAGE_ID,
  DOC_PAGES,
  DOC_SECTIONS,
  firstPageForSection,
  getDocPage,
  matchesDocSearch,
} from './content/docs';

function pageIdFromHash() {
  const hashValue = window.location.hash.replace(/^#/, '').trim();
  return getDocPage(hashValue) ? hashValue : DEFAULT_PAGE_ID;
}

export default function App() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activePageId, setActivePageId] = useState<string>(() =>
    typeof window === 'undefined' ? DEFAULT_PAGE_ID : pageIdFromHash(),
  );
  const [isDark, setIsDark] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const deferredSearchQuery = useDeferredValue(searchQuery);

  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, '', `#${DEFAULT_PAGE_ID}`);
    }

    const handleHashChange = () => {
      setActivePageId(pageIdFromHash());
      setIsMobileMenuOpen(false);
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  const activePage = getDocPage(activePageId) ?? getDocPage(DEFAULT_PAGE_ID)!;

  const searchResults = useMemo(
    () =>
      DOC_PAGES.filter((page) => matchesDocSearch(page, deferredSearchQuery)).slice(0, 6),
    [deferredSearchQuery],
  );

  const sidebarSections = useMemo(
    () =>
      DOC_SECTIONS.map((section) => ({
        ...section,
        pages: DOC_PAGES.filter(
          (page) =>
            page.section === section.id &&
            (page.id === activePage.id || matchesDocSearch(page, deferredSearchQuery)),
        ),
      })),
    [activePage.id, deferredSearchQuery],
  );

  const navigateToPage = (pageId: string) => {
    if (!getDocPage(pageId)) {
      return;
    }

    startTransition(() => {
      setActivePageId(pageId);
      setSearchQuery('');
      setIsMobileMenuOpen(false);
    });

    if (window.location.hash !== `#${pageId}`) {
      window.location.hash = pageId;
    }
  };

  return (
    <div
      className={`h-screen overflow-hidden transition-colors duration-300 ${
        isDark
          ? 'bg-[#0a0908] text-stone-200'
          : 'bg-[#f7f2e8] text-stone-800'
      }`}
    >
      <Header
        activeSectionId={activePage.section}
        isDark={isDark}
        onMenuToggle={() => setIsMobileMenuOpen((open) => !open)}
        onSearchChange={setSearchQuery}
        onSelectPage={navigateToPage}
        searchQuery={searchQuery}
        searchResults={searchResults}
        sections={DOC_SECTIONS.map((section) => ({
          ...section,
          firstPageId: firstPageForSection(section.id)?.id ?? DEFAULT_PAGE_ID,
          pages: DOC_PAGES.filter((page) => page.section === section.id).map((page) => ({
            id: page.id,
            summary: page.summary,
            title: page.title,
          })),
        }))}
        toggleTheme={() => setIsDark((value) => !value)}
      />
      <div className="mt-16 flex h-[calc(100vh-4rem)] overflow-hidden">
        <Sidebar
          activePageId={activePage.id}
          isDark={isDark}
          isOpen={isMobileMenuOpen}
          onNavigate={navigateToPage}
          searchQuery={deferredSearchQuery}
          sections={sidebarSections}
        />
        <MainContent isDark={isDark} onNavigate={navigateToPage} page={activePage} />
      </div>
    </div>
  );
}
