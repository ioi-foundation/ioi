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
  NAV_GROUPS,
  docPageByLegacyHash,
  docPageByRoutePath,
  getDocPage,
  matchesDocSearch,
  routeForPageId,
  type DocPage,
} from './content/docs';

const SITE_ORIGIN = 'https://developers.ioi.ai';

function pageIdFromLocation() {
  const hashPage = docPageByLegacyHash(window.location.hash);
  if (hashPage) {
    return hashPage.id;
  }

  const routePage = docPageByRoutePath(window.location.pathname);
  return routePage?.id ?? DEFAULT_PAGE_ID;
}

function replaceCurrentUrlWithPageRoute(pageId: string) {
  const routePath = routeForPageId(pageId);
  if (window.location.pathname !== routePath || window.location.hash) {
    window.history.replaceState({ pageId }, '', routePath);
  }
}

function absolutePageUrl(page: DocPage) {
  return `${SITE_ORIGIN}${page.routePath === '/' ? '/' : page.routePath}`;
}

function setMeta(attribute: 'name' | 'property', key: string, content: string) {
  let tag = document.head.querySelector<HTMLMetaElement>(
    `meta[${attribute}="${key}"]`,
  );

  if (!tag) {
    tag = document.createElement('meta');
    tag.setAttribute(attribute, key);
    document.head.appendChild(tag);
  }

  tag.content = content;
}

function updateDocumentSeo(page: DocPage) {
  const title =
    page.routePath === '/'
      ? 'developers.ioi.ai | IOI Builder Docs'
      : `${page.title} | developers.ioi.ai`;
  const url = absolutePageUrl(page);

  document.title = title;
  setMeta('name', 'description', page.summary);
  setMeta('property', 'og:title', title);
  setMeta('property', 'og:description', page.summary);
  setMeta('property', 'og:url', url);
  setMeta('property', 'og:site_name', 'developers.ioi.ai');
  setMeta('property', 'og:type', 'website');
  setMeta('name', 'twitter:card', 'summary');

  let canonical = document.head.querySelector<HTMLLinkElement>(
    'link[rel="canonical"]',
  );
  if (!canonical) {
    canonical = document.createElement('link');
    canonical.rel = 'canonical';
    document.head.appendChild(canonical);
  }
  canonical.href = url;
}

export default function App() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activePageId, setActivePageId] = useState<string>(() =>
    typeof window === 'undefined' ? DEFAULT_PAGE_ID : pageIdFromLocation(),
  );
  const [isDark, setIsDark] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const deferredSearchQuery = useDeferredValue(searchQuery);

  useEffect(() => {
    replaceCurrentUrlWithPageRoute(pageIdFromLocation());

    const handleLocationChange = () => {
      const nextPageId = pageIdFromLocation();
      replaceCurrentUrlWithPageRoute(nextPageId);
      setActivePageId(nextPageId);
      setIsMobileMenuOpen(false);
    };

    window.addEventListener('hashchange', handleLocationChange);
    window.addEventListener('popstate', handleLocationChange);
    return () => {
      window.removeEventListener('hashchange', handleLocationChange);
      window.removeEventListener('popstate', handleLocationChange);
    };
  }, []);

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  const activePage = getDocPage(activePageId) ?? getDocPage(DEFAULT_PAGE_ID)!;

  useEffect(() => {
    updateDocumentSeo(activePage);
  }, [activePage]);

  const searchResults = useMemo(
    () =>
      DOC_PAGES.filter((page) => matchesDocSearch(page, deferredSearchQuery))
        .sort((left, right) => {
          const statusRank = { Current: 0, Preview: 1, Concept: 2 };
          return statusRank[left.status] - statusRank[right.status];
        })
        .slice(0, 6),
    [deferredSearchQuery],
  );

  const sidebarGroups = useMemo(
    () =>
      NAV_GROUPS.map((group) => ({
        ...group,
        pages: group.pageIds
          .map(getDocPage)
          .filter((page): page is DocPage => Boolean(page))
          .filter(
            (page) =>
              page.id === activePage.id || matchesDocSearch(page, deferredSearchQuery),
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

    const routePath = routeForPageId(pageId);
    if (window.location.pathname !== routePath || window.location.hash) {
      window.history.pushState({ pageId }, '', routePath);
    }
  };

  return (
    <div
      className={`min-h-screen transition-colors duration-300 ${
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
        navGroups={NAV_GROUPS}
        toggleTheme={() => setIsDark((value) => !value)}
      />
      <div className="mx-auto mt-16 flex w-full max-w-[1536px] items-start">
        <Sidebar
          activePageId={activePage.id}
          isDark={isDark}
          isOpen={isMobileMenuOpen}
          onNavigate={navigateToPage}
          searchQuery={deferredSearchQuery}
          navGroups={sidebarGroups}
        />
        <MainContent isDark={isDark} onNavigate={navigateToPage} page={activePage} />
      </div>
    </div>
  );
}
