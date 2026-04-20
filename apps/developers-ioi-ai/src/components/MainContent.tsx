import { AnimatePresence, motion } from 'motion/react';
import { Check, Copy, ExternalLink } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { DocLink, DocPage } from '../content/docs';
import {
  Callout,
  RightSidebar,
} from './UIComponents';

interface MainContentProps {
  isDark: boolean;
  onNavigate: (pageId: string) => void;
  page: DocPage;
}

export default function MainContent({ isDark, onNavigate, page }: MainContentProps) {
  const [copied, setCopied] = useState(false);
  const [activeSectionId, setActiveSectionId] = useState(page.sections[0]?.id);
  const containerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'auto' });
    setActiveSectionId(page.sections[0]?.id);

    const updateActiveSection = () => {
      const sections = Array.from(
        document.querySelectorAll<HTMLElement>('[data-doc-section="true"]'),
      );

      let nextActive = page.sections[0]?.id;
      for (const section of sections) {
        // getBoundingClientRect().top is relative to the viewport.
        // We consider a section active if its top is near or above the header + some padding (e.g. 140px + 64px header).
        if (section.getBoundingClientRect().top <= 204) {
          nextActive = section.id;
        }
      }

      setActiveSectionId(nextActive);
    };

    updateActiveSection();
    window.addEventListener('scroll', updateActiveSection, { passive: true });
    return () => window.removeEventListener('scroll', updateActiveSection);
  }, [page]);

  const statusCallout = useMemo(() => {
    if (page.status === 'Preview') {
      return (
        <Callout isDark={isDark} tone="preview" title="Preview surface">
          <p>
            This page reflects the current direction and repo-backed shape of the surface, but the
            exact UX and contracts may still move as the platform evolves.
          </p>
        </Callout>
      );
    }

    if (page.status === 'Concept') {
      return (
        <Callout isDark={isDark} tone="concept" title="Conceptual guidance">
          <p>
            Use this page for mental models and orientation. For low-level source-of-truth details,
            follow the canonical references rather than treating this as a complete technical spec.
          </p>
        </Callout>
      );
    }

    return null;
  }, [isDark, page.status]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  const handleSectionSelect = (sectionId: string) => {
    const node = document.getElementById(sectionId);
    node?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <main
      className={`flex-1 min-w-0 ${
        isDark ? 'bg-transparent' : 'bg-transparent'
      }`}
    >
      <AnimatePresence mode="wait">
        <motion.article
          key={page.id}
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -12 }}
          transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
          className="mx-auto max-w-[1500px] px-6 py-8 pb-32 md:px-10 md:py-10 md:pb-40"
        >
          <div className="grid gap-10 xl:grid-cols-[minmax(0,1fr)_15rem] xl:items-start">
            <div className="min-w-0 space-y-8 xl:pr-8">
              <div className="max-w-4xl space-y-4">
                <h1
                  className={`max-w-4xl text-4xl font-semibold tracking-tight md:text-5xl ${
                    isDark ? 'text-stone-50' : 'text-stone-950'
                  }`}
                >
                  {page.title}
                </h1>
                <p
                  className={`max-w-3xl text-lg leading-8 ${
                    isDark ? 'text-stone-300/86' : 'text-stone-700'
                  }`}
                >
                  {page.summary}
                </p>
              </div>

              <div className="space-y-10 pt-2">
                {statusCallout}

                {page.sections.map((section, index) => (
                  <motion.section
                    key={section.id}
                    id={section.id}
                    data-doc-section="true"
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.2, delay: 0.04 * index }}
                    className={`scroll-mt-28 space-y-5 border-t pt-8 ${
                      isDark ? 'border-stone-900/80' : 'border-stone-200'
                    }`}
                  >
                    <h2
                      className={`text-2xl font-semibold tracking-tight ${
                        isDark ? 'text-stone-100' : 'text-stone-900'
                      }`}
                    >
                      {section.title}
                    </h2>
                    <div>{section.render(isDark)}</div>
                  </motion.section>
                ))}

                <section
                  className={`space-y-5 border-t pt-8 ${
                    isDark ? 'border-stone-900/80' : 'border-stone-200'
                  }`}
                >
                  <div
                    className={`text-[15px] font-medium leading-6 tracking-[-0.01em] ${
                      isDark ? 'text-stone-500' : 'text-stone-500'
                    }`}
                  >
                    Next
                  </div>
                  <div className="space-y-3">
                    {page.nextSteps.map((link) => renderDocAction(link, isDark, onNavigate))}
                  </div>
                </section>
              </div>
            </div>

            <RightSidebar
              activeId={activeSectionId}
              isDark={isDark}
              items={page.sections.map((section) => ({
                id: section.id,
                label: section.title,
              }))}
              onSelect={handleSectionSelect}
            />
          </div>

          <button
            onClick={handleCopy}
            className={`fixed bottom-6 right-6 z-50 inline-flex items-center gap-2 rounded-full border px-3.5 py-2.5 text-[13px] leading-5 tracking-[-0.01em] transition-colors md:bottom-8 md:right-8 ${
              isDark
                ? 'border-stone-800 bg-[rgba(24,23,21,0.96)] text-stone-300 shadow-[0_10px_24px_rgba(0,0,0,0.28)] hover:border-stone-700 hover:text-stone-100'
                : 'border-stone-200 bg-[rgba(255,255,255,0.96)] text-stone-700 shadow-[0_10px_24px_rgba(47,39,32,0.08)] hover:border-stone-300 hover:text-stone-900'
            }`}
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? 'Copied' : 'Copy Page'}
          </button>
        </motion.article>
      </AnimatePresence>
    </main>
  );
}

function renderDocAction(
  link: DocLink,
  isDark: boolean,
  onNavigate: (pageId: string) => void,
) {
  const sharedClass = `group flex w-full items-start justify-between gap-4 rounded-3xl border px-4 py-4 text-left transition-colors ${
    isDark
      ? 'border-stone-800 bg-stone-950/60 text-stone-300 hover:border-stone-700 hover:text-stone-100'
      : 'border-stone-200 bg-white/70 text-stone-700 hover:border-stone-300 hover:text-stone-900'
  }`;

  const content = (
    <>
      <div className="min-w-0">
        <div className="text-sm font-semibold tracking-tight">{link.label}</div>
        {link.description ? (
          <div className={isDark ? 'mt-1 text-xs leading-6 text-stone-500' : 'mt-1 text-xs leading-6 text-stone-500'}>
            {link.description}
          </div>
        ) : null}
      </div>
      <ExternalLink className="mt-1 h-4 w-4 shrink-0 opacity-50 transition-opacity group-hover:opacity-100" />
    </>
  );

  if (!link.external && link.href.startsWith('#')) {
    return (
      <button key={link.label} onClick={() => onNavigate(link.href.replace(/^#/, ''))} className={sharedClass}>
        {content}
      </button>
    );
  }

  return (
    <a
      key={link.label}
      href={link.href}
      target={link.external ? '_blank' : undefined}
      rel={link.external ? 'noreferrer' : undefined}
      className={sharedClass}
    >
      {content}
    </a>
  );
}
