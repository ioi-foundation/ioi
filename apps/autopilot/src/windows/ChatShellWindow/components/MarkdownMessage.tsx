import type { MouseEvent } from "react";
import ReactMarkdown from "react-markdown";
import rehypeKatex from "rehype-katex";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import { openUrl } from "@tauri-apps/plugin-opener";
import "katex/dist/katex.min.css";

const SAFE_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);
const MarkdownRenderer = ReactMarkdown as any;

export function MarkdownMessage({ text }: { text: string }) {
  const handleLinkClick = async (
    event: MouseEvent<HTMLAnchorElement>,
    href?: string,
  ) => {
    if (!href) return;

    let parsed: URL;
    try {
      parsed = new URL(href, window.location.href);
    } catch {
      event.preventDefault();
      return;
    }

    if (!SAFE_PROTOCOLS.has(parsed.protocol)) {
      event.preventDefault();
      return;
    }

    event.preventDefault();
    const safeUrl = parsed.toString();

    try {
      await openUrl(safeUrl);
    } catch {
      window.open(safeUrl, "_blank", "noopener,noreferrer");
    }
  };

  const markdownComponents = {
    a: ({ href, ...props }: any) => (
      <a
        {...props}
        href={href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        onClick={(event: MouseEvent<HTMLAnchorElement>) => {
          void handleLinkClick(event, href);
        }}
      />
    ),
  };

  return (
    <div className="message-content-markdown">
      <MarkdownRenderer
        remarkPlugins={[remarkGfm, remarkMath]}
        rehypePlugins={[rehypeKatex]}
        components={markdownComponents}
      >
        {text}
      </MarkdownRenderer>
    </div>
  );
}
