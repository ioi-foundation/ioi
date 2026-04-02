import type { ReactNode } from 'react';
import { AlertCircle, Check, Copy, FileCode2 } from 'lucide-react';
import { useState } from 'react';

export function Callout({
  children,
  isDark,
  title,
  tone = 'current',
}: {
  children: ReactNode;
  isDark: boolean;
  title?: string;
  tone?: 'current' | 'preview' | 'concept';
}) {
  const palette =
    tone === 'current'
      ? isDark
        ? 'border-[#6b9a7d]/25 bg-[rgba(107,154,125,0.10)] text-stone-200'
        : 'border-[#6b9a7d]/20 bg-[#e8f0eb] text-stone-800'
      : tone === 'preview'
        ? isDark
          ? 'border-[#5a8cec]/25 bg-[rgba(90,140,236,0.10)] text-stone-200'
          : 'border-[#3b5eda]/15 bg-[#edf2fd] text-stone-800'
        : isDark
          ? 'border-[#8e72a8]/25 bg-[rgba(142,114,168,0.10)] text-stone-200'
          : 'border-[#8e72a8]/15 bg-[rgba(142,114,168,0.08)] text-stone-800';

  return (
    <div className={`rounded-3xl border p-5 ${palette}`}>
      <div className="flex gap-3">
        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" />
        <div className="space-y-2 text-sm leading-7">
          {title ? <div className="font-semibold tracking-tight">{title}</div> : null}
          <div>{children}</div>
        </div>
      </div>
    </div>
  );
}

export function CodeBlock({ code, isDark }: { code: string; isDark: boolean }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className={`relative overflow-hidden rounded-3xl border ${isDark ? 'border-stone-800 bg-stone-950/85' : 'border-stone-200 bg-stone-950 text-stone-100'}`}>
      <div className={`flex items-center justify-between border-b px-4 py-3 ${isDark ? 'border-stone-800 bg-stone-950/95' : 'border-stone-800/70 bg-stone-950/95'}`}>
        <div className="flex items-center gap-2 text-[15px] leading-6 tracking-[-0.01em] text-stone-500">
          <FileCode2 className="h-3.5 w-3.5" />
          Command
        </div>
        <button
          onClick={handleCopy}
          className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[15px] leading-6 tracking-[-0.01em] transition-colors ${isDark ? 'border-stone-700 text-stone-300 hover:border-stone-500 hover:text-white' : 'border-stone-700 text-stone-200 hover:border-stone-400 hover:text-white'}`}
        >
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 text-sm leading-6 text-stone-200">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function Table({
  headers,
  rows,
  isDark,
}: {
  headers: string[];
  rows: ReactNode[][];
  isDark: boolean;
}) {
  return (
    <div className={`overflow-hidden rounded-3xl border ${isDark ? 'border-stone-800 bg-stone-950/70' : 'border-stone-200 bg-white'}`}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className={isDark ? 'bg-stone-950 text-stone-300' : 'bg-stone-50 text-stone-700'}>
            <tr>
              {headers.map((header) => (
                <th key={header} className={`border-b px-4 py-4 font-medium ${isDark ? 'border-stone-800' : 'border-stone-200'}`}>
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIndex) => (
              <tr
                key={rowIndex}
                className={isDark ? 'border-b border-stone-900/80 text-stone-300 last:border-b-0' : 'border-b border-stone-100 text-stone-700 last:border-b-0'}
              >
                {row.map((cell, cellIndex) => (
                  <td key={cellIndex} className={`px-4 py-4 align-top leading-6 ${cellIndex === 0 ? (isDark ? 'font-medium text-stone-100' : 'font-medium text-stone-900') : ''}`}>
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function StepList({
  steps,
  isDark,
}: {
  steps: { title: string; body?: string; code?: string }[];
  isDark: boolean;
}) {
  return (
    <div className="space-y-6">
      {steps.map((step, index) => (
        <div key={step.title} className="grid gap-4 md:grid-cols-[auto_minmax(0,1fr)]">
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-full border text-xs font-semibold ${
              isDark
                ? 'border-[#5a8cec]/30 bg-[rgba(90,140,236,0.12)] text-[#c8dcfd]'
                : 'border-[#3b5eda]/20 bg-[#edf2fd] text-[#2740a8]'
            }`}
          >
            {index + 1}
          </div>
          <div className="space-y-3">
            <div className={`text-base font-semibold tracking-tight ${isDark ? 'text-stone-100' : 'text-stone-900'}`}>{step.title}</div>
            {step.body ? (
              <p className={isDark ? 'text-[15px] leading-7 text-stone-300/88' : 'text-[15px] leading-7 text-stone-700'}>
                {step.body}
              </p>
            ) : null}
            {step.code ? <CodeBlock code={step.code} isDark={isDark} /> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

export function RightSidebar({
  items,
  activeId,
  isDark,
  onSelect,
}: {
  items: { id: string; label: string }[];
  activeId?: string;
  isDark: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="hidden w-60 shrink-0 self-start pl-6 xl:block xl:sticky xl:top-8">
      <div className="space-y-4">
        <div className={`text-[15px] font-semibold leading-6 tracking-[-0.01em] ${isDark ? 'text-stone-500' : 'text-stone-500'}`}>
          On this page
        </div>
        <div className={`border-l ${isDark ? 'border-stone-800' : 'border-stone-200'}`}>
          {items.map((item) => {
            const isActive = activeId === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelect(item.id)}
                className={`relative block w-full pl-4 pr-2 py-2 text-left text-[15px] leading-6 tracking-[-0.01em] transition-colors ${
                  isActive
                    ? isDark
                      ? 'text-stone-100'
                      : 'text-stone-900'
                    : isDark
                      ? 'text-stone-500 hover:text-stone-200'
                      : 'text-stone-500 hover:text-stone-800'
                }`}
              >
                {isActive ? (
                  <span
                    className={`absolute bottom-0 left-[-1px] top-0 w-px ${
                      isDark ? 'bg-stone-100' : 'bg-stone-900'
                    }`}
                  />
                ) : null}
                {item.label}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
