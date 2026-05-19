import clsx from "clsx";
import "../../node_modules/@codingame/monaco-vscode-api/vscode/src/vs/base/common/codicons.js";
import { getCodiconFontCharacters } from "../../node_modules/@codingame/monaco-vscode-api/vscode/src/vs/base/common/codiconsUtil.js";

const codiconCharacters = getCodiconFontCharacters();

const codiconAliases: Record<string, string> = {
  "auxiliarybar-maximize": "screen-full",
  "auxiliarybar-restore": "screen-normal",
  "auxiliarybar-close": "close",
  "configure-layout-icon": "layout",
  "panel-left-off": "layout-sidebar-left-off",
  "panel-layout-icon-off": "layout-panel-off",
  "auxiliarybar-right-layout-icon": "layout-sidebar-right",
};

function resolveCodiconCodePoint(name: string): number | undefined {
  const directCodePoint = codiconCharacters[name];
  if (typeof directCodePoint === "number") {
    return directCodePoint;
  }

  const aliasName = codiconAliases[name];
  if (!aliasName) {
    return undefined;
  }

  const aliasCodePoint = codiconCharacters[aliasName];
  return typeof aliasCodePoint === "number" ? aliasCodePoint : undefined;
}

export function Codicon({
  name,
  className,
}: {
  name: string;
  className?: string;
}) {
  const codePoint = resolveCodiconCodePoint(name);
  const glyph = codePoint ? String.fromCodePoint(codePoint) : "";

  return (
    <span
      className={clsx(
        "workspace-codicon",
        "codicon",
        `codicon-${name}`,
        className,
      )}
      aria-hidden="true"
    >
      {glyph}
    </span>
  );
}
