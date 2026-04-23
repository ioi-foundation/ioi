import clsx from "clsx";
import "../../node_modules/@codingame/monaco-vscode-api/vscode/src/vs/base/common/codicons.js";
import { getCodiconFontCharacters } from "../../node_modules/@codingame/monaco-vscode-api/vscode/src/vs/base/common/codiconsUtil.js";

const codiconCharacters = getCodiconFontCharacters();

export function Codicon({
  name,
  className,
}: {
  name: string;
  className?: string;
}) {
  const codePoint = codiconCharacters[name];
  const glyph = typeof codePoint === "number" ? String.fromCodePoint(codePoint) : "";

  return (
    <span className={clsx("workspace-codicon", className)} aria-hidden="true">
      {glyph}
    </span>
  );
}
