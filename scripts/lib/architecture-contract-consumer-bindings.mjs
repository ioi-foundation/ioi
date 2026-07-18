import fs from "node:fs";
import ts from "typescript";

function rustTokens(source) {
  const tokens = [];
  let index = 0;
  while (index < source.length) {
    const character = source[index];
    const next = source[index + 1];
    if (/\s/u.test(character)) {
      index += 1;
      continue;
    }
    if (character === "/" && next === "/") {
      index = source.indexOf("\n", index + 2);
      if (index === -1) break;
      continue;
    }
    if (character === "/" && next === "*") {
      let depth = 1;
      index += 2;
      while (index < source.length && depth > 0) {
        if (source[index] === "/" && source[index + 1] === "*") {
          depth += 1;
          index += 2;
        } else if (source[index] === "*" && source[index + 1] === "/") {
          depth -= 1;
          index += 2;
        } else {
          index += 1;
        }
      }
      continue;
    }
    if (character === "r" && /[#"]/u.test(next ?? "")) {
      let cursor = index + 1;
      let hashes = 0;
      while (source[cursor] === "#") {
        hashes += 1;
        cursor += 1;
      }
      if (source[cursor] === '"') {
        const terminator = `"${"#".repeat(hashes)}`;
        const end = source.indexOf(terminator, cursor + 1);
        index = end === -1 ? source.length : end + terminator.length;
        continue;
      }
    }
    if (character === '"' || character === "'") {
      const quote = character;
      index += 1;
      while (index < source.length) {
        if (source[index] === "\\") {
          index += 2;
        } else if (source[index] === quote) {
          index += 1;
          break;
        } else {
          index += 1;
        }
      }
      continue;
    }
    const identifier = /^[A-Za-z_][A-Za-z0-9_]*/u.exec(source.slice(index));
    if (identifier) {
      tokens.push(identifier[0]);
      index += identifier[0].length;
      continue;
    }
    tokens.push(character);
    index += 1;
  }
  return tokens;
}

function inlineModuleBody(tokens, moduleName) {
  let depth = 0;
  for (let index = 0; index < tokens.length - 3; index += 1) {
    if (
      depth === 0 &&
      tokens[index] === "pub" &&
      tokens[index + 1] === "mod" &&
      tokens[index + 2] === moduleName &&
      tokens[index + 3] === "{"
    ) {
      let bodyDepth = 1;
      for (let cursor = index + 4; cursor < tokens.length; cursor += 1) {
        if (tokens[cursor] === "{") bodyDepth += 1;
        if (tokens[cursor] === "}") bodyDepth -= 1;
        if (bodyDepth === 0) return tokens.slice(index + 4, cursor);
      }
      return null;
    }
    if (tokens[index] === "{") depth += 1;
    if (tokens[index] === "}") depth -= 1;
  }
  return null;
}

function hasDirectRustModule(tokens, moduleName) {
  let depth = 0;
  for (let index = 0; index < tokens.length - 3; index += 1) {
    if (
      depth === 0 &&
      tokens[index] === "pub" &&
      tokens[index + 1] === "mod" &&
      tokens[index + 2] === moduleName &&
      tokens[index + 3] === ";"
    ) {
      return true;
    }
    if (tokens[index] === "{") depth += 1;
    if (tokens[index] === "}") depth -= 1;
  }
  return false;
}

function hasPathOverride(tokens) {
  for (let index = 0; index < tokens.length - 3; index += 1) {
    if (
      tokens[index] === "#" &&
      tokens[index + 1] === "[" &&
      tokens[index + 2] === "path"
    ) {
      return true;
    }
  }
  return false;
}

function bindingNames(name, names) {
  if (ts.isIdentifier(name)) {
    names.push(name.text);
    return;
  }
  for (const element of name.elements) {
    if (!ts.isOmittedExpression(element)) bindingNames(element.name, names);
  }
}

function hasExportModifier(node) {
  return (
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some(
      (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword,
    )
  );
}

function explicitTypescriptExports(document) {
  const explicitExports = [];
  for (const statement of document.statements) {
    if (
      ts.isExportDeclaration(statement) &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause)
    ) {
      const moduleSpecifier =
        statement.moduleSpecifier &&
        ts.isStringLiteral(statement.moduleSpecifier)
          ? statement.moduleSpecifier.text
          : null;
      for (const element of statement.exportClause.elements) {
        explicitExports.push({
          exportedName: element.name.text,
          importedName: element.propertyName?.text ?? element.name.text,
          moduleSpecifier,
        });
      }
      continue;
    }
    if (!hasExportModifier(statement)) continue;
    const names = [];
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        bindingNames(declaration.name, names);
      }
    } else if (
      (ts.isClassDeclaration(statement) ||
        ts.isEnumDeclaration(statement) ||
        ts.isFunctionDeclaration(statement) ||
        ts.isInterfaceDeclaration(statement) ||
        ts.isModuleDeclaration(statement) ||
        ts.isTypeAliasDeclaration(statement)) &&
      statement.name &&
      ts.isIdentifier(statement.name)
    ) {
      names.push(statement.name.text);
    }
    for (const exportedName of names) {
      explicitExports.push({
        exportedName,
        importedName: null,
        moduleSpecifier: null,
      });
    }
  }
  return explicitExports;
}

function typescriptModuleBindings(source, filePath) {
  const document = ts.createSourceFile(
    filePath,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const imports = new Set();
  const exports = new Set();
  for (const statement of document.statements) {
    if (
      ts.isImportDeclaration(statement) &&
      ts.isStringLiteral(statement.moduleSpecifier)
    ) {
      imports.add(statement.moduleSpecifier.text);
    }
    if (
      ts.isExportDeclaration(statement) &&
      statement.moduleSpecifier &&
      ts.isStringLiteral(statement.moduleSpecifier)
    ) {
      exports.add(statement.moduleSpecifier.text);
    }
  }
  return {
    explicitExports: explicitTypescriptExports(document),
    exports,
    imports,
  };
}

function typescriptExportedNames(source, filePath) {
  const document = ts.createSourceFile(
    filePath,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  return new Set(
    explicitTypescriptExports(document).map(({ exportedName }) => exportedName),
  );
}

export function architectureContractConsumerBindingFailures({
  root,
  targets,
  safeRepositoryPath,
}) {
  const failures = [];
  const read = (relativePath, at, { allowMissing = false } = {}) => {
    try {
      const filePath = safeRepositoryPath({
        root,
        relativePath,
        at,
        mustExist: true,
      });
      return {
        filePath,
        source: fs.readFileSync(
          safeRepositoryPath({
            root,
            relativePath,
            at: `${at} read`,
            mustExist: true,
          }),
          "utf8",
        ),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!allowMissing || !message.includes(": path does not exist:")) {
        failures.push(message);
      }
      return null;
    }
  };

  const rustTarget = targets.find((target) => target.kind === "rust_projection");
  if (rustTarget) {
    const module = read(
      rustTarget.module_root_path,
      "rust architecture-contract consumer module",
    );
    if (module) {
      const tokens = rustTokens(module.source);
      const generatedBody = inlineModuleBody(tokens, "generated");
      if (
        generatedBody === null ||
        hasPathOverride(generatedBody) ||
        !hasDirectRustModule(generatedBody, "architecture_contracts")
      ) {
        failures.push(
          `${rustTarget.module_root_path} must bind pub mod generated { pub mod architecture_contracts; } through canonical Rust module resolution`,
        );
      }
    }
  }

  const typescriptTarget = targets.find(
    (target) => target.kind === "typescript_projection",
  );
  let generatedExportNames = new Set();
  if (typescriptTarget) {
    const generated = read(
      typescriptTarget.path,
      "generated TypeScript architecture-contract projection",
      { allowMissing: true },
    );
    if (generated) {
      generatedExportNames = typescriptExportedNames(
        generated.source,
        generated.filePath,
      );
      if (generatedExportNames.size === 0) {
        failures.push(
          `${typescriptTarget.path} must declare generated TypeScript architecture-contract exports`,
        );
      }
    }
  }
  for (const binding of typescriptTarget?.typescript_bindings ?? []) {
    const consumer = read(
      binding.consumer_path,
      `typescript architecture-contract ${binding.binding_kind} consumer`,
    );
    if (!consumer) continue;
    const bindings = typescriptModuleBindings(
      consumer.source,
      consumer.filePath,
    );
    if (!bindings[binding.binding_kind]?.has(binding.module_specifier)) {
      failures.push(
        `${binding.consumer_path} must ${binding.binding_kind} ${binding.module_specifier}`,
      );
    }
    if (binding.binding_kind !== "exports") continue;
    for (const exported of bindings.explicitExports) {
      if (!generatedExportNames.has(exported.exportedName)) continue;
      const preservesCanonicalIdentity =
        exported.moduleSpecifier === binding.module_specifier &&
        exported.importedName === exported.exportedName;
      if (!preservesCanonicalIdentity) {
        failures.push(
          `${binding.consumer_path} must not explicitly override architecture-contract export ${exported.exportedName}; canonical source is ${binding.module_specifier}`,
        );
      }
    }
  }
  return failures;
}
