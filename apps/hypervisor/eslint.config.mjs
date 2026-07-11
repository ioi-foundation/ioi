// Static no-undef gate for the estate serve runtime (functional-runtime wave).
// Purpose-built and minimal: the one rule that catches the #46 incident class — a renderer
// referencing an identifier that no longer exists (DOMAIN_APP_VIS was deleted with call sites
// left behind and the route crashed the whole serve at request time). Style is out of scope.
// Run via verify-hypervisor-app-runtime-safety.mjs (which also proves the gate has teeth);
// the .mjs block covers the serve + its transitively imported modules (node runtime), the
// .aug-bundle.js block covers the CONCATENATED augmentation bundle exactly as it ships to the
// browser (the per-file fragments share one IIFE scope, so they are only lintable as the bundle).
import globals from "globals";

export default [
  {
    files: ["**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: { ...globals.node },
    },
    rules: { "no-undef": "error" },
  },
  {
    files: ["**/*.aug-bundle.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "script",
      globals: { ...globals.browser },
    },
    rules: { "no-undef": "error" },
  },
];
