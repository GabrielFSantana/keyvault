import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "src-tauri", "node_modules", "tools", "e2e/node_modules"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.strictTypeChecked],
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: { project: ["./tsconfig.app.json"], tsconfigRootDir: import.meta.dirname },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // Regras de segurança do frontend (KEYVAULT.md §4 e §8).
      "no-restricted-properties": [
        "error",
        {
          object: "window",
          property: "localStorage",
          message: "Proibido: armazenamento persistente do navegador.",
        },
        { object: "window", property: "sessionStorage", message: "Proibido: armazenamento do navegador." },
        { object: "window", property: "indexedDB", message: "Proibido: armazenamento do navegador." },
        { object: "navigator", property: "clipboard", message: "Clipboard somente via Rust." },
        { object: "navigator", property: "serviceWorker", message: "Proibido: service workers." },
      ],
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "Proibido." },
        { name: "sessionStorage", message: "Proibido." },
        { name: "indexedDB", message: "Proibido." },
        { name: "fetch", message: "Sem rede no aplicativo." },
        { name: "XMLHttpRequest", message: "Sem rede no aplicativo." },
        { name: "WebSocket", message: "Sem rede no aplicativo." },
        { name: "eval", message: "Proibido." },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Proibido renderizar HTML cru.",
        },
        {
          selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
          message: "Proibido renderizar HTML cru.",
        },
      ],
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { group: ["@tauri-apps/plugin-*"], message: "Plugins do Tauri não são usados no frontend." },
          ],
        },
      ],
    },
  },
  {
    files: ["src/**/*.test.{ts,tsx}", "src/test/**"],
    // Testes inspecionam innerHTML/storage de propósito e simulam erros IPC (objetos simples, como o Tauri).
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/require-await": "off",
      "@typescript-eslint/only-throw-error": "off",
      "@typescript-eslint/prefer-promise-reject-errors": "off",
      "@typescript-eslint/no-unnecessary-condition": "off",
      "no-restricted-syntax": "off",
      "no-restricted-properties": "off",
    },
  },
);
