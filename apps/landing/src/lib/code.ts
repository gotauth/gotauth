import type { ComponentProps } from "astro/types";
import type { Code } from "astro:components";

type CodeProps = ComponentProps<typeof Code>;
type Theme = Extract<NonNullable<CodeProps["theme"]>, object>;
type Transformer = NonNullable<CodeProps["transformers"]>[number];

// Shiki writes token colors into inline style attributes. A strict CSP would
// block those, and inline colors cannot follow the page's light/dark tokens.
// So the theme uses placeholder colors, and the transformer below swaps each
// one for a class that global.css colors with design tokens.
const TOKENS = {
  "#000001": "tk-comment",
  "#000002": "tk-keyword",
  "#000003": "tk-string",
  "#000004": "tk-function",
  "#000005": "tk-constant",
  "#000006": "tk-type",
  "#000007": "tk-plain",
} as const;

export const codeTheme = {
  name: "gotauth-tokens",
  type: "dark",
  fg: "#000007",
  bg: "#000000",
  settings: [
    { settings: { foreground: "#000007", background: "#000000" } },
    { scope: ["comment", "punctuation.definition.comment"], settings: { foreground: "#000001" } },
    {
      scope: [
        "keyword",
        "storage.type",
        "storage.modifier",
        "keyword.operator.logical",
        "keyword.operator.new",
        "variable.language",
      ],
      settings: { foreground: "#000002" },
    },
    { scope: ["string", "punctuation.definition.string"], settings: { foreground: "#000003" } },
    {
      scope: [
        "entity.name.function",
        "support.function",
        "meta.function-call.generic",
        "entity.name.function.decorator",
        "meta.function.decorator",
        "punctuation.definition.decorator",
      ],
      settings: { foreground: "#000004" },
    },
    {
      scope: ["constant.language", "constant.numeric", "support.constant", "constant.character.escape"],
      settings: { foreground: "#000005" },
    },
    {
      scope: ["entity.name.type", "entity.name.class", "support.type", "support.class"],
      settings: { foreground: "#000006" },
    },
    { scope: ["keyword.operator", "punctuation", "variable.parameter"], settings: { foreground: "#000007" } },
  ],
} satisfies Theme;

export const tokenClasses: Transformer = {
  name: "gotauth:token-classes",
  pre(node) {
    delete node.properties.style;
  },
  span(node) {
    const style = node.properties.style;
    if (typeof style !== "string") return;
    delete node.properties.style;
    const match = /color:\s*(#[0-9a-f]{6})/i.exec(style);
    const color = match?.[1]?.toLowerCase();
    const className = color && color in TOKENS ? TOKENS[color as keyof typeof TOKENS] : TOKENS["#000007"];
    this.addClassToHast(node, className);
  },
};
