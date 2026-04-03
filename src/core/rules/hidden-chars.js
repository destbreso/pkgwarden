/**
 * Hidden Characters Detection Rule
 *
 * Detects invisible/zero-width Unicode characters, bidirectional text overrides,
 * homoglyph attacks, and other invisible manipulation techniques commonly used
 * in supply chain attacks (Trojan Source).
 */

// Invisible / zero-width characters
const INVISIBLE_CHARS = [
  { char: "\u200B", name: "Zero-Width Space", code: "U+200B" },
  { char: "\u200C", name: "Zero-Width Non-Joiner", code: "U+200C" },
  { char: "\u200D", name: "Zero-Width Joiner", code: "U+200D" },
  { char: "\uFEFF", name: "Zero-Width No-Break Space (BOM)", code: "U+FEFF" },
  { char: "\u00AD", name: "Soft Hyphen", code: "U+00AD" },
  { char: "\u2060", name: "Word Joiner", code: "U+2060" },
  { char: "\u2061", name: "Function Application", code: "U+2061" },
  { char: "\u2062", name: "Invisible Times", code: "U+2062" },
  { char: "\u2063", name: "Invisible Separator", code: "U+2063" },
  { char: "\u2064", name: "Invisible Plus", code: "U+2064" },
  { char: "\u180E", name: "Mongolian Vowel Separator", code: "U+180E" },
];

// Bidirectional override characters (Trojan Source attack)
const BIDI_CHARS = [
  { char: "\u202A", name: "Left-to-Right Embedding", code: "U+202A" },
  { char: "\u202B", name: "Right-to-Left Embedding", code: "U+202B" },
  { char: "\u202C", name: "Pop Directional Formatting", code: "U+202C" },
  { char: "\u202D", name: "Left-to-Right Override", code: "U+202D" },
  { char: "\u202E", name: "Right-to-Left Override", code: "U+202E" },
  { char: "\u2066", name: "Left-to-Right Isolate", code: "U+2066" },
  { char: "\u2067", name: "Right-to-Left Isolate", code: "U+2067" },
  { char: "\u2068", name: "First Strong Isolate", code: "U+2068" },
  { char: "\u2069", name: "Pop Directional Isolate", code: "U+2069" },
  { char: "\u200F", name: "Right-to-Left Mark", code: "U+200F" },
  { char: "\u200E", name: "Left-to-Right Mark", code: "U+200E" },
];

// Confusable/homoglyph characters (look like ASCII but aren't)
const HOMOGLYPH_MAP = new Map([
  ["\u0410", { looks: "A", name: "Cyrillic А", code: "U+0410" }],
  ["\u0412", { looks: "B", name: "Cyrillic В", code: "U+0412" }],
  ["\u0421", { looks: "C", name: "Cyrillic С", code: "U+0421" }],
  ["\u0415", { looks: "E", name: "Cyrillic Е", code: "U+0415" }],
  ["\u041D", { looks: "H", name: "Cyrillic Н", code: "U+041D" }],
  ["\u041A", { looks: "K", name: "Cyrillic К", code: "U+041A" }],
  ["\u041C", { looks: "M", name: "Cyrillic М", code: "U+041C" }],
  ["\u041E", { looks: "O", name: "Cyrillic О", code: "U+041E" }],
  ["\u0420", { looks: "P", name: "Cyrillic Р", code: "U+0420" }],
  ["\u0422", { looks: "T", name: "Cyrillic Т", code: "U+0422" }],
  ["\u0425", { looks: "X", name: "Cyrillic Х", code: "U+0425" }],
  ["\u0430", { looks: "a", name: "Cyrillic а", code: "U+0430" }],
  ["\u0441", { looks: "c", name: "Cyrillic с", code: "U+0441" }],
  ["\u0435", { looks: "e", name: "Cyrillic е", code: "U+0435" }],
  ["\u043E", { looks: "o", name: "Cyrillic о", code: "U+043E" }],
  ["\u0440", { looks: "p", name: "Cyrillic р", code: "U+0440" }],
  ["\u0455", { looks: "s", name: "Cyrillic ѕ", code: "U+0455" }],
  ["\u0445", { looks: "x", name: "Cyrillic х", code: "U+0445" }],
  ["\u0443", { looks: "y", name: "Cyrillic у", code: "U+0443" }],
  ["\u0456", { looks: "i", name: "Cyrillic і", code: "U+0456" }],
  ["\u0458", { looks: "j", name: "Cyrillic ј", code: "U+0458" }],
  ["\u04BB", { looks: "h", name: "Cyrillic һ", code: "U+04BB" }],
  ["\u0261", { looks: "g", name: "Latin g", code: "U+0261" }],
  ["\uFF41", { looks: "a", name: "Fullwidth a", code: "U+FF41" }],
  ["\uFF4F", { looks: "o", name: "Fullwidth o", code: "U+FF4F" }],
]);

// Build regex patterns
const invisiblePattern = new RegExp(
  `[${INVISIBLE_CHARS.map((c) => c.char).join("")}]`,
  "g",
);
const bidiPattern = new RegExp(
  `[${BIDI_CHARS.map((c) => c.char).join("")}]`,
  "g",
);
const homoglyphChars = [...HOMOGLYPH_MAP.keys()].join("");
const homoglyphPattern = new RegExp(`[${homoglyphChars}]`, "g");

const INVISIBLE_LOOKUP = new Map(INVISIBLE_CHARS.map((c) => [c.char, c]));
const BIDI_LOOKUP = new Map(BIDI_CHARS.map((c) => [c.char, c]));

export default {
  id: "hidden-chars",
  name: "Hidden Characters Detection",
  description:
    "Detects invisible Unicode characters, bidirectional overrides (Trojan Source), and homoglyph attacks in source code.",
  severity: "critical",

  checkManifest(_pkg) {
    return [];
  },

  checkSource(content, filePath, _pkgName) {
    const findings = [];

    // 1. Invisible / zero-width characters
    const invisibleMatches = content.matchAll(invisiblePattern);
    for (const match of invisibleMatches) {
      const info = INVISIBLE_LOOKUP.get(match[0]);
      const line = getLineNumber(content, match.index);
      findings.push({
        rule: "hidden-chars",
        severity: "high",
        title: `Invisible character: ${info.name} (${info.code})`,
        description: `Found ${info.name} at line ${line}. This character is invisible and can hide malicious code or alter string behavior.`,
        file: filePath,
        line,
        evidence: getContext(content, match.index),
      });
    }

    // 2. Bidirectional override characters (Trojan Source)
    const bidiMatches = content.matchAll(bidiPattern);
    for (const match of bidiMatches) {
      const info = BIDI_LOOKUP.get(match[0]);
      const line = getLineNumber(content, match.index);
      findings.push({
        rule: "hidden-chars",
        severity: "critical",
        title: `Trojan Source: ${info.name} (${info.code})`,
        description: `Bidirectional text override at line ${line}. This can make code appear different from how it actually executes — a known supply chain attack vector (CVE-2021-42574).`,
        file: filePath,
        line,
        evidence: getContext(content, match.index),
      });
    }

    // 3. Homoglyph characters
    const homoglyphMatches = content.matchAll(homoglyphPattern);
    for (const match of homoglyphMatches) {
      const info = HOMOGLYPH_MAP.get(match[0]);
      const line = getLineNumber(content, match.index);
      findings.push({
        rule: "hidden-chars",
        severity: "high",
        title: `Homoglyph: ${info.name} looks like "${info.looks}" (${info.code})`,
        description: `Character at line ${line} looks like ASCII "${info.looks}" but is actually ${info.name}. This can bypass string comparisons and hide malicious identifiers.`,
        file: filePath,
        line,
        evidence: getContext(content, match.index),
      });
    }

    return findings;
  },
};

function getLineNumber(content, index) {
  return content.substring(0, index).split("\n").length;
}

function getContext(content, index, radius = 40) {
  const start = Math.max(0, index - radius);
  const end = Math.min(content.length, index + radius);
  let context = content.substring(start, end).replace(/\n/g, "↵");
  // Replace the invisible char itself with a visible marker
  return context;
}
