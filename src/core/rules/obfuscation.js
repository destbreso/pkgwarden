const OBFUSCATION_PATTERNS = [
  {
    pattern:
      /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*,\s*['"]base64['"]\s*\)/g,
    severity: "critical",
    desc: "Decodes large base64 string (possible hidden payload)",
  },
  {
    pattern: /atob\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*\)/g,
    severity: "critical",
    desc: "Decodes base64 string with atob()",
  },
  {
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/g,
    severity: "high",
    desc: "Contains hex-escaped string sequence",
  },
  {
    pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}/g,
    severity: "high",
    desc: "Contains unicode-escaped string sequence",
  },
  {
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,?\s*){5,}\)/g,
    severity: "critical",
    desc: "Builds string from char codes (obfuscation)",
  },
  {
    pattern: /\['\\x[0-9a-fA-F]+'\]/g,
    severity: "high",
    desc: "Uses hex-encoded property access",
  },
  {
    pattern: /(?:var|let|const)\s+[_$]{2,}\s*=/g,
    severity: "medium",
    desc: "Uses obfuscated variable names (_ or $)",
  },
  {
    pattern: /\[['"]\\x/g,
    severity: "high",
    desc: "Hex-encoded property accessor",
  },
  {
    pattern: /(?:0x[0-9a-f]+\s*[+\-*^|&]\s*){3,}/g,
    severity: "high",
    desc: "Complex hex arithmetic (possible deobfuscation routine)",
  },
];

const ENTROPY_THRESHOLD = 4.5;

export default {
  id: "obfuscation",
  name: "Code Obfuscation Detection",
  description:
    "Detects obfuscated code, encoded payloads, and suspicious string encoding patterns",

  checkManifest() {
    return [];
  },

  checkSource(content, filePath, pkgName) {
    const findings = [];

    // Pattern matching
    for (const { pattern, severity, desc } of OBFUSCATION_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split("\n").length;
        const matched = match[0];
        const sample =
          matched.length > 120
            ? matched.substring(0, 60) +
              " ⟨…⟩ " +
              matched.substring(matched.length - 40)
            : matched;
        findings.push({
          rule: "obfuscation",
          severity,
          title: desc,
          description:
            "Obfuscated code detected. Legitimate packages rarely use heavy encoding/obfuscation.",
          package: pkgName,
          file: filePath,
          line,
          snippet: getSnippet(content, match.index),
          evidence: sample,
        });
      }
    }

    // Entropy analysis on long strings
    const stringLiterals = content.matchAll(/['"`]([^'"`]{100,})['"`]/g);
    for (const strMatch of stringLiterals) {
      const full = strMatch[0];
      const inner = strMatch[1];
      const entropy = calculateEntropy(inner);
      if (entropy > ENTROPY_THRESHOLD) {
        const line = content.substring(0, strMatch.index).split("\n").length;
        // Build a readable sample: first 60 chars + last 40 chars
        const sampleLen = inner.length;
        let sample;
        if (sampleLen > 120) {
          sample =
            inner.substring(0, 60) +
            ` ⟨…${sampleLen - 100} more chars…⟩ ` +
            inner.substring(sampleLen - 40);
        } else {
          sample = inner;
        }
        findings.push({
          rule: "obfuscation",
          severity: "high",
          title: `High-entropy string (${entropy.toFixed(2)} bits/char, ${sampleLen} chars)`,
          description: `Entropy ${entropy.toFixed(2)} exceeds threshold ${ENTROPY_THRESHOLD}. High entropy suggests encoded, compressed, or obfuscated content.`,
          package: pkgName,
          file: filePath,
          line,
          snippet: getSnippet(content, strMatch.index),
          evidence: sample,
        });
      }
    }

    return findings;
  },
};

function calculateEntropy(str) {
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function getSnippet(content, index, contextLines = 1) {
  const lines = content.split("\n");
  let charCount = 0;
  let targetLine = 0;
  for (let i = 0; i < lines.length; i++) {
    charCount += lines[i].length + 1;
    if (charCount > index) {
      targetLine = i;
      break;
    }
  }
  const start = Math.max(0, targetLine - contextLines);
  const end = Math.min(lines.length - 1, targetLine + contextLines);
  return lines.slice(start, end + 1).join("\n");
}
