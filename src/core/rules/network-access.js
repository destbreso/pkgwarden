const NETWORK_PATTERNS = [
  {
    pattern: /require\s*\(\s*['"]https?['"]\s*\)/g,
    severity: "medium",
    desc: "Imports HTTP/HTTPS module",
  },
  {
    pattern: /require\s*\(\s*['"]net['"]\s*\)/g,
    severity: "high",
    desc: "Imports net module (raw TCP)",
  },
  {
    pattern: /require\s*\(\s*['"]dgram['"]\s*\)/g,
    severity: "high",
    desc: "Imports dgram module (UDP)",
  },
  {
    pattern: /require\s*\(\s*['"]dns['"]\s*\)/g,
    severity: "medium",
    desc: "Imports dns module",
  },
  {
    pattern: /import\s.*from\s+['"]https?['"]/g,
    severity: "medium",
    desc: "Imports HTTP/HTTPS module (ESM)",
  },
  {
    pattern: /import\s.*from\s+['"]net['"]/g,
    severity: "high",
    desc: "Imports net module (ESM)",
  },
  {
    pattern: /fetch\s*\(/g,
    severity: "medium",
    desc: "Uses fetch() for network requests",
  },
  {
    pattern: /XMLHttpRequest/g,
    severity: "medium",
    desc: "Uses XMLHttpRequest",
  },
  {
    pattern: /\.request\s*\(\s*\{/g,
    severity: "medium",
    desc: "Makes HTTP request",
  },
  {
    pattern: /new\s+WebSocket\s*\(/g,
    severity: "high",
    desc: "Opens WebSocket connection",
  },
  {
    pattern: /axios|got\(|node-fetch|request\(/g,
    severity: "medium",
    desc: "Uses HTTP client library",
  },
];

const SUSPICIOUS_URLS = [
  {
    pattern: /pastebin\.com/gi,
    severity: "critical",
    desc: "References pastebin.com (common malware host)",
  },
  {
    pattern: /raw\.githubusercontent\.com/gi,
    severity: "high",
    desc: "Downloads from GitHub raw URLs",
  },
  {
    pattern: /discord(app)?\.com\/api\/webhooks/gi,
    severity: "critical",
    desc: "Discord webhook (data exfiltration)",
  },
  {
    pattern: /ngrok\.io/gi,
    severity: "critical",
    desc: "References ngrok tunnel",
  },
  {
    pattern: /burpcollaborator/gi,
    severity: "critical",
    desc: "References Burp Collaborator",
  },
  {
    pattern: /requestbin/gi,
    severity: "critical",
    desc: "References RequestBin",
  },
  { pattern: /pipedream/gi, severity: "high", desc: "References Pipedream" },
  {
    pattern: /webhook\.site/gi,
    severity: "critical",
    desc: "References webhook.site",
  },
  {
    pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
    severity: "high",
    desc: "Contains hardcoded IP address",
  },
];

export default {
  id: "network-access",
  name: "Network Access Detection",
  description:
    "Detects network access patterns that could indicate data exfiltration or C2 communication",

  checkManifest() {
    return [];
  },

  checkSource(content, filePath, pkgName) {
    const findings = [];

    for (const { pattern, severity, desc } of NETWORK_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split("\n").length;
        findings.push({
          rule: "network-access",
          severity,
          title: desc,
          description: `Network access detected in package source. This may indicate the package communicates with external servers.`,
          package: pkgName,
          file: filePath,
          line,
          snippet: getSnippet(content, match.index),
        });
      }
    }

    for (const { pattern, severity, desc } of SUSPICIOUS_URLS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split("\n").length;
        findings.push({
          rule: "network-access",
          severity,
          title: desc,
          description: `Suspicious URL or domain found in package source.`,
          package: pkgName,
          file: filePath,
          line,
          snippet: getSnippet(content, match.index),
        });
      }
    }

    return findings;
  },
};

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
