const ENV_HARVEST_PATTERNS = [
  {
    pattern:
      /process\.env(?!\s*\.\s*(?:NODE_ENV|PATH|HOME|PWD|SHELL|TERM|LANG|USER|LOGNAME|HOSTNAME|npm_\w+)\b)/g,
    severity: "medium",
    desc: "Accesses process.env (possible env harvesting)",
  },
  {
    pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)/g,
    severity: "critical",
    desc: "Serializes entire process.env (data exfiltration)",
  },
  {
    pattern: /Object\.(keys|values|entries)\s*\(\s*process\.env\s*\)/g,
    severity: "critical",
    desc: "Enumerates all environment variables",
  },
  {
    pattern:
      /process\.env\s*\[\s*['"](TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|API_KEY|PRIVATE)/gi,
    severity: "critical",
    desc: "Accesses sensitive environment variable",
  },
];

const EXFIL_PATTERNS = [
  {
    pattern:
      /fetch\s*\(\s*[`'"](https?:\/\/)[^'"]*[`'"]\s*,\s*\{[^}]*method\s*:\s*['"]POST/gs,
    severity: "critical",
    desc: "POSTs data to external URL",
  },
  {
    pattern: /\.post\s*\(\s*[`'"](https?:\/\/)/g,
    severity: "high",
    desc: "POSTs data using HTTP client",
  },
  {
    pattern: /dns\.resolve|dns\.lookup/g,
    severity: "high",
    desc: "DNS operations (possible DNS exfiltration)",
  },
  {
    pattern: /\.send\s*\(\s*(?:JSON\.stringify|Buffer\.from)/g,
    severity: "high",
    desc: "Sends serialized data through connection",
  },
  {
    pattern: /os\.hostname|os\.userInfo|os\.networkInterfaces|os\.platform/g,
    severity: "medium",
    desc: "Collects system information",
  },
  {
    pattern:
      /require\s*\(\s*['"]os['"]\s*\)(?:[\s\S]*?)(hostname|userInfo|networkInterfaces)/g,
    severity: "high",
    desc: "Imports os module and collects system info",
  },
];

export default {
  id: "data-exfiltration",
  name: "Data Exfiltration Detection",
  description:
    "Detects patterns that could indicate data collection and exfiltration",

  checkManifest() {
    return [];
  },

  checkSource(content, filePath, pkgName) {
    const findings = [];

    for (const { pattern, severity, desc } of [
      ...ENV_HARVEST_PATTERNS,
      ...EXFIL_PATTERNS,
    ]) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split("\n").length;
        findings.push({
          rule: "data-exfiltration",
          severity,
          title: desc,
          description:
            "Potential data collection or exfiltration pattern detected.",
          package: pkgName,
          file: filePath,
          line,
          snippet: getSnippet(content, match.index),
        });
      }
    }

    // Detect the combined pattern: collect env + send network request
    const hasEnvAccess = /process\.env/.test(content);
    const hasNetworkSend =
      /fetch|\.post|\.request|http\.request|https\.request/.test(content);
    if (hasEnvAccess && hasNetworkSend) {
      findings.push({
        rule: "data-exfiltration",
        severity: "critical",
        title: "Combined env access + network request (likely exfiltration)",
        description:
          "This file accesses environment variables AND makes network requests. This is a strong indicator of credential exfiltration.",
        package: pkgName,
        file: filePath,
      });
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
