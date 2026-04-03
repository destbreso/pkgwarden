const CODE_EXEC_PATTERNS = [
  {
    pattern: /\beval\s*\(/g,
    severity: "critical",
    desc: "Uses eval() for dynamic code execution",
  },
  {
    pattern: /new\s+Function\s*\(/g,
    severity: "critical",
    desc: "Uses Function constructor for dynamic code execution",
  },
  {
    pattern: /Function\s*\(\s*['"]/g,
    severity: "critical",
    desc: "Uses Function() to create code from string",
  },
  {
    pattern: /require\s*\(\s*['"]child_process['"]\s*\)/g,
    severity: "high",
    desc: "Imports child_process module",
  },
  {
    pattern: /import\s.*from\s+['"]child_process['"]/g,
    severity: "high",
    desc: "Imports child_process (ESM)",
  },
  {
    pattern: /\bexecSync\s*\(/g,
    severity: "high",
    desc: "Executes synchronous shell command",
  },
  {
    pattern: /\bexec\s*\(\s*[`'"]/g,
    severity: "high",
    desc: "Executes shell command",
  },
  {
    pattern: /\bspawnSync\s*\(/g,
    severity: "medium",
    desc: "Spawns synchronous child process",
  },
  {
    pattern: /\bspawn\s*\(\s*[`'"]/g,
    severity: "medium",
    desc: "Spawns child process",
  },
  {
    pattern: /\bexecFile\s*\(/g,
    severity: "medium",
    desc: "Executes file as child process",
  },
  {
    pattern: /require\s*\(\s*['"]vm['"]\s*\)/g,
    severity: "high",
    desc: "Imports vm module (code sandbox escape)",
  },
  {
    pattern: /import\s.*from\s+['"]vm['"]/g,
    severity: "high",
    desc: "Imports vm module (ESM)",
  },
  {
    pattern: /vm\.runInNewContext|vm\.runInThisContext|vm\.createContext/g,
    severity: "critical",
    desc: "Executes code in VM context",
  },
  {
    pattern: /process\.binding\s*\(/g,
    severity: "critical",
    desc: "Uses process.binding (low-level access)",
  },
  {
    pattern: /require\s*\(\s*['"]worker_threads['"]\s*\)/g,
    severity: "low",
    desc: "Uses worker threads",
  },
];

export default {
  id: "code-execution",
  name: "Dynamic Code Execution",
  description:
    "Detects eval, Function constructor, child_process, and similar dynamic code execution patterns",

  checkManifest() {
    return [];
  },

  checkSource(content, filePath, pkgName) {
    const findings = [];

    for (const { pattern, severity, desc } of CODE_EXEC_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        // Skip if inside a comment
        const lineStart = content.lastIndexOf("\n", match.index) + 1;
        const lineContent = content.substring(lineStart, match.index);
        if (
          lineContent.trimStart().startsWith("//") ||
          lineContent.trimStart().startsWith("*")
        ) {
          continue;
        }

        const line = content.substring(0, match.index).split("\n").length;
        findings.push({
          rule: "code-execution",
          severity,
          title: desc,
          description:
            "Dynamic code execution detected. This can be used to run arbitrary code, potentially for malicious purposes.",
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
