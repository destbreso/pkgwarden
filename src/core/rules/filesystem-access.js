const SENSITIVE_PATHS = [
  {
    pattern: /['"]\.env['"]/g,
    severity: "critical",
    desc: "Accesses .env file (secrets)",
  },
  {
    pattern: /['"]\.ssh/g,
    severity: "critical",
    desc: "Accesses .ssh directory",
  },
  {
    pattern: /['"]\.npmrc['"]/g,
    severity: "critical",
    desc: "Accesses .npmrc (registry tokens)",
  },
  {
    pattern: /['"]\.gitconfig['"]/g,
    severity: "high",
    desc: "Accesses .gitconfig",
  },
  {
    pattern: /['"]\.bash_history['"]/g,
    severity: "critical",
    desc: "Accesses bash history",
  },
  {
    pattern: /['"]\.zsh_history['"]/g,
    severity: "critical",
    desc: "Accesses zsh history",
  },
  {
    pattern: /['"]\/etc\/passwd['"]/g,
    severity: "critical",
    desc: "Accesses /etc/passwd",
  },
  {
    pattern: /['"]\/etc\/shadow['"]/g,
    severity: "critical",
    desc: "Accesses /etc/shadow",
  },
  {
    pattern: /['"]~\/\.aws/g,
    severity: "critical",
    desc: "Accesses AWS credentials",
  },
  {
    pattern: /['"]~\/\.kube/g,
    severity: "critical",
    desc: "Accesses Kubernetes config",
  },
  {
    pattern: /['"]~\/\.docker/g,
    severity: "high",
    desc: "Accesses Docker config",
  },
  {
    pattern: /['"]~\/\.gnupg/g,
    severity: "critical",
    desc: "Accesses GnuPG keys",
  },
  {
    pattern: /credentials|\.pem|\.key|id_rsa|id_ed25519/g,
    severity: "high",
    desc: "References credential files",
  },
];

const FS_OPERATIONS = [
  {
    pattern: /readFileSync\s*\(\s*(?:process\.env\.HOME|os\.homedir)/g,
    severity: "high",
    desc: "Reads files from home directory",
  },
  {
    pattern: /writeFileSync\s*\(\s*['"]\/(?!tmp)/g,
    severity: "high",
    desc: "Writes outside tmp directory",
  },
  {
    pattern: /unlinkSync|rmSync|rmdirSync/g,
    severity: "medium",
    desc: "Deletes files/directories",
  },
  {
    pattern:
      /readdirSync\s*\(\s*(?:process\.env\.HOME|os\.homedir|['"]~|['"]\/home)/g,
    severity: "high",
    desc: "Lists home directory contents",
  },
  {
    pattern: /createReadStream\s*\(\s*(?:process\.env\.HOME|os\.homedir)/g,
    severity: "high",
    desc: "Streams files from home directory",
  },
];

export default {
  id: "filesystem-access",
  name: "Filesystem Access Detection",
  description: "Detects access to sensitive files and directories",

  checkManifest() {
    return [];
  },

  checkSource(content, filePath, pkgName) {
    const findings = [];

    for (const { pattern, severity, desc } of SENSITIVE_PATHS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split("\n").length;
        findings.push({
          rule: "filesystem-access",
          severity,
          title: desc,
          description:
            "Access to sensitive paths detected. This package may be trying to read credentials or secrets.",
          package: pkgName,
          file: filePath,
          line,
          snippet: getSnippet(content, match.index),
        });
      }
    }

    for (const { pattern, severity, desc } of FS_OPERATIONS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split("\n").length;
        findings.push({
          rule: "filesystem-access",
          severity,
          title: desc,
          description: "Suspicious filesystem operation detected.",
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
