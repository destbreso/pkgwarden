function assessScriptSeverity(script) {
  const criticalPatterns = [
    /curl\s/i,
    /wget\s/i,
    /node\s+-e/i,
    /eval/i,
    /bash\s+-c/i,
    /sh\s+-c/i,
    /powershell/i,
    /\|\s*sh/i,
    /\|\s*bash/i,
    /base64/i,
    /env\s+(PASSWORD|TOKEN|SECRET|KEY)/i,
  ];

  for (const pattern of criticalPatterns) {
    if (pattern.test(script)) return "critical";
  }

  const highPatterns = [/node\s/, /python/i, /ruby/i, /\.sh$/];

  for (const pattern of highPatterns) {
    if (pattern.test(script)) return "high";
  }

  return "medium";
}

export default {
  id: "install-scripts",
  name: "Suspicious Install Scripts",
  description:
    "Detects potentially dangerous preinstall/postinstall lifecycle scripts",

  checkManifest(pkg) {
    const findings = [];
    const scripts = pkg.scripts || {};
    const dangerousHooks = [
      "preinstall",
      "postinstall",
      "preuninstall",
      "postuninstall",
    ];

    for (const hook of dangerousHooks) {
      if (scripts[hook]) {
        const script = scripts[hook];
        const sev = assessScriptSeverity(script);

        findings.push({
          rule: "install-scripts",
          severity: sev,
          title: `Lifecycle script detected: ${hook}`,
          description: `Package defines a "${hook}" script that runs automatically during installation. This is a common malware vector.`,
          package: pkg.name,
          detail: { hook, script },
          snippet: `"${hook}": "${script}"`,
        });
      }
    }

    return findings;
  },

  checkSource() {
    return [];
  },
};
