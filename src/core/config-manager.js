import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

const DEFAULT_CONFIG = {
  severity: {
    threshold: "medium", // Block installs at this severity: low, medium, high, critical
    failCI: "high", // Fail CI at this severity
  },
  rules: {
    installScripts: true, // Check for suspicious install scripts
    networkAccess: true, // Detect network calls in package code
    filesystemAccess: true, // Detect sensitive fs operations
    codeExecution: true, // Detect eval, Function(), etc.
    obfuscation: true, // Detect obfuscated code
    dataExfiltration: true, // Detect data exfiltration patterns
    typosquatting: true, // Check for typosquatting
    deprecatedPackages: true, // Warn about deprecated packages
    unmaintained: true, // Warn about packages not updated in 2+ years
  },
  bestPractices: {
    enforceIgnoreScripts: true, // Set ignore-scripts=true in .npmrc
    enforceLockfile: true, // Require lockfile for installs
    enforceExactVersions: false, // Require exact versions (no ^ or ~)
    enforceEngineStrict: true, // Enforce engine-strict=true
    auditOnInstall: true, // Run npm audit as part of install
    registryUrl: "https://registry.npmjs.org/",
  },
  allowlist: [], // Packages that skip scanning
  blocklist: [], // Packages that are always blocked
  ignorePatterns: [
    // File patterns to ignore in scans
    "node_modules",
    ".git",
    "test",
    "__tests__",
    "*.test.js",
    "*.spec.js",
  ],
};

const CONFIG_FILENAMES = [
  ".pkgwarden.yml",
  ".pkgwarden.yaml",
  "pkgwarden.config.yml",
  "pkgwarden.config.yaml",
  ".hekate.yml",
  ".hekate.yaml",
  ".argus.yml",
  ".argus.yaml",
  "argus.config.yml",
  "argus.config.yaml",
];

export class ConfigManager {
  #config;
  #configPath;
  #cwd;

  constructor(cwd = process.cwd()) {
    this.#cwd = cwd;
    this.#configPath = null;
    this.#config = { ...DEFAULT_CONFIG };
    this.#load();
  }

  get config() {
    return this.#config;
  }

  get configPath() {
    return this.#configPath;
  }

  get exists() {
    return this.#configPath !== null;
  }

  #load() {
    for (const filename of CONFIG_FILENAMES) {
      const fullPath = join(this.#cwd, filename);
      if (existsSync(fullPath)) {
        try {
          const raw = readFileSync(fullPath, "utf-8");
          const parsed = parseYaml(raw);
          this.#config = this.#merge(DEFAULT_CONFIG, parsed || {});
          this.#configPath = fullPath;
          return;
        } catch {
          // Invalid config, use defaults
        }
      }
    }
  }

  #merge(defaults, overrides) {
    const result = { ...defaults };
    for (const [key, value] of Object.entries(overrides)) {
      if (
        value &&
        typeof value === "object" &&
        !Array.isArray(value) &&
        defaults[key]
      ) {
        result[key] = this.#merge(defaults[key], value);
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  toYaml() {
    const { stringify } = require("yaml");
    return stringify(this.#config);
  }

  generateConfigContent(overrides = {}) {
    const config = this.#merge(DEFAULT_CONFIG, overrides);
    return `# PKGWARDEN — Security Configuration
# Package Guardian With Auditing, Reporting & Detection
  # Local project policy for package auditing

# Severity thresholds
severity:
  threshold: ${config.severity.threshold}    # Block installs: low | medium | high | critical
  failCI: ${config.severity.failCI}          # Fail CI pipelines: low | medium | high | critical

# Detection rules
rules:
  installScripts: ${config.rules.installScripts}        # Detect suspicious install scripts (preinstall/postinstall)
  networkAccess: ${config.rules.networkAccess}           # Detect network calls (fetch, http.request, etc.)
  filesystemAccess: ${config.rules.filesystemAccess}     # Detect sensitive fs operations (.env, .ssh, etc.)
  codeExecution: ${config.rules.codeExecution}           # Detect eval(), new Function(), child_process
  obfuscation: ${config.rules.obfuscation}               # Detect obfuscated/encoded code
  dataExfiltration: ${config.rules.dataExfiltration}     # Detect data exfiltration patterns
  typosquatting: ${config.rules.typosquatting}           # Check for typosquat similarities
  deprecatedPackages: ${config.rules.deprecatedPackages} # Warn about deprecated packages
  unmaintained: ${config.rules.unmaintained}             # Warn about stale packages (2+ years)

# Best practice enforcement
bestPractices:
  enforceIgnoreScripts: ${config.bestPractices.enforceIgnoreScripts}   # Set ignore-scripts in .npmrc
  enforceLockfile: ${config.bestPractices.enforceLockfile}             # Require lockfile present
  enforceExactVersions: ${config.bestPractices.enforceExactVersions}   # No ^ or ~ in versions
  enforceEngineStrict: ${config.bestPractices.enforceEngineStrict}     # engine-strict=true
  auditOnInstall: ${config.bestPractices.auditOnInstall}               # Run audit during install
  registryUrl: ${config.bestPractices.registryUrl}

# Package allowlist (skip scanning for these)
allowlist: ${config.allowlist.length === 0 ? "[]" : ""}
${config.allowlist.map((p) => `  - ${p}`).join("\n")}

# Package blocklist (always block these)
blocklist: ${config.blocklist.length === 0 ? "[]" : ""}
${config.blocklist.map((p) => `  - ${p}`).join("\n")}

# File patterns to ignore during scans
ignorePatterns:
${config.ignorePatterns.map((p) => `  - "${p}"`).join("\n")}
`;
  }

  static getDefaultConfig() {
    return { ...DEFAULT_CONFIG };
  }

  isAllowed(pkgName) {
    return this.#config.allowlist.includes(pkgName);
  }

  isBlocked(pkgName) {
    return this.#config.blocklist.includes(pkgName);
  }

  isRuleEnabled(rule) {
    return this.#config.rules[rule] !== false;
  }

  getSeverityLevel(severity) {
    const levels = { low: 1, medium: 2, high: 3, critical: 4 };
    return levels[severity] || 0;
  }

  meetsThreshold(severity) {
    const threshold = this.getSeverityLevel(this.#config.severity.threshold);
    return this.getSeverityLevel(severity) >= threshold;
  }

  meetsCIThreshold(severity) {
    const threshold = this.getSeverityLevel(this.#config.severity.failCI);
    return this.getSeverityLevel(severity) >= threshold;
  }
}
