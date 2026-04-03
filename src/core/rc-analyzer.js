import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

/**
 * RC Analyzer — Detects and evaluates security settings in package manager
 * configuration files (.npmrc, .yarnrc.yml, .pnpmrc).
 */

// ─── npm / pnpm (.npmrc) ────────────────────────────────────────────────────

const NPMRC_BEST_PRACTICES = [
  {
    key: "ignore-scripts",
    expected: "true",
    severity: "high",
    title: "ignore-scripts should be true",
    description:
      "Prevents automatic execution of preinstall/postinstall scripts, which is the #1 malware vector in npm.",
    fix: "ignore-scripts=true",
  },
  {
    key: "engine-strict",
    expected: "true",
    severity: "medium",
    title: "engine-strict should be true",
    description:
      "Prevents installing packages that declare incompatible engines.",
    fix: "engine-strict=true",
  },
  {
    key: "audit",
    expected: "true",
    severity: "medium",
    title: "audit should be enabled",
    description:
      "Runs npm audit automatically during install to catch known vulnerabilities.",
    fix: "audit=true",
  },
  {
    key: "fund",
    expected: "false",
    severity: "low",
    title: "fund messages should be disabled",
    description:
      "Reduces noise. Not a security risk, but keeps output clean for CI.",
    fix: "fund=false",
  },
  {
    key: "loglevel",
    expected: "warn",
    severity: "low",
    title: "loglevel should be warn or higher",
    description: "Avoids leaking verbose information in CI logs.",
    fix: "loglevel=warn",
  },
  {
    key: "package-lock",
    expected: "true",
    severity: "high",
    title: "package-lock should be enabled",
    description:
      "Lockfile ensures deterministic installs. Disabling it opens the door to supply chain drift.",
    fix: "package-lock=true",
  },
  {
    key: "prefer-offline",
    expected: "true",
    severity: "low",
    title: "prefer-offline reduces registry dependency",
    description:
      "Uses local cache when available instead of fetching from registry every time.",
    fix: "prefer-offline=true",
  },
  {
    key: "save-exact",
    expected: "true",
    severity: "medium",
    title: "save-exact pins versions on install",
    description:
      "Prevents ^ or ~ ranges that could pull in unexpected updates.",
    fix: "save-exact=true",
  },
];

// Dangerous settings that should NOT be present
const NPMRC_DANGEROUS = [
  {
    key: "registry",
    pattern: /^(?!https:\/\/registry\.npmjs\.org)/,
    severity: "high",
    title: "Non-default registry configured",
    description:
      "Using a non-standard registry. Verify this is your private registry and not a malicious redirect.",
  },
  {
    key: "strict-ssl",
    bad: "false",
    severity: "critical",
    title: "SSL verification is DISABLED",
    description:
      "Disabling SSL allows man-in-the-middle attacks. Never disable in production.",
    fix: "strict-ssl=true",
  },
  {
    key: "//",
    isToken: true,
    severity: "critical",
    title: "Auth token found in .npmrc",
    description:
      "Registry auth tokens should come from environment variables, not be hardcoded in .npmrc. Risk of token leak via git.",
    fix: "Use NPM_TOKEN env var instead",
  },
];

// ─── Yarn Berry (.yarnrc.yml) ───────────────────────────────────────────────

const YARNRC_BEST_PRACTICES = [
  {
    key: "enableScripts",
    expected: false,
    severity: "high",
    title: "enableScripts should be false",
    description: "Prevents execution of lifecycle scripts during install.",
    fix: "enableScripts: false",
  },
  {
    key: "enableStrictSsl",
    expected: true,
    severity: "critical",
    title: "enableStrictSsl should be true",
    description: "Ensures SSL certificate validation for registry connections.",
    fix: "enableStrictSsl: true",
  },
  {
    key: "enableTelemetry",
    expected: false,
    severity: "low",
    title: "enableTelemetry should be false",
    description: "Prevents sending usage data to Yarn servers.",
    fix: "enableTelemetry: false",
  },
  {
    key: "enableImmutableInstalls",
    expected: true,
    severity: "medium",
    title: "enableImmutableInstalls should be true (CI)",
    description:
      "Prevents lockfile modifications during install. Essential for CI.",
    fix: "enableImmutableInstalls: true",
  },
  {
    key: "checksumBehavior",
    expected: "throw",
    severity: "high",
    title: 'checksumBehavior should be "throw"',
    description:
      "Throws on checksum mismatch instead of updating silently. Prevents tampered packages.",
    fix: 'checksumBehavior: "throw"',
  },
];

const YARNRC_DANGEROUS = [
  {
    key: "unsafeHttpWhitelist",
    severity: "critical",
    title: "unsafeHttpWhitelist allows plain HTTP",
    description:
      "Allowing plain HTTP connections opens the door to MITM attacks.",
  },
  {
    key: "enableStrictSsl",
    bad: false,
    severity: "critical",
    title: "SSL verification is DISABLED",
    description: "Never disable SSL in production.",
    fix: "enableStrictSsl: true",
  },
];

// ─── Analyzer ───────────────────────────────────────────────────────────────

export class RcAnalyzer {
  #cwd;
  #pmName;

  constructor(cwd, pmName) {
    this.#cwd = cwd;
    this.#pmName = pmName;
  }

  analyze() {
    switch (this.#pmName) {
      case "npm":
      case "pnpm":
        return this.#analyzeNpmrc();
      case "yarn":
        return this.#analyzeYarnrc();
      default:
        return this.#analyzeNpmrc();
    }
  }

  getRecommendedSettings() {
    switch (this.#pmName) {
      case "npm":
      case "pnpm":
        return NPMRC_BEST_PRACTICES.map((bp) => ({
          key: bp.key,
          value: bp.expected,
          fix: bp.fix,
          title: bp.title,
        }));
      case "yarn":
        return YARNRC_BEST_PRACTICES.map((bp) => ({
          key: bp.key,
          value: bp.expected,
          fix: bp.fix,
          title: bp.title,
        }));
      default:
        return [];
    }
  }

  getRcPath() {
    switch (this.#pmName) {
      case "npm":
      case "pnpm":
        return join(this.#cwd, ".npmrc");
      case "yarn":
        return join(this.#cwd, ".yarnrc.yml");
      default:
        return join(this.#cwd, ".npmrc");
    }
  }

  get pmName() {
    return this.#pmName;
  }

  apply(selectedSettings = null) {
    switch (this.#pmName) {
      case "npm":
      case "pnpm":
        return this.#applyNpmrc(selectedSettings);
      case "yarn":
        return this.#applyYarnrc(selectedSettings);
      default:
        return this.#applyNpmrc(selectedSettings);
    }
  }

  #applyNpmrc(selectedSettings) {
    const rcPath = join(this.#cwd, ".npmrc");
    let content = "";
    let parsed = {};

    if (existsSync(rcPath)) {
      content = readFileSync(rcPath, "utf-8");
      parsed = parseNpmrc(content);
    }

    const practices = selectedSettings || NPMRC_BEST_PRACTICES;
    const applied = [];

    for (const bp of practices) {
      const key = bp.key;
      const expected = bp.expected ?? bp.value;
      if (parsed[key] === expected) continue;

      if (parsed[key] !== undefined) {
        // Replace existing value
        const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        content = content.replace(
          new RegExp(`^${escapedKey}\\s*=.*$`, "m"),
          `${key}=${expected}`,
        );
      } else {
        // Append new setting
        if (!content.endsWith("\n") && content.length > 0) content += "\n";
        if (!content.includes("# pkgwarden")) {
          content += "\n# pkgwarden — Security Best Practices\n";
        }
        content += `${key}=${expected}\n`;
      }
      applied.push({ key, value: expected });
    }

    if (applied.length > 0) {
      writeFileSync(rcPath, content, "utf-8");
    }

    return { path: rcPath, applied };
  }

  #applyYarnrc(selectedSettings) {
    const rcPath = join(this.#cwd, ".yarnrc.yml");
    let parsed = {};

    if (existsSync(rcPath)) {
      const content = readFileSync(rcPath, "utf-8");
      try {
        parsed = parseYaml(content) || {};
      } catch {
        parsed = {};
      }
    }

    const practices = selectedSettings || YARNRC_BEST_PRACTICES;
    const applied = [];

    for (const bp of practices) {
      const key = bp.key;
      const expected = bp.expected ?? bp.value;
      if (parsed[key] === expected) continue;

      parsed[key] = expected;
      applied.push({ key, value: expected });
    }

    if (applied.length > 0) {
      writeFileSync(rcPath, stringifyYaml(parsed), "utf-8");
    }

    return { path: rcPath, applied };
  }

  #analyzeNpmrc() {
    const results = { findings: [], settings: {}, exists: false, path: null };
    const rcPath = join(this.#cwd, ".npmrc");

    if (!existsSync(rcPath)) {
      results.findings.push({
        severity: "medium",
        title: "No .npmrc found",
        description: "Create a .npmrc with security-hardened defaults.",
        fix: "Run pkgwarden init to generate one.",
      });
      return results;
    }

    results.exists = true;
    results.path = rcPath;

    const content = readFileSync(rcPath, "utf-8");
    const parsed = parseNpmrc(content);
    results.settings = parsed;

    // Check best practices
    for (const bp of NPMRC_BEST_PRACTICES) {
      if (parsed[bp.key] === bp.expected) {
        results.findings.push({
          severity: "info",
          title: `✔ ${bp.title}`,
          status: "pass",
        });
      } else if (parsed[bp.key] === undefined) {
        results.findings.push({
          severity: bp.severity,
          title: bp.title,
          description: bp.description,
          fix: bp.fix,
          status: "missing",
        });
      } else {
        results.findings.push({
          severity: bp.severity,
          title: `${bp.title} (current: ${parsed[bp.key]})`,
          description: bp.description,
          fix: bp.fix,
          status: "wrong",
        });
      }
    }

    // Check dangerous settings
    for (const danger of NPMRC_DANGEROUS) {
      if (danger.isToken) {
        // Check for hardcoded tokens
        const hasToken = content.match(
          /\/\/[^:]+:_authToken\s*=\s*[^\s${}]+/gm,
        );
        if (hasToken) {
          results.findings.push({
            severity: danger.severity,
            title: danger.title,
            description: danger.description,
            fix: danger.fix,
            status: "danger",
          });
        }
      } else if (
        danger.bad !== undefined &&
        parsed[danger.key] === danger.bad
      ) {
        results.findings.push({
          severity: danger.severity,
          title: danger.title,
          description: danger.description,
          fix: danger.fix,
          status: "danger",
        });
      } else if (
        danger.pattern &&
        parsed[danger.key] &&
        danger.pattern.test(parsed[danger.key])
      ) {
        results.findings.push({
          severity: danger.severity,
          title: `${danger.title}: ${parsed[danger.key]}`,
          description: danger.description,
          status: "warning",
        });
      }
    }

    return results;
  }

  #analyzeYarnrc() {
    const results = { findings: [], settings: {}, exists: false, path: null };
    const rcPath = join(this.#cwd, ".yarnrc.yml");

    if (!existsSync(rcPath)) {
      results.findings.push({
        severity: "medium",
        title: "No .yarnrc.yml found",
        description: "Create a .yarnrc.yml with security-hardened defaults.",
        fix: "Run pkgwarden init to generate one.",
      });
      return results;
    }

    results.exists = true;
    results.path = rcPath;

    const content = readFileSync(rcPath, "utf-8");
    let parsed = {};
    try {
      parsed = parseYaml(content) || {};
    } catch {
      results.findings.push({
        severity: "high",
        title: "Invalid .yarnrc.yml",
        description: "The YAML file could not be parsed.",
        status: "danger",
      });
      return results;
    }

    results.settings = parsed;

    // Check best practices
    for (const bp of YARNRC_BEST_PRACTICES) {
      if (parsed[bp.key] === bp.expected) {
        results.findings.push({
          severity: "info",
          title: `✔ ${bp.title}`,
          status: "pass",
        });
      } else if (parsed[bp.key] === undefined) {
        results.findings.push({
          severity: bp.severity,
          title: bp.title,
          description: bp.description,
          fix: bp.fix,
          status: "missing",
        });
      } else {
        results.findings.push({
          severity: bp.severity,
          title: `${bp.title} (current: ${parsed[bp.key]})`,
          description: bp.description,
          fix: bp.fix,
          status: "wrong",
        });
      }
    }

    // Check dangerous settings
    for (const danger of YARNRC_DANGEROUS) {
      if (danger.bad !== undefined && parsed[danger.key] === danger.bad) {
        results.findings.push({
          severity: danger.severity,
          title: danger.title,
          description: danger.description,
          fix: danger.fix,
          status: "danger",
        });
      } else if (parsed[danger.key] !== undefined && danger.bad === undefined) {
        results.findings.push({
          severity: danger.severity,
          title: danger.title,
          description: danger.description,
          status: "warning",
        });
      }
    }

    return results;
  }
}

function parseNpmrc(content) {
  const settings = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx > 0) {
      const key = trimmed.substring(0, eqIdx).trim();
      const value = trimmed.substring(eqIdx + 1).trim();
      settings[key] = value;
    }
  }
  return settings;
}
