import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import semver from "semver";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

// ─── Reference ──────────────────────────────────────────────────────────────
// All practices are based on:
// https://github.com/lirantal/npm-security-best-practices
// by Liran Tal — Apache 2.0
// https://yarnpkg.com/configuration/yarnrc

export const BEST_PRACTICES_GUIDE =
  "https://github.com/lirantal/npm-security-best-practices";

// ─── Harden levels ──────────────────────────────────────────────────────────

export const HARDEN_LEVELS = {
  minimal: {
    label: "Minimal",
    hint: "Critical & high only — the non-negotiables",
    severities: ["critical", "high"],
  },
  recommended: {
    label: "Recommended",
    hint: "Critical, high & medium — solid baseline (default)",
    severities: ["critical", "high", "medium"],
  },
  strict: {
    label: "Strict",
    hint: "All findings including low-impact settings",
    severities: ["critical", "high", "medium", "low"],
  },
};

export function severitiesForLevel(level) {
  return (
    HARDEN_LEVELS[level]?.severities ?? HARDEN_LEVELS.recommended.severities
  );
}

/**
 * RC Analyzer — Detects and evaluates security settings in package manager
 * configuration files (.npmrc, .yarnrc.yml, pnpm-workspace.yaml, bunfig.toml).
 *
 * Reference: https://github.com/lirantal/npm-security-best-practices
 */

// ─── npm — .npmrc ────────────────────────────────────────────────────────────
// These settings apply ONLY to npm. pnpm uses a different set.

const NPM_PRACTICES = [
  {
    key: "ignore-scripts",
    expected: "true",
    severity: "high",
    ref: "#1-disable-post-install-scripts",
    title: "ignore-scripts should be true",
    description:
      "Prevents automatic execution of preinstall/postinstall scripts — the #1 supply chain attack vector in npm.",
    fix: "ignore-scripts=true",
  },
  {
    key: "allow-git",
    expected: "none",
    severity: "high",
    ref: "#1-disable-post-install-scripts",
    title: "allow-git=none closes ignore-scripts bypass via git deps",
    description:
      "A git-based dep can ship its own .npmrc that re-enables lifecycle scripts, silently bypassing --ignore-scripts. Requires npm 11.10.0+.",
    fix: "allow-git=none",
  },
  {
    key: "min-release-age",
    expected: "3",
    severity: "medium",
    ref: "#2-install-with-cooldown",
    title: "min-release-age adds install cooldown (3 days recommended)",
    description:
      "Delays installs of freshly-published versions. Attackers rely on semver ranges to pull in malicious packages quickly — a cooldown gives the community time to react.",
    fix: "min-release-age=3",
    check: (val) =>
      Number.isInteger(parseInt(val, 10)) && parseInt(val, 10) >= 3,
  },
  {
    key: "package-lock",
    expected: "true",
    severity: "high",
    ref: "#5-use-npm-ci",
    title: "package-lock should be enabled",
    description:
      "The lockfile ensures deterministic installs. Disabling it opens the door to supply chain drift.",
    fix: "package-lock=true",
  },
  {
    key: "engine-strict",
    expected: "true",
    severity: "medium",
    ref: null,
    title: "engine-strict should be true",
    description:
      "Refuses to install packages that declare incompatible Node.js engines.",
    fix: "engine-strict=true",
  },
  {
    key: "save-exact",
    expected: "true",
    severity: "medium",
    ref: "#6-avoid-blind-npm-package-upgrades",
    title: "save-exact pins versions on install",
    description:
      "Prevents ^ or ~ ranges that could silently pull in unexpected updates.",
    fix: "save-exact=true",
  },
  {
    key: "audit",
    expected: "true",
    severity: "medium",
    ref: null,
    title: "audit should be enabled",
    description:
      "Runs npm audit automatically during install to surface known CVEs.",
    fix: "audit=true",
  },
  {
    key: "fund",
    expected: "false",
    severity: "low",
    ref: null,
    title: "fund messages should be disabled",
    description: "Reduces noise in CI logs. Has no security impact.",
    fix: "fund=false",
  },
  {
    key: "loglevel",
    expected: "warn",
    severity: "low",
    ref: null,
    title: "loglevel should be warn or higher",
    description: "Avoids leaking verbose information in CI logs.",
    fix: "loglevel=warn",
  },
  {
    key: "prefer-offline",
    expected: "true",
    severity: "low",
    ref: null,
    title: "prefer-offline reduces registry exposure",
    description:
      "Uses the local cache when available, reducing unnecessary network requests.",
    fix: "prefer-offline=true",
  },
];

// Dangerous npm .npmrc settings
const NPM_DANGEROUS = [
  {
    key: "registry",
    pattern: /^(?!https:\/\/registry\.npmjs\.org)/,
    severity: "high",
    title: "Non-default registry configured",
    description:
      "A non-standard registry could be a malicious redirect. Verify it is intentional.",
  },
  {
    key: "strict-ssl",
    bad: "false",
    severity: "critical",
    title: "SSL verification is DISABLED",
    description:
      "Disabling SSL allows man-in-the-middle attacks during package downloads.",
    fix: "strict-ssl=true",
  },
  {
    key: "//",
    isToken: true,
    severity: "critical",
    title: "Auth token hardcoded in .npmrc",
    description:
      "Hardcoded tokens get committed to git and can be extracted from builds. Use $NPM_TOKEN instead.",
    fix: "Use the NPM_TOKEN environment variable: //registry.npmjs.org/:_authToken=${NPM_TOKEN}",
  },
];

// ─── pnpm — .npmrc ───────────────────────────────────────────────────────────
// pnpm inherits a small subset of npm .npmrc keys. Most security settings
// for pnpm go in pnpm-workspace.yaml (see PNPM_WORKSPACE_PRACTICES below).

const PNPM_NPMRC_PRACTICES = [
  {
    key: "engine-strict",
    expected: "true",
    severity: "medium",
    ref: null,
    title: "engine-strict should be true",
    description:
      "Refuses to install packages that declare incompatible Node.js engines.",
    fix: "engine-strict=true",
  },
  {
    key: "save-exact",
    expected: "true",
    severity: "medium",
    ref: "#6-avoid-blind-npm-package-upgrades",
    title: "save-exact pins versions on install",
    description:
      "Prevents ^ or ~ ranges that could silently pull in unexpected updates.",
    fix: "save-exact=true",
  },
];

const PNPM_NPMRC_DANGEROUS = [
  {
    key: "strict-ssl",
    bad: "false",
    severity: "critical",
    title: "SSL verification is DISABLED",
    description:
      "Disabling SSL allows man-in-the-middle attacks during package downloads.",
    fix: "strict-ssl=true",
  },
  {
    key: "//",
    isToken: true,
    severity: "critical",
    title: "Auth token hardcoded in .npmrc",
    description:
      "Hardcoded tokens get committed to git and can be extracted from builds.",
    fix: "Use the NPM_TOKEN environment variable: //registry.npmjs.org/:_authToken=${NPM_TOKEN}",
  },
];

// ─── pnpm — pnpm-workspace.yaml ─────────────────────────────────────────────

const PNPM_WORKSPACE_PRACTICES = [
  {
    key: "strictDepBuilds",
    expected: true,
    severity: "high",
    ref: "#1-disable-post-install-scripts",
    title: "strictDepBuilds should be true",
    description:
      "Makes unreviewed lifecycle scripts a CI-blocking error. Any transitive dep trying to run a lifecycle script not in allowBuilds aborts the install. Requires pnpm 10.3+.",
    fix: "strictDepBuilds: true",
  },
  {
    key: "blockExoticSubdeps",
    expected: true,
    severity: "high",
    ref: "#4-prevent-npm-lockfile-injection",
    title: "blockExoticSubdeps should be true",
    description:
      "Prevents transitive deps from pulling code from git repos or raw tarball URLs. Only direct dependencies may use exotic sources. Requires pnpm 10.26+.",
    fix: "blockExoticSubdeps: true",
  },
  {
    key: "minimumReleaseAge",
    expected: 4320,
    severity: "medium",
    ref: "#2-install-with-cooldown",
    title: "minimumReleaseAge should be set (4320 min = 3 days recommended)",
    description:
      "Only installs package versions published at least N minutes ago. Protects against freshly-published malicious packages. Requires pnpm 10.16+.",
    fix: "minimumReleaseAge: 4320 # 3 days in minutes",
    check: (val) => typeof val === "number" && val > 0,
  },
  {
    key: "trustPolicy",
    expected: "no-downgrade",
    severity: "medium",
    ref: "#1-disable-post-install-scripts",
    title: 'trustPolicy should be "no-downgrade"',
    description:
      "Aborts install when a package's provenance/trust level has decreased vs a previously published version — early signal of account compromise. Requires pnpm 10.21+.",
    fix: "trustPolicy: no-downgrade",
  },
];

// ─── Yarn Berry — .yarnrc.yml ────────────────────────────────────────────────

const YARN_PRACTICES = [
  {
    key: "enableScripts",
    expected: false,
    severity: "high",
    ref: "#1-disable-post-install-scripts",
    title: "enableScripts should be false",
    description:
      "Prevents execution of lifecycle scripts during install. Equivalent to npm's ignore-scripts.",
    fix: "enableScripts: false",
  },
  {
    key: "enableStrictSsl",
    expected: true,
    severity: "critical",
    ref: null,
    title: "enableStrictSsl should be true",
    description:
      "Ensures SSL certificate validation for all registry connections.",
    fix: "enableStrictSsl: true",
  },
  {
    key: "checksumBehavior",
    expected: "throw",
    severity: "high",
    ref: "#4-prevent-npm-lockfile-injection",
    title: 'checksumBehavior should be "throw"',
    description:
      "Throws on checksum mismatch instead of updating silently. Prevents tampered packages from being installed.",
    fix: 'checksumBehavior: "throw"',
  },
  {
    key: "npmMinimalAgeGate",
    expected: "3d",
    severity: "medium",
    ref: "#2-install-with-cooldown",
    title: 'npmMinimalAgeGate should be set (e.g. "3d")',
    description:
      "Only considers package versions published at least 3 days ago. Reduces risk of installing compromised packages. Requires Yarn >=4.10.",
    fix: 'npmMinimalAgeGate: "3d"',
    check: (val) => typeof val === "string" && val.length > 0,
    minVersion: "4.10.0",
  },
  {
    key: "enableImmutableInstalls",
    expected: true,
    severity: "medium",
    ref: "#5-use-npm-ci",
    title: "enableImmutableInstalls should be true (CI)",
    description:
      "Prevents lockfile modifications during install. Equivalent to npm ci — essential for reproducible builds.",
    fix: "enableImmutableInstalls: true",
  },
  {
    key: "enableTelemetry",
    expected: false,
    severity: "low",
    ref: null,
    title: "enableTelemetry should be false",
    description: "Prevents sending usage data to Yarn servers.",
    fix: "enableTelemetry: false",
  },
];

const YARN_DANGEROUS = [
  {
    key: "unsafeHttpWhitelist",
    severity: "critical",
    title: "unsafeHttpWhitelist allows plain HTTP registries",
    description:
      "Plain HTTP connections are vulnerable to man-in-the-middle attacks. All registry traffic should use HTTPS.",
  },
  {
    key: "enableStrictSsl",
    bad: false,
    severity: "critical",
    title: "SSL verification is DISABLED",
    description: "Never disable SSL certificate validation.",
    fix: "enableStrictSsl: true",
  },
];

// ─── Bun — bunfig.toml ───────────────────────────────────────────────────────
// Bun disables lifecycle scripts by default and maintains its own allowlist.
// Settings live in bunfig.toml under [install].

const BUN_PRACTICES = [
  {
    section: "install",
    key: "lifecycleScripts",
    expected: false,
    severity: "high",
    ref: "#1-disable-post-install-scripts",
    title: "lifecycleScripts should be false in [install]",
    description:
      "Explicitly disables all lifecycle scripts. Bun disables them by default, but setting it explicitly prevents accidental re-enablement.",
    fix: "[install]\nlifecycleScripts = false",
  },
  {
    section: "install",
    key: "minimumReleaseAge",
    expected: 259200,
    severity: "medium",
    ref: "#2-install-with-cooldown",
    title: "minimumReleaseAge should be set (259200 s = 3 days) in [install]",
    description:
      "Only installs package versions published at least N seconds ago. Requires Bun 1.3+.",
    fix: "[install]\nminimumReleaseAge = 259200 # 3 days in seconds",
    check: (val) => typeof val === "number" && val > 0,
  },
];

// ─── Analyzer ───────────────────────────────────────────────────────────────

export class RcAnalyzer {
  #cwd;
  #pmName;
  #pmVersion;

  constructor(cwd, pmName, pmVersion = null) {
    this.#cwd = cwd;
    this.#pmName = pmName;
    this.#pmVersion = pmVersion;
  }

  /** Filter practices that require a minVersion the current PM doesn't meet */
  #compatible(practices) {
    if (!this.#pmVersion) return practices;
    const coerced = semver.coerce(this.#pmVersion);
    if (!coerced) return practices;
    return practices.filter(
      (bp) => !bp.minVersion || semver.gte(coerced, bp.minVersion),
    );
  }

  analyze() {
    switch (this.#pmName) {
      case "npm":
        return this.#analyzeNpmrc(NPM_PRACTICES, NPM_DANGEROUS, ".npmrc");
      case "pnpm":
        return this.#analyzeNpmrc(
          PNPM_NPMRC_PRACTICES,
          PNPM_NPMRC_DANGEROUS,
          ".npmrc",
        );
      case "yarn":
        return this.#analyzeYarnrc();
      case "bun":
        return this.#analyzeBun();
      default:
        return this.#analyzeNpmrc(NPM_PRACTICES, NPM_DANGEROUS, ".npmrc");
    }
  }

  getRecommendedSettings() {
    const toShape = (bp) => ({
      key: bp.key,
      value: bp.expected,
      fix: bp.fix,
      title: bp.title,
      ref: bp.ref ?? null,
    });
    switch (this.#pmName) {
      case "npm":
        return NPM_PRACTICES.map(toShape);
      case "pnpm":
        return PNPM_NPMRC_PRACTICES.map(toShape);
      case "yarn":
        return this.#compatible(YARN_PRACTICES).map(toShape);
      case "bun":
        return BUN_PRACTICES.map(toShape);
      default:
        return NPM_PRACTICES.map(toShape);
    }
  }

  getRcPath() {
    switch (this.#pmName) {
      case "npm":
      case "pnpm":
        return join(this.#cwd, ".npmrc");
      case "yarn":
        return join(this.#cwd, ".yarnrc.yml");
      case "bun":
        return join(this.#cwd, "bunfig.toml");
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
        return this.#applyNpmrc(selectedSettings, NPM_PRACTICES, ".npmrc");
      case "pnpm":
        return this.#applyNpmrc(
          selectedSettings,
          PNPM_NPMRC_PRACTICES,
          ".npmrc",
        );
      case "yarn":
        return this.#applyYarnrc(selectedSettings);
      case "bun":
        return this.#applyBun(selectedSettings);
      default:
        return this.#applyNpmrc(selectedSettings, NPM_PRACTICES, ".npmrc");
    }
  }

  analyzeWorkspace() {
    if (this.#pmName !== "pnpm") return null;
    return this.#analyzePnpmWorkspace();
  }

  applyWorkspace(selectedSettings = null) {
    if (this.#pmName !== "pnpm") return null;
    return this.#applyPnpmWorkspace(selectedSettings);
  }

  // ── Private: npmrc (shared by npm & pnpm) ─────────────────────────────────

  #applyNpmrc(selectedSettings, defaultPractices, filename) {
    const rcPath = join(this.#cwd, filename);
    let content = "";
    let parsed = {};

    if (existsSync(rcPath)) {
      content = readFileSync(rcPath, "utf-8");
      parsed = parseNpmrc(content);
    }

    const practices = selectedSettings || defaultPractices;
    const applied = [];

    for (const bp of practices) {
      const key = bp.key;
      const expected = bp.expected ?? bp.value;
      const alreadySet = bp.check
        ? bp.check(parsed[key])
        : parsed[key] === String(expected);
      if (alreadySet) continue;

      if (parsed[key] !== undefined) {
        const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        content = content.replace(
          new RegExp(`^${escapedKey}\\s*=.*$`, "m"),
          `${key}=${expected}`,
        );
      } else {
        if (!content.endsWith("\n") && content.length > 0) content += "\n";
        if (!content.includes("# pkgwarden")) {
          content +=
            "\n# pkgwarden — Security Best Practices\n# Ref: " +
            BEST_PRACTICES_GUIDE +
            "\n";
        }
        content += `${key}=${expected}\n`;
      }
      applied.push({ key, value: expected });
    }

    if (applied.length > 0) writeFileSync(rcPath, content, "utf-8");
    return { path: rcPath, applied };
  }

  #analyzeNpmrc(practices, dangerous, filename) {
    const results = { findings: [], settings: {}, exists: false, path: null };
    const rcPath = join(this.#cwd, filename);

    if (!existsSync(rcPath)) {
      results.findings.push({
        severity: "medium",
        title: `No ${filename} found`,
        description: `Create a ${filename} with security-hardened defaults.`,
        fix: "Run pkgwarden init to generate one.",
      });
      return results;
    }

    results.exists = true;
    results.path = rcPath;

    const content = readFileSync(rcPath, "utf-8");
    const parsed = parseNpmrc(content);
    results.settings = parsed;

    for (const bp of practices) {
      const val = parsed[bp.key];
      const passes = bp.check ? bp.check(val) : val === String(bp.expected);
      if (passes) {
        results.findings.push({
          severity: "info",
          title: `✔ ${bp.title}`,
          status: "pass",
          key: bp.key,
          ref: bp.ref,
        });
      } else if (val === undefined) {
        results.findings.push({
          severity: bp.severity,
          title: bp.title,
          description: bp.description,
          fix: bp.fix,
          status: "missing",
          key: bp.key,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
        });
      } else {
        results.findings.push({
          severity: bp.severity,
          title: `${bp.title} (current: ${val})`,
          description: bp.description,
          fix: bp.fix,
          status: "wrong",
          key: bp.key,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
        });
      }
    }

    for (const danger of dangerous) {
      if (danger.isToken) {
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

  // ── Private: .yarnrc.yml ──────────────────────────────────────────────────

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

    const practices = selectedSettings || this.#compatible(YARN_PRACTICES);
    const applied = [];

    for (const bp of practices) {
      const key = bp.key;
      const expected = bp.expected ?? bp.value;
      const alreadySet = bp.check
        ? bp.check(parsed[key])
        : parsed[key] === expected;
      if (alreadySet) continue;
      parsed[key] = expected;
      applied.push({ key, value: expected });
    }

    if (applied.length > 0)
      writeFileSync(rcPath, stringifyYaml(parsed), "utf-8");
    return { path: rcPath, applied };
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

    for (const bp of this.#compatible(YARN_PRACTICES)) {
      const val = parsed[bp.key];
      const passes = bp.check ? bp.check(val) : val === bp.expected;
      if (passes) {
        results.findings.push({
          severity: "info",
          title: `✔ ${bp.title}`,
          status: "pass",
          key: bp.key,
          ref: bp.ref,
        });
      } else if (val === undefined) {
        results.findings.push({
          severity: bp.severity,
          title: bp.title,
          description: bp.description,
          fix: bp.fix,
          status: "missing",
          key: bp.key,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
        });
      } else {
        results.findings.push({
          severity: bp.severity,
          title: `${bp.title} (current: ${val})`,
          description: bp.description,
          fix: bp.fix,
          status: "wrong",
          key: bp.key,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
        });
      }
    }

    for (const danger of YARN_DANGEROUS) {
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

  // ── Private: pnpm-workspace.yaml ─────────────────────────────────────────

  #analyzePnpmWorkspace() {
    const results = {
      findings: [],
      settings: {},
      exists: false,
      path: null,
      isWorkspace: true,
    };
    const wsPath = join(this.#cwd, "pnpm-workspace.yaml");

    if (!existsSync(wsPath)) {
      results.findings.push({
        severity: "medium",
        title: "No pnpm-workspace.yaml found",
        description:
          "pnpm security settings (strictDepBuilds, blockExoticSubdeps, trustPolicy, minimumReleaseAge) belong in pnpm-workspace.yaml.",
        fix: "Create pnpm-workspace.yaml with security hardening settings.",
        status: "missing",
      });
      return results;
    }

    results.exists = true;
    results.path = wsPath;

    const content = readFileSync(wsPath, "utf-8");
    let parsed = {};
    try {
      parsed = parseYaml(content) || {};
    } catch {
      results.findings.push({
        severity: "high",
        title: "Invalid pnpm-workspace.yaml",
        description: "The YAML file could not be parsed.",
        status: "danger",
      });
      return results;
    }

    results.settings = parsed;

    for (const bp of PNPM_WORKSPACE_PRACTICES) {
      const val = parsed[bp.key];
      const passes = bp.check ? bp.check(val) : val === bp.expected;
      if (passes) {
        results.findings.push({
          severity: "info",
          title: `✔ ${bp.title}`,
          status: "pass",
          key: bp.key,
          ref: bp.ref,
        });
      } else if (val === undefined) {
        results.findings.push({
          severity: bp.severity,
          title: bp.title,
          description: bp.description,
          fix: bp.fix,
          status: "missing",
          key: bp.key,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
        });
      } else {
        results.findings.push({
          severity: bp.severity,
          title: `${bp.title} (current: ${val})`,
          description: bp.description,
          fix: bp.fix,
          status: "wrong",
          key: bp.key,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
        });
      }
    }

    return results;
  }

  #applyPnpmWorkspace(selectedSettings) {
    const wsPath = join(this.#cwd, "pnpm-workspace.yaml");
    let parsed = {};

    if (existsSync(wsPath)) {
      const content = readFileSync(wsPath, "utf-8");
      try {
        parsed = parseYaml(content) || {};
      } catch {
        parsed = {};
      }
    }

    const practices = selectedSettings || PNPM_WORKSPACE_PRACTICES;
    const applied = [];

    for (const bp of practices) {
      const key = bp.key;
      const expected = bp.expected ?? bp.value;
      const alreadySet = bp.check
        ? bp.check(parsed[key])
        : parsed[key] === expected;
      if (alreadySet) continue;
      parsed[key] = expected;
      applied.push({ key, value: expected });
    }

    if (applied.length > 0)
      writeFileSync(wsPath, stringifyYaml(parsed), "utf-8");
    return { path: wsPath, applied };
  }

  // ── Private: bunfig.toml ─────────────────────────────────────────────────

  #analyzeBun() {
    const results = { findings: [], settings: {}, exists: false, path: null };
    const tomlPath = join(this.#cwd, "bunfig.toml");

    if (!existsSync(tomlPath)) {
      results.findings.push({
        severity: "medium",
        title: "No bunfig.toml found",
        description:
          "Create a bunfig.toml with security-hardened [install] defaults.",
        fix: "Run pkgwarden init to generate one.",
      });
      return results;
    }

    results.exists = true;
    results.path = tomlPath;

    const content = readFileSync(tomlPath, "utf-8");
    const parsed = parseBunfig(content);
    results.settings = parsed;

    for (const bp of BUN_PRACTICES) {
      const sectionData = parsed[bp.section] ?? {};
      const val = sectionData[bp.key];
      const passes = bp.check ? bp.check(val) : val === bp.expected;
      if (passes) {
        results.findings.push({
          severity: "info",
          title: `✔ ${bp.title}`,
          status: "pass",
          key: `${bp.section}.${bp.key}`,
          ref: bp.ref,
        });
      } else if (val === undefined) {
        results.findings.push({
          severity: bp.severity,
          title: bp.title,
          description: bp.description,
          fix: bp.fix,
          status: "missing",
          key: `${bp.section}.${bp.key}`,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
          _bunSection: bp.section,
          _bunKey: bp.key,
        });
      } else {
        results.findings.push({
          severity: bp.severity,
          title: `${bp.title} (current: ${val})`,
          description: bp.description,
          fix: bp.fix,
          status: "wrong",
          key: `${bp.section}.${bp.key}`,
          expected: bp.expected,
          check: bp.check,
          ref: bp.ref,
          _bunSection: bp.section,
          _bunKey: bp.key,
        });
      }
    }

    return results;
  }

  #applyBun(selectedSettings) {
    const tomlPath = join(this.#cwd, "bunfig.toml");
    let content = existsSync(tomlPath) ? readFileSync(tomlPath, "utf-8") : "";

    const practices = selectedSettings || BUN_PRACTICES;
    const applied = [];

    for (const bp of practices) {
      const section = bp._bunSection ?? bp.section;
      const key = bp._bunKey ?? bp.key;
      const expected = bp.expected ?? bp.value;
      const parsed = parseBunfig(content);
      const sectionData = parsed[section] ?? {};
      const alreadySet = bp.check
        ? bp.check(sectionData[key])
        : sectionData[key] === expected;
      if (alreadySet) continue;

      content = setBunfigValue(content, section, key, expected);
      applied.push({ key: `${section}.${key}`, value: expected });
    }

    if (applied.length > 0) writeFileSync(tomlPath, content, "utf-8");
    return { path: tomlPath, applied };
  }
}

function parseNpmrc(content) {
  const settings = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";"))
      continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx > 0) {
      const key = trimmed.substring(0, eqIdx).trim();
      const value = trimmed.substring(eqIdx + 1).trim();
      settings[key] = value;
    }
  }
  return settings;
}

/**
 * Minimal bunfig.toml parser — returns { [section]: { key: value } }.
 * Only handles flat key=value and [section] headers.
 */
function parseBunfig(content) {
  const result = {};
  let currentSection = "_root";
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      if (!result[currentSection]) result[currentSection] = {};
      continue;
    }
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx > 0) {
      const key = trimmed.substring(0, eqIdx).trim();
      const rawVal = trimmed.substring(eqIdx + 1).trim();
      let value = rawVal;
      if (rawVal === "true") value = true;
      else if (rawVal === "false") value = false;
      else if (/^-?\d+$/.test(rawVal)) value = parseInt(rawVal, 10);
      else if (/^-?\d+\.\d+$/.test(rawVal)) value = parseFloat(rawVal);
      if (!result[currentSection]) result[currentSection] = {};
      result[currentSection][key] = value;
    }
  }
  return result;
}

/**
 * Sets a value in bunfig.toml text content, creating the section if needed.
 */
function setBunfigValue(content, section, key, value) {
  const lines = content.split("\n");
  const sectionHeader = `[${section}]`;
  const sectionIdx = lines.findIndex((l) => l.trim() === sectionHeader);

  const tomlVal =
    typeof value === "boolean"
      ? String(value)
      : typeof value === "number"
        ? String(value)
        : `"${value}"`;
  const newLine = `${key} = ${tomlVal}`;

  if (sectionIdx === -1) {
    // Section doesn't exist — append it
    if (content.length > 0 && !content.endsWith("\n")) content += "\n";
    content += `\n${sectionHeader}\n${newLine}\n`;
    return content;
  }

  // Find if key already exists within the section
  let nextSectionIdx = lines.findIndex(
    (l, i) => i > sectionIdx && /^\[/.test(l.trim()),
  );
  if (nextSectionIdx === -1) nextSectionIdx = lines.length;

  const keyPattern = new RegExp(`^\\s*${key}\\s*=`);
  const existingKeyIdx = lines.findIndex(
    (l, i) => i > sectionIdx && i < nextSectionIdx && keyPattern.test(l),
  );

  if (existingKeyIdx !== -1) {
    lines[existingKeyIdx] = newLine;
  } else {
    // Insert after section header
    lines.splice(sectionIdx + 1, 0, newLine);
  }

  return lines.join("\n");
}
