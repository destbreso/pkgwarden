import {
  mkdtempSync,
  rmSync,
  readdirSync,
  readFileSync,
  statSync,
  existsSync,
} from "node:fs";
import { join, extname, relative } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";
import { getEnabledRules } from "./rules/index.js";
import { RegistryClient } from "./registry-client.js";

const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
  ".json",
  ".sh",
  ".bash",
  ".cmd",
  ".bat",
  ".ps1",
]);

const MAX_FILE_SIZE = 1024 * 1024; // 1MB

export class Scanner {
  #config;
  #registry;
  #enabledRules;

  constructor(config) {
    this.#config = config;
    this.#registry = new RegistryClient(
      config.config.policies?.registryUrl,
    );
    this.#enabledRules = getEnabledRules(config);
  }

  async scanPackage(pkgName, version = "latest", { onProgress } = {}) {
    const findings = [];

    // 1. Check blocklist
    if (this.#config.isBlocked(pkgName)) {
      findings.push({
        rule: "blocklist",
        severity: "critical",
        title: `Package "${pkgName}" is in the blocklist`,
        description:
          "This package has been explicitly blocked in your pkgwarden configuration.",
        package: pkgName,
      });
      return { findings, metadata: null };
    }

    // 2. Check allowlist
    if (this.#config.isAllowed(pkgName)) {
      return { findings: [], metadata: null, skipped: true };
    }

    // 3. Fetch package metadata
    onProgress?.("Fetching package metadata...");
    const metadata = await this.#registry.getPackageVersion(pkgName, version);
    if (!metadata) {
      findings.push({
        rule: "registry",
        severity: "high",
        title: `Package "${pkgName}@${version}" not found in registry`,
        description:
          "The package does not exist in the configured registry. This could indicate a typosquat or private package confusion attack.",
        package: pkgName,
      });
      return { findings, metadata: null };
    }

    // 4. Run manifest checks
    onProgress?.("Analyzing package manifest...");
    for (const rule of this.#enabledRules) {
      const results = rule.checkManifest(metadata);
      findings.push(...results);
    }

    // 5. Check package metadata red flags
    const metaFindings = this.#checkMetadata(metadata, pkgName);
    findings.push(...metaFindings);

    // 6. Download and scan source code
    onProgress?.("Downloading package tarball...");
    const tmpDir = mkdtempSync(join(tmpdir(), "pkgwarden-"));

    try {
      const tarballUrl = metadata.dist?.tarball;
      if (tarballUrl) {
        onProgress?.("Extracting package...");
        await this.#downloadAndExtract(tarballUrl, tmpDir);

        onProgress?.("Scanning source code...");
        const files = this.#getScannableFiles(tmpDir);
        let scanned = 0;

        for (const filePath of files) {
          try {
            const content = readFileSync(filePath, "utf-8");
            const relPath = relative(tmpDir, filePath);

            for (const rule of this.#enabledRules) {
              const results = rule.checkSource(content, relPath, pkgName);
              findings.push(...results);
            }
          } catch {
            // Skip unreadable files
          }

          scanned++;
          if (scanned % 10 === 0) {
            onProgress?.(`Scanning files... (${scanned}/${files.length})`);
          }
        }
      }
    } finally {
      // Cleanup temp directory
      try {
        rmSync(tmpDir, { recursive: true, force: true });
      } catch {}
    }

    // Deduplicate findings
    const deduped = this.#deduplicateFindings(findings);

    return {
      findings: deduped,
      metadata: {
        name: metadata.name,
        version: metadata.version,
        description: metadata.description,
        author: metadata.author,
        license: metadata.license,
        dependencies: Object.keys(metadata.dependencies || {}),
        devDependencies: Object.keys(metadata.devDependencies || {}),
      },
    };
  }

  async scanDirectory(dirPath, { onProgress } = {}) {
    const findings = [];
    const files = this.#getScannableFiles(dirPath);
    let scanned = 0;

    for (const filePath of files) {
      try {
        const content = readFileSync(filePath, "utf-8");
        const relPath = relative(dirPath, filePath);
        const pkgName = this.#extractPkgName(relPath);

        for (const rule of this.#enabledRules) {
          const results = rule.checkSource(content, relPath, pkgName);
          findings.push(...results);
        }
      } catch {
        // Skip unreadable files
      }

      scanned++;
      if (scanned % 50 === 0) {
        onProgress?.(`Scanning... (${scanned}/${files.length})`);
      }
    }

    return {
      findings: this.#deduplicateFindings(findings),
      filesScanned: scanned,
    };
  }

  #checkMetadata(metadata, pkgName) {
    const findings = [];

    // Check for very new package with no downloads
    if (metadata._npmUser && !metadata.maintainers?.length) {
      findings.push({
        rule: "metadata",
        severity: "medium",
        title: "Package has no listed maintainers",
        description:
          "Packages without maintainer info may be less trustworthy.",
        package: pkgName,
      });
    }

    // Check for suspiciously high number of dependencies
    const depCount = Object.keys(metadata.dependencies || {}).length;
    if (depCount > 20) {
      findings.push({
        rule: "metadata",
        severity: "low",
        title: `Package has ${depCount} dependencies`,
        description: "Large dependency trees increase attack surface.",
        package: pkgName,
      });
    }

    // Check for missing license
    if (!metadata.license) {
      findings.push({
        rule: "metadata",
        severity: "low",
        title: "Package has no license",
        description:
          "Missing license information. Legitimate packages typically include a license.",
        package: pkgName,
      });
    }

    // Check for missing repository
    if (!metadata.repository) {
      findings.push({
        rule: "metadata",
        severity: "low",
        title: "Package has no repository link",
        description:
          "Missing source repository. This makes it harder to verify the package.",
        package: pkgName,
      });
    }

    return findings;
  }

  async #downloadAndExtract(tarballUrl, destDir) {
    const registry = new RegistryClient();
    const buffer = await registry.downloadTarball(tarballUrl);
    const tarPath = join(destDir, "package.tgz");

    const { writeFileSync } = await import("node:fs");
    writeFileSync(tarPath, buffer);

    try {
      execSync(`tar xzf "${tarPath}" -C "${destDir}" --strip-components=1`, {
        stdio: "ignore",
        timeout: 30000,
      });
    } catch {
      // Fallback: try without strip-components
      execSync(`tar xzf "${tarPath}" -C "${destDir}"`, {
        stdio: "ignore",
        timeout: 30000,
      });
    }
  }

  #getScannableFiles(dirPath) {
    const files = [];
    const ignorePatterns = this.#config.config.ignorePatterns || [];

    const walk = (dir) => {
      try {
        const entries = readdirSync(dir);
        for (const entry of entries) {
          const fullPath = join(dir, entry);
          const relPath = relative(dirPath, fullPath);

          // Skip ignored patterns
          if (ignorePatterns.some((p) => relPath.includes(p) || entry === p)) {
            continue;
          }

          try {
            const stat = statSync(fullPath);
            if (stat.isDirectory()) {
              walk(fullPath);
            } else if (stat.isFile() && stat.size < MAX_FILE_SIZE) {
              const ext = extname(entry);
              if (SCANNABLE_EXTENSIONS.has(ext) || entry === "package.json") {
                files.push(fullPath);
              }
            }
          } catch {
            // Skip inaccessible files
          }
        }
      } catch {
        // Skip inaccessible directories
      }
    };

    walk(dirPath);
    return files;
  }

  #extractPkgName(relPath) {
    const parts = relPath.split("/");
    if (parts[0] === "node_modules") {
      if (parts[1]?.startsWith("@")) {
        return `${parts[1]}/${parts[2]}`;
      }
      return parts[1];
    }
    return "unknown";
  }

  #deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter((f) => {
      const key = `${f.rule}|${f.title}|${f.file || ""}|${f.line || ""}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  static countBySeverity(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
    counts.total = findings.length;
    return counts;
  }
}
