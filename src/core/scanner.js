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
import typosquattingRule from "./rules/typosquatting.js";

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
const MAX_TARBALL_SIZE = 15 * 1024 * 1024; // 15MB — skip source scan for huge packages

export class Scanner {
  #config;
  #registry;
  #enabledRules;

  constructor(config) {
    this.#config = config;
    this.#registry = new RegistryClient(config.config.policies?.registryUrl);
    this.#enabledRules = getEnabledRules(config);
  }

  /**
   * Lightweight scan — metadata + manifest + registry intel only.
   * No tarball download, no source code scan, no transitive deps.
   * Used for bare install bulk scanning to avoid OOM.
   */
  async scanPackageLight(pkgName, version = "latest", { onProgress } = {}) {
    const findings = [];

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

    if (this.#config.isAllowed(pkgName)) {
      return { findings: [], metadata: null, skipped: true };
    }

    // Typosquatting (zero network)
    if (this.#config.isRuleEnabled("typosquatting")) {
      const typoFindings = typosquattingRule.analyzePackageName(pkgName);
      for (const f of typoFindings) f.package = f.package || pkgName;
      findings.push(...typoFindings);
    }

    // Fetch version metadata (small — single version doc)
    onProgress?.(`Fetching ${pkgName} metadata...`);
    const metadata = await this.#registry.getPackageVersion(pkgName, version);
    if (!metadata) {
      findings.push({
        rule: "registry",
        severity: "high",
        title: `Package "${pkgName}@${version}" not found in registry`,
        description: "The package does not exist in the configured registry.",
        package: pkgName,
      });
      return { findings, metadata: null };
    }

    // Manifest checks (install scripts detection — no download needed)
    for (const rule of this.#enabledRules) {
      const results = rule.checkManifest(metadata);
      findings.push(...results);
    }

    // Basic metadata red flags
    const metaFindings = this.#checkMetadata(metadata, pkgName);
    findings.push(...metaFindings);

    // Registry intelligence using ABBREVIATED metadata (low memory)
    onProgress?.(`Checking ${pkgName} registry intel...`);
    const registryFindings = await this.#checkRegistryIntelligenceLight(
      pkgName,
      version,
      metadata,
    );
    findings.push(...registryFindings);

    return {
      findings: this.#deduplicateFindings(findings),
      metadata: {
        name: metadata.name,
        version: metadata.version,
        description: metadata.description,
      },
    };
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

    // 3. Typosquatting analysis (before any download)
    if (this.#config.isRuleEnabled("typosquatting")) {
      onProgress?.("Checking for typosquatting...");
      const typoFindings = typosquattingRule.analyzePackageName(pkgName);
      for (const f of typoFindings) {
        f.package = f.package || pkgName;
      }
      findings.push(...typoFindings);
    }

    // 4. Fetch package metadata
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

    // 5. Registry intelligence — deep metadata analysis
    onProgress?.("Analyzing registry intelligence...");
    const registryFindings = await this.#checkRegistryIntelligence(
      pkgName,
      version,
      metadata,
    );
    findings.push(...registryFindings);

    // 6. Run manifest checks (install scripts, etc.)
    onProgress?.("Analyzing package manifest...");
    for (const rule of this.#enabledRules) {
      const results = rule.checkManifest(metadata);
      findings.push(...results);
    }

    // 7. Check package metadata red flags
    const metaFindings = this.#checkMetadata(metadata, pkgName);
    findings.push(...metaFindings);

    // 8. Download and scan source code
    onProgress?.("Downloading package tarball...");
    const tmpDir = mkdtempSync(join(tmpdir(), "pkgwarden-"));

    try {
      const tarballUrl = metadata.dist?.tarball;
      if (tarballUrl) {
        onProgress?.("Extracting package...");
        await this.#downloadAndExtract(tarballUrl, tmpDir);

        // 8a. Verify tarball integrity if shasum available
        if (metadata.dist?.shasum) {
          const integrityOk = await this.#verifyShasum(
            tmpDir,
            metadata.dist.shasum,
          );
          if (!integrityOk) {
            findings.push({
              rule: "integrity",
              severity: "critical",
              title: "Package tarball integrity check FAILED",
              description:
                "The downloaded tarball checksum does not match the registry value. This could indicate a tampered package.",
              package: pkgName,
            });
          }
        }

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

        // 9. Scan direct dependencies (1 level deep) for critical patterns
        const directDeps = Object.keys(metadata.dependencies || {});
        if (directDeps.length > 0 && directDeps.length <= 30) {
          onProgress?.(`Checking ${directDeps.length} direct dependencies...`);
          const depFindings = await this.#scanTransitiveDeps(directDeps);
          findings.push(...depFindings);
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

  async #checkRegistryIntelligence(pkgName, version, versionMeta) {
    const findings = [];

    try {
      // Fetch full package info (all versions, times, maintainers)
      const fullInfo = await this.#registry.getPackageInfo(pkgName);
      if (!fullInfo) return findings;

      const now = Date.now();
      const resolvedVersion =
        version === "latest"
          ? fullInfo["dist-tags"]?.latest || versionMeta.version
          : versionMeta.version;

      // 1. Publish age — flag very recently published versions
      const versionTime = fullInfo.time?.[resolvedVersion];
      if (versionTime) {
        const publishDate = new Date(versionTime);
        const ageDays = Math.floor(
          (now - publishDate.getTime()) / (24 * 60 * 60 * 1000),
        );

        if (ageDays < 1) {
          findings.push({
            rule: "registry-intel",
            severity: "high",
            title: `Version ${resolvedVersion} published TODAY`,
            description: `This version was published less than 24 hours ago. Very recently published versions have a higher risk of being malicious.`,
            package: pkgName,
            evidence: `Published: ${publishDate.toISOString()}`,
          });
        } else if (ageDays < 7) {
          findings.push({
            rule: "registry-intel",
            severity: "medium",
            title: `Version ${resolvedVersion} published ${ageDays} day(s) ago`,
            description: `This version is less than a week old. Exercise caution.`,
            package: pkgName,
            evidence: `Published: ${publishDate.toISOString().split("T")[0]}`,
          });
        }
      }

      // 2. Package creation age — brand new packages
      const createdTime = fullInfo.time?.created;
      if (createdTime) {
        const createdDate = new Date(createdTime);
        const createdAgeDays = Math.floor(
          (now - createdDate.getTime()) / (24 * 60 * 60 * 1000),
        );

        if (createdAgeDays < 7) {
          findings.push({
            rule: "registry-intel",
            severity: "high",
            title: `Package created ${createdAgeDays} day(s) ago`,
            description: `Brand new package with no track record. Very common pattern for malicious packages.`,
            package: pkgName,
            evidence: `Created: ${createdDate.toISOString().split("T")[0]}`,
          });
        } else if (createdAgeDays < 30) {
          findings.push({
            rule: "registry-intel",
            severity: "medium",
            title: `Package created ${createdAgeDays} day(s) ago`,
            description: `Relatively new package. Verify the publisher's reputation.`,
            package: pkgName,
          });
        }
      }

      // 3. Version count — single-version packages are riskier
      const versionCount = Object.keys(fullInfo.versions || {}).length;
      if (versionCount === 1) {
        findings.push({
          rule: "registry-intel",
          severity: "medium",
          title: "Package has only 1 published version",
          description:
            "Packages with a single version have no update history, which is common for throwaway attack packages.",
          package: pkgName,
        });
      }

      // 4. Rapid version publishing — many versions in a short time
      const versionTimes = Object.entries(fullInfo.time || {})
        .filter(([key]) => key !== "created" && key !== "modified")
        .map(([ver, time]) => ({ ver, time: new Date(time).getTime() }))
        .sort((a, b) => b.time - a.time)
        .slice(0, 10);

      if (versionTimes.length >= 5) {
        const newest = versionTimes[0].time;
        const fifth = versionTimes[4].time;
        const spanHours = (newest - fifth) / (1000 * 60 * 60);

        if (spanHours < 1) {
          findings.push({
            rule: "registry-intel",
            severity: "high",
            title: "Rapid version publishing detected",
            description: `5+ versions published within ${Math.round(spanHours * 60)} minutes. This pattern is common in malicious packages testing payloads.`,
            package: pkgName,
            evidence: `${versionTimes.length} recent versions in ${spanHours.toFixed(1)}h`,
          });
        }
      }

      // 5. Download count — low downloads with new version suspicious
      const downloads = await this.#registry.getDownloadCount(pkgName);
      if (downloads < 100 && versionCount > 1) {
        findings.push({
          rule: "registry-intel",
          severity: "low",
          title: `Very low download count: ${downloads}/week`,
          description:
            "Packages with very few downloads may not be widely vetted by the community.",
          package: pkgName,
          evidence: `Weekly downloads: ${downloads}`,
        });
      } else if (downloads === 0) {
        findings.push({
          rule: "registry-intel",
          severity: "medium",
          title: "Package has ZERO downloads",
          description:
            "A package with no downloads at all is highly unusual. Verify its legitimacy.",
          package: pkgName,
        });
      }

      // 6. Maintainer changes — if latest version has different publisher
      const latestMaintainers = fullInfo.maintainers || [];
      const publisher = versionMeta._npmUser;
      if (
        publisher &&
        latestMaintainers.length > 0 &&
        !latestMaintainers.some(
          (m) => m.name === publisher.name || m.email === publisher.email,
        )
      ) {
        findings.push({
          rule: "registry-intel",
          severity: "high",
          title: "Publisher is NOT a listed maintainer",
          description: `Version was published by "${publisher.name}" who is not in the maintainers list. This could indicate an account takeover.`,
          package: pkgName,
          evidence: `Publisher: ${publisher.name} | Maintainers: ${latestMaintainers.map((m) => m.name).join(", ")}`,
        });
      }
    } catch {
      // Non-blocking — registry intelligence is best-effort
    }

    return findings;
  }

  async #scanTransitiveDeps(depNames) {
    const findings = [];

    for (const dep of depNames) {
      try {
        // Quick metadata check only (no source download for transitives)
        const depMeta = await this.#registry.getPackageVersion(dep, "latest");
        if (!depMeta) continue;

        // Typosquatting on transitive deps
        if (this.#config.isRuleEnabled("typosquatting")) {
          const typoFindings = typosquattingRule.analyzePackageName(dep);
          for (const f of typoFindings) {
            f.title = `[transitive] ${f.title}`;
            f.description = `Transitive dependency "${dep}": ${f.description}`;
          }
          findings.push(...typoFindings);
        }

        // Check for install scripts in transitive deps (critical vector)
        const scripts = depMeta.scripts || {};
        const dangerousHooks = ["preinstall", "postinstall"];
        for (const hook of dangerousHooks) {
          if (scripts[hook]) {
            findings.push({
              rule: "transitive-dep",
              severity: "high",
              title: `[transitive] "${dep}" has ${hook} script`,
              description: `Transitive dependency "${dep}" defines a "${hook}" script: ${scripts[hook]}. This script will execute automatically.`,
              package: dep,
              evidence: `"${hook}": "${scripts[hook]}"`,
            });
          }
        }

        // Check if transitive dep is very new
        const fullDepInfo = await this.#registry.getPackageInfo(dep);
        if (fullDepInfo?.time?.created) {
          const ageDays = Math.floor(
            (Date.now() - new Date(fullDepInfo.time.created).getTime()) /
              (24 * 60 * 60 * 1000),
          );
          if (ageDays < 7) {
            findings.push({
              rule: "transitive-dep",
              severity: "high",
              title: `[transitive] "${dep}" created ${ageDays} day(s) ago`,
              description: `Transitive dependency "${dep}" is brand new. This is a common attack pattern — inject a new malicious sub-dependency.`,
              package: dep,
            });
          }
        }
      } catch {
        // Non-blocking per dep
      }
    }

    return findings;
  }

  async #verifyShasum(extractedDir, expectedShasum) {
    try {
      const tgzPath = join(extractedDir, "package.tgz");
      if (!existsSync(tgzPath)) return true; // Already extracted, can't verify
      const { createHash } = await import("node:crypto");
      const fileBuffer = readFileSync(tgzPath);
      const actualShasum = createHash("sha1").update(fileBuffer).digest("hex");
      return actualShasum === expectedShasum;
    } catch {
      return true; // Can't verify — don't block
    }
  }

  /**
   * Lightweight registry intelligence — uses abbreviated metadata
   * to avoid fetching the full (potentially 50MB+) package document.
   */
  async #checkRegistryIntelligenceLight(pkgName, version, versionMeta) {
    const findings = [];

    try {
      // Use abbreviated metadata — much smaller than full
      const abbrev = await this.#registry.getPackageInfoAbbreviated(pkgName);
      if (!abbrev) return findings;

      const now = Date.now();

      // Check version time if available in abbreviated response
      const modifiedTime = abbrev.modified;
      if (modifiedTime) {
        const modDate = new Date(modifiedTime);
        const ageDays = Math.floor(
          (now - modDate.getTime()) / (24 * 60 * 60 * 1000),
        );
        // If the whole package was very recently modified and has few versions
        const versionCount = Object.keys(abbrev.versions || {}).length;
        if (ageDays < 7 && versionCount <= 2) {
          findings.push({
            rule: "registry-intel",
            severity: "high",
            title: `Package modified ${ageDays} day(s) ago with only ${versionCount} version(s)`,
            description:
              "Very recently updated package with minimal history. Common pattern for attack packages.",
            package: pkgName,
          });
        }
      }

      // Maintainer check from version metadata (already fetched, no extra call)
      const publisher = versionMeta._npmUser;
      const maintainers = versionMeta.maintainers || [];
      if (
        publisher &&
        maintainers.length > 0 &&
        !maintainers.some(
          (m) => m.name === publisher.name || m.email === publisher.email,
        )
      ) {
        findings.push({
          rule: "registry-intel",
          severity: "high",
          title: "Publisher is NOT a listed maintainer",
          description: `Version was published by "${publisher.name}" who is not in the maintainers list.`,
          package: pkgName,
          evidence: `Publisher: ${publisher.name} | Maintainers: ${maintainers.map((m) => m.name).join(", ")}`,
        });
      }

      // Check downloads (small API call)
      const downloads = await this.#registry.getDownloadCount(pkgName);
      if (downloads === 0) {
        findings.push({
          rule: "registry-intel",
          severity: "medium",
          title: "Package has ZERO downloads",
          description: "A package with no downloads at all is highly unusual.",
          package: pkgName,
        });
      }
    } catch {
      // Best-effort
    }

    return findings;
  }

  async #downloadAndExtract(tarballUrl, destDir) {
    const registry = new RegistryClient();
    const buffer = await registry.downloadTarball(tarballUrl, {
      maxSize: MAX_TARBALL_SIZE,
    });
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
