import * as p from "@clack/prompts";
import pc from "picocolors";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { join, relative, extname } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";
import semver from "semver";
import { printBanner } from "../ui/banner.js";
import { icons, severityBadge, theme, divider, box } from "../ui/theme.js";
import { Reporter } from "../ui/reporter.js";
import { ConfigManager } from "../core/config-manager.js";
import { Scanner } from "../core/scanner.js";
import { RegistryClient } from "../core/registry-client.js";

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

const MAX_FILE_SIZE = 512 * 1024; // 512KB per file

/**
 * Attack patterns to detect in diffs — things that appear ONLY in new code.
 */
const DIFF_ATTACK_PATTERNS = [
  {
    id: "new-install-script",
    severity: "critical",
    title: "New install script added",
    test: (diff) => {
      const hooks = ["preinstall", "postinstall", "preuninstall", "install"];
      for (const hook of hooks) {
        if (
          diff.manifestChanges?.scripts?.added?.[hook] ||
          diff.manifestChanges?.scripts?.changed?.[hook]
        ) {
          return `"${hook}": "${diff.manifestChanges.scripts.added?.[hook] || diff.manifestChanges.scripts.changed?.[hook]?.to}"`;
        }
      }
      return null;
    },
  },
  {
    id: "new-dependency",
    severity: "medium",
    title: "New dependency introduced",
    test: (diff) => {
      const added = Object.keys(
        diff.manifestChanges?.dependencies?.added || {},
      );
      if (added.length > 0) return `Added: ${added.join(", ")}`;
      return null;
    },
  },
  {
    id: "many-new-dependencies",
    severity: "high",
    title: "Large number of new dependencies added",
    test: (diff) => {
      const added = Object.keys(
        diff.manifestChanges?.dependencies?.added || {},
      );
      if (added.length >= 5)
        return `${added.length} new deps: ${added.slice(0, 8).join(", ")}${added.length > 8 ? "..." : ""}`;
      return null;
    },
  },
  {
    id: "new-network-access",
    severity: "high",
    title: "New network/HTTP calls in added code",
    pattern:
      /\b(https?:\/\/[^\s'"]+|fetch\s*\(|http\.get|https\.get|net\.connect|XMLHttpRequest|\.open\s*\(\s*['"](?:GET|POST|PUT))/gi,
    fileOnly: true,
  },
  {
    id: "new-eval-exec",
    severity: "critical",
    title: "New eval/exec usage in added code",
    pattern:
      /\b(eval\s*\(|Function\s*\(|exec\s*\(|execSync\s*\(|spawn\s*\(|spawnSync\s*\(|child_process)/gi,
    fileOnly: true,
  },
  {
    id: "new-fs-write",
    severity: "high",
    title: "New filesystem write operations in added code",
    pattern:
      /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|fs\.write|fs\.rename|fs\.unlink|fs\.rm)\b/gi,
    fileOnly: true,
  },
  {
    id: "new-env-access",
    severity: "medium",
    title: "New environment variable access in added code",
    pattern: /process\.env\[?['"]\w+|process\.env\.\w+/gi,
    fileOnly: true,
  },
  {
    id: "new-base64-decode",
    severity: "high",
    title: "New Base64 decoding in added code",
    pattern: /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)|atob\s*\(/gi,
    fileOnly: true,
  },
  {
    id: "new-obfuscation",
    severity: "high",
    title: "Possible obfuscation in added code",
    pattern:
      /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|String\.fromCharCode|unescape\s*\(|decodeURIComponent\s*\(/gi,
    fileOnly: true,
  },
  {
    id: "new-data-exfil",
    severity: "critical",
    title: "Possible data exfiltration pattern in added code",
    pattern:
      /\b(dns\.resolve|dns\.lookup)\b.{0,100}(process\.env|os\.hostname|os\.userInfo|os\.homedir)|\.send\s*\(.{0,50}(process\.env|os\.hostname)/gis,
    fileOnly: true,
  },
  {
    id: "new-crypto-mining",
    severity: "critical",
    title: "Possible cryptominer reference in added code",
    pattern: /\b(stratum\+tcp|coinhive|cryptonight|monero|xmrig|minergate)\b/gi,
    fileOnly: true,
  },
  {
    id: "new-hidden-chars",
    severity: "high",
    title: "Hidden Unicode characters in added code",
    pattern: /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/g,
    fileOnly: true,
  },
  {
    id: "minified-replacement",
    severity: "medium",
    title: "Previously readable code replaced with minified version",
    test: (diff) => {
      let count = 0;
      for (const file of diff.changedFiles) {
        if (file.status !== "modified") continue;
        if (!SCANNABLE_EXTENSIONS.has(extname(file.path))) continue;
        // Heuristic: average line length in new file > 300 chars and old was < 100
        if (file.newContent) {
          const newLines = file.newContent.split("\n").filter((l) => l.trim());
          const oldLines = (file.oldContent || "")
            .split("\n")
            .filter((l) => l.trim());
          if (newLines.length > 0 && oldLines.length > 0) {
            const avgNew =
              newLines.reduce((s, l) => s + l.length, 0) / newLines.length;
            const avgOld =
              oldLines.reduce((s, l) => s + l.length, 0) / oldLines.length;
            if (avgNew > 300 && avgOld < 100) count++;
          }
        }
      }
      if (count > 0) return `${count} file(s) appear newly minified/obfuscated`;
      return null;
    },
  },
];

export async function diffCommand(packageName, options = {}) {
  const cwd = options.cwd || process.cwd();
  const isCI = options.ci || !!process.env.CI;
  const json = options.json || false;
  let targetVersion = options.target || null;

  printBanner(true);
  console.log();

  const config = new ConfigManager(cwd);
  const reporter = new Reporter({ ci: isCI });
  const registry = new RegistryClient();

  // ── Fetch all versions ────────────────────────────────────────
  const s = p.spinner();
  s.start(`Fetching version history for ${pc.cyan(packageName)}...`);

  const fullInfo = await registry.getPackageInfo(packageName);
  if (!fullInfo) {
    s.stop(`${icons.error} Package not found`);
    p.log.error(`Package "${packageName}" does not exist in the registry.`);
    return;
  }

  const allVersions = Object.keys(fullInfo.versions || {})
    .filter((v) => semver.valid(v))
    .sort(semver.compare);

  if (allVersions.length < 2) {
    s.stop(`${icons.warning} Not enough versions`);
    p.log.warn(
      `Package "${packageName}" has fewer than 2 versions — nothing to diff.`,
    );
    return;
  }

  s.stop(`Found ${pc.bold(String(allVersions.length))} versions`);

  // ── Resolve target version ────────────────────────────────────
  if (!targetVersion || targetVersion === "latest") {
    targetVersion =
      fullInfo["dist-tags"]?.latest || allVersions[allVersions.length - 1];
  }

  // Interactive version picker when not in CI and no version specified
  if (!options.target && !isCI) {
    const recentVersions = allVersions.slice(-20).reverse();
    const selected = await p.select({
      message: "Select the version to compare (vs its previous version)",
      options: recentVersions.map((v) => {
        const time = fullInfo.time?.[v];
        const dateStr = time ? new Date(time).toLocaleDateString() : "";
        const tag = Object.entries(fullInfo["dist-tags"] || {}).find(
          ([, ver]) => ver === v,
        );
        const hint = [dateStr, tag ? pc.cyan(`[${tag[0]}]`) : ""]
          .filter(Boolean)
          .join(" ");
        return { value: v, label: v, hint };
      }),
      initialValue: targetVersion,
    });

    if (p.isCancel(selected)) {
      p.outro(`${icons.shield} Cancelled.`);
      return;
    }
    targetVersion = selected;
  }

  // Find the previous version
  const targetIdx = allVersions.indexOf(targetVersion);
  if (targetIdx < 0) {
    p.log.error(
      `Version "${targetVersion}" not found. Available: ${allVersions.slice(-5).join(", ")}`,
    );
    return;
  }
  if (targetIdx === 0) {
    p.log.warn(
      `Version "${targetVersion}" is the first version — no previous version to compare.`,
    );
    return;
  }

  const prevVersion = allVersions[targetIdx - 1];

  console.log();
  p.intro(
    pc.bgCyan(
      pc.black(
        ` Diff: ${packageName}  ${pc.bold(prevVersion)} → ${pc.bold(targetVersion)} `,
      ),
    ),
  );

  // ── Show version metadata ─────────────────────────────────────
  const prevTime = fullInfo.time?.[prevVersion];
  const targetTime = fullInfo.time?.[targetVersion];
  const prevMeta = fullInfo.versions[prevVersion];
  const targetMeta = fullInfo.versions[targetVersion];

  console.log();
  p.note(
    [
      `${theme.muted("Previous:")}  ${pc.dim(prevVersion)} ${prevTime ? pc.dim(`(${new Date(prevTime).toLocaleDateString()})`) : ""}`,
      `${theme.muted("Current:")}   ${pc.cyan(targetVersion)} ${targetTime ? pc.dim(`(${new Date(targetTime).toLocaleDateString()})`) : ""}`,
      `${theme.muted("Publisher:")} ${targetMeta?._npmUser?.name || pc.dim("unknown")}`,
      `${theme.muted("License:")}   ${targetMeta?.license || fullInfo.license || pc.dim("none")}`,
    ].join("\n"),
    "Version Info",
  );

  // ── Download both versions ────────────────────────────────────
  const tmpPrev = mkdtempSync(join(tmpdir(), "pkgw-prev-"));
  const tmpTarget = mkdtempSync(join(tmpdir(), "pkgw-target-"));

  try {
    s.start(`Downloading ${packageName}@${prevVersion}...`);
    await downloadAndExtract(registry, prevMeta?.dist?.tarball, tmpPrev);
    s.stop(`Downloaded ${prevVersion}`);

    s.start(`Downloading ${packageName}@${targetVersion}...`);
    await downloadAndExtract(registry, targetMeta?.dist?.tarball, tmpTarget);
    s.stop(`Downloaded ${targetVersion}`);

    // ── Compute diff ──────────────────────────────────────────────
    s.start("Computing differences...");
    const diff = computeDiff(tmpPrev, tmpTarget, prevMeta, targetMeta);
    s.stop("Diff computed");

    // ── Display summary ─────────────────────────────────────────
    console.log();
    const statsLines = [
      `${pc.green(`+ ${diff.stats.added} added`)}  ${pc.red(`- ${diff.stats.removed} removed`)}  ${pc.yellow(`~ ${diff.stats.modified} modified`)}`,
      "",
      `${theme.muted("Total files:")}  ${pc.bold(String(diff.stats.totalNew))} (was ${diff.stats.totalOld})`,
      `${theme.muted("Added lines:")}  ${pc.green(`+${diff.stats.linesAdded}`)}`,
      `${theme.muted("Removed lines:")} ${pc.red(`-${diff.stats.linesRemoved}`)}`,
    ];
    console.log(box(statsLines.join("\n"), { title: "File Changes" }));

    // ── File change list ────────────────────────────────────────
    if (diff.changedFiles.length > 0) {
      console.log();
      p.log.info(`${icons.eye} Changed files:`);
      console.log();

      const maxShow = 30;
      const toShow = diff.changedFiles.slice(0, maxShow);

      for (const file of toShow) {
        const statusIcon =
          file.status === "added"
            ? pc.green("+ ")
            : file.status === "removed"
              ? pc.red("- ")
              : pc.yellow("~ ");
        const sizeInfo = file.sizeChange
          ? pc.dim(
              ` (${file.sizeChange > 0 ? "+" : ""}${formatBytes(file.sizeChange)})`,
            )
          : "";
        console.log(`    ${statusIcon}${file.path}${sizeInfo}`);
      }

      if (diff.changedFiles.length > maxShow) {
        console.log(
          pc.dim(
            `    ... and ${diff.changedFiles.length - maxShow} more files`,
          ),
        );
      }
    }

    // ── Manifest changes ────────────────────────────────────────
    displayManifestChanges(diff.manifestChanges, reporter);

    // ── Security scan on diffs ──────────────────────────────────
    console.log();
    s.start("Scanning differences for attack patterns...");
    const findings = scanDiffForThreats(diff, packageName);
    s.stop(
      findings.length === 0
        ? `${pc.green("✔")} No suspicious patterns detected in diff`
        : `${pc.yellow("⚠")} Found ${pc.bold(String(findings.length))} suspicious pattern(s)`,
    );

    if (findings.length > 0) {
      console.log();
      for (const f of findings) {
        reporter.finding(f);
      }

      const counts = Scanner.countBySeverity(findings);
      reporter.summary({
        ...counts,
        scanned: 1,
      });
    }

    // ── JSON output if requested ────────────────────────────────
    if (json) {
      console.log(
        JSON.stringify(
          {
            package: packageName,
            from: prevVersion,
            to: targetVersion,
            stats: diff.stats,
            files: diff.changedFiles.map((f) => ({
              path: f.path,
              status: f.status,
              sizeChange: f.sizeChange,
            })),
            manifestChanges: diff.manifestChanges,
            findings,
          },
          null,
          2,
        ),
      );
    }

    // ── Final verdict ───────────────────────────────────────────
    console.log();
    if (findings.length === 0) {
      p.outro(
        `${icons.success} Version ${pc.cyan(targetVersion)} looks clean compared to ${pc.dim(prevVersion)}.`,
      );
    } else {
      const hasCritical = findings.some((f) => f.severity === "critical");
      if (hasCritical) {
        p.outro(
          `${icons.fire} ${pc.red("CRITICAL")} patterns detected in version ${pc.cyan(targetVersion)}. Review carefully before updating.`,
        );
      } else {
        p.outro(
          `${icons.warning} Suspicious patterns found in ${pc.cyan(targetVersion)}. Review the findings above.`,
        );
      }
    }
  } finally {
    rmSync(tmpPrev, { recursive: true, force: true });
    rmSync(tmpTarget, { recursive: true, force: true });
  }
}

// ── Helpers ───────────────────────────────────────────────────────

async function downloadAndExtract(registry, tarballUrl, destDir) {
  if (!tarballUrl) throw new Error("No tarball URL available");
  const buffer = await registry.downloadTarball(tarballUrl, {
    maxSize: 30 * 1024 * 1024,
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
    execSync(`tar xzf "${tarPath}" -C "${destDir}"`, {
      stdio: "ignore",
      timeout: 30000,
    });
  }
}

function computeDiff(prevDir, targetDir, prevMeta, targetMeta) {
  const prevFiles = collectFiles(prevDir);
  const targetFiles = collectFiles(targetDir);

  const prevSet = new Map(prevFiles.map((f) => [f.relPath, f]));
  const targetSet = new Map(targetFiles.map((f) => [f.relPath, f]));

  const changedFiles = [];
  let linesAdded = 0;
  let linesRemoved = 0;

  // Added files (in target but not in prev)
  for (const [path, file] of targetSet) {
    if (!prevSet.has(path)) {
      const lines = countLines(file.fullPath);
      linesAdded += lines;
      changedFiles.push({
        path,
        status: "added",
        sizeChange: file.size,
        newContent: readSafe(file.fullPath),
      });
    }
  }

  // Removed files (in prev but not in target)
  for (const [path, file] of prevSet) {
    if (!targetSet.has(path)) {
      const lines = countLines(file.fullPath);
      linesRemoved += lines;
      changedFiles.push({
        path,
        status: "removed",
        sizeChange: -file.size,
        oldContent: readSafe(file.fullPath),
      });
    }
  }

  // Modified files (in both, different content)
  for (const [path, targetFile] of targetSet) {
    const prevFile = prevSet.get(path);
    if (!prevFile) continue;

    if (
      prevFile.size !== targetFile.size ||
      !filesEqual(prevFile.fullPath, targetFile.fullPath)
    ) {
      const oldContent = readSafe(prevFile.fullPath);
      const newContent = readSafe(targetFile.fullPath);

      const { added, removed } = diffLineCount(oldContent, newContent);
      linesAdded += added;
      linesRemoved += removed;

      changedFiles.push({
        path,
        status: "modified",
        sizeChange: targetFile.size - prevFile.size,
        oldContent,
        newContent,
      });
    }
  }

  // Sort: added first, then modified, then removed
  changedFiles.sort((a, b) => {
    const order = { added: 0, modified: 1, removed: 2 };
    return (order[a.status] ?? 3) - (order[b.status] ?? 3);
  });

  // Manifest diff
  const manifestChanges = diffManifest(prevMeta, targetMeta);

  return {
    stats: {
      added: changedFiles.filter((f) => f.status === "added").length,
      removed: changedFiles.filter((f) => f.status === "removed").length,
      modified: changedFiles.filter((f) => f.status === "modified").length,
      totalOld: prevFiles.length,
      totalNew: targetFiles.length,
      linesAdded,
      linesRemoved,
    },
    changedFiles,
    manifestChanges,
  };
}

function collectFiles(dir) {
  const results = [];
  const walk = (d) => {
    try {
      for (const entry of readdirSync(d)) {
        const full = join(d, entry);
        try {
          const stat = statSync(full);
          if (stat.isDirectory()) {
            if (entry !== "node_modules" && entry !== ".git") walk(full);
          } else if (stat.size <= MAX_FILE_SIZE) {
            results.push({
              fullPath: full,
              relPath: relative(dir, full),
              size: stat.size,
            });
          }
        } catch {}
      }
    } catch {}
  };
  walk(dir);
  return results;
}

function readSafe(filePath) {
  try {
    return readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

function filesEqual(a, b) {
  try {
    const bufA = readFileSync(a);
    const bufB = readFileSync(b);
    return bufA.equals(bufB);
  } catch {
    return false;
  }
}

function countLines(filePath) {
  try {
    const content = readFileSync(filePath, "utf-8");
    return content.split("\n").length;
  } catch {
    return 0;
  }
}

function diffLineCount(oldContent, newContent) {
  if (!oldContent || !newContent) {
    return {
      added: newContent ? newContent.split("\n").length : 0,
      removed: oldContent ? oldContent.split("\n").length : 0,
    };
  }

  const oldLines = new Set(oldContent.split("\n"));
  const newLines = newContent.split("\n");
  const newSet = new Set(newLines);

  let added = 0;
  let removed = 0;

  for (const line of newLines) {
    if (!oldLines.has(line)) added++;
  }
  for (const line of oldContent.split("\n")) {
    if (!newSet.has(line)) removed++;
  }

  return { added, removed };
}

function diffManifest(prevMeta, targetMeta) {
  const changes = {
    scripts: { added: {}, removed: {}, changed: {} },
    dependencies: { added: {}, removed: {}, changed: {} },
    devDependencies: { added: {}, removed: {}, changed: {} },
    other: [],
  };

  // Scripts diff
  const prevScripts = prevMeta?.scripts || {};
  const targetScripts = targetMeta?.scripts || {};
  for (const [key, val] of Object.entries(targetScripts)) {
    if (!(key in prevScripts)) changes.scripts.added[key] = val;
    else if (prevScripts[key] !== val)
      changes.scripts.changed[key] = { from: prevScripts[key], to: val };
  }
  for (const key of Object.keys(prevScripts)) {
    if (!(key in targetScripts))
      changes.scripts.removed[key] = prevScripts[key];
  }

  // Dependencies diff
  for (const depType of ["dependencies", "devDependencies"]) {
    const prev = prevMeta?.[depType] || {};
    const target = targetMeta?.[depType] || {};
    for (const [key, val] of Object.entries(target)) {
      if (!(key in prev)) changes[depType].added[key] = val;
      else if (prev[key] !== val)
        changes[depType].changed[key] = { from: prev[key], to: val };
    }
    for (const key of Object.keys(prev)) {
      if (!(key in target)) changes[depType].removed[key] = prev[key];
    }
  }

  // Key metadata fields
  const fields = ["main", "module", "types", "exports", "bin", "engines"];
  for (const field of fields) {
    const prev = JSON.stringify(prevMeta?.[field]);
    const target = JSON.stringify(targetMeta?.[field]);
    if (prev !== target) {
      changes.other.push({
        field,
        from: prevMeta?.[field],
        to: targetMeta?.[field],
      });
    }
  }

  return changes;
}

function displayManifestChanges(changes, reporter) {
  const sections = [];

  // Scripts
  const scriptEntries = [
    ...Object.entries(changes.scripts.added).map(([k, v]) =>
      pc.green(`  + "${k}": "${v}"`),
    ),
    ...Object.entries(changes.scripts.removed).map(([k, v]) =>
      pc.red(`  - "${k}": "${v}"`),
    ),
    ...Object.entries(changes.scripts.changed).map(
      ([k, v]) =>
        `  ${pc.red(`- "${k}": "${v.from}"`)}` +
        `\n  ${pc.green(`+ "${k}": "${v.to}"`)}`,
    ),
  ];
  if (scriptEntries.length > 0) {
    sections.push({ title: "Scripts", lines: scriptEntries });
  }

  // Dependencies
  for (const depType of ["dependencies", "devDependencies"]) {
    const entries = [
      ...Object.entries(changes[depType].added).map(([k, v]) =>
        pc.green(`  + ${k}: ${v}`),
      ),
      ...Object.entries(changes[depType].removed).map(([k, v]) =>
        pc.red(`  - ${k}: ${v}`),
      ),
      ...Object.entries(changes[depType].changed).map(
        ([k, v]) =>
          `  ${pc.yellow("~")} ${k}: ${pc.dim(v.from)} → ${pc.cyan(v.to)}`,
      ),
    ];
    if (entries.length > 0) {
      sections.push({ title: depType, lines: entries });
    }
  }

  // Other metadata
  if (changes.other.length > 0) {
    const lines = changes.other.map(
      (c) =>
        `  ${pc.yellow("~")} ${c.field}: ${pc.dim(JSON.stringify(c.from))} → ${pc.cyan(JSON.stringify(c.to))}`,
    );
    sections.push({ title: "Metadata", lines });
  }

  if (sections.length > 0) {
    console.log();
    p.log.info(`${icons.eye} Manifest changes:`);
    for (const section of sections) {
      console.log();
      console.log(`  ${theme.title(section.title)}`);
      for (const line of section.lines) {
        console.log(line);
      }
    }
  }
}

function scanDiffForThreats(diff, pkgName) {
  const findings = [];

  for (const pattern of DIFF_ATTACK_PATTERNS) {
    // Patterns that analyze the diff object directly
    if (pattern.test) {
      const evidence = pattern.test(diff);
      if (evidence) {
        findings.push({
          rule: "version-diff",
          severity: pattern.severity,
          title: pattern.title,
          description: `Detected in version diff analysis.`,
          package: pkgName,
          evidence,
        });
      }
      continue;
    }

    // Regex patterns that scan added/modified file content
    if (pattern.pattern && pattern.fileOnly) {
      for (const file of diff.changedFiles) {
        if (file.status === "removed") continue;

        const ext = extname(file.path);
        if (!SCANNABLE_EXTENSIONS.has(ext)) continue;

        // For added files, scan the whole content
        // For modified files, scan only content that wasn't in the old version
        let contentToScan = "";
        if (file.status === "added") {
          contentToScan = file.newContent || "";
        } else if (
          file.status === "modified" &&
          file.newContent &&
          file.oldContent
        ) {
          // Extract only new lines
          const oldLines = new Set(file.oldContent.split("\n"));
          contentToScan = file.newContent
            .split("\n")
            .filter((line) => !oldLines.has(line))
            .join("\n");
        }

        if (!contentToScan) continue;

        // Reset regex state
        pattern.pattern.lastIndex = 0;
        const matches = [...contentToScan.matchAll(pattern.pattern)];

        if (matches.length > 0) {
          const samples = matches
            .slice(0, 3)
            .map((m) => m[0].substring(0, 80))
            .join(", ");
          findings.push({
            rule: "version-diff",
            severity: pattern.severity,
            title: pattern.title,
            file: file.path,
            package: pkgName,
            evidence: `${matches.length} match(es): ${samples}${matches.length > 3 ? ` +${matches.length - 3} more` : ""}`,
            description: `Suspicious pattern found in ${file.status} code in ${file.path}.`,
          });
        }
      }
    }
  }

  // Deduplicate by pattern id + file
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.title}:${f.file || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatBytes(bytes) {
  const abs = Math.abs(bytes);
  if (abs < 1024) return `${bytes}B`;
  if (abs < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}
