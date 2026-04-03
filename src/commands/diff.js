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
      /\b(?:https?:\/\/(?!localhost\b)[^\s'"]{10,}|fetch\s*\(\s*[^)]*https?|http\.get\s*\(|https\.get\s*\(|http\.request\s*\(|https\.request\s*\(|net\.connect\s*\(|new\s+WebSocket\s*\(|\.open\s*\(\s*['"](?:GET|POST|PUT))/gi,
    fileOnly: true,
    skipMinified: true,
  },
  {
    id: "new-eval-exec",
    severity: "critical",
    title: "New eval/exec usage in added code",
    pattern:
      /\beval\s*\(|new\s+Function\s*\(|\bexecSync\s*\(|\bexec\s*\(\s*['"`]|\bspawn(?:Sync)?\s*\(\s*['"`]|\brequire\s*\(\s*['"]child_process['"]\)|\bimport\s.*['"]child_process['"]/gi,
    fileOnly: true,
    skipMinified: true,
  },
  {
    id: "new-fs-write",
    severity: "high",
    title: "New filesystem write operations in added code",
    pattern:
      /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|fs\.(?:write|rename|unlink|rm)(?:Sync)?)\s*\(/gi,
    fileOnly: true,
    skipMinified: true,
  },
  {
    id: "new-env-access",
    severity: "medium",
    title: "New environment variable access in added code",
    pattern:
      /process\.env\s*(?:\.\s*(?!NODE_ENV|PATH|HOME|PWD|SHELL|TERM|LANG|CI|DEBUG|VERBOSE|npm_)\w{3,}|\[\s*['"](?!NODE_ENV|PATH|HOME|PWD|SHELL|TERM|LANG|CI|DEBUG|VERBOSE|npm_)\w{3,})/gi,
    fileOnly: true,
    skipMinified: true,
  },
  {
    id: "new-base64-decode",
    severity: "high",
    title: "New Base64 decoding in added code",
    pattern:
      /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)|atob\s*\(\s*['"][A-Za-z0-9+/=]{20,}/gi,
    fileOnly: true,
  },
  {
    id: "new-obfuscation",
    severity: "high",
    title: "Possible obfuscation in added code",
    pattern:
      /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){2,}|\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){2,}|String\.fromCharCode\s*\(\s*(?:\d+\s*,?\s*){3,}\)|unescape\s*\(|decodeURIComponent\s*\(\s*['"]%/gi,
    fileOnly: true,
    skipMinified: true,
  },
  {
    id: "new-data-exfil",
    severity: "critical",
    title: "Possible data exfiltration pattern in added code",
    pattern:
      /\b(?:dns\.resolve|dns\.lookup)\b.{0,100}(?:process\.env|os\.hostname|os\.userInfo|os\.homedir)|\.send\s*\(.{0,50}(?:process\.env|os\.hostname)/gis,
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
  const showDiffFlag = options.showDiff || false;
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

    // ── Code-level diffs ────────────────────────────────────────
    let wantsDiff = showDiffFlag;
    if (!wantsDiff && !isCI && diff.changedFiles.length > 0) {
      const codeDiffFiles = diff.changedFiles.filter(
        (f) =>
          f.status !== "removed" && SCANNABLE_EXTENSIONS.has(extname(f.path)),
      );
      if (codeDiffFiles.length > 0) {
        console.log();
        const answer = await p.confirm({
          message: `View code-level diffs for ${codeDiffFiles.length} changed source file(s)?`,
          initialValue: false,
        });
        if (!p.isCancel(answer) && answer) wantsDiff = true;
      }
    }

    if (wantsDiff) {
      displayCodeDiffs(diff.changedFiles);
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

        // Skip minified files for patterns that generate too many false positives
        const isMinified =
          file.path.includes(".min.") || isLikelyMinified(file.newContent);
        if (pattern.skipMinified && isMinified) continue;

        // For added files, scan the whole content
        // For modified files, build a map of new lines with their real line numbers
        const newLineEntries = []; // { lineNum, text }
        if (file.status === "added" && file.newContent) {
          file.newContent.split("\n").forEach((text, i) => {
            newLineEntries.push({ lineNum: i + 1, text });
          });
        } else if (
          file.status === "modified" &&
          file.newContent &&
          file.oldContent
        ) {
          const oldLines = new Set(file.oldContent.split("\n"));
          file.newContent.split("\n").forEach((text, i) => {
            if (!oldLines.has(text)) {
              newLineEntries.push({ lineNum: i + 1, text });
            }
          });
        }

        if (newLineEntries.length === 0) continue;

        // Scan each new line individually to get accurate line numbers
        const matchesWithLines = [];
        for (const { lineNum, text } of newLineEntries) {
          const regex = new RegExp(
            pattern.pattern.source,
            pattern.pattern.flags,
          );
          let m;
          while ((m = regex.exec(text)) !== null) {
            matchesWithLines.push({
              lineNum,
              matched: m[0],
              col: m.index,
              lineText: text,
            });
          }
        }

        if (matchesWithLines.length === 0) continue;

        // Build evidence with line numbers and source context
        const evidenceLines = [`${matchesWithLines.length} match(es) found:`];
        const shown = matchesWithLines.slice(0, 15);
        for (const hit of shown) {
          const matchText =
            hit.matched.length > 100
              ? hit.matched.substring(0, 100) + "…"
              : hit.matched;
          evidenceLines.push(`  L${hit.lineNum}: ${matchText}`);
        }
        if (matchesWithLines.length > 15) {
          evidenceLines.push(`  ... +${matchesWithLines.length - 15} more`);
        }

        // Use the first match for the finding's line number and snippet
        const first = matchesWithLines[0];
        const snippet = getSnippetFromContent(
          file.newContent,
          first.lineNum,
          1,
        );

        findings.push({
          rule: "version-diff",
          severity: pattern.severity,
          title: pattern.title,
          file: file.path,
          line: first.lineNum,
          package: pkgName,
          evidence: evidenceLines.join("\n"),
          snippet,
          description: `Suspicious pattern found in ${file.status} code in ${file.path}.`,
        });
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

/**
 * Heuristic: file is likely minified if average line length > 200 chars
 */
function isLikelyMinified(content) {
  if (!content) return false;
  const lines = content.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return false;
  const avgLen = lines.reduce((s, l) => s + l.length, 0) / lines.length;
  return avgLen > 200;
}

/**
 * Extract a snippet from file content given a 1-based line number.
 */
function getSnippetFromContent(content, lineNum, contextLines = 1) {
  if (!content) return undefined;
  const lines = content.split("\n");
  const start = Math.max(0, lineNum - 1 - contextLines);
  const end = Math.min(lines.length, lineNum + contextLines);
  return lines
    .slice(start, end)
    .map((l) => (l.length > 200 ? l.substring(0, 200) + "…" : l))
    .join("\n");
}

/**
 * Display line-by-line code diffs for changed files.
 */
function displayCodeDiffs(changedFiles) {
  const codeFiles = changedFiles.filter(
    (f) => SCANNABLE_EXTENSIONS.has(extname(f.path)) && f.status !== "removed",
  );

  for (const file of codeFiles) {
    console.log();
    const statusLabel =
      file.status === "added"
        ? pc.green("ADDED")
        : file.status === "modified"
          ? pc.yellow("MODIFIED")
          : pc.red("REMOVED");
    console.log(`  ${pc.bold(file.path)} ${pc.dim("—")} ${statusLabel}`);
    console.log(pc.dim("  " + "─".repeat(60)));

    if (file.status === "added" && file.newContent) {
      // Show entire new file (truncated)
      const lines = file.newContent.split("\n");
      const maxLines = 60;
      for (let i = 0; i < Math.min(lines.length, maxLines); i++) {
        const lineText =
          lines[i].length > 160 ? lines[i].substring(0, 160) + "…" : lines[i];
        console.log(
          `  ${pc.green("+")} ${pc.dim(String(i + 1).padStart(4))} ${pc.green(lineText)}`,
        );
      }
      if (lines.length > maxLines) {
        console.log(pc.dim(`  ... +${lines.length - maxLines} more lines`));
      }
    } else if (
      file.status === "modified" &&
      file.oldContent &&
      file.newContent
    ) {
      // Unified-style diff output
      const oldLines = file.oldContent.split("\n");
      const newLines = file.newContent.split("\n");
      const oldSet = new Set(oldLines);
      const newSet = new Set(newLines);

      // Build simple diff hunks
      const diffLines = [];
      const maxOld = oldLines.length;
      const maxNew = newLines.length;
      let oi = 0;
      let ni = 0;

      // Simple LCS-based approach: show removed then added lines for each change region
      while (oi < maxOld || ni < maxNew) {
        // Find matching lines (context)
        if (oi < maxOld && ni < maxNew && oldLines[oi] === newLines[ni]) {
          diffLines.push({ type: "ctx", line: ni + 1, text: newLines[ni] });
          oi++;
          ni++;
          continue;
        }

        // Collect removed lines
        while (oi < maxOld && !newSet.has(oldLines[oi])) {
          diffLines.push({ type: "del", line: oi + 1, text: oldLines[oi] });
          oi++;
        }
        // Collect added lines
        while (ni < maxNew && !oldSet.has(newLines[ni])) {
          diffLines.push({ type: "add", line: ni + 1, text: newLines[ni] });
          ni++;
        }

        // If stuck (line exists in both sets but not at same position), advance both
        if (oi < maxOld && ni < maxNew && oldLines[oi] !== newLines[ni]) {
          diffLines.push({ type: "del", line: oi + 1, text: oldLines[oi] });
          diffLines.push({ type: "add", line: ni + 1, text: newLines[ni] });
          oi++;
          ni++;
        }
      }

      // Show only changed lines with minimal context (1 line before/after each hunk)
      const maxDiffLines = 80;
      let shown = 0;
      let lastShownIdx = -2;

      for (let i = 0; i < diffLines.length && shown < maxDiffLines; i++) {
        const d = diffLines[i];
        if (d.type === "ctx") {
          // Show only if adjacent to a change
          const nearChange =
            (i > 0 && diffLines[i - 1].type !== "ctx") ||
            (i < diffLines.length - 1 && diffLines[i + 1].type !== "ctx");
          if (!nearChange) continue;
        }

        // Add separator if gap
        if (lastShownIdx >= 0 && i - lastShownIdx > 1) {
          console.log(pc.dim("  ···"));
        }

        const lineText =
          d.text.length > 160 ? d.text.substring(0, 160) + "…" : d.text;
        const lineNum = String(d.line).padStart(4);

        if (d.type === "add") {
          console.log(
            `  ${pc.green("+")} ${pc.dim(lineNum)} ${pc.green(lineText)}`,
          );
        } else if (d.type === "del") {
          console.log(
            `  ${pc.red("-")} ${pc.dim(lineNum)} ${pc.red(lineText)}`,
          );
        } else {
          console.log(
            `  ${pc.dim(" ")} ${pc.dim(lineNum)} ${pc.dim(lineText)}`,
          );
        }
        shown++;
        lastShownIdx = i;
      }

      const totalChanges = diffLines.filter((d) => d.type !== "ctx").length;
      if (shown >= maxDiffLines && totalChanges > shown) {
        console.log(pc.dim(`  ... ${totalChanges - shown} more changed lines`));
      }
    }
  }
}

function formatBytes(bytes) {
  const abs = Math.abs(bytes);
  if (abs < 1024) return `${bytes}B`;
  if (abs < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}
