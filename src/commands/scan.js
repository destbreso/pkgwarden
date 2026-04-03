import * as p from "@clack/prompts";
import pc from "picocolors";
import { printBanner } from "../ui/banner.js";
import { icons, theme } from "../ui/theme.js";
import { Reporter } from "../ui/reporter.js";
import { ConfigManager } from "../core/config-manager.js";
import { PackageManager } from "../core/package-manager.js";
import { Scanner } from "../core/scanner.js";
import { RegistryClient } from "../core/registry-client.js";

export async function scanCommand(packageName, options = {}) {
  const cwd = options.cwd || process.cwd();
  const isCI = options.ci || !!process.env.CI;
  const version = options.version || "latest";
  const json = options.json || false;
  const pageSize = parseInt(options.pageSize, 10) || 10;
  let minSeverity = options.severity || null;

  printBanner(true);
  console.log();

  const config = new ConfigManager(cwd);
  const reporter = new Reporter({ ci: isCI });

  p.intro(pc.bgCyan(pc.black(` Deep Scan: ${packageName}@${version} `)));

  const s = p.spinner();

  // Fetch metadata
  s.start("Fetching package information...");
  const registry = new RegistryClient();
  const fullInfo = await registry.getPackageInfo(packageName);

  if (!fullInfo) {
    s.stop(`${icons.error} Package not found`);
    p.log.error(`Package "${packageName}" does not exist in the registry.`);
    return;
  }

  const versionInfo =
    fullInfo.versions?.[fullInfo["dist-tags"]?.[version] || version] ||
    fullInfo.versions?.[version];
  const resolvedVersion = versionInfo?.version || version;

  s.stop("Package info loaded");

  // Display package info
  const time = fullInfo.time?.[resolvedVersion];
  const downloads = await registry.getDownloadCount(packageName);

  console.log();
  p.note(
    [
      `${theme.muted("Name:")}        ${theme.highlight(packageName)}`,
      `${theme.muted("Version:")}     ${pc.cyan(resolvedVersion)}`,
      `${theme.muted("Published:")}   ${time ? pc.dim(new Date(time).toLocaleDateString()) : pc.dim("unknown")}`,
      `${theme.muted("Downloads:")}   ${pc.dim(downloads.toLocaleString() + "/week")}`,
      `${theme.muted("License:")}     ${fullInfo.license || pc.red("NONE")}`,
      `${theme.muted("Maintainers:")} ${(fullInfo.maintainers || []).map((m) => m.name).join(", ") || pc.dim("unknown")}`,
      `${theme.muted("Homepage:")}    ${fullInfo.homepage || pc.dim("none")}`,
      `${theme.muted("Deps:")}        ${Object.keys(fullInfo.versions?.[resolvedVersion]?.dependencies || {}).length}`,
    ].join("\n"),
    "Package Info",
  );

  // Run scan
  const scanner = new Scanner(config);
  s.start("Downloading and scanning package source...");

  const { findings, metadata } = await scanner.scanPackage(
    packageName,
    resolvedVersion,
    {
      onProgress: (msg) => s.message(msg),
    },
  );

  const counts = Scanner.countBySeverity(findings);

  if (findings.length === 0) {
    s.stop(`${pc.green("✔")} No threats detected`);
    console.log();
    p.log.success(`Package ${pc.cyan(packageName)} appears clean.`);

    reporter.blank();
    reporter.header("Security Score");
    reporter.score(100, 100);
  } else {
    s.stop(
      `${pc.yellow("⚠")} Found ${pc.bold(String(findings.length))} issue(s)`,
    );

    // Sort by severity (highest first)
    const sorted = findings.sort(
      (a, b) =>
        config.getSeverityLevel(b.severity) -
        config.getSeverityLevel(a.severity),
    );

    // Interactive severity filter if not passed via CLI and not CI
    if (!minSeverity && !isCI && findings.length > 5) {
      const levelChoice = await p.select({
        message: `${findings.length} findings found. Filter by minimum severity?`,
        options: [
          {
            value: "all",
            label: `All (${findings.length})`,
            hint: "Show everything",
          },
          {
            value: "low",
            label: `Low+ (${findings.filter((f) => config.getSeverityLevel(f.severity) >= 1).length})`,
          },
          {
            value: "medium",
            label: `Medium+ (${findings.filter((f) => config.getSeverityLevel(f.severity) >= 2).length})`,
          },
          {
            value: "high",
            label: `High+ (${findings.filter((f) => config.getSeverityLevel(f.severity) >= 3).length})`,
          },
          {
            value: "critical",
            label: `Critical only (${findings.filter((f) => f.severity === "critical").length})`,
          },
        ],
        initialValue: "all",
      });
      if (!p.isCancel(levelChoice) && levelChoice !== "all") {
        minSeverity = levelChoice;
      }
    }

    // Apply severity filter
    const filtered = minSeverity
      ? sorted.filter(
          (f) =>
            config.getSeverityLevel(f.severity) >=
            config.getSeverityLevel(minSeverity),
        )
      : sorted;

    if (minSeverity) {
      p.log.info(
        `${icons.info} Showing ${pc.bold(String(filtered.length))}/${findings.length} findings (${pc.cyan(minSeverity)}+)`,
      );
    }

    // Paginated display
    if (!isCI && pageSize > 0 && filtered.length > pageSize) {
      let page = 0;
      const totalPages = Math.ceil(filtered.length / pageSize);

      while (page < totalPages) {
        const start = page * pageSize;
        const end = Math.min(start + pageSize, filtered.length);
        const slice = filtered.slice(start, end);

        for (const finding of slice) {
          reporter.finding(finding);
        }

        page++;
        if (page < totalPages) {
          console.log();
          const remaining = filtered.length - end;
          const next = await p.confirm({
            message: `Showing ${end}/${filtered.length} — ${remaining} more. Continue?`,
            initialValue: true,
          });
          if (p.isCancel(next) || !next) break;
        }
      }
    } else {
      // No pagination needed
      for (const finding of filtered) {
        reporter.finding(finding);
      }
    }

    // Summary (always shows totals for ALL findings, not filtered)
    reporter.summary({ ...counts, scanned: 1 });

    // Score
    const score = calculateScore(findings);
    reporter.blank();
    reporter.header("Security Score");
    reporter.score(score, 100);

    // Recommendation
    console.log();
    if (counts.critical > 0) {
      p.log.error(
        `${icons.fire} ${pc.red(pc.bold("DO NOT INSTALL"))} — Critical security issues detected.`,
      );
    } else if (counts.high > 0) {
      p.log.warn(
        `${icons.warning} ${pc.yellow("CAUTION")} — High severity issues found. Review carefully.`,
      );
    } else {
      p.log.info(
        `${icons.info} Minor issues found. Generally safe to install with awareness.`,
      );
    }
  }

  if (json) {
    reporter.ciOutput({
      package: packageName,
      version: resolvedVersion,
      findings,
      counts,
      score: calculateScore(findings),
    });
  }

  console.log();
  p.outro(`${icons.shield} Scan complete`);
}

function calculateScore(findings) {
  let score = 100;
  for (const f of findings) {
    switch (f.severity) {
      case "critical":
        score -= 25;
        break;
      case "high":
        score -= 15;
        break;
      case "medium":
        score -= 5;
        break;
      case "low":
        score -= 2;
        break;
    }
  }
  return Math.max(0, score);
}
