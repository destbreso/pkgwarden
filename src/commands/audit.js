import * as p from "@clack/prompts";
import pc from "picocolors";
import { join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { printBanner } from "../ui/banner.js";
import { icons, theme } from "../ui/theme.js";
import { Reporter } from "../ui/reporter.js";
import { ConfigManager } from "../core/config-manager.js";
import { PackageManager } from "../core/package-manager.js";
import { Scanner } from "../core/scanner.js";

export async function auditCommand(options = {}) {
  const cwd = options.cwd || process.cwd();
  const isCI = options.ci || !!process.env.CI;
  const json = options.json || false;
  const deep = options.deep || false;

  printBanner(true);
  console.log();

  p.intro(pc.bgCyan(pc.black(" PKGWARDEN AUDIT — Dependency Security Audit ")));

  const config = new ConfigManager(cwd);
  const pm = new PackageManager(cwd);
  const reporter = new Reporter({ ci: isCI });

  // 1. Run native audit
  const s = p.spinner();
  s.start(`Running ${pm.name} audit...`);
  const nativeAudit = await pm.runAudit();
  s.stop(`${pm.name} audit complete`);

  let nativeVulns = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  if (nativeAudit.stdout) {
    try {
      const parsed = JSON.parse(nativeAudit.stdout);
      const vulns =
        parsed.metadata?.vulnerabilities || parsed.vulnerabilities || {};
      nativeVulns = {
        critical: vulns.critical || 0,
        high: vulns.high || 0,
        medium: vulns.medium || 0,
        low: vulns.low || vulns.info || 0,
        total:
          vulns.total ||
          (vulns.critical || 0) +
            (vulns.high || 0) +
            (vulns.medium || 0) +
            (vulns.low || 0),
      };
    } catch {}
  }

  reporter.blank();
  reporter.header("Native Audit Results");
  if (nativeVulns.total === 0) {
    reporter.step("No known vulnerabilities in dependency tree", "success");
  } else {
    reporter.table(
      ["Severity", "Count"],
      [
        [pc.red("Critical"), String(nativeVulns.critical)],
        [pc.yellow("High"), String(nativeVulns.high)],
        [pc.blue("Medium"), String(nativeVulns.medium)],
        [pc.dim("Low"), String(nativeVulns.low)],
      ],
    );
  }

  // 2. Deep scan of node_modules (if --deep)
  let deepFindings = [];
  if (deep) {
    const nmPath = join(cwd, "node_modules");
    if (existsSync(nmPath)) {
      reporter.blank();
      s.start("Deep scanning node_modules (this may take a while)...");

      const scanner = new Scanner(config);
      const result = await scanner.scanDirectory(nmPath, {
        onProgress: (msg) => s.message(msg),
      });

      deepFindings = result.findings;
      const counts = Scanner.countBySeverity(deepFindings);

      s.stop(`Deep scan complete — ${result.filesScanned} files scanned`);

      if (deepFindings.length > 0) {
        // Group by package
        const byPackage = {};
        for (const f of deepFindings) {
          const pkg = f.package || "unknown";
          if (!byPackage[pkg]) byPackage[pkg] = [];
          byPackage[pkg].push(f);
        }

        reporter.blank();
        reporter.header("Deep Scan Findings");

        for (const [pkg, findings] of Object.entries(byPackage)) {
          const pkgCounts = Scanner.countBySeverity(findings);
          const severityLabel =
            pkgCounts.critical > 0
              ? pc.red("CRITICAL")
              : pkgCounts.high > 0
                ? pc.yellow("HIGH")
                : pc.blue("MEDIUM");

          reporter.step(
            `${pc.cyan(pkg)} — ${findings.length} finding(s) [${severityLabel}]`,
          );

          // Show top findings per package
          const top = findings
            .sort(
              (a, b) => getSeverityNum(b.severity) - getSeverityNum(a.severity),
            )
            .slice(0, 3);

          reporter.tree(
            top.map((f) => `${f.title} ${pc.dim(`(${f.severity})`)}`),
          );

          if (findings.length > 3) {
            reporter.step(
              `  ${pc.dim(`... and ${findings.length - 3} more`)}`,
              "info",
            );
          }
        }

        reporter.summary({ ...counts, scanned: Object.keys(byPackage).length });
      } else {
        reporter.step(
          "No suspicious patterns detected in node_modules",
          "success",
        );
      }
    } else {
      p.log.warn("node_modules not found. Run install first.");
    }
  }

  // 3. Check package.json for issues
  reporter.blank();
  reporter.header("Package Configuration");
  const pkgPath = join(cwd, "package.json");
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const issues = checkPackageJson(pkg, config);

    for (const issue of issues) {
      reporter.step(issue.message, issue.status);
    }
  }

  // Overall score
  const totalIssues = nativeVulns.total + deepFindings.length;
  const score = Math.max(
    0,
    100 -
      nativeVulns.critical * 25 -
      nativeVulns.high * 15 -
      nativeVulns.medium * 5 -
      nativeVulns.low * 1 -
      deepFindings.filter((f) => f.severity === "critical").length * 20 -
      deepFindings.filter((f) => f.severity === "high").length * 10,
  );

  reporter.blank();
  reporter.header("Overall Security Score");
  reporter.score(Math.min(score, 100), 100);

  if (json) {
    reporter.ciOutput({
      nativeVulns,
      deepFindings: deepFindings.length,
      score: Math.min(score, 100),
    });
  }

  console.log();
  p.outro(`${icons.shield} Audit complete — ${totalIssues} total issues found`);

  if (isCI && nativeVulns.critical > 0) {
    process.exit(1);
  }
}

function checkPackageJson(pkg, config) {
  const issues = [];

  // Check for lock file
  if (config.config.bestPractices.enforceLockfile) {
    issues.push({
      message: "Lockfile enforcement is active",
      status: "success",
    });
  }

  // Check for range versions
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  let rangeCount = 0;
  for (const [name, ver] of Object.entries(deps)) {
    if (
      ver.startsWith("^") ||
      ver.startsWith("~") ||
      ver === "*" ||
      ver === "latest"
    ) {
      rangeCount++;
    }
  }

  if (rangeCount > 0) {
    issues.push({
      message: `${rangeCount} dependencies use version ranges (^, ~, *)`,
      status: config.config.bestPractices.enforceExactVersions
        ? "error"
        : "warning",
    });
  } else {
    issues.push({
      message: "All dependencies use exact versions",
      status: "success",
    });
  }

  // Check for engines
  if (pkg.engines?.node) {
    issues.push({
      message: `Node engine specified: ${pkg.engines.node}`,
      status: "success",
    });
  } else {
    issues.push({ message: "No Node engine specified", status: "warning" });
  }

  // Check for overrides/resolutions
  if (pkg.overrides || pkg.resolutions) {
    issues.push({
      message:
        "Package overrides/resolutions detected — review these regularly",
      status: "warning",
    });
  }

  return issues;
}

function getSeverityNum(severity) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity] || 0;
}
