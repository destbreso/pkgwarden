import * as p from "@clack/prompts";
import pc from "picocolors";
import { printBanner } from "../ui/banner.js";
import { icons, severityBadge, theme } from "../ui/theme.js";
import { Reporter } from "../ui/reporter.js";
import { ConfigManager } from "../core/config-manager.js";
import { PackageManager } from "../core/package-manager.js";
import { Scanner } from "../core/scanner.js";

export async function installCommand(packages, options = {}) {
  const cwd = options.cwd || process.cwd();
  const isCI = options.ci || !!process.env.CI;
  const isDev = options.dev || false;
  const isExact = options.exact || false;
  const skipScan = options.skipScan || false;
  const force = options.force || false;

  printBanner(true);
  console.log();

  const config = new ConfigManager(cwd);
  const pm = new PackageManager(cwd);
  const reporter = new Reporter({ ci: isCI });

  if (!config.exists && !isCI) {
    p.log.warn(
      `${icons.warning} No pkgwarden config found. Run ${pc.cyan("pkgwarden init")} first for full protection.`,
    );
    console.log();
  }

  p.log.info(`${icons.eye} Package manager: ${theme.highlight(pm.name)}`);

  if (packages.length === 0) {
    // Install all deps — run audit on existing lockfile
    if (config.config.policies.auditOnInstall && !skipScan) {
      const s = p.spinner();
      s.start("Running security audit on current dependencies...");
      const result = await pm.runAudit();
      s.stop("Audit complete");

      if (result.stdout) {
        try {
          const audit = JSON.parse(result.stdout);
          const vulns = audit.metadata?.vulnerabilities || {};
          const total =
            (vulns.critical || 0) +
            (vulns.high || 0) +
            (vulns.medium || 0) +
            (vulns.low || 0);
          if (total > 0) {
            p.log.warn(
              `Found ${pc.bold(String(total))} known vulnerabilities: ${pc.red(`${vulns.critical || 0} critical`)} ${pc.yellow(`${vulns.high || 0} high`)} ${pc.blue(`${vulns.medium || 0} medium`)}`,
            );
          } else {
            p.log.success("No known vulnerabilities found.");
          }
        } catch {}
      }
    }

    p.log.step(`${icons.arrow} Running ${pc.cyan(`${pm.name} install`)}...`);
    console.log();
    const result = await pm.runInstall([], {
      ignoreScripts: config.config.policies.enforceRcSecurity,
    });
    return result;
  }

  // Scan each package before installing
  const scanner = new Scanner(config);
  const allFindings = [];
  const blocked = [];
  const approved = [];

  for (const pkg of packages) {
    const [name, version] =
      pkg.split("@").length > 2
        ? [`@${pkg.split("@")[1]}`, pkg.split("@")[2] || "latest"]
        : [pkg.split("@")[0], pkg.split("@")[1] || "latest"];

    console.log();
    p.intro(pc.bgCyan(pc.black(` Scanning: ${name}@${version} `)));

    if (config.isBlocked(name)) {
      p.log.error(
        `${icons.error} Package ${pc.red(name)} is BLOCKED by your security policy.`,
      );
      blocked.push(name);
      continue;
    }

    if (config.isAllowed(name) || skipScan) {
      p.log.success(
        `${icons.success} Package ${pc.green(name)} is in allowlist — skipping scan.`,
      );
      approved.push(pkg);
      continue;
    }

    const s = p.spinner();

    const { findings, metadata } = await scanner.scanPackage(name, version, {
      onProgress: (msg) => s.message(msg),
    });

    const counts = Scanner.countBySeverity(findings);

    if (findings.length === 0) {
      s.stop(`${pc.green("✔")} No threats detected in ${pc.cyan(name)}`);
      approved.push(pkg);
      continue;
    }

    s.stop(
      `${pc.yellow("⚠")} Found ${pc.bold(String(findings.length))} issue(s) in ${pc.cyan(name)}`,
    );

    // Show findings
    reporter.blank();
    for (const finding of findings.sort(
      (a, b) =>
        config.getSeverityLevel(b.severity) -
        config.getSeverityLevel(a.severity),
    )) {
      reporter.finding(finding);
    }

    reporter.blank();
    reporter.summary({
      ...counts,
      scanned: 1,
    });

    allFindings.push(...findings);

    // Check threshold
    const hasCritical = counts.critical > 0;
    const hasBlockingFindings = findings.some((f) =>
      config.meetsThreshold(f.severity),
    );

    if (isCI) {
      // CI mode: auto-decide based on threshold
      const hasFailingFindings = findings.some((f) =>
        config.meetsCIThreshold(f.severity),
      );
      if (hasFailingFindings) {
        p.log.error(
          `${icons.error} CI threshold exceeded for ${pc.red(name)}. Installation blocked.`,
        );
        blocked.push(name);
        reporter.ciOutput({ package: name, blocked: true, findings });
      } else {
        p.log.warn(
          `${icons.warning} Findings below CI threshold for ${pc.yellow(name)}. Proceeding.`,
        );
        approved.push(pkg);
      }
      continue;
    }

    // Interactive mode: ask user
    console.log();
    const action = await p.select({
      message: `What would you like to do with ${pc.cyan(name)}?`,
      options: [
        ...(hasBlockingFindings
          ? []
          : [
              {
                value: "install",
                label: `${pc.green("Install anyway")}`,
                hint: "Proceed with installation",
              },
            ]),
        {
          value: "install-force",
          label: `${hasCritical ? pc.red("Force install (dangerous)") : pc.yellow("Install with warnings")}`,
          hint: "Install despite findings",
        },
        { value: "skip", label: "Skip this package", hint: "Do not install" },
        {
          value: "details",
          label: "Show more details",
          hint: "View full scan report",
        },
        {
          value: "allowlist",
          label: `Add to allowlist`,
          hint: "Trust and install",
        },
      ],
    });

    if (p.isCancel(action) || action === "skip") {
      p.log.info(`Skipped ${pc.dim(name)}`);
      blocked.push(name);
    } else if (action === "install" || action === "install-force") {
      approved.push(pkg);
    } else if (action === "allowlist") {
      p.log.info(`${icons.success} Added ${pc.cyan(name)} to allowlist.`);
      approved.push(pkg);
    } else if (action === "details") {
      // Show detailed findings
      for (const finding of findings) {
        reporter.finding(finding);
      }

      const retry = await p.confirm({
        message: `Install ${pc.cyan(name)} after reviewing?`,
        initialValue: false,
      });
      if (retry && !p.isCancel(retry)) {
        approved.push(pkg);
      } else {
        blocked.push(name);
      }
    }
  }

  // Execute installation for approved packages
  if (approved.length > 0) {
    console.log();
    p.log.step(
      `${icons.arrow} Installing ${pc.cyan(String(approved.length))} approved package(s)...`,
    );
    console.log();

    const flags = {
      dev: isDev,
      exact: isExact,
      ignoreScripts: config.config.policies.enforceRcSecurity,
    };

    const result = await pm.runInstall(approved, flags);

    if (result.code === 0) {
      console.log();
      p.log.success(
        `${icons.success} Successfully installed: ${pc.cyan(approved.join(", "))}`,
      );
    } else {
      p.log.error(
        `${icons.error} Installation failed with exit code ${result.code}`,
      );
    }
  }

  if (blocked.length > 0) {
    console.log();
    p.log.warn(
      `${icons.warning} Blocked packages: ${pc.red(blocked.join(", "))}`,
    );
  }

  // Final summary
  console.log();
  p.outro(
    `${icons.shield} ${pc.dim(`${approved.length} installed, ${blocked.length} blocked`)}`,
  );

  // Exit with error in CI if anything was blocked
  if (isCI && blocked.length > 0) {
    process.exit(1);
  }
}
