import * as p from "@clack/prompts";
import pc from "picocolors";
import { join } from "node:path";
import { existsSync, readFileSync, accessSync, constants } from "node:fs";
import { printBanner } from "../ui/banner.js";
import { icons, theme, divider } from "../ui/theme.js";
import { ConfigManager } from "../core/config-manager.js";
import { PackageManager } from "../core/package-manager.js";

export async function doctorCommand(options = {}) {
  const cwd = options.cwd || process.cwd();

  printBanner(true);
  console.log();

  p.intro(pc.bgCyan(pc.black(" PKGWARDEN DOCTOR — Security Health Check ")));

  const checks = [];
  const config = new ConfigManager(cwd);
  const pm = new PackageManager(cwd);

  // Check 1: pkgwarden configuration
  console.log();
  p.log.step(`${theme.title("Configuration")}`);

  if (config.exists) {
    checks.push(pass("pkgwarden config found", config.configPath));
  } else {
    checks.push(
      fail(
        "No pkgwarden config found",
        `Run ${pc.cyan("pkgwarden init")} to create one`,
      ),
    );
  }

  // Check 2: Package manager
  p.log.step(`${theme.title("Package Manager")}`);

  if (pm.isAvailable()) {
    checks.push(pass(`${pm.name} is installed`, `v${pm.getVersion()}`));
  } else {
    checks.push(
      fail(`${pm.name} not found`, "Install the detected package manager"),
    );
  }

  // Check 3: Lockfile
  const lockFile = pm.getLockfilePath();
  if (lockFile && existsSync(lockFile)) {
    checks.push(pass("Lockfile present", lockFile.split("/").pop()));
  } else {
    checks.push(
      fail("No lockfile found", "Run install to generate a lockfile"),
    );
  }

  // Check 4: .npmrc / PM config
  p.log.step(`${theme.title("Security Configuration")}`);

  const npmrcPath = join(cwd, ".npmrc");
  if (existsSync(npmrcPath)) {
    const npmrc = readFileSync(npmrcPath, "utf-8");

    if (npmrc.includes("ignore-scripts=true")) {
      checks.push(pass("ignore-scripts is enabled", ".npmrc"));
    } else {
      checks.push(
        warn(
          "ignore-scripts is NOT enabled",
          "Add ignore-scripts=true to .npmrc",
        ),
      );
    }

    if (npmrc.includes("engine-strict=true")) {
      checks.push(pass("engine-strict is enabled", ".npmrc"));
    } else {
      checks.push(
        warn("engine-strict not set", "Add engine-strict=true to .npmrc"),
      );
    }

    if (npmrc.includes("audit=true") || !npmrc.includes("audit=false")) {
      checks.push(pass("npm audit is enabled"));
    } else {
      checks.push(
        warn("npm audit is disabled", "Remove audit=false from .npmrc"),
      );
    }
  } else {
    checks.push(
      warn("No .npmrc found", "Create .npmrc with security settings"),
    );
  }

  // Check 5: Package.json security
  p.log.step(`${theme.title("Package Security")}`);

  const pkgPath = join(cwd, "package.json");
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

    if (pkg.engines?.node) {
      checks.push(pass("Node engine constraint defined", pkg.engines.node));
    } else {
      checks.push(
        warn(
          "No Node engine constraint",
          'Add "engines": {"node": ">=18"} to package.json',
        ),
      );
    }

    if (pkg.packageManager) {
      checks.push(
        pass("packageManager field set (Corepack)", pkg.packageManager),
      );
    } else {
      checks.push(
        warn("No packageManager field", "Set packageManager to pin PM version"),
      );
    }

    // Check for dangerous scripts
    const scripts = pkg.scripts || {};
    const hasPreinstall = !!scripts.preinstall;
    const hasPostinstall = !!scripts.postinstall;

    if (!hasPreinstall && !hasPostinstall) {
      checks.push(pass("No lifecycle install scripts in project"));
    } else {
      checks.push(
        warn(
          "Project defines install lifecycle scripts",
          "Review preinstall/postinstall scripts",
        ),
      );
    }

    // Check dependency count
    const depCount = Object.keys(pkg.dependencies || {}).length;
    const devDepCount = Object.keys(pkg.devDependencies || {}).length;
    checks.push(
      info(`${depCount} dependencies, ${devDepCount} devDependencies`),
    );

    // Check for version ranges
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    let rangeCount = 0;
    let starCount = 0;
    for (const ver of Object.values(deps)) {
      if (ver === "*" || ver === "latest") starCount++;
      else if (ver.startsWith("^") || ver.startsWith("~")) rangeCount++;
    }

    if (starCount > 0) {
      checks.push(
        fail(
          `${starCount} deps use * or latest`,
          "Pin all dependencies to specific versions",
        ),
      );
    }
    if (rangeCount > 0) {
      checks.push(
        warn(
          `${rangeCount} deps use version ranges (^, ~)`,
          "Consider using exact versions",
        ),
      );
    } else if (starCount === 0) {
      checks.push(pass("All dependencies use exact versions"));
    }
  } else {
    checks.push(fail("No package.json found"));
  }

  // Check 6: .gitignore
  p.log.step(`${theme.title("Repository Hygiene")}`);

  const gitignorePath = join(cwd, ".gitignore");
  if (existsSync(gitignorePath)) {
    const gitignore = readFileSync(gitignorePath, "utf-8");
    if (gitignore.includes(".env")) {
      checks.push(pass(".env is in .gitignore"));
    } else {
      checks.push(
        fail(
          ".env is NOT in .gitignore",
          "Add .env to .gitignore to prevent secret leaks",
        ),
      );
    }

    if (gitignore.includes("node_modules")) {
      checks.push(pass("node_modules is in .gitignore"));
    } else {
      checks.push(fail("node_modules not in .gitignore"));
    }
  } else {
    checks.push(warn("No .gitignore found"));
  }

  // Check 7: Env files
  const envFile = join(cwd, ".env");
  if (existsSync(envFile)) {
    checks.push(
      warn(".env file exists — ensure it contains no production secrets"),
    );
  }

  // Results summary
  console.log();
  console.log(`  ${divider("Results")}`);
  console.log();

  const passed = checks.filter((c) => c.status === "pass").length;
  const warned = checks.filter((c) => c.status === "warn").length;
  const failed = checks.filter((c) => c.status === "fail").length;

  for (const check of checks) {
    const icon =
      check.status === "pass"
        ? icons.success
        : check.status === "warn"
          ? icons.warning
          : check.status === "fail"
            ? icons.error
            : icons.info;
    const detail = check.detail ? ` ${pc.dim(`(${check.detail})`)}` : "";
    const fix = check.fix
      ? `\n       ${icons.corner}${icons.line} ${pc.dim(check.fix)}`
      : "";
    console.log(`  ${icon} ${check.message}${detail}${fix}`);
  }

  // Score
  const score = Math.round((passed / checks.length) * 100);
  console.log();
  console.log(`  ${divider("Health Score")}`);
  console.log();

  const barWidth = 30;
  const filled = Math.round((score / 100) * barWidth);
  const empty = barWidth - filled;
  const color = score >= 80 ? pc.green : score >= 50 ? pc.yellow : pc.red;
  console.log(
    `  ${color("█".repeat(filled))}${pc.dim("░".repeat(empty))} ${color(pc.bold(`${score}%`))}`,
  );
  console.log(
    `  ${pc.green(`${passed} passed`)}  ${pc.yellow(`${warned} warnings`)}  ${pc.red(`${failed} failed`)}`,
  );

  console.log();
  p.outro(`${icons.shield} Health check complete`);
}

function pass(message, detail = "") {
  return { status: "pass", message, detail };
}

function warn(message, fix = "") {
  return { status: "warn", message, fix };
}

function fail(message, fix = "") {
  return { status: "fail", message, fix };
}

function info(message, detail = "") {
  return { status: "info", message, detail };
}
