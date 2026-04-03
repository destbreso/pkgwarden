import { Command } from "commander";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { printBanner } from "./ui/banner.js";
import { initCommand } from "./commands/init.js";
import { installCommand } from "./commands/install.js";
import { scanCommand } from "./commands/scan.js";
import { auditCommand } from "./commands/audit.js";
import { doctorCommand } from "./commands/doctor.js";
import { configCommand } from "./commands/config.js";
import { diffCommand } from "./commands/diff.js";
import { hardenCommand } from "./commands/harden.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(
  readFileSync(join(__dirname, "..", "package.json"), "utf-8"),
);

export function run(argv) {
  const program = new Command();

  program
    .name("pkgwarden")
    .description(
      "⊙ PKGWARDEN — Package Guardian With Auditing, Reporting & Detection\n  Security audit layer for Node.js package managers.",
    )
    .version(pkg.version, "-v, --version")
    .hook("preAction", (thisCommand) => {
      // Don't print banner for version/help
    });

  // ── Init ──────────────────────────────────────────
  program
    .command("init")
    .description("Initialize pkgwarden security configuration for this project")
    .option("--cwd <path>", "Working directory")
    .action(async (opts) => {
      await initCommand(opts);
    });

  // ── Install ───────────────────────────────────────
  program
    .command("install [packages...]")
    .alias("i")
    .alias("add")
    .description("Install packages with pre-install security scanning")
    .option("-D, --dev", "Install as devDependency")
    .option("-E, --exact", "Install with exact version")
    .option("--skip-scan", "Skip security scanning")
    .option("--ci", "Run in CI mode (non-interactive)")
    .option("--force", "Force install despite findings")
    .option("--cwd <path>", "Working directory")
    .action(async (packages, opts) => {
      await installCommand(packages, opts);
    });

  // ── Scan ──────────────────────────────────────────
  program
    .command("scan <package>")
    .description("Deep security scan of a package without installing")
    .option("--version <ver>", "Package version to scan", "latest")
    .option(
      "-s, --severity <level>",
      "Minimum severity to display: low, medium, high, critical",
    )
    .option("--page-size <n>", "Findings per page (0 = no pagination)", "10")
    .option("--json", "Output results as JSON")
    .option("--ci", "CI mode")
    .option("--cwd <path>", "Working directory")
    .action(async (packageName, opts) => {
      await scanCommand(packageName, opts);
    });

  // ── Audit ─────────────────────────────────────────
  program
    .command("audit")
    .description("Comprehensive security audit of project dependencies")
    .option("--deep", "Deep scan node_modules source code")
    .option("--json", "Output results as JSON")
    .option("--ci", "CI mode")
    .option("--cwd <path>", "Working directory")
    .action(async (opts) => {
      await auditCommand(opts);
    });

  // ── Doctor ────────────────────────────────────────
  program
    .command("doctor")
    .description("Check security health and best practices of your project")
    .option("--cwd <path>", "Working directory")
    .action(async (opts) => {
      await doctorCommand(opts);
    });

  // ── Config ────────────────────────────────────────
  program
    .command("config [action]")
    .description("View or edit pkgwarden configuration (show|edit|reset|path)")
    .option("--cwd <path>", "Working directory")
    .action(async (action = "show", opts) => {
      await configCommand(action, opts);
    });

  // ── Harden ────────────────────────────────────────
  program
    .command("harden")
    .description(
      "Detect and apply security best practices to your PM configuration (.npmrc, .yarnrc.yml, pnpm-workspace.yaml)",
    )
    .option("--yes", "Auto-apply all recommended fixes without prompting")
    .option("--dry-run", "Show findings without making changes")
    .option("--json", "Output findings as JSON")
    .option("--cwd <path>", "Working directory")
    .action(async (opts) => {
      await hardenCommand(opts);
    });

  // ── Diff ──────────────────────────────────────────
  program
    .command("diff <package>")
    .description(
      "Compare two versions of a package and scan the diff for attack patterns",
    )
    .option("-t, --target <ver>", "Target version to compare (default: latest)")
    .option("-d, --show-diff", "Show code-level diffs for changed files")
    .option("--json", "Output results as JSON")
    .option("--ci", "CI mode (non-interactive)")
    .option("--cwd <path>", "Working directory")
    .action(async (packageName, opts) => {
      await diffCommand(packageName, opts);
    });

  // ── Default (no command) ──────────────────────────
  program.action(() => {
    printBanner();
    program.help();
  });

  program.parseAsync(argv).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
