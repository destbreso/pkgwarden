import * as p from "@clack/prompts";
import pc from "picocolors";
import { printBanner } from "../ui/banner.js";
import { icons, theme } from "../ui/theme.js";
import { PackageManager } from "../core/package-manager.js";
import {
  RcAnalyzer,
  HARDEN_LEVELS,
  severitiesForLevel,
  BEST_PRACTICES_GUIDE,
} from "../core/rc-analyzer.js";
import { ConfigManager } from "../core/config-manager.js";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const SEVERITY_BADGE = {
  critical: (s) => pc.bgRed(pc.white(` ${s} `)),
  high: (s) => pc.red(`[${s}]`),
  medium: (s) => pc.yellow(`[${s}]`),
  low: (s) => pc.dim(`[${s}]`),
};

const RC_FILE = {
  npm: ".npmrc",
  pnpm: ".npmrc",
  yarn: ".yarnrc.yml",
};

export async function hardenCommand(options = {}) {
  const cwd = options.cwd || process.cwd();
  const dryRun = options.dryRun || false;
  const autoYes = options.yes || false;
  const jsonOutput = options.json || false;

  if (!jsonOutput) {
    printBanner(true);
    console.log();
    p.intro(pc.bgRed(pc.white(" PKGWARDEN HARDEN — RC Security Hardening ")));
  }

  const pm = new PackageManager(cwd);
  const pmName = pm.name;
  const analyzer = new RcAnalyzer(cwd, pmName);

  if (!jsonOutput) {
    p.log.info(
      `Detected package manager: ${pc.cyan(pmName)} — analyzing ${pc.dim(RC_FILE[pmName] || ".npmrc")}`,
    );
    if (pmName === "pnpm") {
      p.log.info(`Also checking: ${pc.dim("pnpm-workspace.yaml")}`);
    }
    if (pmName === "bun") {
      p.log.info(`Checking: ${pc.dim("bunfig.toml")}`);
    }
    p.log.info(`Guide: ${pc.dim(BEST_PRACTICES_GUIDE)}`);
    console.log();
  }

  // ── Collect findings from all relevant files ─────────────────────────────

  const sources = [];

  const rcResults = analyzer.analyze();
  sources.push({
    label: RC_FILE[pmName] || ".npmrc",
    results: rcResults,
    type: "rc",
  });

  if (pmName === "pnpm") {
    const wsResults = analyzer.analyzeWorkspace();
    if (wsResults) {
      sources.push({
        label: "pnpm-workspace.yaml",
        results: wsResults,
        type: "workspace",
      });
    }
  }

  const actionable = [];
  const passing = [];
  const dangerous = [];

  for (const source of sources) {
    for (const finding of source.results.findings) {
      if (finding.status === "pass") {
        passing.push({ ...finding, _source: source.label });
      } else if (finding.status === "danger") {
        dangerous.push({ ...finding, _source: source.label });
      } else if (finding.status === "missing" || finding.status === "wrong") {
        if (finding.key) {
          actionable.push({ ...finding, _source: source.label });
        }
      }
    }
  }

  actionable.sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99),
  );

  // ── JSON output ──────────────────────────────────────────────────────────

  if (jsonOutput) {
    process.stdout.write(
      JSON.stringify({ pm: pmName, actionable, passing, dangerous }, null, 2) +
        "\n",
    );
    return;
  }

  // ── Dangerous settings ───────────────────────────────────────────────────

  if (dangerous.length > 0) {
    p.log.step(theme.title("Dangerous Settings Detected"));
    for (const d of dangerous) {
      console.log(
        `  ${pc.bgRed(pc.white(" DANGER "))} ${pc.bold(d.title)} ${pc.dim(`(${d._source})`)}`,
      );
      if (d.description) console.log(`    ${pc.dim(d.description)}`);
      if (d.fix) console.log(`    ${pc.cyan("Fix:")} ${d.fix}`);
    }
    console.log();
  }

  // ── All good ─────────────────────────────────────────────────────────────

  if (actionable.length === 0) {
    p.log.success(
      `All security settings are properly configured for ${pc.cyan(pmName)}!`,
    );
    if (passing.length > 0) {
      p.log.info(`${passing.length} best-practice checks passed.`);
    }
    p.outro(`${icons.shield} Fully hardened`);
    return;
  }

  // ── Show findings ────────────────────────────────────────────────────────

  p.log.step(
    `${theme.title("Security Configuration Findings")} — ${actionable.length} improvable`,
  );
  console.log();

  for (const finding of actionable) {
    const badge =
      (SEVERITY_BADGE[finding.severity] || ((s) => `[${s}]`))(
        finding.severity.toUpperCase(),
      ) + " ";
    const statusIcon =
      finding.status === "missing" ? icons.error : icons.warn || "!";
    console.log(
      `  ${statusIcon} ${badge}${finding.title} ${pc.dim(`(${finding._source})`)}`,
    );
    if (finding.description) {
      console.log(`     ${pc.dim(finding.description)}`);
    }
    if (finding.fix) {
      console.log(`     ${pc.cyan("→")} ${pc.bold(finding.fix)}`);
    }
    if (finding.ref) {
      console.log(
        `     ${pc.dim("ref:")} ${pc.dim(BEST_PRACTICES_GUIDE + finding.ref)}`,
      );
    }
    console.log();
  }

  if (passing.length > 0) {
    p.log.success(
      `${passing.length} check${passing.length !== 1 ? "s" : ""} already passing`,
    );
    console.log();
  }

  if (dryRun) {
    p.outro(
      `${icons.info || "ℹ"} Dry run — no changes made (${actionable.length} fix${actionable.length !== 1 ? "es" : ""} available)`,
    );
    return;
  }

  // ── Select harden level ──────────────────────────────────────────────────

  const config = new ConfigManager(cwd);
  const savedLevel = config.config?.policies?.hardenLevel ?? "recommended";

  const chosenLevel = autoYes
    ? savedLevel
    : await p.select({
        message: "Apply at which hardening level?",
        options: Object.entries(HARDEN_LEVELS).map(([value, meta]) => ({
          value,
          label: `${meta.label} — ${meta.hint}`,
          hint:
            value === savedLevel
              ? "current project setting"
              : `${meta.severities.join(", ")}`,
        })),
        initialValue: savedLevel,
      });

  if (p.isCancel(chosenLevel)) {
    p.outro(pc.dim("Cancelled"));
    return;
  }

  const allowedSeverities = severitiesForLevel(chosenLevel);

  // ── Select fixes ─────────────────────────────────────────────────────────

  const levelActionable = actionable.filter((f) =>
    allowedSeverities.includes(f.severity),
  );
  const levelSkipped = actionable.filter(
    (f) => !allowedSeverities.includes(f.severity),
  );

  if (levelActionable.length === 0) {
    p.log.success(
      `All ${pc.cyan(chosenLevel)}-level settings are already configured!`,
    );
    if (levelSkipped.length > 0) {
      p.log.info(
        `${levelSkipped.length} finding(s) excluded by level — use ${pc.cyan("strict")} to see them all.`,
      );
    }
    p.outro(`${icons.shield} Fully hardened at ${pc.cyan(chosenLevel)} level`);
    return;
  }

  let selectedFixes;

  if (autoYes) {
    selectedFixes = levelActionable;
    p.log.info(
      `Auto-applying all ${levelActionable.length} ${chosenLevel}-level fixes (--yes)`,
    );
  } else {
    const choices = await p.multiselect({
      message: `Select settings to apply (${pc.cyan(chosenLevel)} level — deselect to skip individual items):`,
      options: levelActionable.map((f) => ({
        value: f,
        label: `${(SEVERITY_BADGE[f.severity] || ((s) => `[${s}]`))(f.severity.toUpperCase())} ${f.fix || f.title}`,
        hint: f._source,
        selected: true,
      })),
    });

    if (p.isCancel(choices)) {
      p.outro(pc.dim("Cancelled"));
      return;
    }
    selectedFixes = choices;
  }

  if (levelSkipped.length > 0 && !autoYes) {
    p.log.info(
      `${levelSkipped.length} finding(s) outside ${pc.cyan(chosenLevel)} level — run ${pc.cyan("pkgwarden harden")} with ${pc.cyan("strict")} to include them.`,
    );
  }

  if (selectedFixes.length === 0) {
    p.outro(pc.dim("No fixes selected"));
    return;
  }

  // ── Apply ─────────────────────────────────────────────────────────────────

  const s = p.spinner();
  s.start("Applying security hardening...");

  const rcFixes = selectedFixes.filter(
    (f) => f._source !== "pnpm-workspace.yaml",
  );
  const wsFixes = selectedFixes.filter(
    (f) => f._source === "pnpm-workspace.yaml",
  );

  const applied = [];

  if (rcFixes.length > 0) {
    const result = analyzer.apply(rcFixes);
    for (const a of result.applied) {
      applied.push({ ...a, file: result.path });
    }
  }

  if (wsFixes.length > 0) {
    const result = analyzer.applyWorkspace(wsFixes);
    if (result) {
      for (const a of result.applied) {
        applied.push({ ...a, file: result.path });
      }
    }
  }

  s.stop(`Applied ${applied.length} fix${applied.length !== 1 ? "es" : ""}`);

  if (applied.length > 0) {
    console.log();
    for (const fix of applied) {
      const shortPath = fix.file.replace(cwd + "/", "");
      console.log(
        `  ${icons.success} ${pc.green(`${fix.key}`)}${typeof fix.value === "boolean" ? `: ${fix.value}` : `=${fix.value}`}  ${pc.dim(shortPath)}`,
      );
    }
  }

  console.log();
  p.outro(
    `${icons.shield} Hardening complete — ${applied.length} setting${applied.length !== 1 ? "s" : ""} secured`,
  );
}
