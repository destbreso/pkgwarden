import { writeFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import * as p from "@clack/prompts";
import pc from "picocolors";
import { printShield } from "../ui/banner.js";
import { icons, theme } from "../ui/theme.js";
import { ConfigManager } from "../core/config-manager.js";
import { PackageManager } from "../core/package-manager.js";
import { RcAnalyzer } from "../core/rc-analyzer.js";

export async function initCommand(options = {}) {
  const cwd = options.cwd || process.cwd();

  printShield();
  console.log();

  p.intro(
    pc.bgCyan(pc.black(" PKGWARDEN INIT — Security Configuration Wizard ")),
  );

  // Check if already initialized
  const existingConfig = new ConfigManager(cwd);
  if (existingConfig.exists) {
    const overwrite = await p.confirm({
      message: `pkgwarden config already exists at ${pc.dim(existingConfig.configPath)}. Overwrite?`,
      initialValue: false,
    });

    if (p.isCancel(overwrite) || !overwrite) {
      p.outro(pc.dim("Init cancelled."));
      return;
    }
  }

  // Detect package manager
  const pm = new PackageManager(cwd);
  p.log.info(
    `${icons.eye} Package manager detected: ${theme.highlight(pm.name)} ${pc.dim(`(v${pm.getVersion()})`)}`,
  );

  // Interactive configuration
  const severity = await p.select({
    message: "Security threshold — block installs at what severity?",
    options: [
      {
        value: "critical",
        label: "Critical only",
        hint: "Only block critical threats",
      },
      { value: "high", label: "High and above", hint: "Block high + critical" },
      {
        value: "medium",
        label: "Medium and above",
        hint: "Recommended — block medium+",
      },
      {
        value: "low",
        label: "Everything",
        hint: "Paranoid mode — block all findings",
      },
    ],
    initialValue: "medium",
  });
  if (p.isCancel(severity)) return p.outro(pc.dim("Cancelled."));

  const ciSeverity = await p.select({
    message: "CI/CD threshold — fail pipeline at what severity?",
    options: [
      { value: "critical", label: "Critical only" },
      { value: "high", label: "High and above", hint: "Recommended" },
      { value: "medium", label: "Medium and above" },
      { value: "low", label: "Everything" },
    ],
    initialValue: "high",
  });
  if (p.isCancel(ciSeverity)) return p.outro(pc.dim("Cancelled."));

  const enabledRules = await p.multiselect({
    message: "Which security rules should be active?",
    options: [
      {
        value: "installScripts",
        label: "Install Scripts",
        hint: "Detect suspicious lifecycle scripts",
        selected: true,
      },
      {
        value: "networkAccess",
        label: "Network Access",
        hint: "Detect network calls in packages",
        selected: true,
      },
      {
        value: "filesystemAccess",
        label: "Filesystem Access",
        hint: "Detect sensitive file operations",
        selected: true,
      },
      {
        value: "codeExecution",
        label: "Code Execution",
        hint: "Detect eval, child_process, etc.",
        selected: true,
      },
      {
        value: "obfuscation",
        label: "Obfuscation",
        hint: "Detect obfuscated/encoded code",
        selected: true,
      },
      {
        value: "dataExfiltration",
        label: "Data Exfiltration",
        hint: "Detect data theft patterns",
        selected: true,
      },
      {
        value: "typosquatting",
        label: "Typosquatting",
        hint: "Check for name confusion",
        selected: true,
      },
      {
        value: "hiddenChars",
        label: "Hidden Characters",
        hint: "Detect invisible Unicode, bidi overrides, homoglyphs",
        selected: true,
      },
      {
        value: "deprecatedPackages",
        label: "Deprecated Packages",
        hint: "Warn about deprecated packages",
        selected: true,
      },
      {
        value: "unmaintained",
        label: "Unmaintained",
        hint: "Warn about stale packages",
        selected: true,
      },
    ],
    required: true,
  });
  if (p.isCancel(enabledRules)) return p.outro(pc.dim("Cancelled."));

  const policies = await p.group(
    {
      enforceRcSecurity: () =>
        p.confirm({
          message: `Enforce ${pc.cyan("RC security settings")} for ${pm.name}?`,
          initialValue: true,
        }),
      lockfile: () =>
        p.confirm({
          message: `Enforce lockfile presence?`,
          initialValue: true,
        }),
      exactVersions: () =>
        p.confirm({
          message: `Enforce exact versions (no ^ or ~)?`,
          initialValue: false,
        }),
      auditOnInstall: () =>
        p.confirm({
          message: `Run security audit automatically on install?`,
          initialValue: true,
        }),
    },
    {
      onCancel: () => {
        p.cancel("Cancelled.");
        process.exit(0);
      },
    },
  );

  // Build config
  const rules = {};
  const allRules = [
    "installScripts",
    "networkAccess",
    "filesystemAccess",
    "codeExecution",
    "obfuscation",
    "dataExfiltration",
    "typosquatting",
    "hiddenChars",
    "deprecatedPackages",
    "unmaintained",
  ];
  for (const rule of allRules) {
    rules[rule] = enabledRules.includes(rule);
  }

  const configOverrides = {
    severity: { threshold: severity, failCI: ciSeverity },
    rules,
    policies: {
      enforceRcSecurity: policies.enforceRcSecurity,
      enforceLockfile: policies.lockfile,
      enforceExactVersions: policies.exactVersions,
      auditOnInstall: policies.auditOnInstall,
      registryUrl: "https://registry.npmjs.org/",
    },
  };

  const s = p.spinner();

  // Write config file
  s.start("Writing pkgwarden configuration...");
  const configContent = existingConfig.generateConfigContent(configOverrides);
  const configPath = join(cwd, ".pkgwarden.yml");
  writeFileSync(configPath, configContent, "utf-8");
  s.stop("Configuration written to .pkgwarden.yml");

  // Apply RC security settings via RC analyzer
  if (policies.enforceRcSecurity) {
    s.start(`Applying security settings to ${pm.name} RC file...`);
    const rcAnalyzer = new RcAnalyzer(cwd, pm.name);
    const { path: rcPath, applied } = rcAnalyzer.apply();
    if (applied.length > 0) {
      s.stop(
        `Applied ${applied.length} security setting(s) to ${rcPath.split("/").pop()}`,
      );
    } else {
      s.stop("RC file already has recommended security settings");
    }
  }

  // Summary
  console.log();
  p.note(
    [
      `${pc.green("✔")} Config file:     ${pc.cyan(".pkgwarden.yml")}`,
      `${pc.green("✔")} Package manager:  ${pc.cyan(pm.name)}`,
      `${pc.green("✔")} Severity block:   ${pc.cyan(severity)}`,
      `${pc.green("✔")} CI threshold:     ${pc.cyan(ciSeverity)}`,
      `${pc.green("✔")} Active rules:     ${pc.cyan(enabledRules.length)}/${allRules.length}`,
      `${pc.green("✔")} RC hardened:      ${pc.cyan(policies.enforceRcSecurity ? "yes" : "no")}`,
      "",
      `${pc.dim("Usage:")}`,
      `  ${pc.cyan("pkgwarden install <pkg>")}  Secure install with scanning`,
      `  ${pc.cyan("pkgwarden audit")}          Deep audit of dependencies`,
      `  ${pc.cyan("pkgwarden scan <pkg>")}     Scan package without installing`,
      `  ${pc.cyan("pkgwarden doctor")}         Check security health`,
    ].join("\n"),
    "Setup Complete",
  );

  p.outro(`${icons.shield} pkgwarden is now guarding your dependencies.`);
}
