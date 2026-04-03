import * as p from "@clack/prompts";
import pc from "picocolors";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { printBanner } from "../ui/banner.js";
import { icons, theme } from "../ui/theme.js";
import { ConfigManager } from "../core/config-manager.js";

export async function configCommand(action, options = {}) {
  const cwd = options.cwd || process.cwd();

  printBanner(true);
  console.log();

  const config = new ConfigManager(cwd);

  switch (action) {
    case "show":
      return showConfig(config);
    case "edit":
      return editConfig(config, cwd);
    case "reset":
      return resetConfig(cwd);
    case "path":
      return showPath(config);
    default:
      return showConfig(config);
  }
}

function showConfig(config) {
  p.intro(pc.bgCyan(pc.black(" PKGWARDEN CONFIG ")));

  if (!config.exists) {
    p.log.warn(
      `No config found. Run ${pc.cyan("pkgwarden init")} to create one.`,
    );
    p.outro("");
    return;
  }

  const c = config.config;

  console.log();
  p.log.step(theme.title("Severity"));
  console.log(
    `  ${icons.tee}${icons.line} Threshold: ${pc.cyan(c.severity.threshold)}`,
  );
  console.log(
    `  ${icons.corner}${icons.line} CI Fail:   ${pc.cyan(c.severity.failCI)}`,
  );

  console.log();
  p.log.step(theme.title("Rules"));
  for (const [key, value] of Object.entries(c.rules)) {
    const icon = value ? pc.green("●") : pc.red("○");
    console.log(`  ${icon} ${key}`);
  }

  console.log();
  p.log.step(theme.title("Best Practices"));
  for (const [key, value] of Object.entries(c.bestPractices)) {
    if (typeof value === "boolean") {
      const icon = value ? pc.green("●") : pc.red("○");
      console.log(`  ${icon} ${key}`);
    } else {
      console.log(`  ${icons.dot} ${key}: ${pc.dim(String(value))}`);
    }
  }

  if (c.allowlist.length > 0) {
    console.log();
    p.log.step(theme.title("Allowlist"));
    for (const pkg of c.allowlist) {
      console.log(`  ${icons.success} ${pkg}`);
    }
  }

  if (c.blocklist.length > 0) {
    console.log();
    p.log.step(theme.title("Blocklist"));
    for (const pkg of c.blocklist) {
      console.log(`  ${icons.error} ${pkg}`);
    }
  }

  console.log();
  p.outro(`${icons.shield} Config: ${pc.dim(config.configPath)}`);
}

async function editConfig(config, cwd) {
  p.intro(pc.bgCyan(pc.black(" PKGWARDEN CONFIG — Edit ")));

  if (!config.exists) {
    p.log.warn(`No config found. Run ${pc.cyan("pkgwarden init")} first.`);
    return;
  }

  const section = await p.select({
    message: "What do you want to configure?",
    options: [
      { value: "severity", label: "Severity thresholds" },
      { value: "rules", label: "Detection rules" },
      { value: "practices", label: "Best practice enforcement" },
      { value: "allowlist", label: "Manage allowlist" },
      { value: "blocklist", label: "Manage blocklist" },
    ],
  });

  if (p.isCancel(section)) return;

  const c = { ...config.config };

  if (section === "severity") {
    const threshold = await p.select({
      message: "Block installs at severity:",
      options: [
        { value: "critical", label: "Critical only" },
        { value: "high", label: "High+" },
        { value: "medium", label: "Medium+" },
        { value: "low", label: "All" },
      ],
      initialValue: c.severity.threshold,
    });
    if (!p.isCancel(threshold)) c.severity.threshold = threshold;

    const ciThreshold = await p.select({
      message: "Fail CI at severity:",
      options: [
        { value: "critical", label: "Critical only" },
        { value: "high", label: "High+" },
        { value: "medium", label: "Medium+" },
        { value: "low", label: "All" },
      ],
      initialValue: c.severity.failCI,
    });
    if (!p.isCancel(ciThreshold)) c.severity.failCI = ciThreshold;
  }

  if (section === "rules") {
    const enabled = await p.multiselect({
      message: "Toggle detection rules:",
      options: Object.entries(c.rules).map(([key, val]) => ({
        value: key,
        label: key,
        selected: val,
      })),
    });

    if (!p.isCancel(enabled)) {
      for (const key of Object.keys(c.rules)) {
        c.rules[key] = enabled.includes(key);
      }
    }
  }

  if (section === "allowlist") {
    const action = await p.select({
      message: "Allowlist action:",
      options: [
        { value: "add", label: "Add package" },
        { value: "remove", label: "Remove package" },
        { value: "list", label: "List current" },
      ],
    });

    if (action === "add") {
      const pkg = await p.text({ message: "Package name to allow:" });
      if (!p.isCancel(pkg) && pkg) {
        if (!c.allowlist.includes(pkg)) c.allowlist.push(pkg);
      }
    } else if (action === "remove" && c.allowlist.length > 0) {
      const pkg = await p.select({
        message: "Remove which package?",
        options: c.allowlist.map((p) => ({ value: p, label: p })),
      });
      if (!p.isCancel(pkg)) {
        c.allowlist = c.allowlist.filter((p) => p !== pkg);
      }
    } else if (action === "list") {
      if (c.allowlist.length === 0) {
        p.log.info("Allowlist is empty.");
      } else {
        for (const pkg of c.allowlist) {
          p.log.info(`  ${icons.success} ${pkg}`);
        }
      }
      return;
    }
  }

  if (section === "blocklist") {
    const action = await p.select({
      message: "Blocklist action:",
      options: [
        { value: "add", label: "Add package" },
        { value: "remove", label: "Remove package" },
        { value: "list", label: "List current" },
      ],
    });

    if (action === "add") {
      const pkg = await p.text({ message: "Package name to block:" });
      if (!p.isCancel(pkg) && pkg) {
        if (!c.blocklist.includes(pkg)) c.blocklist.push(pkg);
      }
    } else if (action === "remove" && c.blocklist.length > 0) {
      const pkg = await p.select({
        message: "Remove which package?",
        options: c.blocklist.map((p) => ({ value: p, label: p })),
      });
      if (!p.isCancel(pkg)) {
        c.blocklist = c.blocklist.filter((p) => p !== pkg);
      }
    } else if (action === "list") {
      if (c.blocklist.length === 0) {
        p.log.info("Blocklist is empty.");
      } else {
        for (const pkg of c.blocklist) {
          p.log.info(`  ${icons.error} ${pkg}`);
        }
      }
      return;
    }
  }

  // Write updated config
  const s = p.spinner();
  s.start("Saving config...");
  const content = config.generateConfigContent(c);
  writeFileSync(config.configPath, content, "utf-8");
  s.stop("Configuration saved");

  p.outro(`${icons.success} Config updated`);
}

async function resetConfig(cwd) {
  p.intro(pc.bgCyan(pc.black(" PKGWARDEN CONFIG — Reset ")));

  const confirm = await p.confirm({
    message: "Reset to default configuration?",
    initialValue: false,
  });

  if (p.isCancel(confirm) || !confirm) {
    p.outro(pc.dim("Cancelled"));
    return;
  }

  const config = new ConfigManager(cwd);
  const content = config.generateConfigContent(
    ConfigManager.getDefaultConfig(),
  );
  const configPath = config.configPath || `${cwd}/.pkgwarden.yml`;
  writeFileSync(configPath, content, "utf-8");

  p.outro(`${icons.success} Config reset to defaults`);
}

function showPath(config) {
  if (config.exists) {
    console.log(config.configPath);
  } else {
    console.log("No config file found");
    process.exit(1);
  }
}
