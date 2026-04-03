import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { execSync, spawn } from "node:child_process";

const PM_LOCK_FILES = {
  "pnpm-lock.yaml": "pnpm",
  "yarn.lock": "yarn",
  "bun.lockb": "bun",
  "bun.lock": "bun",
  "package-lock.json": "npm",
};

const PM_CONFIG_FILES = {
  ".npmrc": "npm",
  ".yarnrc.yml": "yarn",
  ".yarnrc": "yarn",
  ".pnpmrc": "pnpm",
};

export class PackageManager {
  #name;
  #cwd;

  constructor(cwd = process.cwd()) {
    this.#cwd = cwd;
    this.#name = this.#detect();
  }

  get name() {
    return this.#name;
  }

  get cwd() {
    return this.#cwd;
  }

  #detect() {
    // 1. Check packageManager field in package.json
    const pkgPath = join(this.#cwd, "package.json");
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
        if (pkg.packageManager) {
          const match = pkg.packageManager.match(/^(npm|yarn|pnpm|bun)@/);
          if (match) return match[1];
        }
      } catch {}
    }

    // 2. Check lock files
    for (const [file, pm] of Object.entries(PM_LOCK_FILES)) {
      if (existsSync(join(this.#cwd, file))) {
        return pm;
      }
    }

    // 3. Default to npm
    return "npm";
  }

  getInstallCommand(packages = [], flags = {}) {
    const pm = this.#name;
    const args = [];

    if (packages.length === 0) {
      // Install all dependencies
      args.push(pm, "install");
    } else {
      // Install specific packages
      switch (pm) {
        case "npm":
          args.push("npm", "install", ...packages);
          break;
        case "yarn":
          args.push("yarn", "add", ...packages);
          break;
        case "pnpm":
          args.push("pnpm", "add", ...packages);
          break;
        case "bun":
          args.push("bun", "add", ...packages);
          break;
      }
    }

    if (flags.dev) {
      switch (pm) {
        case "npm":
          args.push("--save-dev");
          break;
        case "yarn":
          args.push("--dev");
          break;
        case "pnpm":
          args.push("--save-dev");
          break;
        case "bun":
          args.push("--dev");
          break;
      }
    }

    if (flags.exact) {
      switch (pm) {
        case "npm":
          args.push("--save-exact");
          break;
        case "yarn":
          args.push("--exact");
          break;
        case "pnpm":
          args.push("--save-exact");
          break;
        case "bun":
          args.push("--exact");
          break;
      }
    }

    if (flags.ignoreScripts) {
      args.push("--ignore-scripts");
    }

    return args;
  }

  getAuditCommand() {
    switch (this.#name) {
      case "npm":
        return ["npm", "audit", "--json"];
      case "yarn":
        return ["yarn", "audit", "--json"];
      case "pnpm":
        return ["pnpm", "audit", "--json"];
      case "bun":
        return ["bun", "pm", "audit"];
      default:
        return ["npm", "audit", "--json"];
    }
  }

  async exec(args, { stdio = "inherit" } = {}) {
    const [cmd, ...rest] = args;
    return new Promise((resolve, reject) => {
      const child = spawn(cmd, rest, {
        cwd: this.#cwd,
        stdio,
        shell: true,
      });

      let stdout = "";
      let stderr = "";

      if (stdio === "pipe") {
        child.stdout?.on("data", (data) => {
          stdout += data;
        });
        child.stderr?.on("data", (data) => {
          stderr += data;
        });
      }

      child.on("close", (code) => {
        if (code === 0) {
          resolve({ stdout, stderr, code });
        } else {
          resolve({ stdout, stderr, code });
        }
      });

      child.on("error", reject);
    });
  }

  async runInstall(packages = [], flags = {}) {
    const args = this.getInstallCommand(packages, flags);
    return this.exec(args);
  }

  async runAudit() {
    const args = this.getAuditCommand();
    return this.exec(args, { stdio: "pipe" });
  }

  getConfigPath() {
    switch (this.#name) {
      case "npm":
        return join(this.#cwd, ".npmrc");
      case "yarn":
        return join(this.#cwd, ".yarnrc.yml");
      case "pnpm":
        return join(this.#cwd, ".npmrc");
      default:
        return join(this.#cwd, ".npmrc");
    }
  }

  getLockfilePath() {
    for (const [file, pm] of Object.entries(PM_LOCK_FILES)) {
      if (pm === this.#name) {
        return join(this.#cwd, file);
      }
    }
    return null;
  }

  isAvailable() {
    try {
      execSync(`${this.#name} --version`, { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  }

  getVersion() {
    try {
      return execSync(`${this.#name} --version`, { encoding: "utf-8" }).trim();
    } catch {
      return null;
    }
  }
}
