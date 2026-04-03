# ⊙ HEKATE — Guardian of Package Thresholds

```
  ╭───────────────────────────────────────────────────────╮
  │                                                       │
  │   █▀▀█ █▀▀█ █▀▀▀ █  █ █▀▀▀                        │
  │   █▄▄█ █▄▄▀ █ ▀█ █  █ ▀▀▀█                        │
  │   ▀  ▀ ▀ ▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀                        │
  │                                                       │
  │   ⊙  The All-Seeing Package Guardian                 │
  │                                                       │
  ╰───────────────────────────────────────────────────────╯
```

**A security-first CLI proxy for Node.js package managers.** Hekate sits between you and your package manager (npm, yarn, pnpm, bun), performing deep security audits on packages before they are installed and enforcing safer defaults for the repo.

---

## Features

- **Pre-install security scanning** — Downloads and analyzes package source code before installation
- **Malware pattern detection** — Detects suspicious install scripts, obfuscated code, data exfiltration, and more
- **Package manager agnostic** — Auto-detects npm, yarn, pnpm, or bun and delegates installation
- **Interactive & CI modes** — Beautiful terminal UI for humans, JSON output for pipelines
- **Best practice enforcement** — Enforces ignore-scripts, lockfiles, exact versions, engine-strict
- **Configuration wizard** — Interactive setup with `hekate init`
- **Health checks** — `hekate doctor` diagnoses security posture of your project
- **Allowlist/Blocklist** — Fine-grained control over which packages are trusted or forbidden

## Threat Detection Rules

| Rule                | Detects                                             | Severity        |
|---------------------|-----------------------------------------------------|-----------------|
| `install-scripts`   | Suspicious preinstall/postinstall hooks             | High-Critical   |
| `network-access`    | HTTP calls, WebSockets, suspicious URLs             | Medium-Critical |
| `filesystem-access` | Access to .env, .ssh, credentials, etc.             | High-Critical   |
| `code-execution`    | eval(), Function(), child_process                   | High-Critical   |
| `obfuscation`       | Base64 payloads, hex encoding, high-entropy strings | High-Critical   |
| `data-exfiltration` | Env harvesting + network requests combined          | Critical        |

## Installation

```bash
npm install -g hekate-cli
```

Or use without installing:

```bash
npx hekate-cli scan <package-name>
```

## Quick Start

```bash
# Initialize security config for your project
hekate init

# Install packages with security scanning
hekate install express lodash

# Deep scan a package without installing
hekate scan some-unknown-package

# Audit all current dependencies
hekate audit --deep

# Check security health of your project
hekate doctor

# View/edit configuration
hekate config show
hekate config edit
```

## Commands

### `hekate init`

Interactive security configuration wizard. Detects your package manager, lets you choose severity thresholds, enable/disable detection rules, and configure best practices.

### `hekate install [packages...]`

Drop-in replacement for `npm install` / `yarn add` / `pnpm add`. For each package:

1. Downloads the package from the registry
2. Scans source code against all enabled rules
3. Presents findings with severity ratings
4. Lets you decide: install, skip, or add to allowlist
5. Delegates to your actual package manager

```bash
hekate install react                 # Scan and install
hekate install lodash -D             # As devDependency
hekate install express --exact       # Exact version
hekate install --skip-scan           # Skip scanning (install all)
hekate install --ci                  # Non-interactive CI mode
```

### `hekate scan <package>`

Deep analysis of a package without installing it. Shows package metadata, downloads/week, maintainer info, and detailed security findings with a security score.

```bash
hekate scan left-pad
hekate scan some-package --version 2.0.0
hekate scan suspicious-pkg --json    # JSON output for CI
```

### `hekate audit`

Runs both the native package manager audit and Hekate's own static analysis on your dependency tree.

```bash
hekate audit                         # Standard audit
hekate audit --deep                  # Also scan node_modules source code
hekate audit --json --ci             # CI-friendly output
```

### `hekate doctor`

Security health check that examines:
- Hekate configuration
- Package manager setup
- .npmrc security settings (ignore-scripts, engine-strict)
- package.json hygiene (engines, exact versions, lifecycle scripts)
- Repository hygiene (.gitignore, .env exposure)

### `hekate config [action]`

```bash
hekate config show                   # Display current configuration
hekate config edit                   # Interactive config editor
hekate config reset                  # Reset to defaults
hekate config path                   # Print config file path
```

## Configuration

Hekate uses a `.hekate.yml` file in your project root:

```yaml
severity:
  threshold: medium    # Block installs at: low | medium | high | critical
  failCI: high         # Fail CI at: low | medium | high | critical

rules:
  installScripts: true
  networkAccess: true
  filesystemAccess: true
  codeExecution: true
  obfuscation: true
  dataExfiltration: true
  typosquatting: true
  deprecatedPackages: true
  unmaintained: true

bestPractices:
  enforceIgnoreScripts: true
  enforceLockfile: true
  enforceExactVersions: false
  enforceEngineStrict: true
  auditOnInstall: true

allowlist:
  - react
  - express

blocklist:
  - evil-package
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Audit
  run: |
    npx hekate-cli audit --ci --json
```

### CI Mode

When `--ci` flag is set or `CI` environment variable is present:
- All prompts are skipped
- Decisions are made automatically based on configured thresholds
- Output includes JSON for machine parsing
- Exit code is non-zero if threshold is exceeded

## How It Works

1. **Detection** — Auto-detects which package manager your project uses (npm, yarn, pnpm, bun) via lockfiles, `packageManager` field, or config files.

2. **Interception** — When you run `hekate install <pkg>`, Hekate intercepts the request before passing it to your package manager.

3. **Analysis** — Downloads the package tarball, extracts it to a temp directory, and runs all enabled detection rules against the source code.

4. **Decision** — Presents findings to you (interactive) or auto-decides (CI) based on configured severity thresholds.

5. **Delegation** — If approved, delegates the actual installation to your native package manager with all your flags preserved.

## License

MIT
