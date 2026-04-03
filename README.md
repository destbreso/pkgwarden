# ⊙ PKGWARDEN

```
  ╭───────────────────────────────────────────────────────╮
  │                                                       │
  │   ██████╗ ██╗  ██╗  ██████╗  ██╗    ██╗               │
  │   ██╔══██╗██║ ██╔╝ ██╔════╝  ██║    ██║               │
  │   ██████╔╝█████╔╝  ██║  ███╗ ██║ █╗ ██║               │
  │   ██╔═══╝ ██╔═██╗  ██║   ██║ ██║███╗██║               │
  │   ██║     ██║  ██╗ ╚██████╔╝ ╚███╔███╔╝               │
  │   ╚═╝     ╚═╝  ╚═╝  ╚═════╝   ╚══╝╚══╝                │
  │                                                       │
  │   ⊙  Package Guardian · Audit · Detect                │
  │                                                       │
  ╰───────────────────────────────────────────────────────╯
```

**Package Guardian With Auditing, Reporting & Detection.**

A security-first CLI that sits between you and your package manager (npm, yarn, pnpm), performing deep security audits on every package before it touches your project. Scans source code for malware patterns, enforces security policies via RC files, detects typosquatting, compares version diffs for injected threats, and works both interactively and in CI/CD pipelines.

---

## Why PKGWARDEN?

Supply chain attacks are one of the fastest-growing threat vectors in the JavaScript ecosystem. Malicious packages routinely land on npm — stealing tokens, exfiltrating environment variables, executing reverse shells, or injecting cryptominers. By the time `postinstall` runs, it's already too late.

PKGWARDEN intercepts **before** installation, downloads the tarball to a sandbox, runs 7+ detection rules against the source code, checks registry metadata for anomalies, and only delegates to your package manager if the package passes inspection.

---

## Features

- **Pre-install deep scanning** — Downloads tarball, extracts, and scans every source file before installation
- **7 detection rules** — Install scripts, network access, filesystem access, code execution, obfuscation, data exfiltration, hidden Unicode characters
- **Typosquatting detection** — Levenshtein distance, prefix/suffix manipulation, separator confusion against ~130 popular packages
- **Registry intelligence** — Publish age, download count, version history, maintainer/publisher mismatch, rapid publishing detection
- **Version diff analysis** — Compare any two versions of a package and scan the delta for injected attack patterns
- **RC hardening** — Audits and auto-fixes `.npmrc` / `.yarnrc.yml` / `pnpm-workspace.yaml` / `bunfig.toml` against 20+ security best practices, with per-practice severity levels and reference links
- **Package manager agnostic** — Auto-detects npm, Yarn Berry, pnpm, or bun via `packageManager` field or lockfiles
- **Interactive & CI modes** — Beautiful terminal UI with `@clack/prompts` for humans, JSON output with exit codes for pipelines
- **Severity filtering & pagination** — Filter findings by severity level, paginate large result sets
- **Lightweight bulk scanning** — Memory-efficient mode for scanning all `package.json` dependencies on bare install (no OOM on large projects)
- **Allowlist / Blocklist** — Fine-grained control over trusted and forbidden packages
- **Transitive dependency scanning** — Checks direct dependencies (1 level) for install scripts and typosquatting
- **SHA-1 integrity verification** — Validates tarball checksums against registry values

---

## Installation

```bash
npm install -g pkgwarden
```

Or use without installing:

```bash
npx pkgwarden scan <package-name>
```

---

## Quick Start

```bash
# Initialize security config for your project
pkgwarden init

# Install packages with pre-install security scanning
pkgwarden install express lodash

# Bare install — scans ALL package.json deps before installing
pkgwarden install

# Deep scan a package without installing
pkgwarden scan some-unknown-package

# Interactive scan with version picker
pkgwarden scan express          # Prompts you to select from last 20 versions

# Compare two versions of a package for injected threats
pkgwarden diff axios
pkgwarden diff lodash --target 4.17.20 --show-diff

# Audit and auto-fix PM config security (npm/yarn/pnpm/bun)
pkgwarden harden

# Audit all current dependencies
pkgwarden audit --deep

# Check security health of your project
pkgwarden doctor

# View/edit configuration
pkgwarden config show
```

---

## Commands

### `pkgwarden init`

Interactive security configuration wizard. Detects your package manager, lets you choose severity thresholds, enable/disable detection rules, configure policies, and writes security settings directly to your PM's RC file.

```bash
pkgwarden init
```

### `pkgwarden install [packages...]`

Drop-in replacement for `npm install` / `yarn add` / `pnpm add`.

**With packages specified** — scans each package individually:
1. Checks blocklist/allowlist
2. Downloads tarball and scans source code against all enabled rules
3. Runs typosquatting analysis and registry intelligence checks
4. Presents findings with severity ratings
5. Interactive: choose to install, force-install, or skip
6. Delegates to your native package manager

**Bare install (no packages)** — pre-install security gate:
1. RC security pre-check (enforces `ignore-scripts`, `strict-ssl`, etc.)
2. Native package manager audit
3. Lightweight scan of ALL dependencies from `package.json`
4. Interactive/CI gate if issues found
5. Proceeds with actual install

```bash
pkgwarden install react               # Scan and install
pkgwarden install lodash -D            # As devDependency
pkgwarden install express -E           # Exact version
pkgwarden install --skip-scan          # Skip scanning
pkgwarden install --ci                 # Non-interactive CI mode
pkgwarden install --force              # Force install despite findings
```

### `pkgwarden scan <package>`

Deep analysis of a package without installing it. Shows package metadata, downloads/week, maintainer info, and detailed security findings with severity filtering and pagination.

In interactive mode, an **version picker** lets you select from the last 20 published versions (with dates and dist-tags) before scanning.

```bash
pkgwarden scan left-pad                          # Interactive version picker
pkgwarden scan some-package --version 2.0.0      # Specific version
pkgwarden scan suspicious-pkg --severity high    # Only high+ findings
pkgwarden scan suspicious-pkg --page-size 5      # Paginate output
pkgwarden scan suspicious-pkg --json --ci        # JSON output for CI
```

### `pkgwarden diff <package>`

Compare any version of a package against its previous version. Downloads both tarballs, computes a file-by-file diff, shows manifest changes (scripts, dependencies, metadata), and scans _only the new/changed code_ for 13 attack patterns.

In interactive mode, you pick the version from a selector showing the last 20 versions with dates and dist-tags.

```bash
pkgwarden diff axios                          # Interactive version picker
pkgwarden diff express --target 4.21.2        # Specific version
pkgwarden diff lodash -t 4.17.21 --show-diff  # Show code-level diffs
pkgwarden diff react --ci --json              # CI mode with JSON
```

**Diff attack patterns detected:**

| Pattern                | Severity | Description                                          |
|------------------------|----------|------------------------------------------------------|
| New install script     | Critical | `preinstall`/`postinstall` hooks added or changed    |
| eval/exec usage        | Critical | `eval()`, `new Function()`, `child_process`          |
| Data exfiltration      | Critical | DNS + env access, network + system info              |
| Cryptominer references | Critical | `stratum+tcp`, `coinhive`, `xmrig`                   |
| Network calls          | High     | New HTTP requests, WebSocket connections             |
| Filesystem writes      | High     | `writeFileSync`, `fs.unlink`, `createWriteStream`    |
| Base64 decoding        | High     | `Buffer.from(..., 'base64')`, `atob()` with payloads |
| Code obfuscation       | High     | Hex/Unicode escape sequences, `String.fromCharCode`  |
| Hidden Unicode         | High     | Zero-width chars, bidirectional overrides            |
| Minified replacement   | Medium   | Readable code replaced with minified version         |
| New dependencies       | Medium   | Dependencies added to `package.json`                 |
| Many new deps          | High     | 5+ dependencies added at once                        |
| Env variable access    | Medium   | `process.env.SECRET`, `process.env.TOKEN`            |

### `pkgwarden audit`

Runs both the native package manager audit (known CVEs) and pkgwarden's own static analysis on your dependency tree.

```bash
pkgwarden audit                          # Standard audit
pkgwarden audit --deep                   # Also scan node_modules source
pkgwarden audit --json --ci              # CI-friendly output
```

### `pkgwarden doctor`

Security health check. Uses the RC Analyzer to audit your package manager configuration for security best practices. Shows a per-setting pass/warn/fail with an overall health score.

Checks include:
- `ignore-scripts` / `enableScripts` configuration
- `strict-ssl` / `enableStrictSsl` enforcement
- `engine-strict` / `checksumBehavior` settings
- Token exposure in RC files
- Lockfile presence
- Package.json hygiene

```bash
pkgwarden doctor
```

---

### `pkgwarden harden`

Audits your package manager's configuration files against 20+ security best practices from the [npm security best practices guide](https://github.com/lirantal/npm-security-best-practices) and applies fixes interactively.

Supports all four package managers with their respective config files:

| PM   | Config file                      | Rules enforced                                                         |
|------|----------------------------------|------------------------------------------------------------------------|
| npm  | `.npmrc`                         | `ignore-scripts`, `allow-git=none`, `min-release-age`, 7 more          |
| pnpm | `.npmrc` + `pnpm-workspace.yaml` | `engine-strict`, `strictDepBuilds`, `trustPolicy`, 3 more              |
| yarn | `.yarnrc.yml`                    | `enableScripts`, `checksumBehavior`, `enableImmutableInstalls`, 2 more |
| bun  | `bunfig.toml`                    | `lifecycleScripts=false`, `minimumReleaseAge`                          |

Findings are grouped by severity and each comes with a reference link to the relevant section of the security guide.

```bash
pkgwarden harden                  # Interactive — pick which fixes to apply
pkgwarden harden --yes            # Auto-apply all at your configured level
pkgwarden harden --dry-run        # Show findings only, don't change files
pkgwarden harden --json           # Machine-readable output
```

**Harden levels** (set during `pkgwarden init` or saved in `.pkgwarden.yml`):

| Level         | Severities applied                 |
|---------------|------------------------------------|
| `minimal`     | Critical + High only               |
| `recommended` | Critical + High + Medium (default) |
| `strict`      | All (including Low)                |

> **Note on `npmMinimalAgeGate`:** This Yarn Berry setting requires Yarn ≥ 4.10.0. PKGWARDEN automatically detects your Yarn version and only recommends this setting if your version supports it.

### `pkgwarden config [action]`

```bash
pkgwarden config show      # Display current configuration
pkgwarden config edit      # Interactive config editor
pkgwarden config reset     # Reset to defaults
pkgwarden config path      # Print config file path
```

---

## Threat Detection Rules

| Rule                  | ID                  | Detects                                                                                                                   | Severity        |
|-----------------------|---------------------|---------------------------------------------------------------------------------------------------------------------------|-----------------|
| Install Scripts       | `install-scripts`   | Suspicious `preinstall`/`postinstall` lifecycle hooks                                                                     | Medium–Critical |
| Network Access        | `network-access`    | HTTP/HTTPS imports, `fetch()`, WebSocket, suspicious URLs (pastebin, ngrok, discord webhooks), hardcoded IPs              | Medium–Critical |
| Filesystem Access     | `filesystem-access` | Access to `.env`, `.ssh`, `.npmrc`, `/etc/passwd`, AWS/Kube credentials, home directory reads                             | High–Critical   |
| Code Execution        | `code-execution`    | `eval()`, `new Function()`, `child_process`, `vm.runInContext`, `process.binding`                                         | Medium–Critical |
| Obfuscation           | `obfuscation`       | Base64 payloads, hex/unicode encoded strings, `String.fromCharCode`, hex arithmetic, high-entropy strings                 | Medium–Critical |
| Data Exfiltration     | `data-exfiltration` | `JSON.stringify(process.env)`, env enumeration, `fetch` + `POST` combined, DNS exfiltration, system info collection       | Medium–Critical |
| Hidden Characters     | `hidden-chars`      | Zero-width Unicode (U+200B–U+206F), bidirectional overrides (Trojan Source CVE-2021-42574), Cyrillic/fullwidth homoglyphs | High–Critical   |
| Typosquatting         | _(integrated)_      | Levenshtein distance, prefix/suffix manipulation, transposition, separator confusion against ~130 popular packages        | Medium–High     |
| Registry Intelligence | _(integrated)_      | Publish age, package creation age, version count, rapid publishing, download count, publisher/maintainer mismatch         | Low–High        |

---

## Configuration

PKGWARDEN uses a `.pkgwarden.yml` file in your project root:

```yaml
severity:
  threshold: medium          # Block installs at: low | medium | high | critical
  failCI: high               # Fail CI at: low | medium | high | critical

rules:
  installScripts: true
  networkAccess: true
  filesystemAccess: true
  codeExecution: true
  obfuscation: true
  dataExfiltration: true
  hiddenChars: true
  typosquatting: true
  deprecatedPackages: true
  unmaintained: true

policies:
  enforceRcSecurity: true    # Audit .npmrc/.yarnrc.yml for security settings
  enforceLockfile: true       # Require a lockfile
  enforceExactVersions: false # Require exact (pinned) versions
  auditOnInstall: true        # Run native audit on bare install
  registryUrl: "https://registry.npmjs.org/"
  hardenLevel: recommended    # Harden level: minimal | recommended | strict

allowlist:
  - react
  - express
  - lodash

blocklist:
  - evil-package

ignorePatterns:
  - "*.test.js"
  - "__tests__"
```

Generate it interactively:

```bash
pkgwarden init
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install pkgwarden
        run: npm install -g pkgwarden

      - name: Audit dependencies
        run: pkgwarden audit --ci --json

      - name: Scan new dependencies
        run: pkgwarden install --ci
```

### CI Mode Behavior

When `--ci` is set or the `CI` environment variable is present:
- All prompts are skipped
- Decisions are made automatically based on `severity.failCI` threshold
- JSON output is available for machine parsing
- Exit code is non-zero if threshold is exceeded

---

## How It Works

```
                    ┌──────────────┐
                    │  pkgwarden   │
                    │   install    │
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │  RC Security Pre-check  │
              │  (.npmrc / .yarnrc.yml) │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Blocklist / Allowlist │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Typosquatting Analysis │
              │  (Levenshtein + more)   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Registry Intelligence  │
              │  (age, downloads, etc.) │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Download & Extract     │
              │  Tarball → Temp Dir     │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  SHA-1 Integrity Check  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Source Code Scan       │
              │  (7 detection rules)    │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Transitive Dep Check   │
              │  (1 level deep)         │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Findings → Decision    │
              │  (interactive or CI)    │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  Delegate to PM         │
              │  (npm/yarn/pnpm)        │
              └─────────────────────────┘
```

---

## Supported Package Managers

| Package Manager     | Detection                   | Install       | Audit            | RC Analysis                      |
|---------------------|-----------------------------|---------------|------------------|----------------------------------|
| **npm**             | `package-lock.json`         | `npm install` | `npm audit`      | `.npmrc` (10 rules)              |
| **Yarn Berry (2+)** | `yarn.lock` + `.yarnrc.yml` | `yarn add`    | `yarn npm audit` | `.yarnrc.yml` (5–6 rules)        |
| **pnpm**            | `pnpm-lock.yaml`            | `pnpm add`    | `pnpm audit`     | `.npmrc` + `pnpm-workspace.yaml` |
| **bun**             | `bun.lockb` / `bun.lock`    | `bun add`     | —                | `bunfig.toml` (2 rules)          |

---

## Requirements

- Node.js >= 18.0.0
- `tar` command available in PATH (for tarball extraction)

---

## License

MIT
