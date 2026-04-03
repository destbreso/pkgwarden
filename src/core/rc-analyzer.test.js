/**
 * Tests for RcAnalyzer — validates that security practices are detected and
 * applied correctly for npm, yarn, pnpm, and bun config files.
 *
 * Uses Node.js built-in test runner (node:test).
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  existsSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { RcAnalyzer } from "./rc-analyzer.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeTmpDir() {
  return mkdtempSync(join(tmpdir(), "pkgw-test-"));
}

// ─── npm (.npmrc) ─────────────────────────────────────────────────────────────

describe("RcAnalyzer — npm", () => {
  let dir;

  before(() => {
    dir = makeTmpDir();
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reports missing .npmrc as findings", () => {
    const analyzer = new RcAnalyzer(dir, "npm");
    const result = analyzer.analyze();
    // No file — should report "no .npmrc found" finding
    assert.ok(result.findings.length > 0);
    assert.ok(!result.exists);
  });

  it("detects missing ignore-scripts", () => {
    writeFileSync(join(dir, ".npmrc"), "save-exact=true\n");
    const analyzer = new RcAnalyzer(dir, "npm");
    const result = analyzer.analyze();
    const missing = result.findings.filter(
      (f) => f.key === "ignore-scripts" && f.status === "missing",
    );
    assert.ok(missing.length > 0, "should flag ignore-scripts as missing");
  });

  it("detects correctly set ignore-scripts as pass", () => {
    writeFileSync(
      join(dir, ".npmrc"),
      "ignore-scripts=true\nsave-exact=true\n",
    );
    const analyzer = new RcAnalyzer(dir, "npm");
    const result = analyzer.analyze();
    const pass = result.findings.filter(
      (f) => f.key === "ignore-scripts" && f.status === "pass",
    );
    assert.ok(pass.length > 0, "should pass ignore-scripts");
  });

  it("getRecommendedSettings returns npm practices", () => {
    const analyzer = new RcAnalyzer(dir, "npm");
    const settings = analyzer.getRecommendedSettings();
    assert.ok(settings.length > 0);
    const keys = settings.map((s) => s.key);
    assert.ok(keys.includes("ignore-scripts"));
    assert.ok(keys.includes("save-exact"));
  });

  it("apply() creates .npmrc with security settings", () => {
    const freshDir = makeTmpDir();
    try {
      const analyzer = new RcAnalyzer(freshDir, "npm");
      const { applied } = analyzer.apply();
      assert.ok(applied.length > 0, "should apply settings");
      const content = readFileSync(join(freshDir, ".npmrc"), "utf-8");
      assert.ok(
        content.includes("ignore-scripts=true"),
        "ignore-scripts should be set",
      );
      assert.ok(
        content.includes("save-exact=true"),
        "save-exact should be set",
      );
    } finally {
      rmSync(freshDir, { recursive: true, force: true });
    }
  });

  it("apply() skips already-correct settings", () => {
    const freshDir = makeTmpDir();
    try {
      writeFileSync(
        join(freshDir, ".npmrc"),
        "ignore-scripts=true\nsave-exact=true\n",
      );
      const analyzer = new RcAnalyzer(freshDir, "npm");
      const { applied } = analyzer.apply();
      const appliedKeys = applied.map((a) => a.key);
      assert.ok(
        !appliedKeys.includes("ignore-scripts"),
        "should skip ignore-scripts (already set)",
      );
      assert.ok(
        !appliedKeys.includes("save-exact"),
        "should skip save-exact (already set)",
      );
    } finally {
      rmSync(freshDir, { recursive: true, force: true });
    }
  });
});

// ─── yarn (.yarnrc.yml) ───────────────────────────────────────────────────────

describe("RcAnalyzer — yarn", () => {
  let dir;

  before(() => {
    dir = makeTmpDir();
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reports missing .yarnrc.yml as finding", () => {
    const analyzer = new RcAnalyzer(dir, "yarn");
    const result = analyzer.analyze();
    assert.ok(result.findings.length > 0);
    assert.ok(!result.exists);
  });

  it("detects enableScripts: true as wrong", () => {
    writeFileSync(join(dir, ".yarnrc.yml"), "enableScripts: true\n");
    const analyzer = new RcAnalyzer(dir, "yarn");
    const result = analyzer.analyze();
    const wrong = result.findings.filter(
      (f) => f.key === "enableScripts" && f.status === "wrong",
    );
    assert.ok(
      wrong.length > 0,
      "enableScripts: true should be flagged as wrong",
    );
    assert.equal(wrong[0].severity, "high");
  });

  it("detects enableScripts: false as pass", () => {
    writeFileSync(join(dir, ".yarnrc.yml"), "enableScripts: false\n");
    const analyzer = new RcAnalyzer(dir, "yarn");
    const result = analyzer.analyze();
    const pass = result.findings.filter(
      (f) => f.key === "enableScripts" && f.status === "pass",
    );
    assert.ok(pass.length > 0, "enableScripts: false should pass");
  });

  it("excludes npmMinimalAgeGate for Yarn < 4.10", () => {
    writeFileSync(join(dir, ".yarnrc.yml"), "enableScripts: false\n");
    const analyzer = new RcAnalyzer(dir, "yarn", "4.9.1");
    const settings = analyzer.getRecommendedSettings();
    const keys = settings.map((s) => s.key);
    assert.ok(
      !keys.includes("npmMinimalAgeGate"),
      "Yarn 4.9.1 should not include npmMinimalAgeGate",
    );
  });

  it("includes npmMinimalAgeGate for Yarn >= 4.10", () => {
    writeFileSync(join(dir, ".yarnrc.yml"), "enableScripts: false\n");
    const analyzer = new RcAnalyzer(dir, "yarn", "4.10.0");
    const settings = analyzer.getRecommendedSettings();
    const keys = settings.map((s) => s.key);
    assert.ok(
      keys.includes("npmMinimalAgeGate"),
      "Yarn 4.10.0 should include npmMinimalAgeGate",
    );
  });

  it("does not apply npmMinimalAgeGate for Yarn < 4.10", () => {
    const freshDir = makeTmpDir();
    try {
      const analyzer = new RcAnalyzer(freshDir, "yarn", "4.9.1");
      analyzer.apply();
      const rcPath = join(freshDir, ".yarnrc.yml");
      if (existsSync(rcPath)) {
        const content = readFileSync(rcPath, "utf-8");
        assert.ok(
          !content.includes("npmMinimalAgeGate"),
          "should not write npmMinimalAgeGate",
        );
      }
    } finally {
      rmSync(freshDir, { recursive: true, force: true });
    }
  });

  it("detects enableStrictSsl: false as danger", () => {
    writeFileSync(join(dir, ".yarnrc.yml"), "enableStrictSsl: false\n");
    const analyzer = new RcAnalyzer(dir, "yarn");
    const result = analyzer.analyze();
    const danger = result.findings.filter((f) => f.status === "danger");
    assert.ok(danger.length > 0, "enableStrictSsl: false should be danger");
  });
});

// ─── pnpm (.npmrc) ────────────────────────────────────────────────────────────

describe("RcAnalyzer — pnpm", () => {
  let dir;

  before(() => {
    dir = makeTmpDir();
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("getRecommendedSettings has pnpm-specific keys", () => {
    const analyzer = new RcAnalyzer(dir, "pnpm");
    const settings = analyzer.getRecommendedSettings();
    const keys = settings.map((s) => s.key);
    assert.ok(keys.includes("engine-strict"), "pnpm should have engine-strict");
    assert.ok(keys.includes("save-exact"), "pnpm should have save-exact");
    // pnpm should NOT have npm-specific keys like ignore-scripts
    assert.ok(
      !keys.includes("ignore-scripts"),
      "pnpm .npmrc should not have ignore-scripts",
    );
  });

  it("getRcPath returns .npmrc", () => {
    const analyzer = new RcAnalyzer(dir, "pnpm");
    assert.ok(analyzer.getRcPath().endsWith(".npmrc"));
  });
});

// ─── bun (bunfig.toml) ───────────────────────────────────────────────────────

describe("RcAnalyzer — bun", () => {
  let dir;

  before(() => {
    dir = makeTmpDir();
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reports missing bunfig.toml as finding", () => {
    const analyzer = new RcAnalyzer(dir, "bun");
    const result = analyzer.analyze();
    assert.ok(result.findings.length > 0);
    assert.ok(!result.exists);
  });

  it("getRecommendedSettings has bun-specific keys", () => {
    const analyzer = new RcAnalyzer(dir, "bun");
    const settings = analyzer.getRecommendedSettings();
    const keys = settings.map((s) => s.key);
    assert.ok(
      keys.includes("lifecycleScripts"),
      "bun should have lifecycleScripts",
    );
    assert.ok(
      keys.includes("minimumReleaseAge"),
      "bun should have minimumReleaseAge",
    );
  });

  it("getRcPath returns bunfig.toml", () => {
    const analyzer = new RcAnalyzer(dir, "bun");
    assert.ok(analyzer.getRcPath().endsWith("bunfig.toml"));
  });
});
