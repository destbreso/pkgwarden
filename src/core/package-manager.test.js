/**
 * Tests for PackageManager detection logic.
 *
 * Uses Node.js built-in test runner (node:test).
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { PackageManager } from "./package-manager.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeTmpDir() {
  return mkdtempSync(join(tmpdir(), "pkgw-pm-test-"));
}

function writePkg(dir, content) {
  writeFileSync(join(dir, "package.json"), JSON.stringify(content, null, 2));
}

// ─── Detection via packageManager field ──────────────────────────────────────

describe("PackageManager — packageManager field detection", () => {
  let dir;

  before(() => {
    dir = makeTmpDir();
  });
  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("detects npm from packageManager field", () => {
    writePkg(dir, { name: "test", packageManager: "npm@10.9.2" });
    const pm = new PackageManager(dir);
    assert.equal(pm.name, "npm");
    assert.equal(pm.version, "10.9.2");
  });

  it("detects yarn from packageManager field with hash", () => {
    writePkg(dir, {
      name: "test",
      packageManager: "yarn@4.9.1+sha512.abc123def456",
    });
    const pm = new PackageManager(dir);
    assert.equal(pm.name, "yarn");
    assert.equal(pm.version, "4.9.1");
  });

  it("detects pnpm from packageManager field", () => {
    writePkg(dir, { name: "test", packageManager: "pnpm@9.0.0" });
    const pm = new PackageManager(dir);
    assert.equal(pm.name, "pnpm");
    assert.equal(pm.version, "9.0.0");
  });

  it("detects bun from packageManager field", () => {
    writePkg(dir, { name: "test", packageManager: "bun@1.1.0" });
    const pm = new PackageManager(dir);
    assert.equal(pm.name, "bun");
    assert.equal(pm.version, "1.1.0");
  });

  it("version is null when packageManager field has no version", () => {
    // Edge case: packageManager without version (non-standard)
    writePkg(dir, { name: "test" });
    writeFileSync(join(dir, "package-lock.json"), "{}");
    const pm = new PackageManager(dir);
    assert.equal(pm.name, "npm");
    assert.equal(pm.version, null);
  });
});

// ─── Detection via lockfiles ──────────────────────────────────────────────────

describe("PackageManager — lockfile detection", () => {
  let dir;

  before(() => {
    dir = makeTmpDir();
  });
  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("detects npm from package-lock.json", () => {
    writePkg(dir, { name: "test" });
    writeFileSync(join(dir, "package-lock.json"), "{}");
    const pm = new PackageManager(dir);
    assert.equal(pm.name, "npm");
    assert.equal(pm.version, null); // no packageManager field
  });

  it("detects yarn from yarn.lock", () => {
    const d = makeTmpDir();
    try {
      writePkg(d, { name: "test" });
      writeFileSync(join(d, "yarn.lock"), "");
      const pm = new PackageManager(d);
      assert.equal(pm.name, "yarn");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("detects pnpm from pnpm-lock.yaml", () => {
    const d = makeTmpDir();
    try {
      writePkg(d, { name: "test" });
      writeFileSync(join(d, "pnpm-lock.yaml"), "");
      const pm = new PackageManager(d);
      assert.equal(pm.name, "pnpm");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("detects bun from bun.lockb", () => {
    const d = makeTmpDir();
    try {
      writePkg(d, { name: "test" });
      writeFileSync(join(d, "bun.lockb"), "");
      const pm = new PackageManager(d);
      assert.equal(pm.name, "bun");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});

// ─── packageManager field takes priority over lockfile ───────────────────────

describe("PackageManager — priority", () => {
  it("packageManager field overrides lockfile", () => {
    const d = makeTmpDir();
    try {
      writePkg(d, { name: "test", packageManager: "pnpm@9.0.0" });
      writeFileSync(join(d, "package-lock.json"), "{}"); // npm lockfile present
      const pm = new PackageManager(d);
      assert.equal(
        pm.name,
        "pnpm",
        "packageManager field should take priority",
      );
      assert.equal(pm.version, "9.0.0");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("defaults to npm when no signals present", () => {
    const d = makeTmpDir();
    try {
      // No package.json, no lockfiles
      const pm = new PackageManager(d);
      assert.equal(pm.name, "npm");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});
