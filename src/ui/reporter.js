import pc from "picocolors";
import { icons, severityBadge, theme, divider, box } from "./theme.js";

export class Reporter {
  #isCI;
  #silent;

  constructor({ ci = false, silent = false } = {}) {
    this.#isCI = ci || !!process.env.CI;
    this.#silent = silent;
  }

  log(msg = "") {
    if (!this.#silent) console.log(msg);
  }

  blank() {
    this.log("");
  }

  header(title) {
    this.blank();
    this.log(`  ${icons.shield} ${theme.title(title)}`);
    this.log(`  ${divider()}`);
  }

  section(title) {
    this.blank();
    this.log(`  ${theme.title(title)}`);
  }

  step(msg, status = "info") {
    const icon =
      status === "success"
        ? icons.success
        : status === "error"
          ? icons.error
          : status === "warning"
            ? icons.warning
            : icons.arrow;
    this.log(`  ${icon} ${msg}`);
  }

  tree(items, indent = 2) {
    const pad = " ".repeat(indent);
    items.forEach((item, i) => {
      const isLast = i === items.length - 1;
      const prefix = isLast ? icons.corner : icons.tee;
      this.log(`${pad}${prefix}${icons.line} ${item}`);
    });
  }

  finding(finding) {
    const badge = severityBadge[finding.severity] || severityBadge.info;
    this.blank();
    this.log(`  ${badge} ${pc.bold(finding.title)}`);
    this.log(`  ${icons.bar} ${theme.muted("Rule:")} ${finding.rule}`);
    this.log(
      `  ${icons.bar} ${theme.muted("Package:")} ${theme.accent(finding.package)}`,
    );
    if (finding.file) {
      this.log(
        `  ${icons.bar} ${theme.muted("File:")} ${finding.file}${finding.line ? `:${finding.line}` : ""}`,
      );
    }
    if (finding.snippet) {
      this.log(`  ${icons.bar}`);
      const snippetLines = finding.snippet.split("\n").slice(0, 5);
      snippetLines.forEach((line) => {
        this.log(`  ${icons.bar}   ${pc.dim(line)}`);
      });
    }
    if (finding.description) {
      this.log(`  ${icons.bar}`);
      this.log(
        `  ${icons.corner}${icons.line} ${theme.muted(finding.description)}`,
      );
    }
  }

  score(value, max = 100) {
    const pct = Math.round((value / max) * 100);
    const barWidth = 30;
    const filled = Math.round((pct / 100) * barWidth);
    const empty = barWidth - filled;

    let color;
    if (pct >= 80) color = pc.green;
    else if (pct >= 50) color = pc.yellow;
    else color = pc.red;

    const bar = color("█".repeat(filled)) + pc.dim("░".repeat(empty));
    this.log(
      `  ${bar} ${color(pc.bold(`${pct}%`))} ${theme.muted(`(${value}/${max})`)}`,
    );
  }

  table(headers, rows) {
    const colWidths = headers.map((h, i) => {
      return Math.max(
        stripAnsi(h).length,
        ...rows.map((r) => stripAnsi(String(r[i] || "")).length),
      );
    });

    const headerLine = headers
      .map((h, i) => pc.bold(h.padEnd(colWidths[i])))
      .join("  ");
    this.log(`  ${headerLine}`);
    this.log(`  ${colWidths.map((w) => pc.dim("─".repeat(w))).join("  ")}`);

    for (const row of rows) {
      const line = row
        .map((cell, i) => {
          const str = String(cell || "");
          const pad = colWidths[i] - stripAnsi(str).length;
          return str + " ".repeat(Math.max(0, pad));
        })
        .join("  ");
      this.log(`  ${line}`);
    }
  }

  summary(stats) {
    this.blank();
    this.log(
      box(
        [
          `${pc.red(`${stats.critical || 0} critical`)}  ${pc.yellow(`${stats.high || 0} high`)}  ${pc.blue(`${stats.medium || 0} medium`)}  ${pc.dim(`${stats.low || 0} low`)}`,
          "",
          `${theme.muted("Total findings:")} ${pc.bold(String(stats.total || 0))}`,
          `${theme.muted("Packages scanned:")} ${pc.bold(String(stats.scanned || 0))}`,
        ].join("\n"),
        { title: "Scan Summary" },
      ),
    );
  }

  ciOutput(data) {
    if (this.#isCI) {
      console.log(JSON.stringify(data, null, 2));
    }
  }

  progress(current, total, label = "") {
    const pct = Math.round((current / total) * 100);
    const barWidth = 25;
    const filled = Math.round((pct / 100) * barWidth);
    const empty = barWidth - filled;
    const bar = pc.cyan("█".repeat(filled)) + pc.dim("░".repeat(empty));
    const text = `  ${bar} ${pc.dim(`${current}/${total}`)} ${label}`;
    if (!this.#isCI) {
      process.stdout.write(`\r${text}`);
      if (current === total) process.stdout.write("\n");
    }
  }
}

function stripAnsi(str) {
  return str.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, "");
}

export const reporter = new Reporter();
