import pc from "picocolors";

export const icons = {
  success: pc.green("✔"),
  error: pc.red("✖"),
  warning: pc.yellow("⚠"),
  info: pc.blue("ℹ"),
  shield: pc.cyan("⊙"),
  eye: pc.yellow("◉"),
  arrow: pc.cyan("›"),
  dot: pc.dim("·"),
  bar: pc.dim("│"),
  corner: pc.dim("╰"),
  tee: pc.dim("├"),
  line: pc.dim("─"),
  lock: pc.green("🔒"),
  unlock: pc.red("🔓"),
  pkg: pc.cyan("📦"),
  scan: pc.yellow("🔍"),
  fire: pc.red("🔥"),
  check: pc.green("●"),
  cross: pc.red("●"),
  neutral: pc.yellow("●"),
  pending: pc.dim("○"),
};

export const severity = {
  critical: (text) => pc.bgRed(pc.white(pc.bold(` ${text} `))),
  high: (text) => pc.red(pc.bold(text)),
  medium: (text) => pc.yellow(text),
  low: (text) => pc.blue(text),
  info: (text) => pc.dim(text),
};

export const severityBadge = {
  critical: pc.bgRed(pc.white(pc.bold(" CRITICAL "))),
  high: pc.bgRedBright(pc.white(pc.bold(" HIGH "))),
  medium: pc.bgYellow(pc.black(pc.bold(" MEDIUM "))),
  low: pc.bgBlue(pc.white(pc.bold(" LOW "))),
  info: pc.bgWhite(pc.black(" INFO ")),
};

export const theme = {
  title: (text) => pc.bold(pc.cyan(text)),
  subtitle: (text) => pc.dim(text),
  highlight: (text) => pc.bold(pc.white(text)),
  muted: (text) => pc.dim(text),
  accent: (text) => pc.cyan(text),
  success: (text) => pc.green(text),
  danger: (text) => pc.red(text),
  warn: (text) => pc.yellow(text),
  code: (text) => pc.bgBlack(pc.white(` ${text} `)),
};

export function divider(label = "") {
  const width = 55;
  if (label) {
    const pad = Math.max(0, Math.floor((width - label.length - 4) / 2));
    return pc.dim("─".repeat(pad) + `┤ ${pc.white(label)} ├` + "─".repeat(pad));
  }
  return pc.dim("─".repeat(width));
}

export function box(content, { title = "", border = "cyan" } = {}) {
  const lines = content.split("\n");
  const maxLen = Math.max(
    ...lines.map((l) => stripAnsi(l).length),
    title ? stripAnsi(title).length + 4 : 0,
  );
  const width = maxLen + 4;
  const colorFn = pc[border] || pc.cyan;

  let output = "";
  if (title) {
    output += `  ${colorFn("╭─")} ${pc.bold(title)} ${colorFn("─".repeat(Math.max(0, width - stripAnsi(title).length - 5)) + "╮")}\n`;
  } else {
    output += `  ${colorFn("╭" + "─".repeat(width - 2) + "╮")}\n`;
  }

  for (const line of lines) {
    const pad = width - 4 - stripAnsi(line).length;
    output += `  ${colorFn("│")} ${line}${" ".repeat(Math.max(0, pad))} ${colorFn("│")}\n`;
  }

  output += `  ${colorFn("╰" + "─".repeat(width - 2) + "╯")}`;
  return output;
}

function stripAnsi(str) {
  return str.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, "");
}
