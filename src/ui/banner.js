import pc from "picocolors";

const LOGO = `
  ${pc.dim("╭───────────────────────────────────────────────────────╮")}
  ${pc.dim("│")}                                                       ${pc.dim("│")}
  ${pc.dim("│")}  ${pc.bold(pc.cyan("██████╗ ██╗  ██╗  ██████╗"))}  ${pc.bold(pc.white("██╗    ██╗"))}                ${pc.dim("│")}
  ${pc.dim("│")}  ${pc.bold(pc.cyan("██╔══██╗██║ ██╔╝ ██╔════╝"))}  ${pc.bold(pc.white("██║    ██║"))}                ${pc.dim("│")}
  ${pc.dim("│")}  ${pc.bold(pc.cyan("██████╔╝█████╔╝  ██║  ███╗"))} ${pc.bold(pc.white("██║ █╗ ██║"))}                ${pc.dim("│")}
  ${pc.dim("│")}  ${pc.bold(pc.cyan("██╔═══╝ ██╔═██╗  ██║   ██║"))} ${pc.bold(pc.white("██║███╗██║"))}                ${pc.dim("│")}
  ${pc.dim("│")}  ${pc.bold(pc.cyan("██║     ██║  ██╗ ╚██████╔╝"))} ${pc.bold(pc.white("╚███╔███╔╝"))}                ${pc.dim("│")}
  ${pc.dim("│")}  ${pc.bold(pc.cyan("╚═╝     ╚═╝  ╚═╝  ╚═════╝"))}   ${pc.bold(pc.white("╚══╝╚══╝ "))}                ${pc.dim("│")}
  ${pc.dim("│")}                                                       ${pc.dim("│")}
  ${pc.dim("│")}   ${pc.yellow("⊙")}  ${pc.dim("Package Guardian · Audit · Detect")}                ${pc.dim("│")}
  ${pc.dim("│")}   ${pc.dim("─────────────────────────────────────────────────")}   ${pc.dim("│")}
  ${pc.dim("│")}   ${pc.dim("PKG")}${pc.cyan("WARDEN")}  ${pc.dim("·")}  ${pc.dim("v1.0.0")}  ${pc.dim("·")}  ${pc.dim("Supply Chain Security")}      ${pc.dim("│")}
  ${pc.dim("│")}                                                       ${pc.dim("│")}
  ${pc.dim("╰───────────────────────────────────────────────────────╯")}
`;

const LOGO_COMPACT = `  ${pc.yellow("⊙")} ${pc.bold(pc.cyan("PKGWARDEN"))} ${pc.dim("— Package Guardian With Auditing, Reporting & Detection")}   `;

const SHIELD = `
  ${pc.cyan("╭───────────────────────────────────────────────────────╮")}
  ${pc.cyan("│")}                                                       ${pc.cyan("│")}
  ${pc.cyan("│")}       ${pc.yellow("⊙")}    ${pc.bold(pc.white("P K G W A R D E N"))}    ${pc.yellow("⊙")}             ${pc.cyan("│")}
  ${pc.cyan("│")}                                                       ${pc.cyan("│")}
  ${pc.cyan("│")}        ${pc.dim("╔══════════════════════════╗")}                ${pc.cyan("│")}
  ${pc.cyan("│")}        ${pc.dim("║")}  ${pc.green("■")} ${pc.white("Supply Chain Security")}   ${pc.dim("║")}                ${pc.cyan("│")}
  ${pc.cyan("│")}        ${pc.dim("║")}  ${pc.green("■")} ${pc.white("Malware Detection")}       ${pc.dim("║")}                ${pc.cyan("│")}
  ${pc.cyan("│")}        ${pc.dim("║")}  ${pc.green("■")} ${pc.white("Best Practice Enforcer")}  ${pc.dim("║")}                ${pc.cyan("│")}
  ${pc.cyan("│")}        ${pc.dim("║")}  ${pc.green("■")} ${pc.white("Package Manager Proxy")}   ${pc.dim("║")}                ${pc.cyan("│")}
  ${pc.cyan("│")}        ${pc.dim("╚══════════════════════════╝")}                ${pc.cyan("│")}
  ${pc.cyan("│")}                                                       ${pc.cyan("│")}
  ${pc.cyan("│")}      ${pc.dim("v1.0.0")}         ${pc.dim("pkg guardian · audit · detect")}       ${pc.cyan("│")}
  ${pc.cyan("│")}                                                       ${pc.cyan("│")}
  ${pc.cyan("╰───────────────────────────────────────────────────────╯")}
`;

export function printBanner(compact = false) {
  if (compact) {
    console.log(LOGO_COMPACT);
  } else {
    console.log(LOGO);
  }
}

export function printShield() {
  console.log(SHIELD);
}

export function printVersion(version) {
  console.log(
    `  ${pc.yellow("⊙")} ${pc.bold(pc.cyan("PKGWARDEN"))} ${pc.dim(`v${version}`)}`,
  );
}
