/**
 * Typosquatting Detection Rule
 *
 * Detects potential typosquatting attacks by comparing package names against
 * a curated list of popular packages using Levenshtein distance, common
 * character substitutions, and prefix/suffix manipulation patterns.
 */

// Top npm packages most commonly targeted by typosquatting
const POPULAR_PACKAGES = [
  "express",
  "react",
  "react-dom",
  "lodash",
  "axios",
  "chalk",
  "commander",
  "webpack",
  "babel",
  "typescript",
  "eslint",
  "prettier",
  "jest",
  "mocha",
  "moment",
  "underscore",
  "debug",
  "uuid",
  "async",
  "request",
  "bluebird",
  "cheerio",
  "dotenv",
  "mongoose",
  "socket.io",
  "cors",
  "body-parser",
  "jsonwebtoken",
  "bcrypt",
  "nodemon",
  "pm2",
  "morgan",
  "helmet",
  "passport",
  "sequelize",
  "pg",
  "mysql2",
  "redis",
  "aws-sdk",
  "firebase",
  "next",
  "nuxt",
  "vue",
  "angular",
  "svelte",
  "tailwindcss",
  "postcss",
  "autoprefixer",
  "sass",
  "less",
  "puppeteer",
  "playwright",
  "sharp",
  "multer",
  "formidable",
  "yargs",
  "inquirer",
  "ora",
  "glob",
  "rimraf",
  "mkdirp",
  "semver",
  "minimist",
  "cross-env",
  "concurrently",
  "nodemailer",
  "luxon",
  "date-fns",
  "ramda",
  "rxjs",
  "graphql",
  "apollo",
  "prisma",
  "drizzle-orm",
  "zod",
  "joi",
  "yup",
  "ajv",
  "fastify",
  "koa",
  "hapi",
  "esbuild",
  "vite",
  "rollup",
  "parcel",
  "turbo",
  "lerna",
  "nx",
  "pnpm",
  "yarn",
  "npm",
  "colors",
  "color",
  "nanoid",
  "cuid",
  "got",
  "node-fetch",
  "superagent",
  "http-proxy",
  "ws",
  "socket.io-client",
  "winston",
  "pino",
  "bunyan",
  "dayjs",
  "chalk",
  "picocolors",
  "execa",
  "shelljs",
  "fs-extra",
  "chokidar",
  "commander",
  "meow",
  "oclif",
  "path-to-regexp",
  "cookie-parser",
  "express-session",
  "connect",
  "http-errors",
  "serve-static",
  "compression",
  "rate-limiter-flexible",
  "ioredis",
  "knex",
  "typeorm",
  "mikro-orm",
  "better-sqlite3",
  "msw",
  "nock",
  "sinon",
  "chai",
  "vitest",
  "cypress",
  "storybook",
  "testing-library",
];

// Common typosquatting techniques
const SUSPICIOUS_PREFIXES = ["node-", "js-", "npm-", "get-", "the-", "my-"];
const SUSPICIOUS_SUFFIXES = [
  "-js",
  "-node",
  "-npm",
  "-lib",
  "-util",
  "-utils",
  "-tool",
  "-cli",
  "-pkg",
  "2",
  "3",
  "s",
];

// Known malicious name patterns
const MALICIOUS_PATTERNS = [
  /^@[^/]+\/(?:core|http|fs|net|util|path|crypto|stream|events|os|child.?process|vm)$/,
  /_/g, // Packages using _ instead of -
];

export default {
  name: "typosquatting",
  title: "Typosquatting Detection",
  description:
    "Detects potential typosquatting attacks on popular package names.",
  severity: "high",

  analyzePackageName(packageName) {
    const findings = [];
    const name = packageName.toLowerCase();

    // Strip scope for comparison
    const bareName = name.startsWith("@") ? name.split("/")[1] || name : name;

    for (const popular of POPULAR_PACKAGES) {
      if (bareName === popular) continue; // Exact match = safe

      const distance = levenshtein(bareName, popular);

      // Edit distance 1 — very suspicious
      if (distance === 1) {
        findings.push({
          rule: "typosquatting",
          severity: "high",
          title: `Possible typosquat of "${popular}"`,
          description: `Package "${packageName}" is 1 character away from popular package "${popular}". This is a common typosquatting pattern.`,
          evidence: `Levenshtein distance: ${distance}`,
        });
        continue;
      }

      // Edit distance 2 with short name — still suspicious
      if (distance === 2 && popular.length <= 6) {
        findings.push({
          rule: "typosquatting",
          severity: "medium",
          title: `May be a typosquat of "${popular}"`,
          description: `Package "${packageName}" is 2 characters away from popular short package "${popular}".`,
          evidence: `Levenshtein distance: ${distance}`,
        });
        continue;
      }

      // Check prefix/suffix manipulation
      for (const prefix of SUSPICIOUS_PREFIXES) {
        if (bareName === `${prefix}${popular}`) {
          findings.push({
            rule: "typosquatting",
            severity: "medium",
            title: `Suspicious prefix: "${prefix}" added to "${popular}"`,
            description: `Package "${packageName}" adds prefix "${prefix}" to popular package "${popular}". Verify this is an official package.`,
            evidence: `Pattern: ${prefix}<popular_name>`,
          });
        }
      }

      for (const suffix of SUSPICIOUS_SUFFIXES) {
        if (bareName === `${popular}${suffix}`) {
          findings.push({
            rule: "typosquatting",
            severity: "medium",
            title: `Suspicious suffix: "${suffix}" added to "${popular}"`,
            description: `Package "${packageName}" adds suffix "${suffix}" to popular package "${popular}". Verify this is an official package.`,
            evidence: `Pattern: <popular_name>${suffix}`,
          });
        }
      }

      // Check character swap (transposition)
      if (distance === 2 && isTransposition(bareName, popular)) {
        findings.push({
          rule: "typosquatting",
          severity: "high",
          title: `Character swap of "${popular}"`,
          description: `Package "${packageName}" looks like "${popular}" with swapped characters.`,
          evidence: `Detected transposition`,
        });
      }

      // Check hyphen/underscore confusion
      if (
        bareName.replace(/[-_]/g, "") === popular.replace(/[-_]/g, "") &&
        bareName !== popular
      ) {
        findings.push({
          rule: "typosquatting",
          severity: "medium",
          title: `Separator confusion with "${popular}"`,
          description: `Package "${packageName}" differs from "${popular}" only in separator characters (- vs _).`,
          evidence: `Normalized match: ${bareName.replace(/[-_]/g, "")}`,
        });
      }
    }

    // Check for suspicious scoped packages mimicking core modules
    if (name.startsWith("@")) {
      const scopedName = name.split("/")[1];
      const coreModules = [
        "fs",
        "path",
        "http",
        "https",
        "crypto",
        "os",
        "net",
        "util",
        "stream",
        "events",
        "child_process",
        "vm",
        "buffer",
        "url",
        "querystring",
        "zlib",
        "dns",
        "tls",
        "cluster",
        "worker_threads",
      ];
      if (coreModules.includes(scopedName)) {
        findings.push({
          rule: "typosquatting",
          severity: "critical",
          title: `Scoped package mimics Node.js core module "${scopedName}"`,
          description: `Package "${packageName}" uses a scope to impersonate a Node.js core module. This is a known attack vector.`,
          evidence: `Core module: ${scopedName}`,
        });
      }
    }

    return findings;
  },
};

// Levenshtein distance implementation
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[m][n];
}

function isTransposition(a, b) {
  if (a.length !== b.length) return false;
  let diffs = 0;
  const diffPositions = [];
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      diffs++;
      diffPositions.push(i);
    }
  }
  if (diffs !== 2) return false;
  const [i, j] = diffPositions;
  return a[i] === b[j] && a[j] === b[i];
}
