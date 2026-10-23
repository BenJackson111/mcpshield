/**
 * Public starter CLI. Pro commands (scan, fix, lock, annex4, risk-register, SARIF)
 * are sold separately and are not implemented here.
 */

const PRO_COMMANDS = ["scan", "fix", "lock", "annex4", "risk-register", "sarif"];

export function helpText() {
  return [
    "MCPShield public starter v1.0.0",
    "",
    "Usage:",
    "  node bin/mcpshield.mjs --help",
    "  node bin/mcpshield.mjs --version",
    "  node bin/mcpshield.mjs rules",
    "",
    "This repository includes the browser auditor (docs/), the open OWASP MCP",
    "Top 10 rule catalog (starter/rules.mjs), sample configs, and starter templates.",
    "",
    "Not included (MCPShield Pro / Team):",
    `  ${PRO_COMMANDS.join(", ")}`,
    "",
    "Run the free auditor by opening docs/index.html, or download",
    "docs/releases/mcpshield-starter-v1.0.0.tar.gz."
  ].join("\n");
}

export function main(argv, io = { stdout: console.log, stderr: console.error }) {
  const [command] = argv;

  if (!command || command === "--help" || command === "-h" || command === "help") {
    io.stdout(helpText());
    return 0;
  }

  if (command === "--version" || command === "-V" || command === "version") {
    io.stdout("1.0.0");
    return 0;
  }

  if (command === "rules") {
    return printRules(io);
  }

  if (PRO_COMMANDS.includes(command)) {
    io.stderr(
      `'${command}' is part of MCPShield Pro and is not included in this public repository.`
    );
    io.stderr("See: node bin/mcpshield.mjs --help");
    return 1;
  }

  io.stderr(`Unknown command: ${command}`);
  io.stderr(helpText());
  return 1;
}

async function printRules(io) {
  const { OWASP_MCP_RULES } = await import("../starter/rules.mjs");
  for (const rule of OWASP_MCP_RULES) {
    io.stdout(`${rule.id}\t${rule.severity}\t${rule.title}`);
  }
  return 0;
}
