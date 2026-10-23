/**
 * MCPShield Rule Registry — OWASP MCP Top 10:2025 & EU AI Act (2026 Enforcement) Mapping
 * 100% deterministic, zero-dependency static & schema inspection catalog.
 */

export const OWASP_MCP_RULES = [
  {
    id: "MCP01",
    code: "OWASP-MCP01-2025",
    title: "Token Mismanagement & Hardcoded Secret Exposure",
    severity: "critical",
    weight: 22,
    euAiActArticles: [
      "Article 15 (Accuracy, Robustness & Cybersecurity)",
      "Annex IV §2(g) (Cybersecurity Controls)"
    ],
    description:
      "Detects hardcoded API keys, bearer tokens, AWS keys, GitHub PATs, Slack tokens, database credentials, or plaintext secrets embedded directly in MCP server `env` or `args` blocks instead of environment variable references.",
    remediation:
      "Replace literal credentials with `${ENV_VAR}` interpolation or host keychain references, rotate exposed tokens immediately, and commit only `.env.example` templates."
  },
  {
    id: "MCP02",
    code: "OWASP-MCP02-2025",
    title: "Privilege Escalation via Scope Creep & Root Mounts",
    severity: "high",
    weight: 14,
    euAiActArticles: [
      "Article 9 (Risk Management System)",
      "Article 15(4) (Resilience Against Unauthorized Use)"
    ],
    description:
      "Detects overly permissive filesystem mounts (`/`, `/etc`, `/home`, `~/.ssh`, `C:\\`), `--privileged` container flags, wildcard OAuth scopes (`*`, `admin`, `full_access`), or unrestricted shell access.",
    remediation:
      "Restrict filesystem servers to an isolated project subdirectory (e.g., `./workspace/allowed`), drop `--privileged`, and enforce least-privilege read-only scopes."
  },
  {
    id: "MCP03",
    code: "OWASP-MCP03-2025",
    title: "Tool Poisoning, Prompt Injection & Unstrict JSON Schemas",
    severity: "critical",
    weight: 18,
    euAiActArticles: [
      "Article 15(5) (Prevention of Data/Model Poisoning & Adversarial Manipulation)",
      "Annex IV §2(d) (Input Validation & Schema Specification)"
    ],
    description:
      "Detects hidden instruction overrides in tool descriptions (`ignore previous`, `<system>`, `do not mention`, zero-width characters) and tool `inputSchema` definitions missing `additionalProperties: false`.",
    remediation:
      "Sanitize all tool descriptions, enforce `additionalProperties: false` on every tool `inputSchema`, and pin SHA-256 tool hashes using `mcpshield lock`."
  },
  {
    id: "MCP04",
    code: "OWASP-MCP04-2025",
    title: "Software Supply Chain Attacks & Unpinned Package Runners",
    severity: "high",
    weight: 14,
    euAiActArticles: [
      "Article 11 & Annex IV §1(d) (Third-Party Component Provenance)",
      "Article 15 (Supply Chain Integrity)"
    ],
    description:
      "Detects mutable package execution such as `npx -y pkg@latest`, unversioned `npx` or `uvx` invocations, mutable Docker `:latest` images, or unpinned Git branch URLs.",
    remediation:
      "Pin exact semantic versions (`pkg@1.4.2`) or SHA-256 container digests and maintain a cryptographic `mcp-lock.json` file in version control."
  },
  {
    id: "MCP05",
    code: "OWASP-MCP05-2025",
    title: "Command Injection & Arbitrary Shell Execution",
    severity: "critical",
    weight: 18,
    euAiActArticles: [
      "Article 15 (Cybersecurity & Execution Safety)",
      "Article 9 (High-Severity Operational Risk Mitigation)"
    ],
    description:
      "Detects shell interpreter wrappers (`sh -c`, `bash -c`, `cmd.exe /c`, `powershell -e`), pipe-to-shell patterns (`curl ... | sh`), or dynamic `eval` launchers inside MCP server commands.",
    remediation:
      "Invoke verified binaries directly with structured argument arrays (`command` + `args`) and never pass concatenated strings to a shell interpreter."
  },
  {
    id: "MCP06",
    code: "OWASP-MCP06-2025",
    title: "Intent Flow Subversion & Human-in-the-Loop Bypass",
    severity: "high",
    weight: 12,
    euAiActArticles: [
      "Article 14 (Human Oversight Obligations)",
      "Annex IV §2(e) (Human Oversight Technical Measures)"
    ],
    description:
      "Detects wildcard auto-approval lists (`autoApprove: [\"*\"]`, `alwaysAllow: true`, `--yes-all`) or destructive tools marked with misleading `readOnlyHint: true` or `destructiveHint: false`.",
    remediation:
      "Remove wildcard `autoApprove` rules, require explicit human confirmation for all write/delete/network/payment actions, and only allowlist verified read-only tools."
  },
  {
    id: "MCP07",
    code: "OWASP-MCP07-2025",
    title: "Insufficient Authentication & Insecure Cleartext Transport",
    severity: "high",
    weight: 10,
    euAiActArticles: [
      "Article 15 (Secure Communication & Authentication)",
      "GDPR Article 32 (Encryption in Transit)"
    ],
    description:
      "Detects remote SSE/HTTP MCP endpoints using cleartext `http://` (outside localhost), disabled TLS certificate verification (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `--insecure`), or unauthenticated remote servers.",
    remediation:
      "Enforce `https://` with valid TLS 1.3 certificates, remove TLS verification overrides, and require short-lived OAuth 2.1 tokens with PKCE and audience binding."
  },
  {
    id: "MCP08",
    code: "OWASP-MCP08-2025",
    title: "Lack of Audit Logging & EU AI Act Article 12 Record-Keeping",
    severity: "medium",
    weight: 8,
    euAiActArticles: [
      "Article 12 (Record-Keeping & Automatic Logging)",
      "Article 26(6) (Deployer Log Retention >= 6 Months)"
    ],
    description:
      "Detects MCP configurations that explicitly disable logging (`--no-log`, `--quiet`, `LOG_LEVEL=none`) or lack an `audit` / `logging` policy block for traceability.",
    remediation:
      "Enable structured JSON audit logging with secret redaction and configure immutable retention for at least 6 months to satisfy EU AI Act Article 12 & Article 26(6)."
  },
  {
    id: "MCP09",
    code: "OWASP-MCP09-2025",
    title: "Shadow MCP Servers & Missing Governance Metadata",
    severity: "medium",
    weight: 6,
    euAiActArticles: [
      "Article 9 (Inventory & Governance of AI Subsystems)",
      "Annex IV §1 (System Architecture & Component Registry)"
    ],
    description:
      "Detects unvetted MCP server entries lacking owner/purpose metadata or pulling from untrusted third-party namespaces without an approved registry policy.",
    remediation:
      "Declare an explicit `governance` block (`owner`, `purpose`, `dataClassification`, `approvedDate`) or enforce an organization allowlist (`MCP_SERVER_ALLOWLIST_POLICY.md`)."
  },
  {
    id: "MCP10",
    code: "OWASP-MCP10-2025",
    title: "Context Over-Sharing & Unscoped Database / PII Access",
    severity: "medium",
    weight: 8,
    euAiActArticles: [
      "Article 10 (Data & Data Governance)",
      "Article 50 (AI Transparency Obligations)",
      "GDPR Article 35 (Data Protection Impact Assessment)"
    ],
    description:
      "Detects database or CRM connectors configured with superuser/write connection strings (`postgres://postgres:...`, `mongodb+srv://admin:...`) or missing read-only / PII-redaction guardrails.",
    remediation:
      "Connect AI agents via dedicated read-only database views with PII columns masked, and enforce row-level security (RLS) before context reaches the model."
  }
];

export const SECRET_PATTERNS = [
  { name: "OpenAI / Anthropic / Stripe Secret Key", regex: /\b(sk-[a-zA-Z0-9_-]{16,}|sk-ant-[a-zA-Z0-9_-]{16,}|sk_live_[a-zA-Z0-9]{16,}|rk_live_[a-zA-Z0-9]{16,})\b/ },
  { name: "GitHub Personal Access Token", regex: /\b(ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})\b/ },
  { name: "Slack Bot / User Token", regex: /\b(xox[baprs]-[a-zA-Z0-9-]{10,})\b/ },
  { name: "AWS Access Key ID", regex: /\b(AKIA[0-9A-Z]{16})\b/ },
  { name: "Hardcoded Bearer / API Secret Value", regex: /\b(Bearer\s+[a-zA-Z0-9._-]{20,}|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/ }
];

export const SENSITIVE_ENV_KEY_REGEX = /(API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|CLIENT_SECRET|AUTH_TOKEN|DATABASE_URL|CONNECTION_STRING)/i;
