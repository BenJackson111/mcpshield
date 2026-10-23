# EU AI Act Annex IV — Technical Documentation Template (2026 Enforcement)

**Regulation:** Regulation (EU) 2024/1689 (EU Artificial Intelligence Act) — Annex IV & Article 11  
**Enforcement Date:** August 2, 2026  
**System Name:** `[REPLACE: AI Agent / MCP Gateway Name]`  
**Provider / Deployer Legal Entity:** `[REPLACE: Company Name & Registration Number]`  
**Document Version:** `1.0`  

---

## 1. General Description of the AI System (Annex IV §1)
- **1.1 Intended Purpose:** Describe the exact business task, user base, and operational environment of the AI agent and its connected Model Context Protocol (MCP) servers.
- **1.2 Interaction with External Systems:** List every MCP server (`stdio` or remote `https://` SSE/Streamable HTTP) that the model can invoke.
- **1.3 Third-Party Component Provenance (OWASP MCP04):** Attach `mcp-lock.json` containing pinned semantic versions and SHA-256 digests of every MCP server binary/package.

## 2. Design Specifications, Input Schemas & Validation (Annex IV §2)
- **2.1 Tool Schema Integrity (OWASP MCP03):** Every MCP tool must define a strict JSON Schema with `additionalProperties: false` and explicit pattern/enum constraints.
- **2.2 Prompt Injection & Tool Poisoning Defense:** All external content returned by MCP tools is treated as untrusted data and wrapped in structural boundary markers.

## 3. Risk Management & Cybersecurity Controls (Article 9 & Article 15)
- **3.1 Credential Isolation (OWASP MCP01):** Zero secrets stored in configuration files; all credentials injected at runtime via environment variables or hardware-backed secret managers.
- **3.2 Least-Privilege Scoping (OWASP MCP02 & MCP10):** Filesystem mounts restricted to `./workspace/sandbox`; database connectors restricted to `readOnly: true` views with PII masked.

## 4. Human Oversight & Automatic Record-Keeping (Article 12 & Article 14)
- **4.1 Human-in-the-Loop Approval (Article 14 / OWASP MCP06):** Wildcard `autoApprove` is prohibited. All write, delete, financial, or external communication actions require explicit human confirmation.
- **4.2 Traceability Logs (Article 12 & Article 26(6) / OWASP MCP08):** Structured JSON audit logs (`mcp-audit.jsonl`) with automatic secret redaction retained for >= 180 days.
