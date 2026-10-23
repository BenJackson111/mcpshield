# 🛡️ MCPShield — OWASP MCP Top 10 Security Scanner & EU AI Act Annex IV Toolkit

**Audit, harden, and certify your Model Context Protocol (`mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`) servers in 10 seconds.**

- **100% Client-Side Live Browser Auditor:** Paste any MCP configuration in your browser — zero data leaves your device.
- **Deterministic OWASP MCP Top 10:2025 Coverage:** Detects hardcoded tokens (`MCP01`), root filesystem scope creep (`MCP02`), prompt-injected tool schemas (`MCP03`), unpinned `npx -y @latest` supply chain drift (`MCP04`), shell injection wrappers (`MCP05`), wildcard `autoApprove` (`MCP06`), cleartext HTTP (`MCP07`), missing audit logs (`MCP08`), shadow servers (`MCP09`), and unscoped database connectors (`MCP10`).
- **EU AI Act (Post-Aug 2, 2026 Enforcement) Alignment:** Maps every finding directly to **Regulation (EU) 2024/1689 Articles 9, 10, 11, 12, 14, 15, 50 & Annex IV** and **UK/EU GDPR Articles 32 & 35**.

---

## What's in This Repository (Free & Open Source Starter)

| Path | Description |
| :--- | :--- |
| `docs/` | Full static web application & 100% client-side **MCPShield Live Auditor & Auto-Hardener**, plus 3 technical engineering guides |
| `bin/mcpshield.mjs` | Public starter entrypoint (`node bin/mcpshield.mjs --help`). Lists the open rule catalog. Does not include Pro commands. |
| `starter/rules.mjs` | Open-source OWASP MCP Top 10:2025 (`MCP01`–`MCP10`) & EU AI Act rule catalog |
| `starter/examples/` | Sample vulnerable (`0/100 Grade F`) and auto-hardened (`100/100 Grade A+`) `mcp.json` configurations |
| `starter/templates/` | Starter EU AI Act Annex IV Dossier outline and MCP Server Allowlist Policy |

---

## Upgrade to MCPShield Pro (£49) or Team & Agency Pack (£149)

Need the full offline Node.js CLI (`mcpshield scan / fix / lock / annex4 / risk-register`), GitHub Code Scanning SARIF v2.1.0 CI/CD gate, cryptographic `mcp-lock.json` baseline generator, and all 6 auditor-ready EU AI Act Annex IV & GDPR Article 35 DPIA templates?

- **Pro Developer License (£49 / $59 one-time):** Zero recurring SaaS fees. Offline CLI + auto-hardener + SARIF CI gate + Annex IV generator.
- **Team & Agency Audit Pack (£149 / $179 one-time):** Unlimited repositories & engineers + Board/CISO Executive Risk Register exporter + all 6 compliance templates + client audit rights.
- **Checkout:** [https://polar.sh/mcpsheild1](https://polar.sh/mcpsheild1)

---

## Support & Community

- **Bug Reports & Rule Requests:** [GitHub Issues](https://github.com/BenJackson111/mcpshield/issues) · [support@mcpshield.bid](mailto:support@mcpshield.bid)
- **Q&A & Architecture Discussions:** [GitHub Discussions](https://github.com/BenJackson111/mcpshield/discussions)
