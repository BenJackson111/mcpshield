# Approved MCP Server Registry & Shadow AI Prevention Policy (OWASP MCP09)

## 1. Prohibition of Unvetted Shadow MCP Servers
Engineers and automated agents may only connect MCP servers listed in the organization's verified registry and locked in `mcp-lock.json`.

## 2. Mandatory Vetting Checklist Before Approving a New MCP Server
1. **Source & Maintainer Verification:** Official vendor repository or internally audited fork.
2. **Exact Version Pinning:** Never allow `@latest`, mutable Git branches, or unpinned Docker tags (`MCP04`).
3. **Zero Token Passthrough:** Server must use its own least-privilege OAuth scope or API token (`MCP01`, `MCP07`).
4. **Governance Block Present:** Every entry in `mcp.json` must declare `governance.owner`, `governance.purpose`, `governance.riskTier`, and `governance.approvedDate`.
