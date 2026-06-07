# VAOS-Kernel MCP Integration Configs
#
# VAOS-Kernel exposes 6 MCP tools that any AI coding assistant can use:
#   request_credential  — get a 60-second intent-bound JWT
#   verify_credential   — check a JWT against expected intent
#   record_audit        — write a signed audit entry
#   verify_chain        — check chain integrity
#   get_public_key      — get the Ed25519 verification key
#   register_agent      — add a new agent to the registry
#
# Below are configs for each tool. Adjust the path to vaos-mcp.

# =====================================================================
# CLAUDE CODE / CLAUDE DESKTOP
# Add to ~/.claude/settings.json (Claude Code)
# or Claude Desktop > Settings > Developer > Edit Config
# =====================================================================
# {
#   "mcpServers": {
#     "vaos-kernel": {
#       "command": "/Users/speed/vaos-kernel/bin/vaos-mcp",
#       "args": [],
#       "env": {
#         "VAOS_JWT_SECRET": "*** (min 32 bytes)"
#       }
#     }
#   }
# }

# =====================================================================
# CURSOR
# Add to ~/.cursor/mcp.json
# =====================================================================
# {
#   "mcpServers": {
#     "vaos-kernel": {
#       "command": "/Users/speed/vaos-kernel/bin/vaos-mcp",
#       "args": [],
#       "env": {
#         "VAOS_JWT_SECRET": "*** (min 32 bytes)"
#       }
#     }
#   }
# }

# =====================================================================
# WINDSURF
# Add to ~/.codeium/windsurf/mcp_config.json
# =====================================================================
# {
#   "mcpServers": {
#     "vaos-kernel": {
#       "command": "/Users/speed/vaos-kernel/bin/vaos-mcp",
#       "args": [],
#       "env": {
#         "VAOS_JWT_SECRET": "*** (min 32 bytes)"
#       }
#     }
#   }
# }

# =====================================================================
# OPENAI CODEX
# Add to ~/.codex/config.toml
# =====================================================================
# [mcp_servers.vaos-kernel]
# command = "/Users/speed/vaos-kernel/bin/vaos-mcp"
# args = []
# [mcp_servers.vaos-kernel.env]
# VAOS_JWT_SECRET=*** (min 32 bytes)"

# =====================================================================
# HERMES AGENT
# Add to ~/.hermes/config.yaml
# =====================================================================
# mcp_servers:
#   vaos-kernel:
#     command: "/Users/speed/vaos-kernel/bin/vaos-mcp"
#     args: []
#     env:
#       VAOS_JWT_SECRET: "*** (min 32 bytes)"
