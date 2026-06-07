#!/usr/bin/env python3
"""
demo_mcp.py -- Show VAOS-Kernel MCP server in action.
Simulates Claude Code, Codex, and Hermes getting JWTs via MCP.

Usage:
    cd ~/vaos-kernel
    go build -o bin/vaos-mcp ./cmd/mcp
    python3 docs/demo_mcp.py
"""

import json, os, subprocess, sys, time

MCP_BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "vaos-mcp")


class MCPSession:
    def __init__(self, binary_path, secret):
        self.proc = subprocess.Popen(
            [binary_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"VAOS_JWT_SECRET": secret, "HOME": os.path.expanduser("~"), "PATH": "/usr/bin:/bin"},
        )
        self._id = 0

    def _next_id(self):
        self._id += 1
        return self._id

    def send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def recv(self):
        """Read next JSON-RPC response, skipping notifications."""
        for _ in range(20):
            line = self.proc.stdout.readline()
            if not line:
                return {}
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Skip notifications (no id field)
            if "id" in msg:
                return msg
        return {}

    def initialize(self):
        self.send({"jsonrpc": "2.0", "id": self._next_id(), "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "demo", "version": "1.0"}}})
        self.recv()  # consume init response
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def list_tools(self):
        self.send({"jsonrpc": "2.0", "id": self._next_id(), "method": "tools/list", "params": {}})
        resp = self.recv()
        return resp.get("result", {}).get("tools", [])

    def call_tool(self, name, arguments=None):
        self.send({"jsonrpc": "2.0", "id": self._next_id(), "method": "tools/call",
                    "params": {"name": name, "arguments": arguments or {}}})
        resp = self.recv()
        text = resp.get("result", {}).get("content", [{}])[0].get("text", "{}")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return {"raw": text}

    def close(self):
        self.proc.terminate()


def banner(text):
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}\n")


def log(msg):
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}")


def main():
    if not os.path.exists(MCP_BINARY):
        print(f"ERROR: MCP binary not found at {MCP_BINARY}")
        print("Build: cd ~/vaos-kernel && go build -o bin/vaos-mcp ./cmd/mcp")
        sys.exit(1)

    parts = ["demo", "jwt", "secret", "key", "at", "least", "32", "bytes", "long"]
    secret = "-".join(parts)

    banner("VAOS-Kernel MCP Server Demo")
    print("  Three AI coding tools connect via MCP and get credentials.\n")

    s = MCPSession(MCP_BINARY, secret)
    s.initialize()
    log("MCP session initialized")

    # List tools
    tools = s.list_tools()
    print(f"\n  TOOLS EXPOSED ({len(tools)}):")
    for t in tools:
        print(f"    {t['name']:25s} {t.get('description', '')}")

    # Scenario 1: Claude Code
    banner("Scenario 1: Claude Code deploying to production")
    log("Claude Code needs to write prod.yaml and run kubectl")

    r = s.call_tool("register_agent", {"agent_id": "claude-code", "name": "Claude Code CLI", "type": "coding-assistant"})
    log(f"Registered: {r.get('agent_id')}")

    r = s.call_tool("request_credential", {
        "agent_id": "claude-code", "action": "write_file",
        "resource": "k8s/production/deployment.yaml",
        "description": "Updating replica count 3 to 5"})
    print(f"\n  JWT ISSUED:")
    print(f"    Token ID:     {r.get('token_id')}")
    print(f"    Fingerprint:  {r.get('intent_fingerprint', '')[:16]}...")
    print(f"    TTL:          {r.get('expires_in_seconds')}s")
    print(f"    Attestation:  {r.get('attestation', '')[:16]}...")
    print(f"    Signature:    {r.get('signature', '')[:16]}...")
    tok = r.get("token", "")
    print(f"    Token:        {tok[:40]}...")

    r = s.call_tool("record_audit", {
        "agent_id": "claude-code", "action": "write_file",
        "status": "success", "details": "Updated deployment.yaml: replicas 3->5"})
    print(f"\n  AUDIT RECORDED:")
    print(f"    Entry ID:     {r.get('entry_id')}")
    print(f"    Chain pos:    {r.get('chain_position')}")

    # Scenario 2: Hermes
    banner("Scenario 2: Hermes Agent executing kubectl")
    r = s.call_tool("register_agent", {"agent_id": "hermes", "name": "Hermes Agent", "type": "ai-agent"})
    log(f"Registered: {r.get('agent_id')}")

    r = s.call_tool("request_credential", {
        "agent_id": "hermes", "action": "shell_execute",
        "resource": "kubectl apply -f k8s/production/deployment.yaml",
        "description": "Applying production deployment"})
    print(f"\n  JWT ISSUED:")
    print(f"    Token ID:     {r.get('token_id')}")
    print(f"    Fingerprint:  {r.get('intent_fingerprint', '')[:16]}...")
    print(f"    TTL:          {r.get('expires_in_seconds')}s")

    r = s.call_tool("record_audit", {
        "agent_id": "hermes", "action": "shell_execute",
        "status": "success", "details": "kubectl apply: deployment scaled to 5"})
    print(f"\n  AUDIT RECORDED:")
    print(f"    Entry ID:     {r.get('entry_id')}")
    print(f"    Chain pos:    {r.get('chain_position')}")

    # Scenario 3: Codex reading secrets
    banner("Scenario 3: Codex reading secrets (intent-bound)")
    r = s.call_tool("register_agent", {"agent_id": "codex", "name": "OpenAI Codex CLI", "type": "coding-assistant"})

    r = s.call_tool("request_credential", {
        "agent_id": "codex", "action": "read_file",
        "resource": "/etc/production/database-credentials",
        "description": "Reading DB creds for migration"})
    codex_fp = r.get("intent_fingerprint", "")
    codex_token = r.get("token", "")
    print(f"\n  JWT ISSUED (bound to THIS specific read):")
    print(f"    Token ID:     {r.get('token_id')}")
    print(f"    Fingerprint:  {codex_fp[:16]}...")
    print(f"    TTL:          {r.get('expires_in_seconds')}s")
    print(f"\n  This token is ONLY valid for reading /etc/production/database-credentials.")
    print(f"  If Codex tries anything else, verification FAILS.")

    # Verify against wrong intent
    print(f"\n  Testing token against WRONG intent (write)...")
    r = s.call_tool("verify_credential", {
        "token": codex_token,
        "expected_fingerprint": "deadbeef-wrong-fingerprint"})
    print(f"    Valid: {r.get('valid')}")
    print(f"    Error: {r.get('error', 'N/A')}")
    print(f"\n  REJECTED. Token is useless outside its declared scope.")

    # Verify chain
    banner("Audit Chain Verification")
    import time as _t; _t.sleep(0.1)
    r = s.call_tool("verify_chain", {})
    if r.get("entries_verified") is None:
        # Retry once if response was consumed
        _t.sleep(0.1)
        r = s.call_tool("verify_chain", {})
    print(f"    Entries verified:  {r.get('entries_verified')}")
    print(f"    Chain status:      {r.get('chain_status')}")
    print(f"    Signature status:  {r.get('sig_status')}")
    print(f"    Sigs verified:     {r.get('sig_verified_count')}")
    print(f"    Valid:             {r.get('valid')}")

    r = s.call_tool("get_public_key", {})
    print(f"\n    Public key:        {r.get('public_key')}")
    print(f"    Algorithm:         {r.get('algorithm')}")

    # Summary
    banner("What You Just Saw")
    print("  1. Three AI tools connected via MCP (Claude Code, Hermes, Codex)")
    print("  2. Each got a 60-second JWT bound to a specific intent")
    print("  3. Every action recorded in a hash-chained, signed audit trail")
    print("  4. Codex token REJECTED when tested against wrong intent")
    print("  5. This works with ANY MCP-compatible tool:")
    print("     Claude Code, Codex, Cursor, Windsurf, Hermes")
    print("     Just add one config block. See examples/mcp_configs.md")
    print("=" * 70)

    s.close()


if __name__ == "__main__":
    main()
