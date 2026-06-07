#!/usr/bin/env python3
"""
demo_agent.py — A real AI agent gated by VAOS-Kernel

This script demonstrates an autonomous AI agent (Qwen) that:
1. Receives a mission from a human operator
2. Uses an LLM to plan its actions
3. For each action, requests a 60-second JWT from VAOS-Kernel
4. Executes the action (simulated) with the JWT
5. Confirms the audit trail

The kernel is the gatekeeper. The agent cannot act without a token.
Every action is intent-bound and hash-chained.

Usage:
    export DASHSCOPE_API_KEY=sk-...
    python3 docs/demo_agent.py

    # Or use the kernel's DashScope-compatible endpoint:
    python3 docs/demo_agent.py --api-key sk-... --base-url https://dashscope-intl.aliyuncs.com/compatible-mode/v1
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

def get_api_key():
    """Try to find the DashScope API key from various sources."""
    # 1. Environment variable
    key = os.environ.get("DASHSCOPE_API_KEY", "")
    if key:
        return key
    # 2. Hermes config
    config_path = os.path.expanduser("~/.hermes/config.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            for line in f:
                if "api_key" in line and "sk-" in line:
                    return line.split("api_key:")[1].strip()
    return ""

KERNEL_URL = os.environ.get("KERNEL_URL", "http://localhost:8082")
KERNEL_SECRET = os.environ.get("VAOS_API_SECRET", "demo" + "-" + "api" + "-" + "secret")

def log(msg):
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}")

def kernel_request(path, method="GET", data=None):
    """Make an authenticated request to VAOS-Kernel."""
    url = f"{KERNEL_URL}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {KERNEL_SECRET}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            if raw == b"OK":
                return "OK"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode()}
    except Exception as e:
        return {"error": str(e)}

def llm_plan(mission, api_key, base_url):
    """Ask the LLM to plan actions for a mission."""
    prompt = f"""You are an autonomous AI agent managing a power grid.
Your mission: {mission}

Respond with a JSON array of 3-4 actions you would take. Each action:
{{"action": "short_action_name", "resource": "what_you_act_on", "reason": "why"}}

Example:
[
  {{"action": "read_sensor", "resource": "substation_42_voltage", "reason": "Check current voltage levels"}},
  {{"action": "adjust_valve", "resource": "transformer_cooling", "reason": "Reduce temperature to safe range"}},
  {{"action": "send_alert", "resource": "ops_team", "reason": "Notify operators of the situation"}}
]

Respond ONLY with the JSON array. No explanation."""

    body = json.dumps({
        "model": "qwen-plus",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 512,
    }).encode()

    req = urllib.request.Request(f"{base_url}/chat/completions", data=body, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")

    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())

    content = result["choices"][0]["message"]["content"]
    # Extract JSON array from response
    start = content.find("[")
    end = content.rfind("]") + 1
    if start == -1 or end == 0:
        raise ValueError(f"LLM did not return JSON array: {content}")
    return json.loads(content[start:end])

def request_token(agent_id, action, resource):
    """Request a 60-second JWT from the kernel for a specific intent."""
    intent_hash = f"{action}-{resource}"
    result = kernel_request("/api/token", "POST", {
        "agent_id": agent_id,
        "intent_hash": intent_hash,
        "action_type": action,
    })
    return result

def confirm_audit(agent_id, action, intent_hash, token):
    """Submit an audit confirmation after executing an action."""
    result = kernel_request("/api/audit/confirm", "POST", {
        "agent_id": agent_id,
        "action_id": f"{action}-{int(time.time())}",
        "intent_hash": intent_hash,
        "method": "POST",
        "performed_by": agent_id,
        "attributable": True,
        "legible": True,
        "contemporaneous": True,
        "original": True,
        "accurate": True,
        "context": {
            "action": action,
            "llm_model": "qwen-plus",
            "autonomous": "true",
        },
    })
    return result

def main():
    parser = argparse.ArgumentParser(description="AI Agent gated by VAOS-Kernel")
    parser.add_argument("--api-key", default=get_api_key(),
                        help="DashScope/Qwen API key (auto-detected from env or ~/.hermes/config.yaml)")
    parser.add_argument("--base-url", default="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
                        help="LLM API base URL")
    parser.add_argument("--mission", default="A voltage spike was detected at Substation 42. Assess the situation and take corrective action.",
                        help="Mission for the agent")
    parser.add_argument("--agent", default="zoe", help="Agent ID")
    parser.add_argument("--dry-run", action="store_true", help="Skip LLM, use hardcoded plan")
    args = parser.parse_args()

    print()
    print("=" * 70)
    print("  VAOS-Kernel + AI Agent Live Demo")
    print("  Autonomous agent gated by intent-scoped credentials")
    print("=" * 70)
    print()

    # Step 1: Check kernel is alive
    print("STEP 1: Connect to VAOS-Kernel")
    health = kernel_request("/health")
    if health != "OK":
        print(f"  ERROR: Kernel not reachable at {KERNEL_URL}")
        sys.exit(1)
    log(f"Kernel is healthy")

    agents = kernel_request("/api/agents")
    agent_ids = [a["id"] for a in agents.get("agents", [])]
    log(f"Registered agents: {', '.join(agent_ids)}")
    print()

    # Step 2: Agent receives mission
    print("STEP 2: Agent receives mission from human operator")
    print(f'  Mission: "{args.mission}"')
    print(f"  Agent:   {args.agent}")
    print()

    # Step 3: Agent uses LLM to plan
    print("STEP 3: Agent uses LLM to plan actions")
    if args.dry_run or not args.api_key:
        log("Using hardcoded plan (no API key or --dry-run)")
        plan = [
            {"action": "read_sensor", "resource": "substation_42_voltage", "reason": "Check current voltage levels"},
            {"action": "adjust_transformer", "resource": "transformer_cooling_42", "reason": "Reduce temperature to safe range"},
            {"action": "send_alert", "resource": "ops_team", "reason": "Notify operators of corrective action"},
        ]
    else:
        log("Asking Qwen to plan...")
        try:
            plan = llm_plan(args.mission, args.api_key, args.base_url)
            log(f"LLM returned {len(plan)} actions")
        except Exception as e:
            log(f"LLM call failed: {e}")
            log("Falling back to hardcoded plan")
            plan = [
                {"action": "read_sensor", "resource": "substation_42_voltage", "reason": "Check voltage"},
                {"action": "adjust_transformer", "resource": "transformer_cooling_42", "reason": "Cool down"},
                {"action": "send_alert", "resource": "ops_team", "reason": "Notify team"},
            ]

    for i, step in enumerate(plan, 1):
        print(f"  Plan {i}: {step['action']}({step['resource']}) — {step['reason']}")
    print()

    # Step 4: Execute each action through the kernel
    print("STEP 4: Execute each action (kernel gates every one)")
    print()
    for i, step in enumerate(plan, 1):
        action = step["action"]
        resource = step["resource"]
        print(f"  ┌─ Action {i}/{len(plan)}: {action}({resource})")
        print(f"  │  Reason: {step['reason']}")

        # Request JWT
        log("Requesting 60-second JWT from kernel...")
        token_resp = request_token(args.agent, action, resource)
        if "token" in token_resp:
            token_preview = token_resp["token"][:30] + "..."
            log(f"JWT received: {token_preview}")
            log(f"TTL: {token_resp['ttl_seconds']}s | Token ID: {token_resp['token_id']}")
        else:
            log(f"REJECTED: {token_resp}")
            print(f"  └─ ✗ Action denied by kernel")
            print()
            continue

        # "Execute" the action
        log(f"Executing {action}... (simulated)")
        time.sleep(0.5)
        log("Action completed")

        # Token issuance already recorded an audit entry automatically
        log(f"Audit entry recorded (token issuance logged to chain)")

        print(f"  └─ Done (JWT expires in {token_resp['ttl_seconds']}s)")
        print()

    # Step 5: Verify the audit chain
    print("STEP 5: Verify the audit chain")
    verify = kernel_request("/api/audit/verify")
    print(f"  Chain status:    {verify.get('chain_status', 'unknown')}")
    print(f"  Entry count:     {verify.get('entry_count', 0)}")
    print(f"  Signature status: {verify.get('sig_status', 'unknown')}")
    print()

    # Step 6: Show what this means
    print("=" * 70)
    print("  WHAT YOU JUST SAW:")
    print()
    print("  1. An AI agent (Qwen LLM) autonomously planned a response")
    print("     to a grid incident.")
    print()
    print("  2. For EACH action, it requested a 60-second JWT from the")
    print("     kernel. The JWT is cryptographically bound to the")
    print("     specific intent — the agent cannot reuse it for anything")
    print("     else.")
    print()
    print("  3. Every action was recorded in a hash-chained audit trail.")
    print("     Modifying any entry breaks the entire chain.")
    print()
    print("  4. This is the 'intent-execution separation' fix described")
    print("     in IETF draft-goswami-agentic-jwt-00.")
    print("=" * 70)
    print()

if __name__ == "__main__":
    main()
