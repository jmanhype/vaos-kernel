#!/usr/bin/env python3
"""End-to-end smoke test for the mounted Agentic JWT P0 endpoints."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode


REPO = Path(__file__).resolve().parents[1]
API_SECRET = "smoke-api-secret"
REGISTRAR_CLIENT_ID = "registrar"
REGISTRAR_CLIENT_SECRET = "registrar-smoke-secret-with-32-bytes"
WORKFLOW_CLIENT_ID = "workflow-admin"
WORKFLOW_CLIENT_SECRET = "workflow-admin-smoke-secret-32-b!"
TOKEN_CLIENT_ID = "token-issuer"
TOKEN_CLIENT_SECRET = "token-issuer-smoke-secret-32-by!"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def b64url_raw(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def request_json(
    method: str,
    url: str,
    payload: dict | None = None,
    token: str | None = None,
) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read()
            if not raw:
                return response.status, {}
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, {"raw": raw.decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return exc.code, parsed


def request_form(url: str, form: dict[str, str]) -> tuple[int, dict]:
    body = urlencode(form).encode("ascii")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return exc.code, parsed


def transport_token(base_url: str, client_id: str, client_secret: str, scope: str) -> str:
    status, response = request_form(
        f"{base_url}/v1/oauth/token",
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
    if status != 200 or response.get("token_type") != "Bearer":
        raise AssertionError(f"transport token = {status} {response}")
    if response.get("scope") != scope:
        raise AssertionError(f"transport scope = {response.get('scope')}, want {scope}")
    return response["access_token"]


def jwt_payload(token: str) -> dict:
    payload_segment = token.split(".", 3)[1]
    payload_segment += "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_segment))


def main() -> int:
    http_port = free_port()
    grpc_port = free_port()
    base_url = f"http://127.0.0.1:{http_port}"

    with tempfile.TemporaryDirectory(prefix="vaos-agentic-smoke-") as temp_dir:
        temp = Path(temp_dir)
        binary = temp / "vaos-kernel"
        private_pem = temp / "ed25519-private.pem"
        registry_path = temp / "agentic-registry.json"

        subprocess.run(
            ["go", "build", "-o", str(binary), "./cmd/kernel"],
            cwd=REPO,
            check=True,
        )
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                str(private_pem),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        private_der = subprocess.check_output(
            ["openssl", "pkey", "-in", str(private_pem), "-outform", "DER"]
        )
        public_der = subprocess.check_output(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_pem),
                "-pubout",
                "-outform",
                "DER",
            ]
        )
        if len(private_der) < 32 or len(public_der) < 32:
            raise RuntimeError("openssl returned an invalid Ed25519 key")
        signing_seed = b64url_raw(private_der[-32:])
        agent_public = b64url_raw(public_der[-32:])

        env = os.environ.copy()
        env.update(
            {
                "VAOS_KERNEL_WS_ADDR": f"127.0.0.1:{http_port}",
                "VAOS_KERNEL_GRPC_ADDR": f"127.0.0.1:{grpc_port}",
                "VAOS_KERNEL_MODE": "sync",
                "VAOS_AUDIT_STDOUT": "false",
                "VAOS_API_SECRET": API_SECRET,
                "VAOS_AGENTIC_JWT_ENABLED": "true",
                "VAOS_AGENTIC_JWT_APP_ID": "smoke-app",
                "VAOS_AGENTIC_JWT_ISSUER": f"{base_url}/agentic",
                "VAOS_AGENTIC_JWT_SIGNING_KEY": f"seed:{signing_seed}",
                "VAOS_AGENTIC_JWT_REGISTRY_PATH": str(registry_path),
                "VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_ID": REGISTRAR_CLIENT_ID,
                "VAOS_AGENTIC_JWT_REGISTRAR_CLIENT_SECRET": REGISTRAR_CLIENT_SECRET,
                "VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_ID": WORKFLOW_CLIENT_ID,
                "VAOS_AGENTIC_JWT_WORKFLOW_CLIENT_SECRET": WORKFLOW_CLIENT_SECRET,
                "VAOS_AGENTIC_JWT_TOKEN_CLIENT_ID": TOKEN_CLIENT_ID,
                "VAOS_AGENTIC_JWT_TOKEN_CLIENT_SECRET": TOKEN_CLIENT_SECRET,
                "VAOS_AGENTIC_JWT_TTL_SECONDS": "300",
            }
        )

        logs = (temp / "kernel.log").open("w+", encoding="utf-8")
        process = subprocess.Popen(
            [str(binary)],
            cwd=REPO,
            env=env,
            stdout=logs,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                try:
                    status, _ = request_json("GET", f"{base_url}/health")
                    if status == 200:
                        break
                except Exception:
                    pass
                if process.poll() is not None:
                    logs.seek(0)
                    raise RuntimeError(logs.read())
                time.sleep(0.05)
            else:
                logs.seek(0)
                raise RuntimeError(f"kernel did not become healthy:\n{logs.read()}")

            status, _ = request_json("POST", f"{base_url}/v1/intent/token", {})
            if status != 401:
                raise AssertionError(f"unauthenticated token status = {status}")

            status, _ = request_json(
                "POST",
                f"{base_url}/v1/intent/token",
                {},
                API_SECRET,
            )
            if status != 401:
                raise AssertionError(f"shared-secret token status = {status}, want 401")

            status, _ = request_form(
                f"{base_url}/v1/oauth/token",
                {
                    "grant_type": "client_credentials",
                    "client_id": REGISTRAR_CLIENT_ID,
                    "client_secret": "wrong-smoke-secret-with-32-bytes!!",
                    "scope": "agentic:register-agent",
                },
            )
            if status != 401:
                raise AssertionError(f"wrong OAuth client status = {status}, want 401")

            registrar_transport = transport_token(
                base_url,
                REGISTRAR_CLIENT_ID,
                REGISTRAR_CLIENT_SECRET,
                "agentic:register-agent",
            )
            workflow_transport = transport_token(
                base_url,
                WORKFLOW_CLIENT_ID,
                WORKFLOW_CLIENT_SECRET,
                "agentic:register-workflow",
            )
            token_transport = transport_token(
                base_url,
                TOKEN_CLIENT_ID,
                TOKEN_CLIENT_SECRET,
                "generate:intent-token",
            )

            status, jwks = request_json("GET", f"{base_url}/.well-known/jwks.json")
            if status != 200 or len(jwks.get("keys", [])) != 1:
                raise AssertionError(f"JWKS response = {status} {jwks}")
            key_id = jwks["keys"][0]["kid"]

            agent_spec = {
                "agent_id": "smoke-agent",
                "prompt": "Run the authorized smoke workflow only.",
                "tools": [
                    {
                        "name": "run_step",
                        "signature": "run_step(step string)",
                        "description": "Run one authorized workflow step",
                    }
                ],
                "configuration": {"model_name": "smoke"},
            }
            status, registration = request_json(
                "POST",
                f"{base_url}/v1/intent/register/agent",
                {"agent_components": agent_spec, "public_key": agent_public},
                registrar_transport,
            )
            if status != 200 or registration.get("agent_id") != "smoke-agent":
                raise AssertionError(f"registration = {status} {registration}")

            workflow = {
                "workflow_id": "smoke-workflow",
                "steps": [
                    {
                        "step_id": "analyze",
                        "required": True,
                        "agent_id": "smoke-agent",
                    },
                    {"step_id": "approval", "approval_gate": True},
                    {
                        "step_id": "apply",
                        "required": True,
                        "requires_approval": True,
                        "agent_id": "smoke-agent",
                    },
                ],
            }
            status, workflow_response = request_json(
                "POST",
                f"{base_url}/v1/intent/register/workflow",
                workflow,
                workflow_transport,
            )
            if status != 200 or workflow_response.get("status") != "registered":
                raise AssertionError(f"workflow registration = {status} {workflow_response}")

            token_request = {
                "grant_type": "agent_checksum",
                "agent_id": "smoke-agent",
                "computed_checksum": registration["checksum"],
                "workflow_enabled": True,
                "workflow_id": "smoke-workflow",
                "workflow_step": "apply",
                "requested_scopes": ["smoke:run"],
                "audience": "https://resource.example.test",
                "delegation_context": {
                    "chain": ["smoke-agent"],
                    "completed_steps": ["analyze", "approval"],
                },
            }
            status, token_response = request_json(
                "POST",
                f"{base_url}/v1/intent/token",
                token_request,
                token_transport,
            )
            if status != 200 or token_response.get("token_type") != "Bearer":
                raise AssertionError(f"token = {status} {token_response}")

            claims = jwt_payload(token_response["access_token"])
            if claims.get("iss") != env["VAOS_AGENTIC_JWT_ISSUER"]:
                raise AssertionError(f"issuer = {claims.get('iss')}")
            if claims.get("aud") != ["https://resource.example.test"]:
                raise AssertionError(f"audience = {claims.get('aud')}")
            if claims.get("scope") != "smoke:run":
                raise AssertionError(f"scope = {claims.get('scope')}")
            if claims.get("agent_proof", {}).get("registration_id") != registration["registration_id"]:
                raise AssertionError(f"agent proof = {claims.get('agent_proof')}")

            header_segment = token_response["access_token"].split(".", 3)[0]
            header_segment += "=" * (-len(header_segment) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_segment))
            if header.get("kid") != key_id:
                raise AssertionError(f"JWT kid = {header.get('kid')}, JWKS kid = {key_id}")

            status, audit = request_json(
                "GET",
                f"{base_url}/api/audit/entries?per_page=100",
                token=API_SECRET,
            )
            if status != 200:
                raise AssertionError(f"audit entries = {status} {audit}")
            actions = {
                entry.get("action")
                for entry in audit.get("entries", [])
                if isinstance(entry, dict)
            }
            required_actions = {
                "agentic_agent_registered",
                "agentic_workflow_registered",
                "agentic_token_minted",
            }
            if not required_actions.issubset(actions):
                raise AssertionError(f"audit actions = {sorted(actions)}")

            status, replay = request_json("GET", f"{base_url}/api/audit/verify")
            if status != 200 or replay.get("chain_status") != "ok":
                raise AssertionError(f"audit replay = {status} {replay}")

            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            logs.close()

            restart_logs = (temp / "kernel-restart.log").open(
                "w+", encoding="utf-8"
            )
            logs = restart_logs
            process = subprocess.Popen(
                [str(binary)],
                cwd=REPO,
                env=env,
                stdout=logs,
                stderr=subprocess.STDOUT,
            )
            for _ in range(100):
                try:
                    status, _ = request_json("GET", f"{base_url}/health")
                    if status == 200:
                        break
                except Exception:
                    pass
                if process.poll() is not None:
                    logs.seek(0)
                    raise RuntimeError(logs.read())
                time.sleep(0.05)
            else:
                logs.seek(0)
                raise RuntimeError(
                    f"restarted kernel did not become healthy:\n{logs.read()}"
                )

            token_transport = transport_token(
                base_url,
                TOKEN_CLIENT_ID,
                TOKEN_CLIENT_SECRET,
                "generate:intent-token",
            )
            status, restarted_response = request_json(
                "POST",
                f"{base_url}/v1/intent/token",
                token_request,
                token_transport,
            )
            if status != 200 or restarted_response.get("token_type") != "Bearer":
                raise AssertionError(
                    f"restarted token = {status} {restarted_response}"
                )
            restarted_claims = jwt_payload(restarted_response["access_token"])
            if restarted_claims.get("jti") == claims["jti"]:
                raise AssertionError("restart minted the same jti unexpectedly")
            if (
                restarted_claims.get("agent_proof", {}).get("registration_id")
                != registration["registration_id"]
            ):
                raise AssertionError(
                    f"restarted agent proof = {restarted_claims.get('agent_proof')}"
                )

            print(
                json.dumps(
                    {
                        "status": "passed",
                        "http_port": http_port,
                        "grpc_port": grpc_port,
                        "jwks_kid": key_id,
                        "registration_id": registration["registration_id"],
                        "workflow_id": workflow["workflow_id"],
                        "token_jti": claims["jti"],
                        "restart_token_jti": restarted_claims["jti"],
                        "registry_restart_persisted": True,
                        "audit_actions": sorted(actions),
                        "audit_entry_count": replay.get("entry_count"),
                        "audit_chain_status": replay.get("chain_status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            logs.close()


if __name__ == "__main__":
    raise SystemExit(main())
