"""MCP Server for Enterprise RBAC Least-Privilege Policy Synthesizer."""
import sys
import json
import time
from client import EnterpriseRBACLeastPrivilegePolicySynthesizer

synthesizer = EnterpriseRBACLeastPrivilegePolicySynthesizer()

def handle_call_tool(params):
    name = params.get("name")
    args = params.get("arguments", {})
    if name != "synthesize_rbac_policy":
        raise ValueError(f"Unknown tool: {name}")

    action = args.get("action", "synthesize_least_privilege_policy")
    agent_id = args.get("agent_id", "agent_worker_1")
    logs = args.get("execution_logs", [])

    if action == "synthesize_least_privilege_policy":
        return synthesizer.synthesize_least_privilege_policy(agent_id, logs)
    elif action == "audit_policy_blast_radius":
        broad = args.get("current_policy", {"statements": [{"actions": ["*"], "resource": "*"}]})
        synth = synthesizer.synthesize_least_privilege_policy(agent_id, logs)
        return synthesizer.audit_policy_blast_radius(broad, synth)
    elif action == "validate_action_against_policy":
        pol = args.get("current_policy", {})
        return synthesizer.validate_action_against_policy(
            policy=pol,
            requested_action=args.get("requested_action", "read"),
            requested_resource=args.get("requested_resource", "doc_1")
        )
    else:
        raise ValueError(f"Invalid action: {action}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Running self-test...")
        logs = [
            {"action": "docs:read_table", "resource": "tencent_docs:sheet_01", "status": "SUCCESS"},
            {"action": "docs:export_pdf", "resource": "tencent_docs:sheet_01", "status": "SUCCESS"},
            {"action": "meeting:schedule", "resource": "tencent_meeting:room_4", "status": "SUCCESS"},
            {"action": "admin:delete_database", "resource": "mysql:root", "status": "FAILED"}
        ]
        synth = synthesizer.synthesize_least_privilege_policy("workbuddy_docs_agent", logs)
        assert synth["total_distinct_actions_allowed"] == 3
        # admin:delete_database failed and must not be in allowed policy
        allowed_actions = []
        for s in synth["statements"]:
            allowed_actions.extend(s["actions"])
        assert "admin:delete_database" not in allowed_actions

        audit = synthesizer.audit_policy_blast_radius({"statements": [{"actions": ["*"], "resource": "*"}]}, synth)
        assert audit["has_wildcard_vulnerability"] is True
        assert audit["attack_surface_reduction_pct"] > 70.0
        print("Self-test PASSED!")
        sys.exit(0)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            msg_id = req.get("id")
            method = req.get("method")
            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "EnterpriseRBACLeastPrivilegePolicySynthesizer", "version": "1.0.0"},
                        "capabilities": {"tools": {}}
                    }
                }
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [{
                            "name": "synthesize_rbac_policy",
                            "description": "Analyze agent audit logs, identify over-permissioned wildcards, generate granular least-privilege RBAC/ABAC policies, and measure blast-radius reduction.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "action": {"type": "string", "enum": ["synthesize_least_privilege_policy", "audit_policy_blast_radius"]},
                                    "agent_id": {"type": "string"},
                                    "execution_logs": {"type": "array"}
                                },
                                "required": ["action"]
                            }
                        }]
                    }
                }
            elif method == "tools/call":
                res = handle_call_tool(req.get("params", {}))
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
                }
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            print(json.dumps(resp), flush=True)
        except Exception as e:
            err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(e)}}
            print(json.dumps(err_resp), flush=True)

if __name__ == "__main__":
    main()
