"""Example usage for EnterpriseRBACLeastPrivilegePolicySynthesizer."""
import sys
import json
from client import EnterpriseRBACLeastPrivilegePolicySynthesizer

sys.stdout.reconfigure(encoding='utf-8')

def main():
    print("=== Enterprise Agent Least-Privilege IAM Policy Synthesizer Demo ===")
    synthesizer = EnterpriseRBACLeastPrivilegePolicySynthesizer()

    execution_history = [
        {"action": "docs:read_sheet", "resource": "docs.tencent.com/sheet/001", "status": "SUCCESS"},
        {"action": "docs:write_cells", "resource": "docs.tencent.com/sheet/001", "status": "SUCCESS"},
        {"action": "wechat_work:send_msg", "resource": "work.weixin.qq.com/bot/finance", "status": "SUCCESS"},
        {"action": "cloud:restart_server", "resource": "tencentcloud:cvm/*", "status": "FAILED"} # failed unauth
    ]

    # 1. Synthesize minimal least-privilege policy from legitimate operations
    print("\n--- 1. Synthesizing Scoped Least-Privilege IAM Policy ---")
    synth_policy = synthesizer.synthesize_least_privilege_policy("workbuddy_finance_bot", execution_history)
    print(json.dumps(synth_policy, indent=2))

    # 2. Audit blast radius reduction against over-permissioned wildcard policy
    print("\n--- 2. Auditing Attack Surface & Blast Radius Reduction ---")
    legacy_wildcard_policy = {
        "policy_id": "LEGACY-ADMIN-WILDCARD",
        "statements": [{"effect": "ALLOW", "actions": ["*"], "resource": "*"}]
    }
    audit = synthesizer.audit_policy_blast_radius(legacy_wildcard_policy, synth_policy)
    print(f"Wildcard Vulnerability Eliminated: {audit['has_wildcard_vulnerability']}")
    print(f"Blast Radius Score: {audit['baseline_blast_radius_score']} -> {audit['least_privilege_blast_radius_score']}")
    print(f"Total Attack Surface Reduction: {audit['attack_surface_reduction_pct']}%")

    # 3. Validate unauthorized privilege escalation attempt
    print("\n--- 3. Verifying Policy Guardrail Against Privilege Escalation ---")
    chk_allowed = synthesizer.validate_action_against_policy(synth_policy, "docs:read_sheet", "docs.tencent.com/sheet/001")
    print(f"Action 'docs:read_sheet': Allowed = {chk_allowed['allowed']}")

    chk_denied = synthesizer.validate_action_against_policy(synth_policy, "cloud:terminate_instance", "tencentcloud:cvm/*")
    print(f"Action 'cloud:terminate_instance': Allowed = {chk_denied['allowed']} ({chk_denied['reason']})")

if __name__ == "__main__":
    main()
