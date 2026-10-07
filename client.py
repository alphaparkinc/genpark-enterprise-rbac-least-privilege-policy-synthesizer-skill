"""
Enterprise RBAC Least-Privilege Policy Synthesizer (Zero External Dependencies)
Discovers exact resource action boundaries from audit logs and synthesizes tightly scoped IAM policies.
"""
import time
import math
import hashlib
import json
from typing import Dict, Any, List, Optional, Set

class EnterpriseRBACLeastPrivilegePolicySynthesizer:
    def __init__(self):
        pass

    def synthesize_least_privilege_policy(
        self,
        agent_id: str,
        execution_logs: List[Dict[str, Any]],
        role_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyzes tool calls in logs and synthesizes exact least-privilege policy.
        Groups allowed actions by resource prefix.
        """
        observed_actions: Set[str] = set()
        resource_map: Dict[str, Set[str]] = {}

        for log in execution_logs:
            if log.get("status") in ("SUCCESS", "COMPLETED", "OK", True):
                action = log.get("action") or log.get("tool_name")
                resource = log.get("resource") or log.get("target_resource") or "default"
                if action:
                    observed_actions.add(action)
                    if resource not in resource_map:
                        resource_map[resource] = set()
                    resource_map[resource].add(action)

        statements = []
        for res, actions in sorted(resource_map.items()):
            statements.append({
                "effect": "ALLOW",
                "actions": sorted(list(actions)),
                "resource": res,
                "conditions": {"mfa_required": False, "max_session_ttl_hours": 8}
            })

        policy_id = f"POL-{agent_id.upper()}-LEAST-PRIVILEGE"

        return {
            "policy_id": policy_id,
            "agent_id": agent_id,
            "role_name": role_name or f"Role_{agent_id}",
            "generated_at": time.time(),
            "total_distinct_actions_allowed": len(observed_actions),
            "total_resource_targets": len(resource_map),
            "statements": statements
        }

    def audit_policy_blast_radius(
        self,
        current_broad_policy: Dict[str, Any],
        synthesized_least_privilege_policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compares broad wildcard policy vs synthesized policy, computing blast-radius reduction."""
        broad_statements = current_broad_policy.get("statements", [])
        has_wildcard = any("*" in s.get("actions", []) or "*" in s.get("resource", "") for s in broad_statements)

        # Baseline theoretical blast radius index (wildcard = 100.0)
        baseline_radius = 100.0 if has_wildcard else 50.0
        
        # Synthesized radius: proportional to specific statements and actions
        synth_actions_count = synthesized_least_privilege_policy.get("total_distinct_actions_allowed", 1)
        synth_resources_count = synthesized_least_privilege_policy.get("total_resource_targets", 1)
        scoped_radius = min(25.0, (synth_actions_count * 1.5) + (synth_resources_count * 1.2))

        reduction_pct = round(((baseline_radius - scoped_radius) / baseline_radius) * 100.0, 1)

        return {
            "has_wildcard_vulnerability": has_wildcard,
            "baseline_blast_radius_score": baseline_radius,
            "least_privilege_blast_radius_score": round(scoped_radius, 1),
            "attack_surface_reduction_pct": max(0.0, reduction_pct),
            "risk_assessment": "CRITICAL_WILDCARD_ELIMINATED" if has_wildcard else "REFINED_SCOPING"
        }

    def validate_action_against_policy(
        self,
        policy: Dict[str, Any],
        requested_action: str,
        requested_resource: str
    ) -> Dict[str, Any]:
        """Validates whether an incoming agent action is permitted under policy."""
        for stmt in policy.get("statements", []):
            if stmt.get("effect") == "ALLOW":
                res_match = (stmt.get("resource") == requested_resource) or (stmt.get("resource") == "*")
                act_match = (requested_action in stmt.get("actions", [])) or ("*" in stmt.get("actions", []))
                if res_match and act_match:
                    return {"allowed": True, "reason": "Permitted by policy statement"}

        return {"allowed": False, "reason": f"Action '{requested_action}' on '{requested_resource}' denied by least-privilege boundary"}
