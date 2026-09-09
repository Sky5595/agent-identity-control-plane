"""A minimal deterministic authorization layer for tool-using AI agents."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json

@dataclass(frozen=True)
class ActionRequest:
    user_id: str
    user_role: str
    tenant_id: str
    agent_id: str
    task: str
    tool_name: str
    params: dict
    source: str = "user"

class PolicyEngine:
    """Model-generated or retrieved content never grants authority."""
    def evaluate(self, request: ActionRequest) -> dict:
        if request.source != "user":
            return self._deny("POL-DENY-UNTRUSTED-001", "Untrusted retrieved content cannot grant tool authority.")
        if request.tool_name == "ticket.create":
            allowed_roles = {"support_agent", "support_manager"}
            allowed_fields = {"customer_id", "summary", "priority"}
            if request.user_role not in allowed_roles:
                return self._deny("POL-DENY-ROLE-001", "The requester role cannot create support tickets.")
            if not set(request.params).issubset(allowed_fields):
                return self._deny("POL-DENY-PARAM-001", "The requested parameters are outside the ticket allowlist.")
            return {"allowed": True, "policy_id": "POL-ALLOW-TICKET-001", "reason": "Bounded ticket creation is allowed.", "scope": {"tool": "ticket.create", "tenant_id": request.tenant_id, "permitted_fields": sorted(request.params)}}
        if request.tool_name == "customer.export":
            return self._deny("POL-DENY-EXPORT-001", "Bulk customer export is not delegated to this agent.")
        return self._deny("POL-DENY-UNKNOWN-001", "This tool is not approved for the agent workflow.")
    @staticmethod
    def _deny(policy_id, reason):
        return {"allowed": False, "policy_id": policy_id, "reason": reason, "scope": None}

class AuditLogger:
    def __init__(self, path="audit_events.jsonl"):
        self.path = Path(path)
    def record(self, request: ActionRequest, decision: dict, outcome: dict) -> dict:
        event = {"timestamp": datetime.now(timezone.utc).isoformat(), "trace_id": f"trace-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}", "user_id": request.user_id, "agent_id": request.agent_id, "tenant_id": request.tenant_id, "task": request.task, "tool_name": request.tool_name, "policy_id": decision["policy_id"], "decision": "allow" if decision["allowed"] else "deny", "reason": decision["reason"], "outcome": outcome}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        return event

class ToolGateway:
    """Deny by default; a policy-approved scope must match the requested tool."""
    def execute(self, request: ActionRequest, decision: dict) -> dict:
        if not decision["allowed"]:
            return {"status": "denied", "reason": decision["reason"]}
        if decision["scope"]["tool"] != request.tool_name:
            return {"status": "denied", "reason": "Granted scope does not match requested tool."}
        if request.tool_name == "ticket.create":
            return {"status": "created", "ticket_id": "TCK-1042", "customer_id": request.params["customer_id"], "priority": request.params.get("priority", "normal")}
        return {"status": "denied", "reason": "Tool is not registered at the gateway."}

class SecureAgent:
    def __init__(self, audit_path="audit_events.jsonl"):
        self.policy_engine = PolicyEngine()
        self.gateway = ToolGateway()
        self.audit_logger = AuditLogger(audit_path)
    def handle(self, request: ActionRequest) -> dict:
        decision = self.policy_engine.evaluate(request)
        outcome = self.gateway.execute(request, decision)
        audit_event = self.audit_logger.record(request, decision, outcome)
        return {"request": asdict(request), "decision": decision, "outcome": outcome, "audit_event": audit_event}
