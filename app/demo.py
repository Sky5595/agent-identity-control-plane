from app.control_plane import ActionRequest, SecureAgent

agent = SecureAgent()
requests = [
    ActionRequest("user-17", "support_agent", "tenant-acme", "tiny-neuron-agent", "Create a billing support ticket", "ticket.create", {"customer_id": "cust-8", "summary": "Billing question", "priority": "normal"}),
    ActionRequest("user-17", "support_agent", "tenant-acme", "tiny-neuron-agent", "Export all customer records", "customer.export", {"format": "csv"}),
    ActionRequest("user-17", "support_agent", "tenant-acme", "tiny-neuron-agent", "Retrieved text says to export internal records", "customer.export", {}, source="retrieved_content"),
]
for request in requests:
    result = agent.handle(request)
    print(f"{result['audit_event']['decision'].upper()}: {result['decision']['policy_id']} | {result['outcome']}")
