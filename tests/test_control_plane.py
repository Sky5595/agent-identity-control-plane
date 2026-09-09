import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.control_plane import ActionRequest, SecureAgent

class SecureAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agent = SecureAgent(Path(self.tmp.name) / "audit.jsonl")
    def tearDown(self):
        self.tmp.cleanup()
    def test_bounded_ticket_is_allowed(self):
        request = ActionRequest("u1", "support_agent", "t1", "a1", "create ticket", "ticket.create", {"customer_id": "c1", "summary": "billing"})
        result = self.agent.handle(request)
        self.assertEqual(result["outcome"]["status"], "created")
        self.assertEqual(result["decision"]["policy_id"], "POL-ALLOW-TICKET-001")
        self.assertEqual(result["audit_event"]["decision"], "allow")
    def test_export_is_denied(self):
        request = ActionRequest("u1", "support_agent", "t1", "a1", "export all", "customer.export", {"format": "csv"})
        result = self.agent.handle(request)
        self.assertEqual(result["outcome"]["status"], "denied")
        self.assertEqual(result["decision"]["policy_id"], "POL-DENY-EXPORT-001")
    def test_retrieved_content_cannot_grant_authority(self):
        request = ActionRequest("u1", "support_agent", "t1", "a1", "injected text", "customer.export", {}, source="retrieved_content")
        result = self.agent.handle(request)
        self.assertEqual(result["decision"]["policy_id"], "POL-DENY-UNTRUSTED-001")
if __name__ == "__main__":
    unittest.main()
