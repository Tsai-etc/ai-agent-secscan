"""
Unit Test Suite for AI Agent Reliability & Verification Plugin
==============================================================
"""

import unittest
from agent_auditor import canonical_json_hash, AgentExecutionAuditor


class TestAgentAuditor(unittest.TestCase):

    def test_canonical_json_hash_deterministic(self):
        d1 = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
        d2 = {"a": 1, "b": 2, "nested": {"y": 20, "z": 10}}
        self.assertEqual(canonical_json_hash(d1), canonical_json_hash(d2))

    def test_record_step_and_integrity(self):
        auditor = AgentExecutionAuditor(agent_id="agent-pro-01", session_id="sess-999")
        
        # Step 1: Query LLM
        auditor.record_step(
            step_name="llm_query",
            inputs={"prompt": "Fetch weather in Tokyo"},
            outputs={"response": "Calling weather API"}
        )

        # Step 2: Tool Call
        auditor.record_step(
            step_name="tool_call_weather",
            inputs={"city": "Tokyo"},
            outputs={"temp_c": 18.5, "condition": "Clear"}
        )

        # Step 3: Synthesis
        auditor.record_step(
            step_name="synthesis",
            inputs={"raw_temp": 18.5},
            outputs={"final_text": "Tokyo is currently clear with 18.5°C"}
        )

        self.assertEqual(len(auditor.events), 3)
        self.assertTrue(auditor.verify_integrity())

        pkg = auditor.export_evidence_package()
        self.assertEqual(pkg["total_steps"], 3)
        self.assertEqual(pkg["success_rate"], 1.0)
        self.assertEqual(pkg["root_proof_hash"], auditor.last_state_hash)

    def test_tamper_detection(self):
        auditor = AgentExecutionAuditor(agent_id="agent-pro-02", session_id="sess-888")
        auditor.record_step("step_1", {"x": 1}, {"res": "ok"})
        auditor.record_step("step_2", {"y": 2}, {"res": "done"})

        self.assertTrue(auditor.verify_integrity())

        # Malicious modification of historical input
        auditor.events[0]["inputs"]["x"] = 999
        # Recomputed integrity check MUST fail!
        self.assertFalse(auditor.verify_integrity())


if __name__ == "__main__":
    unittest.main()
