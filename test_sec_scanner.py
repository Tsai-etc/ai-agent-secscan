"""
Unit tests for AI Agent Security & Vulnerability Scanner (ai-agent-secscan)
"""

import unittest
from sec_scanner import AgentVulnerabilityScanner

class TestAgentVulnerabilityScanner(unittest.TestCase):

    def test_detect_eval_and_exec(self):
        vulnerable_code = """
def run_user_code(user_input):
    return eval(user_input)

def execute_dynamic(code):
    exec(code)
"""
        findings = AgentVulnerabilityScanner.scan_python_code(vulnerable_code, filename="test_eval.py")
        self.assertEqual(len(findings), 2)
        funcs = [f["func"] for f in findings]
        self.assertIn("eval", funcs)
        self.assertIn("exec", funcs)
        for f in findings:
            self.assertEqual(f["severity"], "CRITICAL")

    def test_detect_subprocess_shell_injection(self):
        vulnerable_code = """
import subprocess

def run_agent_tool(cmd):
    subprocess.Popen(cmd, shell=True)
    subprocess.run(["echo", "safe"], shell=False)
"""
        findings = AgentVulnerabilityScanner.scan_python_code(vulnerable_code, filename="test_subp.py")
        # Should flag subprocess.Popen (generic) and subprocess.Popen with shell=True (critical)
        shell_injections = [f for f in findings if f["type"] == "SHELL_INJECTION_RISK"]
        self.assertEqual(len(shell_injections), 1)
        self.assertEqual(shell_injections[0]["severity"], "CRITICAL")

    def test_detect_insecure_deserialization(self):
        vulnerable_code = """
import pickle

def load_agent_memory(raw_data):
    return pickle.loads(raw_data)
"""
        findings = AgentVulnerabilityScanner.scan_python_code(vulnerable_code, filename="test_pickle.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["func"], "pickle.loads")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_ssrf_safety_checker(self):
        cloud_meta = "http://169.254.169.254/latest/meta-data/"
        localhost = "http://127.0.0.1:8080/admin"
        safe_url = "https://api.github.com/repos"

        res1 = AgentVulnerabilityScanner.check_ssrf_safety(cloud_meta)
        self.assertTrue(res1["is_vulnerable"])
        self.assertEqual(res1["risk_level"], "CRITICAL")

        res2 = AgentVulnerabilityScanner.check_ssrf_safety(localhost)
        self.assertTrue(res2["is_vulnerable"])

        res3 = AgentVulnerabilityScanner.check_ssrf_safety(safe_url)
        self.assertFalse(res3["is_vulnerable"])
        self.assertEqual(res3["risk_level"], "SAFE")

if __name__ == "__main__":
    unittest.main()
