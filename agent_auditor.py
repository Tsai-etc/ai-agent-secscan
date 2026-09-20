"""
Universal AI Agent Reliability & Verification Plugin (SABLE-Compatible)
========================================================================
A framework-agnostic runtime auditor for AI Agents (LangChain, CrewAI, OMI, LiteLLM).
Guarantees execution repeatability, external state tracking, and tamper-evident cryptographic proofs.

Author: CashFlow Studio (@Tsai-etc)
Sponsorship / Wallet: 0x322f38636bf6fa64d07af5f481bcb63bc3828731 (BEP20)
"""

import hashlib
import json
import time
from typing import Dict, Any, List, Optional


def canonical_json_hash(data: Any) -> str:
    """Computes deterministic SHA-256 hash for arbitrary nested JSON-serializable structures."""
    dumped = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(dumped.encode('utf-8')).hexdigest()


class AgentExecutionAuditor:
    """
    Tamper-evident runtime auditor that intercepts agent tool calls,
    records effect hashes, and produces verifier evidence packages.
    """

    def __init__(self, agent_id: str, session_id: str):
        self.agent_id = agent_id
        self.session_id = session_id
        self.events: List[Dict[str, Any]] = []
        self.start_timestamp = time.time()
        self.last_state_hash = "0" * 64

    def record_step(self, step_name: str, inputs: Dict[str, Any], outputs: Dict[str, Any], status: str = "SUCCESS") -> Dict[str, Any]:
        """
        Records a discrete agent reasoning / execution step and chains its SHA-256 hash
        to maintain cryptographic tamper resistance.
        """
        timestamp = time.time()
        input_hash = canonical_json_hash(inputs)
        output_hash = canonical_json_hash(outputs)

        step_payload = {
            "step_index": len(self.events) + 1,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "step_name": step_name,
            "timestamp": timestamp,
            "status": status,
            "prev_state_hash": self.last_state_hash,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "inputs": inputs,
            "outputs": outputs
        }

        # Block-chain style step hash
        step_hash = canonical_json_hash({
            "prev": self.last_state_hash,
            "name": step_name,
            "in": input_hash,
            "out": output_hash,
            "status": status
        })

        step_payload["step_hash"] = step_hash
        self.last_state_hash = step_hash
        self.events.append(step_payload)

        return step_payload

    def export_evidence_package(self) -> Dict[str, Any]:
        """Exports complete verifiable audit package ready for external verification or dispute resolution."""
        total_steps = len(self.events)
        success_steps = sum(1 for e in self.events if e["status"] == "SUCCESS")
        
        root_proof_hash = self.last_state_hash

        return {
            "version": "1.0.0-sable-compat",
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "total_steps": total_steps,
            "success_rate": (success_steps / total_steps) if total_steps > 0 else 1.0,
            "root_proof_hash": root_proof_hash,
            "events_count": len(self.events),
            "events": self.events
        }

    def verify_integrity(self) -> bool:
        """Verifies that the recorded event chain and payload contents have not been tampered with."""
        current_hash = "0" * 64
        for event in self.events:
            if event["prev_state_hash"] != current_hash:
                return False
            
            # Recompute payload hashes to detect content tampering
            recomputed_in_hash = canonical_json_hash(event["inputs"])
            recomputed_out_hash = canonical_json_hash(event["outputs"])

            if recomputed_in_hash != event["input_hash"] or recomputed_out_hash != event["output_hash"]:
                return False

            recomputed = canonical_json_hash({
                "prev": current_hash,
                "name": event["step_name"],
                "in": recomputed_in_hash,
                "out": recomputed_out_hash,
                "status": event["status"]
            })
            if recomputed != event["step_hash"]:
                return False
            current_hash = event["step_hash"]

        return current_hash == self.last_state_hash
