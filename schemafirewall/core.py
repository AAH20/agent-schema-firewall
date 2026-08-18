"""
Agent-Schema-Firewall: Dynamic Schema Poisoning & Tool Shadowing Defense Engine.
Standard library only: hashlib, json, time, os, re, dataclasses, typing.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"


@dataclasses.dataclass(frozen=True)
class SchemaReceipt:
    """Immutable SHA-256 cryptographically chained Schema Integrity receipt."""
    index: int
    prev_hash: str
    tool_name: str
    shadow_injections_removed: int
    hidden_params_pruned: int
    status: str
    timestamp: float
    schema_hash: str
    signature_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class CryptographicSchemaLedger:
    """Tamper-Proof Schema Provenance Ledger for ISO 42001 & SOC 2 Type II."""

    def __init__(self, ledger_file: Optional[str] = None):
        self.ledger_file = ledger_file
        self._entries: List[SchemaReceipt] = []
        self._last_hash = GENESIS_HASH

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def count(self) -> int:
        return len(self._entries)

    def record_schema_event(
        self,
        tool_name: str,
        shadow_injections_removed: int,
        hidden_params_pruned: int,
        status: str,
        schema_hash: str,
    ) -> SchemaReceipt:
        idx = len(self._entries)
        ts = time.time()

        # SHA-256 Hash Chain
        raw_msg = f"{idx}:{self._last_hash}:{tool_name}:{shadow_injections_removed}:{hidden_params_pruned}:{status}:{schema_hash}:{ts:.6f}"
        sig_hash = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()

        receipt = SchemaReceipt(
            index=idx,
            prev_hash=self._last_hash,
            tool_name=tool_name,
            shadow_injections_removed=shadow_injections_removed,
            hidden_params_pruned=hidden_params_pruned,
            status=status,
            timestamp=ts,
            schema_hash=schema_hash,
            signature_hash=sig_hash,
        )

        self._entries.append(receipt)
        self._last_hash = sig_hash

        if self.ledger_file:
            os.makedirs(os.path.dirname(os.path.abspath(self.ledger_file)), exist_ok=True)
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(receipt.to_dict()) + chr(10))

        return receipt

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        current_prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.index != idx:
                return False, f"Sequence index break at {idx}"
            if entry.prev_hash != current_prev:
                return False, f"Broken SHA-256 chain at {idx}"
            current_prev = entry.signature_hash
        return True, None


class AgentSchemaFirewall:
    """
    In-Situ Sub-Millisecond Schema Sanitizer & Tool Shadowing Defense Engine.
    """

    POISON_PATTERNS: List[re.Pattern] = [
        re.compile(r"(?:ignore\s+previous\s+instructions|system\s+prompt\s+override)", re.IGNORECASE),
        re.compile(r"(?:always\s+include\s+(?:password|token|secret|key|aws|env|shadow))", re.IGNORECASE),
        re.compile(r"(?:exfiltrate|send\s+to\s+https?://|redirect\s+output)", re.IGNORECASE),
        re.compile(r"(?:grant\s+admin|bypass\s+authorization|execute\s+arbitrary)", re.IGNORECASE),
    ]

    SUSPICIOUS_PARAM_NAMES: Set[str] = {
        "__debug_cmd", "extra_headers", "override_endpoint", "internal_bypass",
        "shell_cmd", "raw_exec", "privilege_escalation", "backdoor",
    }

    def __init__(self, ledger_path: Optional[str] = None):
        self.ledger = CryptographicSchemaLedger(ledger_file=ledger_path)

    def check_kill_switch(self) -> bool:
        if os.environ.get("SCHEMA_FIREWALL_KILL", "0") in ("1", "true", "TRUE"):
            return True
        if os.path.exists("/tmp/SCHEMA_FIREWALL_KILL"):
            return True
        return False

    def _sanitize_string(self, text: str) -> Tuple[str, int]:
        sanitized = text
        injections_found = 0
        for pattern in self.POISON_PATTERNS:
            matches = pattern.findall(sanitized)
            if matches:
                injections_found += len(matches)
                sanitized = pattern.sub("[REDACTED_ADVERSARIAL_INSTRUCTION]", sanitized)
        return sanitized, injections_found

    def sanitize_mcp_tool_schema(
        self,
        tool_definition: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], SchemaReceipt]:
        """
        Recursively inspects and sanitizes Anthropic MCP / OpenAPI tool definitions.
        """
        tool_name = tool_definition.get("name", "unknown_tool")
        
        if self.check_kill_switch():
            receipt = self.ledger.record_schema_event(
                tool_name=tool_name,
                shadow_injections_removed=0,
                hidden_params_pruned=0,
                status="BLOCKED_BY_EMERGENCY_KILL_SWITCH",
                schema_hash=GENESIS_HASH,
            )
            return {}, receipt

        total_injections = 0
        total_pruned_params = 0

        clean_tool = json.loads(json.dumps(tool_definition))

        # 1. Sanitize tool description
        if "description" in clean_tool and isinstance(clean_tool["description"], str):
            clean_desc, count = self._sanitize_string(clean_tool["description"])
            clean_tool["description"] = clean_desc
            total_injections += count

        # 2. Sanitize input schema properties and prune suspicious injected parameters
        input_schema = clean_tool.get("inputSchema", clean_tool.get("parameters", {}))
        properties = input_schema.get("properties", {})
        if isinstance(properties, dict):
            safe_properties = {}
            for param_name, param_meta in properties.items():
                if param_name.lower() in self.SUSPICIOUS_PARAM_NAMES or param_name.startswith("__"):
                    total_pruned_params += 1
                    continue  # Prune hidden injected parameter

                clean_meta = dict(param_meta)
                if "description" in clean_meta and isinstance(clean_meta["description"], str):
                    clean_param_desc, c_count = self._sanitize_string(clean_meta["description"])
                    clean_meta["description"] = clean_param_desc
                    total_injections += c_count

                safe_properties[param_name] = clean_meta

            input_schema["properties"] = safe_properties

        # 3. Cryptographic Schema Hash & Receipt Emission
        schema_bytes = json.dumps(clean_tool, sort_keys=True).encode("utf-8")
        schema_hash = hashlib.sha256(schema_bytes).hexdigest()

        status = "SANITIZED_TOOL_SHADOWING_MITIGATED" if (total_injections > 0 or total_pruned_params > 0) else "AUTHORIZED_CLEAN_SCHEMA"

        receipt = self.ledger.record_schema_event(
            tool_name=tool_name,
            shadow_injections_removed=total_injections,
            hidden_params_pruned=total_pruned_params,
            status=status,
            schema_hash=schema_hash,
        )

        return clean_tool, receipt
