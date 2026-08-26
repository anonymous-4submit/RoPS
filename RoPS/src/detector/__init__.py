"""detector — Stage 2: suspicious pickle opcode sequence detection."""

from .scanner import build_json_report_for_blob, scan_one_blob

__all__ = ["build_json_report_for_blob", "scan_one_blob"]
