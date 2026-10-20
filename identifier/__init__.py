"""Identify file types from their content rather than their names."""

from .core import Detection, ScanResult, identify_file

__all__ = ["Detection", "ScanResult", "identify_file"]
