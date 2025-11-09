"""IOCEXTRACT — Extract & defang IOCs (IPs/domains/hashes/URLs) from any text."""
from iocextract.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
