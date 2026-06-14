"""IOCEXTRACT MCP server — exposes extract() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from iocextract.core import extract


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-iocextract[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-iocextract[mcp]'")
        return 1
    app = FastMCP("iocextract")

    @app.tool()
    def iocextract_scan(target: str) -> str:
        """Extract & defang IOCs from text. Returns JSON findings."""
        if not isinstance(target, str):
            return json.dumps({"error": "target must be a string"})
        result = extract(target)
        return json.dumps(result.as_dict())

    app.run()
    return 0
