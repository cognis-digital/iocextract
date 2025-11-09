"""IOCEXTRACT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from iocextract.core import scan, to_json

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
        """Extract & defang IOCs (IPs/domains/hashes/URLs) from any text. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
