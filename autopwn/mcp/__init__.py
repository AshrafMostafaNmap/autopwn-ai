"""Model Context Protocol: external tool servers for the agent."""
from .bridge import qualified_name, register_mcp_tools
from .client import MCPClient
from .config import TRANSPORTS, MCPServerConfig
from .manager import MCPManager
from .presets import PRESETS, MCPPreset

__all__ = ["MCPClient", "MCPManager", "MCPServerConfig", "MCPPreset", "PRESETS",
           "TRANSPORTS", "qualified_name", "register_mcp_tools"]
