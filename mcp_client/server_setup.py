from pathlib import Path
from typing import Optional
from fastmcp import FastMCP
from mcp_client.gateway import register_gateway_tools
from mcp_client.tool_profiles import (
    TOOL_PROFILES,
    DEFAULT_PROFILE,
    FULL_PROFILE,
    CYBER_RANGE_PROFILE,
    resolve_profile_dependencies,
)
from mcp_client.plugin_mcp_loader import load_plugin_tools

try:
    from fastmcp.server.providers.skills import SkillsDirectoryProvider
except ImportError:
    SkillsDirectoryProvider = None

def _register_skills(mcp: FastMCP, logger) -> None:
    """Mount the local skills/ directory as MCP resources if it exists."""
    if SkillsDirectoryProvider is None:
        logger.warning("fastmcp SkillsDirectoryProvider not available; skipping skills registration")
        return
    skills_dir = Path(__file__).parent.parent.parent / "AI/skills"
    if not skills_dir.exists():
        return
    
    mcp.add_provider(SkillsDirectoryProvider(roots=skills_dir))
    logger.info(f"🤖 Skills initialized")

def setup_mcp_server(api_client, logger, compact: bool = False, profiles: Optional[list] = None) -> FastMCP:
    """
    Set up the MCP server with all enhanced tool functions

    Args:
        api_client: Initialized API client
        logger: Logger instance for logging
        compact: If True, register only classify_task and run_tool gateway tools
        profiles: Optional list of tool profiles to load (e.g., ["core_network", "web_app"])

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("mcp-server")

    _register_skills(mcp, logger)

    if compact:
        # Register gateway tools for task classification and tool execution
        register_gateway_tools(mcp, api_client)

        logger.info("Compact mode: only gateway tools registered (classify_task, run_tool)")
        return mcp

    # Determine which profiles to load
    if profiles:
        if "default" in profiles:
            selected_profiles = DEFAULT_PROFILE
        elif "full" in profiles:
            selected_profiles = FULL_PROFILE
        elif "cyber-range" in profiles:
            # Named aggregate profile (like default/full): the curated tool set
            # Hades drives in the cyber-range deployment. Registered here so
            # `--profile cyber-range` resolves instead of matching no category.
            selected_profiles = CYBER_RANGE_PROFILE
        else:
            selected_profiles = profiles
    else:
        selected_profiles = DEFAULT_PROFILE

    # Register tools for each selected profile
    selected_profiles = resolve_profile_dependencies(selected_profiles)

    registered = set()
    for profile in selected_profiles:
        for reg_func in TOOL_PROFILES.get(profile, []):
            if reg_func not in registered:
                reg_func(mcp, api_client, logger)
                registered.add(reg_func)  

    # Load plugin MCP tools (plugins/tools/<name>/mcp_tool.py)
    load_plugin_tools(mcp, api_client, logger)

    # Register the plan-and-approve contract (Pilar 4, cap. 8). This is the
    # core of the supervised audit loop and is always available regardless of
    # the loaded profiles so Hades can drive a plan-and-approve audit.
    try:
        from mcp_client.plan_and_approve import register_plan_approve_tools
        register_plan_approve_tools(mcp, api_client, logger)
        logger.info("Plan-and-approve tools registered")
    except Exception:
        logger.warning("Could not register plan-and-approve tools", exc_info=True)

    return mcp
