import argparse
from mcp_client.api_client import DEFAULT_API_SERVER_URL, DEFAULT_REQUEST_TIMEOUT

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the MCP client")
    parser.add_argument("--server", type=str, default=DEFAULT_API_SERVER_URL,
                      help=f"API server URL (default: {DEFAULT_API_SERVER_URL})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--compact", action="store_true", help="Compact mode: register only classify_task and run_tool for small LLM clients")
    parser.add_argument("--profile", nargs="+", type=str, default=[], help="Tool profile(s) to load (e.g., web_crawl, exploit_framework, recon or default/full)")
    parser.add_argument("--auth-token", type=str, default="",
                        help="Bearer token for authentication with the API server")
    parser.add_argument("--disable-ssl-verify", action="store_true", help="Disable SSL certificate verification when connecting to the API server in front of reverse proxies")
    # Transport: stdio (default, subprocess MCP) or http (serve MCP over the
    # network, e.g. a Kubernetes sidecar the agent connects to via URL).
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "http"],
                        help="MCP transport (default: stdio). Use 'http' to serve MCP over the network (sidecar mode).")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Bind host for --transport http (default: 127.0.0.1; use 0.0.0.0 in a container)")
    parser.add_argument("--mcp-port", type=int, default=9000,
                        help="Bind port for --transport http (default: 9000)")
    return parser.parse_args()
