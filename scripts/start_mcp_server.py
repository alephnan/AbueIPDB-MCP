#!/usr/bin/env python3
"""
MCP-specific startup script for AbuseIPDB server.

This script ensures proper environment loading and provides better
diagnostics for Claude app integration issues.
"""

import os
import sys
import subprocess
from pathlib import Path


def find_env_file():
    """Find .env file in current directory or parent directories."""
    current_dir = Path.cwd()
    for path in [current_dir] + list(current_dir.parents):
        env_file = path / '.env'
        if env_file.exists():
            return env_file
    return None


def load_env_file(env_file_path):
    """Load environment variables from .env file."""
    env_vars = {}
    try:
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    except Exception as e:
        print(f"[MCP Startup] Warning: Could not load .env file: {e}", file=sys.stderr)
    return env_vars


def validate_environment():
    """Validate that required environment variables are set."""
    api_key = os.environ.get('ABUSEIPDB_API_KEY', '').strip()

    print(f"[MCP Startup] Environment validation:", file=sys.stderr)
    print(f"  - Working directory: {Path.cwd()}", file=sys.stderr)
    print(f"  - API key set: {'YES' if api_key else 'NO'}", file=sys.stderr)

    if api_key:
        # Mask the key for safe logging
        if len(api_key) > 8:
            masked = f"{api_key[:4]}...{api_key[-4:]} (len={len(api_key)})"
        else:
            masked = f"{api_key[:2]}***{api_key[-2:]}"
        print(f"  - API key value: {masked}", file=sys.stderr)
    else:
        print(f"  - ERROR: ABUSEIPDB_API_KEY not found in environment", file=sys.stderr)
        return False

    return True


def main():
    """Main startup function."""
    print("[MCP Startup] Starting AbuseIPDB MCP server...", file=sys.stderr)

    # Try to find and load .env file if not already loaded
    if not os.environ.get('ABUSEIPDB_API_KEY'):
        print("[MCP Startup] API key not in environment, looking for .env file...", file=sys.stderr)

        env_file = find_env_file()
        if env_file:
            print(f"[MCP Startup] Found .env file: {env_file}", file=sys.stderr)
            env_vars = load_env_file(env_file)

            # Set environment variables from .env file
            for key, value in env_vars.items():
                if key not in os.environ:  # Don't override existing env vars
                    os.environ[key] = value
                    print(f"[MCP Startup] Set {key} from .env file", file=sys.stderr)
        else:
            print("[MCP Startup] No .env file found in current or parent directories", file=sys.stderr)

    # Validate environment
    if not validate_environment():
        print("[MCP Startup] FATAL: Environment validation failed", file=sys.stderr)
        print("[MCP Startup] Please ensure ABUSEIPDB_API_KEY is set in:", file=sys.stderr)
        print("  1. Claude app MCP configuration 'env' section, OR", file=sys.stderr)
        print("  2. .env file in project directory", file=sys.stderr)
        sys.exit(1)

    # Start the MCP server
    print("[MCP Startup] Environment validated, starting server...", file=sys.stderr)

    try:
        # Import and run the server
        from mcp_abuseipdb.server import main as server_main
        server_main()
    except KeyboardInterrupt:
        print("[MCP Startup] Server stopped by user", file=sys.stderr)
    except Exception as e:
        print(f"[MCP Startup] Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()