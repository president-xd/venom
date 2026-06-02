#!/usr/bin/env bash
# Launch Burp Suite with the MCP Server extension loaded (keyless local SSE).
#
# Usage:
#   scripts/run_burp_mcp.sh
#   HEADLESS=1 scripts/run_burp_mcp.sh     # needs a virtual display (xvfb-run)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${VENOM_TOOLS_DIR:-$SCRIPT_DIR/../tools}/burp"
EDITION="${BURP_EDITION:-community}"
BURP_JAR="$TOOLS_DIR/burpsuite_${EDITION}.jar"
CFG_FILE="$TOOLS_DIR/venom-burp-config.json"

command -v java >/dev/null 2>&1 || { echo "Java not found. Install JRE/JDK 17+."; exit 1; }
[[ -f "$BURP_JAR" ]] || { echo "Burp jar missing. Run scripts/setup_burp.sh first."; exit 1; }

ARGS=(-jar "$BURP_JAR")
[[ -f "$CFG_FILE" ]] && ARGS+=("--user-config-file=$CFG_FILE")

echo "Launching Burp ($EDITION) with MCP extension..."
echo "  MCP SSE endpoint will be at: http://127.0.0.1:9876/sse"

if [[ "${HEADLESS:-0}" == "1" ]]; then
  # Community has no native headless mode; wrap in a virtual display.
  if command -v xvfb-run >/dev/null 2>&1; then
    exec xvfb-run -a java "${ARGS[@]}"
  else
    echo "  xvfb-run not found; install xvfb for headless, or run with a display."
    exec java "${ARGS[@]}"
  fi
else
  exec java "${ARGS[@]}"
fi
