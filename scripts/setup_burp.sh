#!/usr/bin/env bash
# Download Burp Suite + the PortSwigger MCP Server extension into ./tools/burp.
# Keyless: the MCP extension runs locally inside Burp (loopback SSE).
#
# Usage:
#   scripts/setup_burp.sh                 # community, latest
#   BURP_VERSION=2025.5.6 scripts/setup_burp.sh
#   scripts/setup_burp.sh --check
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${VENOM_TOOLS_DIR:-$SCRIPT_DIR/../tools}/burp"
EDITION="${BURP_EDITION:-community}"
VERSION="${BURP_VERSION:-latest}"
MCP_URL="${BURP_MCP_EXT_URL:-}"
MCP_PORT="${BURP_MCP_PORT:-9876}"

BURP_JAR="$TOOLS_DIR/burpsuite_${EDITION}.jar"
MCP_JAR="$TOOLS_DIR/burp-mcp-server.jar"
CFG_FILE="$TOOLS_DIR/venom-burp-config.json"

mkdir -p "$TOOLS_DIR"

check_java() {
  if command -v java >/dev/null 2>&1; then
    echo "  Java: $(command -v java)"
  else
    echo "  WARNING: Java not found. Install JRE/JDK 17+ (https://adoptium.net)."
  fi
}

if [[ "${1:-}" == "--check" ]]; then
  echo "Burp MCP install check ($TOOLS_DIR):"
  check_java
  [[ -f "$BURP_JAR" ]] && echo "  Burp jar      : present" || echo "  Burp jar      : MISSING"
  [[ -f "$MCP_JAR"  ]] && echo "  MCP extension : present" || echo "  MCP extension : MISSING"
  [[ -f "$CFG_FILE" ]] && echo "  User config   : present" || echo "  User config   : MISSING"
  exit 0
fi

echo "== VENOM :: Burp + MCP setup =="
check_java

# 1. Burp Suite jar
if [[ -f "$BURP_JAR" ]]; then
  echo "  Burp jar already present: $BURP_JAR"
else
  URL="https://portswigger.net/burp/releases/download?product=${EDITION}&version=${VERSION}&type=Jar"
  echo "  Downloading Burp $EDITION ($VERSION)..."
  if ! curl -fL --retry 2 -o "$BURP_JAR" "$URL"; then
    echo "  WARNING: Burp download failed. Pick a version from"
    echo "           https://portswigger.net/burp/releases and set BURP_VERSION."
  fi
fi

# 2. MCP Server extension jar
if [[ -f "$MCP_JAR" ]]; then
  echo "  MCP extension already present: $MCP_JAR"
else
  if [[ -z "$MCP_URL" ]]; then
    echo "  Resolving latest MCP Server extension from GitHub..."
    MCP_URL="$(curl -fsSL -H 'User-Agent: venom-setup' \
      https://api.github.com/repos/PortSwigger/mcp-server/releases/latest \
      | grep -oE '"browser_download_url": *"[^"]+\.jar"' | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')" || true
  fi
  if [[ -n "$MCP_URL" ]]; then
    echo "  Downloading MCP extension: $MCP_URL"
    curl -fL --retry 2 -o "$MCP_JAR" "$MCP_URL"
  else
    echo "  WARNING: No MCP extension URL. Install 'MCP Server' from Burp's BApp Store,"
    echo "           or set BURP_MCP_EXT_URL to a release jar."
  fi
fi

# 3. Burp user-config that auto-loads the extension
cat > "$CFG_FILE" <<JSON
{
  "user_options": {
    "extender": {
      "extensions": [
        { "type": "java", "name": "MCP Server", "errors_to": "ui",
          "output_to": "ui", "loaded": true, "extension_file": "$MCP_JAR" }
      ]
    }
  }
}
JSON
echo "  Wrote Burp user-config: $CFG_FILE"

cat <<EOF

Done. Next:
  1) scripts/run_burp_mcp.sh             # launches Burp with the extension
  2) In .env set: BURP_MCP_ENABLED=true  (BURP_MCP_URL=http://127.0.0.1:${MCP_PORT}/sse)
  3) venom burp --status                # verify connectivity
EOF
