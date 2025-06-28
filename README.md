# Umbrix MCP Server

### 1. Get Your API Key
Visit [umbrix.dev](https://umbrix.dev), sign in, and generate an API key from Account Settings.

### 2. Configure Claude Desktop
Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "umbrix": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "UMBRIX_API_KEY",
        "-e", "UMBRIX_API_BASE_URL", 
        "ghcr.io/trvon/umbrix-mcp:latest"
      ],
      "env": {
        "UMBRIX_API_KEY": "your-api-key-here",
        "UMBRIX_API_BASE_URL": "https://umbrix.dev/api"
      }
    }
  }
}
```

**Config locations:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### 3. Build the Docker Image
```bash
git clone https://github.com/umbrix/umbrix-mcp.git
cd umbrix-mcp
docker build -t umbrix-mcp:latest .
```

##  Available Tools

> **Note**: The umbrix-mcp client provides 17 tools that interface with Umbrix's threat intelligence platform. The backend MCP server has 17 core tools, while this client adds additional convenience tools for easier interaction.

### Discovery & Search (5 tools - client only)
- **discover_recent_threats** - Start here! Shows latest activity and data overview
- **search_threats** - Search across all threat intelligence sources using natural language
- **find_threat_actors** - Find active threat actors with recent activity
- **find_recent_indicators** - Find latest IOCs by type and timeframe
- **find_vulnerabilities** - Find exploited CVEs and vulnerabilities

### Core Intelligence Analysis (3 tools)
- **analyze_indicator** - Analyze IPs, domains, hashes, URLs with full context
- **get_threat_actor** - Get detailed threat actor profiles and attribution
- **threat_intel_chat** - Natural language Q&A about threats with graph context

### Graph Query (1 tool)
- **execute_graph_query** - Run Cypher queries against the threat intelligence graph
- **get_malware_details** - Detailed malware analysis and family information
- **get_campaign_details** - Threat campaign analysis and attribution

### Threat Hunting & Reporting (3 tools)
- **threat_hunting_query_builder** - Generate threat hunting queries
- **report_generation** - Generate threat intelligence reports
- **system_health_check** - Check system component health and metrics

##  Development

```bash
# Clone repository
git clone https://github.com/umbrix/umbrix-mcp.git
cd umbrix-mcp

# Install dependencies  
uv install

# Run tests
uv run pytest

# Build Docker image
docker build -t umbrix-mcp:latest .

# Test the server
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  docker run --rm -i -e UMBRIX_API_KEY=test umbrix-mcp:latest
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**[umbrix.dev](https://umbrix.dev)** • **[Documentation](https://umbrix.dev/docs)**
