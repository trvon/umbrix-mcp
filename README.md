# Umbrix MCP Server

Connect your AI assistant directly to live threat intelligence with 18 specialized MCP tools for comprehensive threat analysis.

## 🚀 Quick Start

### 1. Get Your API Key
Visit [umbrix.dev](https://umbrix.dev/account.html), sign in, and generate an API key from Account Settings.

### 2. Install & Configure

#### Option A: Docker (Recommended)
```bash
git clone https://github.com/trvon/umbrix-mcp.git
cd umbrix-mcp
docker build -t umbrix-mcp:latest .
```

#### Option B: Python Package
```bash
pip install git+https://github.com/trvon/umbrix-mcp.git
```

### 3. Configure Claude Desktop
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
        "umbrix-mcp:latest"
      ],
      "env": {
        "UMBRIX_API_KEY": "your-api-key-here",
        "UMBRIX_API_BASE_URL": "https://umbrix.dev/api"
      }
    }
  }
}
```

**Config file locations:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### 4. Alternative: Python Installation
If using pip install instead of Docker:

```json
{
  "mcpServers": {
    "umbrix": {
      "command": "python",
      "args": ["-m", "umbrix_mcp"],
      "env": {
        "UMBRIX_API_KEY": "your-api-key-here",
        "UMBRIX_API_BASE_URL": "https://umbrix.dev/api"
      }
    }
  }
}
```

##  Available Tools

> **Note**: The umbrix-mcp client provides 18 tools that interface with Umbrix's threat intelligence platform. The backend MCP server has 18 core tools, while this client adds additional convenience tools for easier interaction.

### Discovery & Search (4 tools - client only)
- **discover_recent_threats** - Start here! Shows latest activity and data overview
- **find_threat_actors** - Find active threat actors with recent activity
- **find_recent_indicators** - Find latest IOCs by type and timeframe
- **find_vulnerabilities** - Find exploited CVEs and vulnerabilities

### Core Intelligence Analysis (3 tools)
- **analyze_indicator** - Analyze IPs, domains, hashes, URLs with full context
- **get_threat_actor** - Get detailed threat actor profiles and attribution
- **threat_intel_chat** - Natural language Q&A about threats with graph context

### Graph Query (2 tools)
- **execute_graph_query** - Run Cypher queries against the threat intelligence graph
- **intelligent_graph_query** - Natural language to Cypher query translation

### Threat Hunting & Reporting (4 tools)
- **threat_hunting_query_builder** - Generate threat hunting queries
- **report_generation** - Generate threat intelligence reports
- **system_health** - Check system component health and metrics
- **ioc_validation** - Validate and enrich indicators of compromise

### Feed Management (3 tools)
- **feed_status** - Check the status and health of threat intelligence feeds
- **feed_reputation** - Analyze and rank threat intelligence feeds by reputation
- **feed_metrics** - Get detailed performance metrics for threat intelligence feeds

### User Management (1 tool)
- **user_quota** - Monitor and manage user quotas, usage limits, and access controls

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
