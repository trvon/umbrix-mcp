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

### Core Intelligence Analysis (5 tools)
- **search_threats** - Search across all threat intelligence sources using natural language
- **analyze_indicator** - Analyze IPs, domains, hashes, URLs with full STIX details
- **get_threat_actor** - Get detailed threat actor profiles and attribution
- **threat_intel_chat** - Natural language Q&A about threats with graph context
- **execute_graph_query** - Run Cypher queries against the threat intelligence graph

### Entity Details (4 tools)
- **get_malware_details** - Detailed malware analysis and family information
- **get_campaign_details** - Threat campaign analysis and attribution
- **get_attack_pattern_details** - MITRE ATT&CK technique details and usage
- **get_vulnerability_details** - CVE details, CVSS scores, and exploitation data

### Threat Analysis & Correlation (6 tools)
- **threat_correlation** - Find relationships between threat entities
- **indicator_reputation** - Multi-source reputation scoring for indicators
- **threat_actor_attribution** - Attribute indicators to threat actors
- **ioc_validation** - Validate and enrich indicators with context
- **network_analysis** - Analyze network ranges for threat intelligence
- **timeline_analysis** - Analyze threat activity over time periods

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
