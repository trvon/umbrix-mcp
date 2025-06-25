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

### Threat Intelligence (5 tools)
- **search_threats** - Search across all threat intelligence sources
- **analyze_indicator** - Analyze IPs, domains, hashes, URLs
- **get_threat_actor** - Get detailed threat actor information
- **visualize_threat_graph** - Generate threat relationship visualizations  
- **quick_ioc_check** - Instant IoC maliciousness verification

### Backend Integration (5 tools)
- **graph_statistics** - Get live graph database statistics
- **execute_graph_query** - Run Cypher queries against the threat graph
- **feed_management** - Manage threat intelligence feeds
- **system_health** - Check system component health status
- **threat_intel_chat** - Natural language Q&A about threats

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
