# Umbrix MCP Server

Connect your AI assistant directly to live threat intelligence with **smart MCP tools** optimized for both large and small AI models.

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

## 🤖 Smart MCP Tools

**Optimized for all AI model sizes** - from GPT-4 to smaller local models.

### 🎯 Tool Selection Assistant (Perfect for Smaller Models)
- **get_tool_recommendation** - 🆕 Describe what you want to research → Get personalized tool suggestions
  - Example: `get_tool_recommendation("I want to research APT29")` → Suggests best tools for that task

### 🔍 Discovery & Exploration (Great Starting Points)
- **discover_recent_threats** - Start here! Shows latest activity and data overview
- **threat_correlation** - Search for any threat entities with simple terms
- **analyze_indicator** - Deep analysis of specific IOCs (IPs, domains, hashes)

### 💬 Natural Language Queries (Enhanced for Small Models)
- **execute_graph_query** - 🚀 **ENHANCED** Smart tool that converts simple patterns to database queries
  - **New patterns**: `"recent threats"`, `"APT29"`, `"192.168.1.1"`, `"ransomware campaigns"`
  - **Still supports**: Advanced Cypher queries for expert users
- **threat_intel_chat** - Natural language Q&A about threats with graph context

### 🎯 Specific Entity Lookups
- **get_threat_actor** - Detailed threat actor profiles and attribution
- **get_malware_details** - Comprehensive malware analysis from graph database
- **get_campaign_details** - In-depth campaign intelligence from verified data
- **get_cve_details** - Comprehensive CVE analysis with severity and exploitation status

### 📊 Advanced Analysis
- **timeline_analysis** - Temporal patterns and activity analysis
- **indicator_reputation** - Reputation scoring for IOCs
- **network_analysis** - Analyze IP ranges and networks
- **threat_actor_attribution** - Attribute indicators to actors
- **ioc_validation** - Validate and enrich indicators

### 🛠️ System & Management
- **system_health_check** - Verify platform status when other tools fail
- **feed_status** - Check threat intelligence feed health
- **user_quota** - Monitor usage limits and access controls

## 🧠 Model Size Optimization

### For **Smaller Models** (Claude 3 Haiku, Local LLMs):
1. Start with `get_tool_recommendation("describe your task")`
2. Use `discover_recent_threats` for exploration
3. Try `execute_graph_query` with simple patterns like `"recent threats"` or `"APT29"`

### For **Larger Models** (GPT-4, Claude 3.5 Sonnet):
- Full access to advanced Cypher queries in `execute_graph_query`
- Complex natural language processing in `threat_intel_chat`
- Multi-step analysis workflows

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
