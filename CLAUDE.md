# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HexStrike AI is an AI-powered penetration testing MCP (Model Context Protocol) framework that provides 150+ security tools and 12+ autonomous AI agents for cybersecurity automation. It consists of two main components:

1. **hexstrike_server.py** (17k+ lines) - Flask-based API server with AI agents and tool orchestration
2. **hexstrike_mcp.py** (5k+ lines) - FastMCP client that exposes security tools to AI agents

## Development Commands

### Environment Setup

```bash
# Create and activate virtual environment
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate  # Linux/Mac
# hexstrike-env\Scripts\activate   # Windows

# Install dependencies
pip3 install -r requirements.txt
```

### Running the System

```bash
# Start the MCP server (default port 8888)
python3 hexstrike_server.py

# With debug mode
python3 hexstrike_server.py --debug

# Custom port
python3 hexstrike_server.py --port 9000

# Run MCP client (connects to server)
python3 hexstrike_mcp.py --server http://localhost:8888

# Debug MCP client
python3 hexstrike_mcp.py --debug
```

### Testing and Verification

```bash
# Test server health
curl http://localhost:8888/health

# Test AI intelligence endpoint
curl -X POST http://localhost:8888/api/intelligence/analyze-target \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "analysis_type": "comprehensive"}'

# Check cache statistics
curl http://localhost:8888/api/cache/stats

# View running processes
curl http://localhost:8888/api/processes/list
```

## Architecture

### Two-Script System

**hexstrike_server.py** - Core server containing:
- Flask API server (port 8888 by default)
- AI Decision Engine and workflow managers
- Process management system
- Caching layer (LRU cache with TTL)
- Browser automation (Selenium/Chrome)
- 150+ security tool integrations

**hexstrike_mcp.py** - MCP client containing:
- FastMCP integration using `@mcp.tool()` decorators
- Client wrapper for server API calls
- Colored logging and output formatting
- Tool definitions exposed to AI agents

### Key Components in hexstrike_server.py

**AI Agents & Intelligence** (lines ~100-8000):
- `ModernVisualEngine` - Real-time dashboards and visual output
- `IntelligentDecisionEngine` - Tool selection and parameter optimization
- `BugBountyWorkflowManager` - Bug bounty hunting workflows
- `CTFWorkflowManager` - CTF challenge solving
- `CTFToolManager` - CTF-specific tool management
- `CVEIntelligenceManager` - Vulnerability intelligence and exploit analysis

**Infrastructure** (lines ~5000-14000):
- `EnhancedProcessManager` - Smart process control with real-time monitoring
- `ProcessManager` - Basic process lifecycle management
- `FileOperationsManager` - File operations and artifact handling
- `BrowserAgent` - Headless Chrome automation with Selenium

**API Endpoints** (lines ~14000+):
- `/health` - Health check with tool availability
- `/api/command` - Execute arbitrary commands with caching
- `/api/intelligence/*` - AI intelligence endpoints
- `/api/processes/*` - Process management endpoints
- `/api/cache/stats` - Cache performance metrics

### MCP Tool Registration Pattern

In `hexstrike_mcp.py`, tools are registered using FastMCP decorators:

```python
@mcp.tool()
def tool_name(param1: str, param2: Optional[int] = None) -> str:
    """Tool description for AI agent"""
    response = hexstrike_client.call_api(
        "/api/endpoint",
        {"param1": param1, "param2": param2}
    )
    return response
```

All tools follow the pattern: decorator → docstring → API call → response formatting.

## Code Organization Principles

### Color Theming

The codebase uses a consistent "reddish hacker theme" color palette defined in both files:
- **Server**: `ModernVisualEngine.COLORS` (hexstrike_server.py)
- **Client**: `HexStrikeColors` (hexstrike_mcp.py)

When adding visual output, use these predefined color constants. Never hardcode ANSI color codes.

### Logging Standards

Both files use enhanced logging with emojis and colors:
- Use `logger.info()`, `logger.warning()`, `logger.error()`, `logger.debug()`
- Emojis are used for visual categorization (✅ success, ❌ error, 🔍 info, etc.)
- Colors are applied via `ColoredFormatter` class

### Error Handling Pattern

The codebase uses comprehensive try/except blocks with:
- Detailed error logging with stack traces
- User-friendly error messages
- Graceful degradation (tools work even if some dependencies fail)
- Recovery mechanisms in AI agents

### API Response Format

All API endpoints return JSON with this structure:
```python
{
    "success": bool,
    "data": {...},      # On success
    "error": str,       # On failure
    "timestamp": str,
    "execution_time": float
}
```

## External Dependencies

### Python Packages (requirements.txt)

**Core Framework**:
- flask - Web framework for API server
- fastmcp - MCP framework integration
- requests - HTTP client library
- psutil - System and process utilities

**Web Automation**:
- selenium - Browser automation
- webdriver-manager - ChromeDriver management
- beautifulsoup4 - HTML parsing
- aiohttp - Async HTTP client

**Security Tools**:
- pwntools - Binary exploitation framework
- angr - Binary analysis with symbolic execution
- mitmproxy - HTTP proxy for traffic interception

### External Security Tools

HexStrike integrates with 150+ external tools that must be installed separately. See README.md "Install Security Tools" section for categories:
- Network & Reconnaissance (25+ tools): nmap, masscan, rustscan, amass, subfinder, nuclei
- Web Application (40+ tools): gobuster, feroxbuster, ffuf, sqlmap, wpscan, nikto
- Authentication (12+ tools): hydra, john, hashcat, medusa
- Binary Analysis (25+ tools): ghidra, radare2, gdb, binwalk, volatility3
- Cloud Security (20+ tools): prowler, scout-suite, trivy, kube-hunter
- CTF & Forensics (20+ tools): volatility3, foremost, steghide, exiftool

Tools are invoked via subprocess - the system gracefully handles missing tools.

## Configuration

### Environment Variables

- `HEXSTRIKE_PORT` - Server port (default: 8888)
- `HEXSTRIKE_HOST` - Server host (default: 127.0.0.1)

### AI Client Integration

Claude Desktop/Cursor config (`~/.config/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": ["/path/to/hexstrike-ai/hexstrike_mcp.py", "--server", "http://localhost:8888"],
      "timeout": 300
    }
  }
}
```

## Important Development Notes

### Security Tool Execution

All security tools are executed via subprocess with:
- Timeout mechanisms (default varies by tool)
- Output capture (stdout/stderr)
- Return code checking
- Process management for long-running tools

When adding new tools, follow the pattern in existing tool functions.

### Caching System

The server implements an LRU cache with TTL:
- Cache key: `hashlib.md5(command.encode()).hexdigest()`
- Default TTL: varies by tool type
- Manual cache invalidation available
- Cache stats available at `/api/cache/stats`

Expensive operations (nmap, nuclei, etc.) are automatically cached.

### Process Management

Long-running tools use `EnhancedProcessManager`:
- Real-time output streaming
- Process termination on timeout
- Resource monitoring
- Graceful cleanup on server shutdown

### Browser Agent Specifics

`BrowserAgent` class uses Selenium with headless Chrome:
- Requires chromium-browser or google-chrome installed
- Uses webdriver-manager for driver management
- Supports proxy integration (mitmproxy)
- Captures screenshots, analyzes DOM, monitors network traffic

## Common Workflows

### Adding a New Security Tool

1. Add tool function to `hexstrike_server.py` (follow existing pattern)
2. Add MCP tool decorator in `hexstrike_mcp.py`
3. Document in README.md tool list
4. Handle missing tool gracefully (check with `shutil.which()`)

### Adding a New AI Agent

1. Create class inheriting appropriate base (see existing agents)
2. Implement required methods (analyze, execute, report)
3. Integrate with `IntelligentDecisionEngine` if needed
4. Add colored output using `ModernVisualEngine.COLORS`

### Debugging Issues

1. Enable debug mode: `python3 hexstrike_server.py --debug`
2. Check server logs: `hexstrike.log`
3. Test endpoints individually with curl
4. Use `/api/processes/list` to monitor running tools
5. Check `/api/cache/stats` for cache hit/miss ratios
