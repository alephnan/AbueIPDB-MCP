# MCP AbuseIPDB Server

An MCP (Model Context Protocol) server that provides threat intelligence lookups against the AbuseIPDB database. This server enables any MCP-capable client to perform IP reputation checks, CIDR block analysis, and access curated blacklists with intelligent caching and rate limiting.

## Features

- **IP Reputation Checks**: Single IP address lookups with detailed abuse data
- **CIDR Block Analysis**: Check entire network ranges for malicious activity
- **Blacklist Access**: Retrieve current AbuseIPDB blacklist with configurable confidence levels
- **Bulk Operations**: Check multiple IP addresses efficiently
- **Log Enrichment**: Extract and analyze IP addresses from log lines
- **Intelligent Caching**: SQLite-based caching with TTL to minimize API usage
- **Rate Limiting**: Built-in quota management for AbuseIPDB API limits
- **Security Focused**: Input validation, private IP filtering, and secure defaults

## Quick Start

### Prerequisites

- Python 3.11 or higher
- AbuseIPDB API key (get one at [abuseipdb.com](https://www.abuseipdb.com/api))

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd AbuseIPDB-MCP
```

2. Install the package:
```bash
pip install -e .
```

3. Set up your environment:
```bash
cp .env.example .env
# Edit .env and add your ABUSEIPDB_API_KEY
```

4. Run the server:
```bash
python -m mcp_abuseipdb.server
```

### MCP Client Configuration

#### Option 1: Using the Enhanced Startup Script (Recommended)

Add to your MCP client configuration (e.g., `mcp.json`):

```json
{
  "mcpServers": {
    "mcp-abuseipdb": {
      "command": "python",
      "args": ["scripts/start_mcp_server.py"],
      "cwd": "/path/to/AbuseIPDB-MCP",
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

#### Option 2: Direct Module Execution

```json
{
  "mcpServers": {
    "mcp-abuseipdb": {
      "command": "python",
      "args": ["-m", "mcp_abuseipdb.server"],
      "cwd": "/path/to/AbuseIPDB-MCP",
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

**Important Notes:**
- Replace `your_api_key_here` with your actual AbuseIPDB API key
- Update `/path/to/AbuseIPDB-MCP` to the actual path where you cloned this repository
- The enhanced startup script (Option 1) provides better error diagnostics
- Ensure your API key is valid and not expired on the AbuseIPDB website

## Available Tools

### `check_ip`
Check the reputation of a single IP address.

**Parameters:**
- `ip_address` (required): IP address to check
- `max_age_days` (optional): Maximum age of reports (default: 30)
- `verbose` (optional): Include detailed reports (default: false)
- `threshold` (optional): Confidence threshold for flagging (default: 75)

### `check_block`
Check the reputation of a CIDR network block.

**Parameters:**
- `network` (required): CIDR network (e.g., "192.168.1.0/24")
- `max_age_days` (optional): Maximum age of reports (default: 30)

### `get_blacklist`
Retrieve the AbuseIPDB blacklist.

**Parameters:**
- `confidence_minimum` (optional): Minimum confidence level (default: 90)
- `limit` (optional): Maximum entries to retrieve

### `bulk_check`
Check multiple IP addresses efficiently.

**Parameters:**
- `ip_addresses` (required): List of IP addresses
- `max_age_days` (optional): Maximum age of reports (default: 30)
- `threshold` (optional): Confidence threshold for flagging (default: 75)

### `enrich_log_line`
Extract and analyze IP addresses from log entries.

**Parameters:**
- `log_line` (required): Log line containing IP addresses
- `threshold` (optional): Confidence threshold for flagging (default: 75)
- `max_age_days` (optional): Maximum age of reports (default: 30)

## Available Resources

### `cache://info`
Get current cache statistics and rate limiter status.

### `doc://usage`
Complete API usage documentation and examples.

## Available Prompts

### `triage_ip`
Generate security analyst triage notes for an IP address.

**Parameters:**
- `ip_data` (required): IP check data from AbuseIPDB

## Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and customize:

### Required Settings
- `ABUSEIPDB_API_KEY`: Your AbuseIPDB API key

### Optional Settings
- `MAX_AGE_DAYS`: Default report age limit (default: 30)
- `CONFIDENCE_THRESHOLD`: Default confidence threshold (default: 75)
- `DAILY_QUOTA`: API request quota (default: 1000)
- `CACHE_DB_PATH`: SQLite cache file location (default: ./cache.db)
- `LOG_LEVEL`: Logging level (default: INFO)
- `ALLOW_PRIVATE_IPS`: Allow checking private IPs (default: false)

## Usage Examples

### Basic IP Check
```
Check the reputation of 8.8.8.8
```

### Log Analysis
```
Analyze this log line for threats:
192.168.1.100 - - [10/Jan/2024:10:00:00 +0000] "GET /admin/login.php HTTP/1.1" 200 1234
```

### Bulk Analysis
```
Check these IPs for malicious activity:
- 203.0.113.100
- 198.51.100.50
- 192.0.2.25
```

### Security Investigation
```
I'm investigating suspicious activity from 203.0.113.100. Can you:
1. Check its reputation with detailed reports
2. Analyze the surrounding network block
3. Generate triage notes for our security team
```

See `examples/queries.md` for more detailed examples.

## Docker Deployment

Build and run with Docker:

```bash
# Build the image
docker build -f docker/Dockerfile -t mcp-abuseipdb .

# Run the container
docker run -e ABUSEIPDB_API_KEY=your_key_here mcp-abuseipdb
```

## Development

### Setup Development Environment
```bash
pip install -e ".[dev]"
pre-commit install
```

### Run Tests
```bash
pytest
```


## Security Considerations

- **API Key Protection**: Never commit API keys to version control
- **Private IP Filtering**: Private IPs are blocked by default
- **Rate Limiting**: Built-in quota management prevents API abuse
- **Input Validation**: All inputs are validated and sanitized
- **Caching**: Reduces API calls and improves performance

## Rate Limits

AbuseIPDB free tier provides 1,000 requests per day. This server:
- Implements intelligent caching to minimize API usage
- Provides rate limiting with configurable quotas
- Gracefully handles rate limit errors with backoff

## Troubleshooting

### "Unauthorized API key" Error in Claude App

If you're getting unauthorized API key errors when using the MCP server with Claude:

1. **Verify API Key Configuration**:
   ```bash
   # Test your API key with the diagnostic script
   python diagnostics/api_auth_diagnostic.py
   ```

2. **Check Claude App Configuration**:
   - Ensure your `mcp.json` has the correct API key in the `env` section
   - Verify the `cwd` path points to your project directory
   - Make sure the API key value matches exactly (no extra spaces)

3. **Use Enhanced Startup Script**:
   - Switch to Option 1 configuration (enhanced startup script)
   - Check the server logs in Claude app for diagnostic messages
   - Look for `[MCP AbuseIPDB]` prefixed messages

4. **Environment Variable Issues**:
   - Ensure your `.env` file is in the project root directory
   - Verify the API key in `.env` matches your Claude app configuration
   - Check that the API key is valid on the AbuseIPDB website

5. **Debug Steps**:
   ```bash
   # Test local server startup
   python scripts/start_mcp_server.py

   # Check environment loading
   python -c "from mcp_abuseipdb.settings import Settings; print('API key loaded:', bool(Settings().abuseipdb_api_key))"
   ```

### Common Issues

- **"No .env file found"**: Make sure `.env` exists in project root or set API key in Claude app config
- **"Settings API key: EMPTY"**: API key not properly loaded from environment
- **"Environment var: EMPTY"**: API key not set in Claude app MCP configuration
- **Connection timeouts**: Check your internet connection and AbuseIPDB service status

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite and linting
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: See `examples/` directory
- Issues: Please report bugs and feature requests via GitHub issues
- API Documentation: [AbuseIPDB API Docs](https://docs.abuseipdb.com/)

## Changelog

### v0.1.0
- Initial release
- Basic IP checking functionality
- CIDR block analysis
- Blacklist access
- Bulk operations
- Log enrichment
- Caching and rate limiting
- Docker support