# AbuseIPDB MCP Server Query Examples

This document provides example queries and prompts for using the AbuseIPDB MCP server.

## Basic IP Checks

### Check a single IP with default settings
```
Check the reputation of 8.8.8.8
```

### Check an IP with custom threshold
```
Check 1.1.1.1 with a threshold of 50% and include detailed reports
```

### Check an IP with extended timeframe
```
Check 192.0.2.1 using reports from the last 90 days
```

## CIDR Block Analysis

### Check a network block
```
Check the reputation of the 203.0.113.0/24 network block
```

### Analyze multiple networks
```
Check these network blocks for malicious activity:
- 198.51.100.0/24
- 203.0.113.0/24
```

## Blacklist Operations

### Get current blacklist
```
Retrieve the AbuseIPDB blacklist with minimum 95% confidence
```

### Get limited blacklist for analysis
```
Get the top 100 entries from the AbuseIPDB blacklist
```

## Bulk Operations

### Check multiple IPs
```
Check these IPs and flag any with confidence above 80%:
- 8.8.8.8
- 1.1.1.1
- 9.9.9.9
- 208.67.222.222
```

### Analyze a list of suspicious IPs
```
Perform bulk analysis on these potentially malicious IPs:
192.0.2.100, 203.0.113.50, 198.51.100.25
```

## Log Enrichment

### Apache access log enrichment
```
Enrich this Apache log line with threat intelligence:
192.0.2.100 - - [10/Jan/2024:10:00:00 +0000] "GET /admin/login.php HTTP/1.1" 200 1234
```

### Multiple IP extraction
```
Extract and analyze all IP addresses from this log entry:
[2024-01-10 10:15:30] Connection from 203.0.113.50 forwarded through 198.51.100.25 to internal server 10.0.1.100
```

### Firewall log analysis
```
Analyze this firewall log for threats:
Jan 10 10:30:15 firewall: DENY TCP 192.0.2.200:45678 -> 10.0.1.5:22 (SSH brute force attempt)
```

## Advanced Analysis

### Security incident investigation
```
I'm investigating a security incident. Can you:
1. Check the reputation of 203.0.113.100
2. Get the current blacklist with confidence above 90%
3. Check if any IPs in the 203.0.113.0/24 block are flagged
4. Generate triage notes for the findings
```

### Threat hunting workflow
```
Help me with threat hunting:
1. Get the latest blacklist entries
2. Check these suspicious IPs from our logs: 192.0.2.50, 198.51.100.75
3. Analyze this network traffic log:
   "2024-01-10 15:45:22 TCP 203.0.113.33:12345 -> 10.0.1.10:443 ESTABLISHED"
```

### Daily security review
```
Perform a daily security review:
1. Get blacklist summary statistics
2. Check our public IP ranges: 203.0.113.0/24, 198.51.100.0/24
3. Analyze recent connection attempts from these IPs: [list from security logs]
```

## Resource Access

### Cache information
```
What's the current status of the AbuseIPDB cache?
```

### Usage documentation
```
Show me the complete usage documentation for the AbuseIPDB MCP server
```

## Prompt Usage

### Generate analyst notes
```
Generate security analyst triage notes for IP 203.0.113.100 based on its AbuseIPDB data
```

### Risk assessment
```
Using the triage_ip prompt, create a risk assessment for the IP address 192.0.2.150
```

## Integration Examples

### SIEM Integration
```
I need to integrate AbuseIPDB checks into our SIEM. Can you:
1. Check these high-volume source IPs from today's alerts
2. Provide a summary suitable for SOC analysts
3. Flag any IPs that exceed our 85% confidence threshold
```

### Incident Response
```
We're responding to a potential breach. The attacker IP is 203.0.113.200. Can you:
1. Get full reputation data including reports
2. Check if this IP is part of a known malicious network
3. Generate a threat assessment for our incident report
```

### Proactive Monitoring
```
Set up proactive monitoring analysis:
1. Check our edge network 203.0.113.0/26 for any flagged IPs
2. Get current blacklist entries from our country (use appropriate country code)
3. Analyze this sample of today's connection logs: [paste logs]
```