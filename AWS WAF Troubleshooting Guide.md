# AWS WAF Troubleshooting Guide

This guide contains useful CloudWatch Logs Insights queries for troubleshooting AWS WAF issues, particularly focusing on analyzing blocked requests and identifying rule patterns.

## Table of Contents

- [General Troubleshooting Queries](#general-troubleshooting-queries)
- [PDF-Specific Issues](#pdf-specific-issues)
- [Targeted Analysis Queries](#targeted-analysis-queries)
- [Best Practices](#best-practices)

## General Troubleshooting Queries

### Basic Query to Find ALL Blocked Requests

```sql
fields @timestamp
| filter action = 'BLOCK'
| display 
    @timestamp,
    httpSourceIp,
    httpRequest.uri,
    httpRequest.headers.host,
    terminatingRuleId,
    terminatingRuleName,
    httpRequest.headers."user-agent",
    httpRequest.country,
    httpRequest.args,
    terminatingRuleMatchDetails,
    httpStatusCode
| sort @timestamp desc
| limit 20
```

### Comprehensive Query with Detailed Display

```sql
fields @timestamp, @message
| filter action='BLOCK'
| display 
    @timestamp,
    terminatingRuleId,
    terminatingRuleName,
    terminatingRuleType,
    terminatingRuleMatchDetails,
    httpSourceIp,
    httpMethod,
    httpRequest.uri,
    httpRequest.headers.host,
    httpRequest.headers."user-agent",
    httpRequest.country,
    httpRequest.args,
    ruleGroupList,
    labels,
    webaclId,
    webaclName,
    action,
    httpStatusCode,
    requestHeadersInserted,
    responseCodeSent
| sort @timestamp desc
| limit 100
```

### Summary of All Blocking Rules

```sql
fields @timestamp
| filter action = 'BLOCK'
| stats 
    count(*) as blockCount,
    min(@timestamp) as firstBlock,
    max(@timestamp) as lastBlock by 
    terminatingRuleId,
    terminatingRuleName
| sort blockCount desc
```

### Filter by Timestamp Range

```sql
fields @timestamp
| filter action = 'BLOCK' 
    and @timestamp >= 'YYYY-MM-DD HH:mm:ss'
    and @timestamp <= 'YYYY-MM-DD HH:mm:ss'
| display 
    @timestamp,
    terminatingRuleId,
    terminatingRuleName,
    httpSourceIp,
    httpRequest.uri,
    terminatingRuleMatchDetails
| sort @timestamp desc
```

### Filter by IP Address

```sql
fields @timestamp
| filter action = 'BLOCK' 
    and httpSourceIp like 'YOUR-IP-ADDRESS'
| display 
    @timestamp,
    terminatingRuleId,
    terminatingRuleName,
    httpRequest.uri,
    terminatingRuleMatchDetails,
    httpRequest.headers."user-agent"
| sort @timestamp desc
```

### Filter by URI Path

```sql
fields @timestamp
| filter action = 'BLOCK' 
    and httpRequest.uri like '/your-path'
| display 
    @timestamp,
    terminatingRuleId,
    terminatingRuleName,
    httpSourceIp,
    terminatingRuleMatchDetails
| sort @timestamp desc
```

## PDF-Specific Issues

### Identify PDF-Related Blocks

```sql
fields @timestamp
| filter action = 'BLOCK' 
    and (httpRequest.uri like '%.pdf' 
    or httpRequest.headers."content-type" like '%pdf%')
| display 
    @timestamp,
    terminatingRuleId,
    terminatingRuleName,
    httpRequest.uri,
    httpRequest.headers."content-type",
    terminatingRuleMatchDetails,
    httpRequest.size
| sort @timestamp desc
```
```
fields @timestamp, terminatingRuleId, terminatingRuleName, httpRequest.uri, httpRequest.method, httpRequest.headers, httpRequest.clientIp, httpRequest.country, action
| filter httpRequest.uri like ".pdf" and action="BLOCK"
| sort @timestamp desc
| limit 10000
```
### Check Size Constraint Rule Issues

```sql
fields @timestamp
| filter action = 'BLOCK' 
    and terminatingRuleName like '%size%'
| display 
    httpRequest.size,
    terminatingRuleId,
    terminatingRuleName,
    httpRequest.uri
```

### Check Body Inspection Rules for PDF Content

```sql
fields @timestamp
| filter action = 'BLOCK' 
    and httpRequest.headers."content-type" like '%pdf%'
| stats count(*) as blockCount by 
    terminatingRuleId,
    terminatingRuleName,
    terminatingRuleMatchDetails
```

### Check Custom Rules for PDF Handling

```sql
fields @timestamp
| filter action = 'BLOCK' 
    and terminatingRuleType = 'CUSTOM'
    and httpRequest.uri like '%.pdf'
| display 
    terminatingRuleId,
    terminatingRuleName,
    httpRequest.uri
```

### Check Rate Limiting Impact on PDF Requests

```sql
fields @timestamp
| filter terminatingRuleType = 'RATE_BASED'
    and httpRequest.uri like '%.pdf'
| stats count(*) as requestCount by 
    httpSourceIp,
    terminatingRuleId
```

## Targeted Analysis Queries

### Rate-Based Rule Analysis

```sql
fields @timestamp
| filter terminatingRuleType = 'RATE_BASED'
| stats count(*) as requestCount by 
    httpSourceIp,
    terminatingRuleId,
    terminatingRuleName
| sort requestCount desc
```

### Geographic Block Analysis

```sql
fields @timestamp
| filter action = 'BLOCK'
| stats count(*) as blockCount by 
    httpRequest.country,
    terminatingRuleId
| sort blockCount desc
```

### Filter by Specific Country (e.g., India)

```sql
fields httpRequest.clientIp, httpRequest.country, action, terminatingRuleId, terminatingRuleType, bin(60s) as minute 
| filter httpRequest.country = "IN" 
| stats count(*) as totalRequests, sum(action="BLOCK") as blockCount, blockCount/60 as blockRatePerMinute by httpRequest.clientIp, minute, terminatingRuleId, terminatingRuleType 
| filter blockCount > 0
| sort blockCount desc 
| limit 10000
```

### SQL Injection Attack Analysis

```sql
fields @timestamp
| filter terminatingRuleMatchDetails like /SQL_INJECTION/
| display 
    @timestamp,
    httpSourceIp,
    httpRequest.uri,
    terminatingRuleMatchDetails,
    httpRequest.args
```

### User-Agent Analysis

```sql
fields @timestamp
| filter action='BLOCK'
| stats count(*) as blockCount by 
    httpRequest.headers."user-agent",
    terminatingRuleId
| sort blockCount desc
| limit 20
```

### URI Pattern Analysis

```sql
fields @timestamp
| filter action='BLOCK'
| parse httpRequest.uri "*" as uri
| stats count(*) as hitCount by 
    uri,
    terminatingRuleId,
    terminatingRuleName
| sort hitCount desc
```

### Pattern Matching Rules Analysis

```sql
fields @timestamp
| filter action = 'BLOCK'
| stats count(*) as blockCount by 
    terminatingRuleMatchDetails,
    terminatingRuleName
| sort blockCount desc
```

### Monitor PDF Access Patterns

```sql
fields @timestamp
| filter httpRequest.uri like '%.pdf'
| stats 
    count(*) as requestCount,
    count_distinct(httpSourceIp) as uniqueIPs by 
    action,
    terminatingRuleId,
    terminatingRuleName
| sort requestCount desc
```

## Best Practices

### Before Making Changes
- Back up current rules before making changes
- Test rule changes in Count mode first
- Verify changes work in test environment
- Monitor for false positives

### Documentation
- Document all rule exceptions
- Keep track of size limits
- Note custom rules for specific file types

### Implementation Steps for PDF Issues
1. Create a rule group exception:
   - Path pattern: *.pdf
   - Content-type: application/pdf

2. Add condition statements:
   - NOT statements for PDF paths
   - Exclude PDF content-types

3. Configure size limits:
   - Increase for PDF endpoints
   - Set separate limits for documents

### Regular Monitoring
- Set up CloudWatch alerts
- Monitor access patterns
- Track blocking rates
- Monitor response times
- Track success rates
- Watch for timeout issues

### Query Tips
- Adjust the time range in CloudWatch Logs appropriately
- Use the 'limit' parameter to control the number of results
- Add or remove fields based on your specific needs
- Consider adding filters for specific IPs or rules of interest
- Use appropriate aggregation periods for your analysis
- Remember WAF logs are typically available within 5 minutes
- Keep the time range reasonable to avoid timeout
