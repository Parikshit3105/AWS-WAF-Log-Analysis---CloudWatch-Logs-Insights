# AWS WAF Log Analysis - Ultimate Comprehensive Guide

## Overview

This document provides an exhaustive guide to CloudWatch Logs Insights queries for AWS Web Application Firewall (WAF) log analysis. These queries are designed to help security teams, network administrators, and DevOps professionals gain deep insights into web traffic, security events, and potential threats.

## Preface: Understanding WAF Log Analysis

### Why Log Analysis Matters
- Detect potential security threats
- Understand traffic patterns
- Identify unusual access attempts
- Improve overall web application security
- Compliance and auditing requirements

### Key Metrics to Monitor
- Request volumes
- Geographic traffic sources
- HTTP method distributions
- Allow vs. Block ratios
- Suspicious IP activities

## Comprehensive Query Catalog

### 1. HTTP Method Analysis with Action Filtering

#### Query
```
fields httpRequest.httpMethod, action
| filter action in ['BLOCK', 'ALLOW', 'CAPTCHA', 'CHALLENGE']
| stats count(*) as count by httpRequest.httpMethod
| sort count desc
| limit 100
```

#### Purpose
- Analyze distribution of HTTP methods
- Understand which methods are most frequently used
- Track actions taken on different HTTP methods

#### Expected Output
- `httpRequest.httpMethod`: HTTP method (GET, POST, etc.)
- `count`: Number of requests for each method
- Sorted by most frequent methods

#### Use Cases
- Identifying unusual HTTP method usage
- Detecting potential API abuse
- Method-level security analysis

### 2. Top Client IP Request Analysis

#### Query
```
fields httpRequest.clientIp
| stats count(*) as requestCount by httpRequest.clientIp
| sort requestCount desc
| limit 100
```

#### Purpose
- Identify top client IPs by request volume
- Detect potential suspicious IP activity
- Understand traffic sources

#### Expected Output
- `httpRequest.clientIp`: Client IP address
- `requestCount`: Total number of requests from each IP
- Sorted by highest request count

#### Use Cases
- Threat detection
- IP-based traffic analysis
- Identifying potential DDoS sources

### 3. Country-Based Request Analysis

#### Query
```
fields @timestamp, ltrim(@log) as __log__grafana_internal__, ltrim(@logStream) as __logstream__grafana_internal__
| fields httpRequest.country 
| stats count(*) as requestCount by httpRequest.country
```

#### Purpose
- Analyze request distribution by country
- Understand geographic traffic patterns
- Identify potential geographically-based threats

#### Expected Output
- `httpRequest.country`: Country of origin
- `requestCount`: Number of requests from each country

#### Use Cases
- Geoblocking strategies
- Traffic origin analysis
- Identifying unusual international traffic

### 4. Client IP Request and Action Analysis (Time-Binned)

#### Query
```
fields httpRequest.clientIp, @timestamp
| stats count(*) as requestCount, 
        sum(action="ALLOW") as allowRequest, 
        sum(action="BLOCK") as blockRequest
  by httpRequest.clientIp, bin(1m) as minute
| sort requestCount desc
| limit 100
```

#### Purpose
- Detailed analysis of IP requests with action breakdown
- Time-based granular view of IP activity
- Understand allow/block patterns for specific IPs

#### Expected Output
- `httpRequest.clientIp`: Client IP address
- `minute`: Specific minute timestamp
- `requestCount`: Total requests
- `allowRequest`: Allowed requests
- `blockRequest`: Blocked requests

#### Use Cases
- Detailed security investigation
- Time-based traffic pattern analysis
- Identifying suspicious IP behaviors

### 5. Detailed IP Request Timing Analysis

#### Query
```
fields httpRequest.clientIp, @timestamp
| stats count(*) as requestCount by httpRequest.clientIp, bin(1m) as minute
| sort minute asc
```

#### Purpose
- Analyze request distribution over time
- Understand traffic patterns for each IP
- Detect potential automated or burst traffic

#### Expected Output
- `httpRequest.clientIp`: Client IP address
- `minute`: Minute timestamp
- `requestCount`: Requests in that minute

#### Use Cases
- Detecting automated attacks
- Traffic load distribution analysis
- Anomaly detection

### 6. Top Client IPs with Forbidden (403) Requests by Country

#### Query
```
fields httpRequest.country 
| filter httpRequest.status = 403 
| stats count(*) as requestCount by httpRequest.country
| sort requestCount desc
| limit 100
```

#### Purpose
- Identify countries with high forbidden request rates
- Analyze 403 (Forbidden) error distributions
- Detect potential unauthorized access attempts

#### Expected Output
- `httpRequest.country`: Country of origin
- `requestCount`: Number of 403 forbidden requests

#### Use Cases
- Security threat investigation
- Access control analysis
- Geographic security insights

### 7. Comprehensive Country and IP Traffic Analysis

#### Query
```
fields httpRequest.country, httpRequest.clientIp, action
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount
  by httpRequest.clientIp, httpRequest.country
| sort totalRequests desc
| limit 100
```

#### Purpose
- Detailed traffic analysis by country and IP
- Understand allow and block patterns
- Identify specific problematic IPs

#### Expected Output
- `httpRequest.country`: Country of origin
- `httpRequest.clientIp`: Specific client IP
- `totalRequests`: Total number of requests
- `allowCount`: Allowed requests
- `blockCount`: Blocked requests

#### Use Cases
- Granular security investigation
- IP and country-level threat analysis
- Detailed traffic pattern understanding

### 8. Detailed Country and IP Action Analysis

#### Query
```
fields httpRequest.country, httpRequest.clientIp, action 
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount 
  by httpRequest.clientIp, httpRequest.country 
| sort totalRequests desc 
| limit 100
```

#### Purpose
- Comprehensive traffic analysis by country and IP
- Understand detailed allow and block patterns
- Identify specific client behaviors across different countries

#### Expected Output
- `httpRequest.country`: Country of origin
- `httpRequest.clientIp`: Specific client IP address
- `totalRequests`: Total number of requests
- `allowCount`: Number of allowed requests
- `blockCount`: Number of blocked requests

#### Use Cases
- Detailed security forensics
- Identifying potentially suspicious IP activities
- Geographic-level security analysis
- Granular traffic pattern investigation

### 9. Comprehensive Rule-Level Traffic Analysis

#### Query
```
fields httpRequest.clientIp, httpRequest.country, action, 
       terminatingRuleId, terminatingRuleType, 
       bin(60s) as minute
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount, 
        count(*)/60 as requestsPerMinute
  by httpRequest.clientIp, httpRequest.country, minute, 
     terminatingRuleId, terminatingRuleType
| sort totalRequests desc
| limit 10000
```
```
fields httpRequest.clientIp, httpRequest.country, action, terminatingRuleId, terminatingRuleType, bin(60s) as minute 
| filter httpRequest.country = "IN" and action = "BLOCK" 
| stats count(*) as blockCount, count(*)/60 as blockRatePerMinute by httpRequest.clientIp, minute, terminatingRuleId, terminatingRuleType 
| sort blockCount desc 
| limit 10000

```
#### Purpose
- Detailed analysis that includes the specific WAF rules being triggered
- Understand which rule types and rule IDs are most frequently matched
- Correlate client IPs and countries with specific rule matches
- Analyze traffic patterns with minute-level granularity

#### Expected Output
- `httpRequest.clientIp`: Client IP address
- `httpRequest.country`: Country of origin
- `minute`: Specific 60-second time bucket
- `terminatingRuleId`: The specific WAF rule that terminated the request evaluation
- `terminatingRuleType`: The type of rule that was triggered (e.g., rate-based, managed rule group)
- `totalRequests`: Total requests matching these criteria
- `allowCount`: Allowed requests
- `blockCount`: Blocked requests
- `requestsPerMinute`: Normalized request rate

#### Use Cases
- Rule effectiveness evaluation
- Detailed security forensics
- Identifying which rules are triggering for specific IPs or countries
- Fine-tuning WAF rule configurations
- Root cause analysis of blocked/allowed traffic
- Advanced threat hunting and investigation

### 10. Comprehensive Per-Minute Traffic Analysis

#### Query
```
fields httpRequest.country, httpRequest.clientIp, action, bin(60s) as minute
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount, 
        count(*)/60 as requestsPerMinute
  by httpRequest.clientIp, httpRequest.country, minute
| sort totalRequests desc
| limit 100
```

#### Purpose
- Analyze traffic patterns with minute-level granularity
- Understand request rates and actions over short time intervals
- Detect potential burst attacks or unusual traffic patterns

#### Expected Output
- `httpRequest.country`: Country of origin
- `httpRequest.clientIp`: Specific client IP
- `minute`: Specific 60-second time bucket
- `totalRequests`: Total requests in that minute
- `allowCount`: Allowed requests
- `blockCount`: Blocked requests
- `requestsPerMinute`: Normalized request rate

#### Use Cases
- Real-time traffic monitoring
- Detecting sudden traffic spikes
- Identifying potential DDoS attempts
- Minute-by-minute security analysis

## Advanced Analysis Strategies

### 1. Correlation and Context
- Cross-reference IP activities with threat intelligence
- Combine WAF logs with other security logs
- Look for patterns across multiple data sources

### 2. Anomaly Detection
- Establish baseline traffic patterns
- Set up alerts for significant deviations
- Use machine learning for advanced threat detection

### 3. Continuous Improvement
- Regularly review and update WAF rules
- Analyze query results to refine security strategies
- Conduct periodic comprehensive log reviews

## Recommended Tools and Integrations
- AWS CloudWatch
- AWS GuardDuty
- SIEM solutions
- Custom monitoring dashboards
- Threat intelligence platforms

## Best Practices
1. Maintain comprehensive logging
2. Regularly rotate and archive logs
3. Implement least-privilege access
4. Use multi-layered security approaches
5. Keep WAF rules updated

## Disclaimer
- These queries provide insights but are not a complete security solution
- Always combine log analysis with comprehensive security measures
- Consult security professionals for tailored advice

## Getting Started
1. Ensure proper IAM permissions
2. Configure detailed logging
3. Set up automated analysis
4. Create custom dashboards
5. Establish incident response protocols

## Conclusion
Effective WAF log analysis is an ongoing process of monitoring, learning, and adapting to emerging security challenges.
