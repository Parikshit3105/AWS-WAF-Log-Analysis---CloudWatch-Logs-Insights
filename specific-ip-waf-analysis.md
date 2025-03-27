# WAF Log Analysis for IP 103.121.72.77

## 1. Per-Minute Detailed Request Analysis

```
fields httpRequest.country, action, @timestamp
| filter httpRequest.clientIp = "103.121.72.77"
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount,
        sum(action="CHALLENGE") as challengeCount,
        count(distinct httpRequest.country) as uniqueCountries,
        min(@timestamp) as firstSeen,
        max(@timestamp) as lastSeen,
        count(*)/60 as requestsPerMinute
  by bin(1m) as minute, httpRequest.country
| sort minute asc
```

### Query Breakdown
- Filters for specific IP: 103.121.72.77
- Provides per-minute breakdown
- Captures:
  - Total Requests
  - Allowed Requests
  - Blocked Requests
  - Challenge Requests
  - Unique Countries
  - First and Last Request Timestamp
  - Requests per Minute

## 2. Comprehensive IP Traffic Overview

```
fields httpRequest.country, action
| filter httpRequest.clientIp = "103.121.72.77"
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount,
        sum(action="CHALLENGE") as challengeCount,
        count(distinct httpRequest.httpMethod) as uniqueMethods
  by httpRequest.country
| sort totalRequests desc
```

### Query Breakdown
- Aggregates requests by country
- Shows:
  - Total Requests per Country
  - Allowed Requests
  - Blocked Requests
  - Challenge Requests
  - Unique HTTP Methods Used

## 3. Detailed HTTP Method Analysis

```
fields httpRequest.httpMethod, action
| filter httpRequest.clientIp = "103.121.72.77"
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount
  by httpRequest.httpMethod
| sort totalRequests desc
```

### Query Breakdown
- Analyzes HTTP methods used by the IP
- Provides:
  - Total Requests per Method
  - Allowed Requests
  - Blocked Requests

## 4. Time-Based Action Analysis

```
fields action, @timestamp
| filter httpRequest.clientIp = "103.121.72.77"
| stats count(*) as totalRequests, 
        sum(action="ALLOW") as allowCount, 
        sum(action="BLOCK") as blockCount,
        sum(action="CHALLENGE") as challengeCount
  by bin(1h) as timeSlot
| sort timeSlot asc
```

### Query Breakdown
- Hourly breakdown of actions
- Captures:
  - Total Requests
  - Allowed Requests
  - Blocked Requests
  - Challenge Requests

## Key Insights to Look For
1. Request Patterns
2. Geographical Distribution
3. Action Ratios (Allow vs. Block)
4. HTTP Method Diversity
5. Potential Suspicious Behaviors

## Recommended Next Steps
1. Investigate unusual request patterns
2. Check if IP is from a known threat source
3. Review WAF rules for this specific IP
4. Consider IP reputation analysis
5. Implement additional monitoring or blocking if needed

## Important Contextual Information
- IP: 103.121.72.77
- Analysis Timeframe: Entire available log period
- Log Source: AWS WAF Logs
- Log Group: aws-waf-logs-presco-prod

## Disclaimer
This analysis provides a snapshot of the IP's interactions. Continuous monitoring and context are crucial for comprehensive security assessment.
