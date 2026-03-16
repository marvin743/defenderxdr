# Estimate Log Size for Defender Tables (Endpoint, Office, Cloud Apps)

## Query Information

#### Description

This query calculates the estimated log size (in GB) and average entry size (in KB) for Microsoft Defender for Endpoint, Defender for Office 365, and Defender for Cloud Apps tables over the last 30 days. It intentionally excludes `DeviceTvm*` (Threat and Vulnerability Management) tables and provides both a per-table breakdown and a unified grand total. 

**Notes & Considerations:**
* **Estimation Variance:** Please be aware that this calculation is only an estimation based on the `estimate_data_size()` KQL function. Real ingestion values and billing sizes in your workspace or Data Lake may vary by approximately +/- 10%.
* **Storage Savings:** When planning for Data Lake storage, you can typically factor in a **6:1 data compression rate**. Microsoft automatically applies this 6:1 compression ratio for billing Data Lake storage, meaning 600 GB of raw uncompressed logs will effectively be billed as 100 GB of compressed data.

**Note on Advanced Hunting Quotas:**
Running broad queries across multiple extensive tables can consume a significant amount of your Advanced Hunting resources. Microsoft Defender XDR enforces usage limits to ensure service stability. For example, if your queries exceed the allocated **CPU quota** within a 15-minute cycle, you may be temporarily blocked from running further queries until the next cycle begins.

#### Author

- Name: Marvin Rose

#### References

- [estimate_data_size() - Kusto Query Language](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/estimate-data-size-function)
- [Plan costs and understand Microsoft Sentinel pricing and billing](https://learn.microsoft.com/en-us/azure/sentinel/billing)
- [Microsoft Sentinel data lake is now generally available (Blog)](https://techcommunity.microsoft.com/blog/microsoft-security-blog/microsoft-sentinel-data-lake-is-now-generally-available/4456342)

## Defender XDR
> **WARNING: This query will definitely hit the quota of Advanced Hunting.** Because it calculates the size of every single row over a full 30-day period, it consumes significant CPU resources. You may need to reduce the timeframe (e.g., to 1 or 7 days) and extrapolate the results to avoid being temporarily blocked.
```KQL
// Define the base data once to save performance
let LogData = union withsource=TableName 
    Device*,         // All Defender for Endpoint tables
    Email*,          // Defender for Office 365
    UrlClickEvents,  // Defender for Office 365 (Safe Links)
    CloudAppEvents   // Defender for Cloud Apps
| where TableName !startswith "DeviceTvm" // Excludes all tables starting with 'DeviceTvm' (currently not supported for direct log ingestion into datalake)
| where TimeGenerated > ago(30d)          // Use 'Timestamp' if you are running this without Unified Sec Ops Portal activated
| project TableName, size = estimate_data_size(*);
// 1. Calculate stats per table
LogData
| summarize 
    TotalEntries = count(), 
    TotalSizeGB = round(sum(size) / 1073741824.0, 3),                  // Divides by 1024^3 to calculate raw GB
    DataLakeCompressedGB = round((sum(size) / 1073741824.0) / 6.0, 3), // Applies 6:1 compression ratio for Data Lake
    AvgSizeKB = round(avg(size) / 1024.0, 2)                           // Average size per log entry in KB
    by TableName
// Append the grand total row
| union (
    LogData
    | summarize 
        TotalEntries = count(), 
        TotalSizeGB = round(sum(size) / 1073741824.0, 3), 
        DataLakeCompressedGB = round((sum(size) / 1073741824.0) / 6.0, 3),
        AvgSizeKB = round(avg(size) / 1024.0, 2)
    | extend TableName = "--- TOTAL SUM ---"
)
| sort by TotalSizeGB desc
```
**Note on Extrapolation and Accuracy:**
To avoid exceeding Advanced Hunting CPU quotas (which can easily happen when analyzing 30 days of uncompressed data at once), this query analyzes a shorter timeframe (e.g., 1 or 7 days) and extrapolates the results to a 30-day period. Because log generation naturally fluctuates due to weekends, patch days, or sporadic events, you can expect an extrapolation variance of approximately 10% to 15% compared to a full 30-day scan. This margin of error is perfectly normal and generally acceptable for initial Data Lake or SIEM storage sizing. Always include a 15-20% buffer in your final calculation.
```KQL
// Analyze 7 day to save CPU quota, then extrapolate to 30 days
let daysToAnalyze = 7;
let daysToProject = 30;
let LogData = union withsource=TableName 
    Device*,         
    Email*,          
    UrlClickEvents,  
    CloudAppEvents   
| where TableName !startswith "DeviceTvm" 
| where TimeGenerated > ago(1d) // ONLY look at the last 24 hours
| project TableName, size = estimate_data_size(*);
// 1. Calculate stats per table
LogData
| summarize 
    TotalEntries30Days = count() * daysToProject, // Extrapolates entries
    TotalSizeGB = round((sum(size) * daysToProject) / 1073741824.0, 3),                  
    DataLakeCompressedGB = round(((sum(size) * daysToProject) / 1073741824.0) / 6.0, 3), 
    AvgSizeKB = round(avg(size) / 1024.0, 2) // Avg size stays the same                           
    by TableName
// Append the grand total row
| union (
    LogData
    | summarize 
        TotalEntries30Days = count() * daysToProject, 
        TotalSizeGB = round((sum(size) * daysToProject) / 1073741824.0, 3), 
        DataLakeCompressedGB = round(((sum(size) * daysToProject) / 1073741824.0) / 6.0, 3),
        AvgSizeKB = round(avg(size) / 1024.0, 2)
    | extend TableName = "--- TOTAL SUM (30 Days Extrapolated) ---"
)
| sort by TotalSizeGB desc
```
