# Estimate Log Size for Defender Tables (Endpoint, Office, Cloud Apps)

## Query Information

#### Description

This query calculates the estimated log size (in GB) and average entry size (in KB) for Microsoft Defender for Endpoint, Defender for Office 365, and Defender for Cloud Apps tables over the last 30 days. It intentionally excludes `DeviceTvm*` (Threat and Vulnerability Management) tables and provides both a per-table breakdown and a unified grand total. 

**Notes & Considerations:**
* **Estimation Variance:** Please be aware that this calculation is only an estimation based on the `estimate_data_size()` KQL function. Real ingestion values and billing sizes in your workspace or Data Lake may vary by approximately +/- 10%.
* **Storage Savings:** When planning for Data Lake storage, you can typically factor in a **6:1 data compression rate**. Microsoft automatically applies this 6:1 compression ratio for billing Data Lake storage, meaning 600 GB of raw uncompressed logs will effectively be billed as 100 GB of compressed data.

#### Author

- Name: Marvin Rose

#### References

- [estimate_data_size() - Kusto Query Language](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/estimate-data-size-function)
- [Plan costs and understand Microsoft Sentinel pricing and billing](https://learn.microsoft.com/en-us/azure/sentinel/billing)
- [Microsoft Sentinel data lake is now generally available (Blog)](https://techcommunity.microsoft.com/blog/microsoft-security-blog/microsoft-sentinel-data-lake-is-now-generally-available/4456342)

## Defender XDR
```KQL
// Define the base data once to save performance
let LogData = union withsource=TableName 
    Device*,         // All Defender for Endpoint tables
    Email*,          // Defender for Office 365
    UrlClickEvents,  // Defender for Office 365 (Safe Links)
    CloudAppEvents   // Defender for Cloud Apps
| where TableName !startswith "DeviceTvm" // Excludes all tables starting with 'DeviceTvm' (currenlty not supported for direct log ingestion into datalake)
| where TimeGenerated > ago(30d)              // Use 'Timestamp' if you are running this without Unified Sec Ops Portal activated
| project TableName, size = estimate_data_size(*);
// 1. Calculate stats per table
LogData
| summarize 
    TotalEntries = count(), 
    TotalSizeGB = round(sum(size) / 1073741824.0, 3), // Divides by 1024^3 to calculate GB
    AvgSizeKB = round(avg(size) / 1024.0, 2)          // Average size per log entry in KB
    by TableName
// Append the grand total row
| union (
    LogData
    | summarize 
        TotalEntries = count(), 
        TotalSizeGB = round(sum(size) / 1073741824.0, 3), 
        AvgSizeKB = round(avg(size) / 1024.0, 2)
    | extend TableName = "--- TOTAL SUM ---"
)
| sort by TotalSizeGB desc
