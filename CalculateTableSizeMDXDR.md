# Estimate Log Size for Defender Tables (Endpoint, Office, Cloud Apps)

## Query Information

#### Description

This query calculates the estimated log size (in GB) and average entry size (in KB) for Microsoft Defender for Endpoint, Defender for Office 365, and Defender for Cloud Apps tables over the last 30 days. It intentionally excludes `DeviceTvm*` (Threat and Vulnerability Management) tables and provides both a per-table breakdown and a unified grand total. 

**Performance Optimization:** To bypass the strict CPU quotas in Advanced Hunting, this query uses a hybrid calculation approach. Calculating the exact size of every row over 30 days using `estimate_data_size()` is heavily CPU-intensive and will likely crash the query. Instead, this optimized query:
1. Calculates the **average row size** using only the last **1 hour** of data.
2. Retrieves the **total row count** for the last **30 days** (which is highly optimized and fast since it only queries the database index).
3. Multiplies the exact 30-day row count by the 1-hour average size to project a highly accurate total volume without exhausting the tenant's resources.

Additionally, this query is highly valuable for determining and planning the expected data volume that will be ingested into a Data Lake (e.g., when configuring continuous raw data export via the Microsoft Defender Streaming API). It includes a dedicated column that automatically calculates the expected compressed size.

**Notes & Considerations:**
* **Estimation Variance:** Please be aware that this calculation is an estimation. While highly accurate due to the exact 30-day row count, the average row size might slightly fluctuate. Real ingestion values and billing sizes in your workspace or Data Lake may vary by approximately +/- 10%.
* **Storage Savings:** When planning for Data Lake storage, you can typically factor in a **6:1 data compression rate**. Microsoft automatically applies this 6:1 compression ratio for billing Data Lake storage. The column `DataLakeCompressedGB` reflects this calculation.

#### Risk

Without clear visibility into log generation volumes, organizations may face unexpected spikes in data ingestion. This can lead to budget overruns or exceeded storage quotas, especially when forwarding these logs to a SIEM like Microsoft Sentinel or exporting them into a Data Lake.

#### Author

- Name: Marvin Rose

#### References

- [estimate_data_size() - Kusto Query Language](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/estimate-data-size-function)
- [Plan costs and understand Microsoft Sentinel pricing and billing](https://learn.microsoft.com/en-us/azure/sentinel/billing)
- [Microsoft Sentinel data lake is now generally available (Blog)](https://techcommunity.microsoft.com/blog/microsoft-security-blog/microsoft-sentinel-data-lake-is-now-generally-available/4456342)
- [Advanced Hunting Quotas and Usage Parameters](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview#quotas-and-usage-parameters)

## Defender XDR

```KQL
// 1. Sample the average row size using only the last 1 hour (Very CPU efficient)
let SizeSample = union withsource=TableName 
    Device*, UrlClickEvents, CloudAppEvents //, Email*
| where TableName !startswith "DeviceTvm" // Excludes all tables starting with 'DeviceTvm'
| where TimeGenerated > ago(1h)           // Only process heavy size estimation on 1 hour of data
| project TableName, size = estimate_data_size(*)
| summarize AvgSizeByte = avg(size) by TableName;
// 2. Count the exact number of rows for the last 30 days (Fast, uses indexes)
let CountData = union withsource=TableName 
    Device*, UrlClickEvents, CloudAppEvents //, Email*
| where TableName !startswith "DeviceTvm"
| where TimeGenerated > ago(30d)          // Count is cheap, we can do 30 days easily
| summarize TotalEntries30Days = count() by TableName;
// 3. Combine both and calculate the final exact projection
let FinalData = CountData
| join kind=inner SizeSample on TableName
| extend TotalSizeByte = TotalEntries30Days * AvgSizeByte; // Exact 30d count * Avg 1h size
// 4. Format output per table
FinalData
| summarize 
    TotalEntries30Days = sum(TotalEntries30Days), 
    TotalSizeGB = round(sum(TotalSizeByte) / 1073741824.0, 3),                  
    DataLakeCompressedGB = round((sum(TotalSizeByte) / 1073741824.0) / 6.0, 3), 
    AvgSizeKB = round((sum(TotalSizeByte) / sum(TotalEntries30Days)) / 1024.0, 2)
    by TableName
// 5. Append the grand total row
| union (
    FinalData
    | summarize 
        TotalEntries30Days = sum(TotalEntries30Days), 
        TotalSizeGB = round(sum(TotalSizeByte) / 1073741824.0, 3), 
        DataLakeCompressedGB = round((sum(TotalSizeByte) / 1073741824.0) / 6.0, 3),
        AvgSizeKB = round((sum(TotalSizeByte) / sum(TotalEntries30Days)) / 1024.0, 2)
    | extend TableName = "--- TOTAL SUM (30 Days Calculated) ---"
)
| sort by TotalSizeGB desc

## v0.2 
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

## v0.1
```KQL
> **WARNING: Querying anything larger than 1 day may exceed your Advanced Hunting CPU quota.** In tested environments, analyzing more than 24 hours of uncompressed data with this query resulted in immediate quota exhaustion and temporary blocking.
// Analyze a smaller timeframe to save CPU quota, then extrapolate to 30 days
let daysToAnalyze = 1; // Set to 1 because anything larger might exceed the CPU quota
let daysToProject = 30; // Number of days to extrapolate to
let multiplier = todouble(daysToProject) / daysToAnalyze; // Calculates the exact extrapolation factor
let LogData = union withsource=TableName 
    Device*,         
    Email*,          
    UrlClickEvents,  
    CloudAppEvents   
| where TableName !startswith "DeviceTvm" 
| where TimeGenerated > ago(daysToAnalyze * 1d) // Dynamically uses the variable!
| project TableName, size = estimate_data_size(*);
// 1. Calculate stats per table
LogData
| summarize 
    TotalEntries30Days = count() * multiplier, // Extrapolates entries correctly
    TotalSizeGB = round((sum(size) * multiplier) / 1073741824.0, 3),                  
    DataLakeCompressedGB = round(((sum(size) * multiplier) / 1073741824.0) / 6.0, 3), 
    AvgSizeKB = round(avg(size) / 1024.0, 2)   // Avg size stays the same                           
    by TableName
// Append the grand total row
| union (
    LogData
    | summarize 
        TotalEntries30Days = count() * multiplier, 
        TotalSizeGB = round((sum(size) * multiplier) / 1073741824.0, 3), 
        DataLakeCompressedGB = round(((sum(size) * multiplier) / 1073741824.0) / 6.0, 3),
        AvgSizeKB = round(avg(size) / 1024.0, 2)
    | extend TableName = "--- TOTAL SUM (30 Days Extrapolated) ---"
)
| sort by TotalSizeGB desc
```
