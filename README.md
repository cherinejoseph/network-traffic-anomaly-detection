# Network Traffic Anomaly Detection with KQL

This project uses KQL to detect unusual outbound traffic patterns in Azure network logs, identifying high-volume sources and destinations.

## Usage
Run in Azure Sentinel to flag sources sending >10MB in 7 days, with destination details for SOC analysis. Potential use case: Detecting data exfiltration or botnet activity.

## Query
```kql
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(7d)
| summarize TotalBytes = sum(OutboundBytes_d), Destinations = make_set(DestIP_s), Protocols = make_set(L4Protocol_s), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by SrcIP_s
| where TotalBytes > 10000000 and array_length(Destinations) >= 10
| project SrcIP_s, TotalBytes, DestinationCount = array_length(Destinations), Destinations, Protocols, FirstSeen, LastSeen
| order by TotalBytes desc

