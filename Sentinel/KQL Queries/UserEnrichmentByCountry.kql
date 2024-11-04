//User enrichment for specific country

//If you are using the 'country' field for users in Azure Entra ID and would like to find alerts related to users from a specific country

// for MDE Alerts
SecurityAlert
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| extend Entitiesex=parse_json(Entities)
| mv-expand Entitiesex
| where tostring(Entitiesex.Type) == "account"
| where ProviderName == "MDATP"
| extend UserPrincipalName=tostring(Entitiesex.UserPrincipalName)
| join kind=inner (IdentityInfo | where TimeGenerated > ago(30d) | summarize arg_max(TimeGenerated,*) by AccountUPN | where Country == "SWEDEN") on $left.UserPrincipalName==$right.AccountUPN
| distinct SystemAlertId
 
 
// for Azure AD Identity Protection (IPC) Alerts
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| extend Entitiesex=parse_json(Entities)
| mv-expand Entitiesex
| where tostring(Entitiesex.Type) == "account"
| where ProviderName == "IPC"
| extend AadUserId = tostring(Entitiesex.AadUserId)
| join kind=inner (IdentityInfo | where TimeGenerated > ago(30d) | summarize arg_max(TimeGenerated,*) by AccountUPN | where Country == "SWEDEN") on $left.AadUserId==$right.AccountObjectId
| distinct SystemAlertId

