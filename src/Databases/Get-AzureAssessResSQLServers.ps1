<#
.SYNOPSIS
    Gets the SQL Servers for specified subscription and resource group
.EXAMPLE
    PS C:\Get-AzureAssessResSQLServers -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

function Get-AzureAssessResSQLServers() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string]$ResourceGroupName
    )

    # Get the current context
    $context = Get-AzContext
    if ($context.Subscription.Name -ne $SubscriptionId -and $context.Subscription.Id -ne $SubscriptionId) {   
        # Set the desired subscription
        $context = Set-AzContext -Subscription $SubscriptionId
    }
    # Be sure to use subsciptionids as guid
    if ($SubscriptionId -notmatch "^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$") {
        $SubscriptionId = $context.Subscription.Id
    }

    # Get the in the resource group
    $sqlservers = Invoke-RetryCommand -ScriptBlock { Get-AzSqlServer -ResourceGroupName $ResourceGroupName }
    foreach ($sqlserver in $sqlservers) {
        $id = $sqlserver.ResourceId -split "/"
        $Type = $id[6..($id.Count - 2)] -join "/"
        # SQL server is always protected by firewall rules except if it has a private endpoint
        $hasfwrules = $true
        # By default public network access is disabled
        $publicnetworkaccess = $true
        if ($sqlserver.PublicNetworkAccess -eq "Disabled") {
            $publicnetworkaccess = $false
        }        
        # columns to return
        # ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,FullyQualifiedDomainName,MinimalTlsVersion,AdministratorType,EntraOnlyAuth
        "" | select-object `
            @{N="Id";E={$sqlserver.ResourceId}}, `
            @{N="ResourceGroupId";E={"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"}}, `
            @{N="Type";E={$Type}}, `
            @{N="Name";E={$sqlserver.ServerName}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource$($sqlserver.ResourceId)"}}, `
            @{N="Location";E={$sqlserver.Location}}, `
            @{N="PublicNetworkAccess";E={$publicnetworkaccess}}, `
            @{N="HasFirewallRules";E={$hasfwrules}}, `
            @{N="HasPrivateEndpoint";E={$null}}, `
            @{N="FullyQualifiedDomainName";E={$sqlserver.FullyQualifiedDomainName}}, `
            @{N="MinimalTlsVersion";E={$sqlserver.MinimalTlsVersion}}, `
            @{N="AdministratorType";E={$sqlserver.Administrators.AdministratorType}}, `
            @{N="EntraOnlyAuth";E={$sqlserver.Administrators.AzureAdOnlyAuthentication -eq $true}}
    }
}