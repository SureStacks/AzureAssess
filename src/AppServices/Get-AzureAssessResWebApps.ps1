<#
.SYNOPSIS
    Gets the web apps for specified subscription and resource group
.EXAMPLE
    PS C:\Get-AzureAssessApps -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

function Get-AzureAssessResWebApps() {
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
    $webapps = Invoke-RetryCommand -ScriptBlock { Get-AzWebApp -ResourceGroupName $ResourceGroupName }
    foreach ($webapp in $webapps) {
        $id = $webapp.Id -split "/"
        $Type = $id[6..($id.Count - 2)] -join "/"
        $IpSecurityRestrictionsDenies = @($webapp.SiteConfig.IpSecurityRestrictions | Where-Object { $_.Action -eq "Deny" }).Count -gt 0
        $AppServiceEnvironementInbound=$null
        if ($webapp.HostingEnvironmentProfile) {
            if ((Get-AzResource -Id $webapp.HostingEnvironmentProfile.Id).Properties.networkingConfiguration.externalInboundIpAddresses.Count -gt 0) {
                $AppServiceEnvironementInbound = "Public"
            } else {
                $AppServiceEnvironementInbound = "Internal"
            }
        }
        $publicnetworkaccess = $null
        if ($AppServiceEnvironementInbound -eq "Internal") {
            $publicnetworkaccess = $false
        } elseif ($webapp.SiteConfig.PublicNetworkAccess -eq "Enabled") {
            $publicnetworkaccess = $true
        } elseif ($webapp.SiteConfig.PublicNetworkAccess -eq "Disabled") {
            $publicnetworkaccess = $false
        }
        # columns to return
        # Id,ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,State,DefaultHostName,HttpsOnly,MinTlsVersion,FtpsState,AppServiceEnvironementInbound
        "" | select-object `
            @{N="Id";E={$webapp.Id}}, `
            @{N="ResourceGroupId";E={"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"}}, `
            @{N="Type";E={$Type}}, `
            @{N="Name";E={$webapp.Name}}, `
            @{N="Location";E={$webapp.Location}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource$($webapp.Id)"}}, `
            @{N="PublicNetworkAccess";E={$publicnetworkaccess}}, `
            @{N="HasFirewallRules";E={$IpSecurityRestrictionsDenies}}, `
            @{N="HasPrivateEndpoint";E={$null}}, `
            @{N="State";E={$webapp.State}}, `
            @{N="DefaultHostName";E={$webapp.DefaultHostName}}, `
            @{N="HttpsOnly";E={$webapp.HttpsOnly}}, `
            @{N="MinTlsVersion";E={$webapp.SiteConfig.MinTlsVersion}}, `
            @{N="FtpsState";E={$webapp.SiteConfig.FtpsState}}, `
            @{N="AppServiceEnvironementInbound";E={$AppServiceEnvironementInbound}}
    }
}