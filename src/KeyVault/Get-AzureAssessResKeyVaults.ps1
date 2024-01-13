<#
.SYNOPSIS
    Gets Key Vaults for specified subscription and resource group
.EXAMPLE
    PS C:\Get-AzureAssessResKeyVaults -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

function Get-AzureAssessResKeyVaults() {
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
    $res = invoke-azrestmethod -method "GET" -path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
    if ($res.StatusCode -ne 200) {
        return
    }
    $keyvaults = $res.Content | ConvertFrom-Json | Select-Object -ExpandProperty value
    foreach ($kv in $keyvaults) {
        $publicnetworkaccess = $null
        if ($kv.properties.publicNetworkAccess -eq "Enabled") {
            $publicnetworkaccess = $true
        } elseif ($kv.properties.publicNetworkAccess -eq "Disabled") {
            $publicnetworkaccess = $false
        }    
        # columns to return
        # ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,VaultUri,EnableSoftDelete,EnablePurgeProtection
        "" | Select-Object `
            @{N="Id";E={$kv.id}}, `
            @{N="ResourceGroupId";E={"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"}}, `
            @{N="Type";E={$kv.type}}, `
            @{N="Name";E={$kv.name}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource$($kv.id)"}}, `
            @{N="Location";E={$kv.location}}, `
            @{N="PublicNetworkAccess";E={$publicnetworkaccess}}, `
            @{N="HasFirewallRules";E={$kv.properties.networkAcls.defaultAction -eq "Deny"}}, `
            @{N="HasPrivateEndpoint";E={$null}}, `
            @{N="VaultUri";E={$kv.properties.VaultUri}}, `
            @{N="EnableSoftDelete";E={$kv.properties.enableSoftDelete}}, `
            @{N="EnablePurgeProtection";E={$kv.properties.enablePurgeProtection}}
    }
}