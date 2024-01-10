<#
.SYNOPSIS
    Gets the storage accounts for specified subscription and resource group
.EXAMPLE
    PS C:\Get-AzureAssessResStorages -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

function Get-AzureAssessResStorages() {
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
    $storages = Invoke-RetryCommand -ScriptBlock { Get-AzStorageAccount -ResourceGroupName $ResourceGroupName }
    foreach ($storage in $storages) {
        $id = $storage.Id -split "/"
        $Type = $id[6..($id.Count - 2)] -join "/"
        $ServiceEncryption = $null
        $ServiceEncryption = $storage.Encryption.Services.Blob.Enabled -eq $true -or $storage.Encryption.Services.File.Enabled -eq $true -or $storage.Encryption.Services.Queue.Enabled -eq $true -or $storage.Encryption.Services.Table.Enabled -eq $true
        $publicnetworkaccess = $null
        if ($storage.PublicNetworkAccess -eq "Enabled") {
            $publicnetworkaccess = $true
        } elseif ($storage.PublicNetworkAccess -eq "Disabled") {
            $publicnetworkaccess = $false
        }
        # columns to output
        # ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,Sku,MinimumTlsVersion,EnableHttpsTrafficOnly,AllowBlobPublicAccess,InfrastructureEncryption,ServiceEncryption
        "" | select-object `
            @{N="Id";E={$storage.Id}}, `
            @{N="ResourceGroupId";E={"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"}}, `
            @{N="Type";E={$Type}}, `
            @{N="Name";E={$storage.StorageAccountName}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource$($storage.Id)"}}, `
            @{N="Location";E={$storage.Location}}, `
            @{N="PublicNetworkAccess";E={$publicnetworkaccess}}, `
            @{N="HasFirewallRules";E={$storage.NetworkRuleSet.IpRules.Count -gt 0}}, `
            @{N="HasPrivateEndpoint";E={$null}}, `
            @{N="Sku";E={$storage.Sku.Name}}, `
            @{N="MinimumTlsVersion";E={$storage.MinimumTlsVersion}}, `
            @{N="EnableHttpsTrafficOnly";E={$storage.EnableHttpsTrafficOnly}}, `
            @{N="AllowBlobPublicAccess";E={$storage.AllowBlobPublicAccess}}, `
            @{N="InfrastructureEncryption";E={$storage.Encryption.RequireInfrastructureEncryption -eq $true}}, `
            @{N="ServiceEncryption";E={$ServiceEncryption}}
    }
}