<#
.SYNOPSIS
    Gets the private endpoints for specified subscription and resource group
.EXAMPLE
    PS C:\Get-AzureAssessResPrivateEndpoints -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

function Get-AzureAssessResPrivateEndpoints() {
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
    $privateendpoints = Invoke-RetryCommand -ScriptBlock { Get-AzPrivateEndpoint -ResourceGroupName $ResourceGroupName }
    foreach ($privateendpoint in $privateendpoints) {
        # only take into account approved links
        if ($privateendpoint.PrivateLinkServiceConnections.PrivateLinkServiceConnectionState.Status -ne "Approved") {
            continue
        }
        $Service = $privateendpoint.PrivateLinkServiceConnections.PrivateLinkServiceId -replace "/subscriptions/","" -replace "/resourceGroups","" -replace "/providers", "" -split "/"
        # get the type from the id
        # TODO: create a function for that
        $id = $privateendpoint.Id -split "/"
        $Type = $id[6..($id.Count - 2)] -join "/"
        # columns to return
        # ResourceGroupId,Type,Name,Link,Location,ServiceSubscriptionId,ServiceResourceGroupName,ServiceProvider,ServiceName
        "" | select-object `
            @{N="Id";E={$privateendpoint.Id}}, `
            @{N="ResourceGroupId";E={"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"}}, `
            @{N="Type";E={$Type}}, `
            @{N="Name";E={$privateendpoint.Name}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource/$($privateendpoint.Id)"}}, `
            @{N="Location";E={$privateendpoint.Location}}, `
            @{N="ServiceSubscriptionId";E={$Service[0]}}, `
            @{N="ServiceResourceGroupName";E={$Service[1]}}, `
            @{N="ServiceProvider";E={$Service[2..($Service.Count - 2)] -join "/"}}, `
            @{N="ServiceName";E={$Service[$Service.Count - 1]}}
    }
}