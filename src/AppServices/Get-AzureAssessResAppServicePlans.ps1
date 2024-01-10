<#
.SYNOPSIS
    Gets the app service for specified subscription and resource group
.EXAMPLE
    PS C:\Get-AzureAssessAppServicePlans -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

function Get-AzureAssessResAppServicePlans() {
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
    $plans = Invoke-RetryCommand -ScriptBlock { Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName }
    foreach ($plan in $plans) {
        $id = $plan.Id -split "/"
        $Type = $id[6..($id.Count - 2)] -join "/"
        $AppServiceEnvironementInbound=$null
        if ($plan.HostingEnvironmentProfile) {
            if ((Get-AzResource -Id $plan.HostingEnvironmentProfile.Id).Properties.networkingConfiguration.externalInboundIpAddresses.Count -gt 0) {
                $AppServiceEnvironementInbound = "Public"
            } else {
                $AppServiceEnvironementInbound = "Internal"
            }
        }
        # columns to output
        # Id,ResourceGroupId,Type,Name,Link,Location,Sku,AppServiceEnvironementInbound"
        "" | select-object `
            @{N="Id";E={$plan.Id}}, `
            @{N="ResourceGroupId";E={"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"}}, `
            @{N="Type";E={$Type}}, `
            @{N="Name";E={$plan.Name}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource$($plan.Id)"}}, `
            @{N="Location";E={$plan.Location}}, `
            @{N="Sku";E={$plan.Sku.Name}}, `
            @{N="AppServiceEnvironementInbound";E={$AppServiceEnvironementInbound}}
    }
}