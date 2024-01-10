<#
.SYNOPSIS
    Get security recommendations from defender for cloud
.EXAMPLE
    PS C:\Get-AzureAssessResSecurityRecommendations -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

$script:subscriptionRecommendationsCache = @{}
$script:subscriptionsRecommendationMetadataCache = @{}

function Get-AzureAssessResSecurityRecommendations() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [string]$ResourceType
    )

    # get the recommendations to ignore
    $ignores = (Get-Content -Path ".\ignorereco.txt" -ErrorAction:SilentlyContinue) -replace "`r`n","`n" -split "`n"

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

    # update cache for subscription recommendations metadata
    if ($script:subscriptionsRecommendationMetadataCache.Keys -notcontains $SubscriptionId) {
        $script:subscriptionsRecommendationMetadataCache[$SubscriptionId] = Invoke-RetryCommand -ScriptBlock { Get-AzSecurityAssessmentMetadata | Select-Object DisplayName,Description,Severity | Where-Object { $_.DisplayName -inotin $ignores}}
    }

    # update cache for subscription recommendations
    if ($script:subscriptionRecommendationsCache.Keys -notcontains $SubscriptionId) {
        $script:subscriptionRecommendationsCache[$SubscriptionId] = Invoke-RetryCommand -ScriptBlock { Get-AzSecurityAssessment | Where-Object {$_.Status.Code -inotin ("Healthy","NotApplicable") -and $_.DisplayName -inotin $ignores}}
    }

    # columns to retun
    # ResourceGroupId,ResourceType,ResourceName,Recommendation,Description,Severity
    $script:subscriptionRecommendationsCache[$SubscriptionId] `
        | Where-Object { $_.Id -imatch "^/subscriptions/$($SubscriptionId)/resourcegroups/$($ResourceGroupName)/providers/$($ResourceType)/.*" } `
        | Select-Object `
            @{N="ResourceGroupId";E={"/subscriptions/$($SubscriptionId)/resourcegroup/$($ResourceGroupName)"}}, `
            @{N="ResourceId";E={($_.Id -split "/")[0..8] -join "/"}}, `
            @{N="ResourceType";E={($_.Id -split "/")[6..7] -join "/"}}, `
            @{N="ResourceName";E={($_.Id -split "/")[8] -join "/"}}, `
            @{N="Recommendation";E={$_.DisplayName}}, `
            @{N="Description";E={$tmp = $_.DisplayName; ($script:subscriptionsRecommendationMetadataCache[$SubscriptionId] | Where-Object {$_.DisplayName -ieq $tmp}).Description}}, `
            @{N="Severity";E={$tmp = $_.DisplayName; (($script:subscriptionsRecommendationMetadataCache[$SubscriptionId] | Where-Object {$_.DisplayName -ieq $tmp}).Severity -split " ")[0]}}
}