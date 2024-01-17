<#
.SYNOPSIS
    Get Privilege role assignement for specific Id (resource or container)
.EXAMPLE
    PS C:\Get-AzureAssessPrivilegedRoleAssginments -Id /subscriptions/151f94b9-9d98-45cd-bc0b-d3bdee8d2969
#>

$privilgedRoles = @{}
$managementGroupNames = @{}
$subscriptionNames = @{}

function Get-AzureAssessPrivilegedRoleAssignments {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string]$ResourceGroupName
    )
 
    # get context
    $context = get-azcontext

    # Get assignement for privileged roles: Owner, Contributor, User Access Administrator, Role Bases Access Control Administrator
    if ($script:privilgedRoles.Count -eq 0) {
        $res = invoke-azrestmethod -method "GET" -path "/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
        if ($res.StatusCode -eq 200) {
            $res.Content `
                | ConvertFrom-Json | Select-Object -ExpandProperty value `
                | Where-Object { $_.properties.roleName -in ("Owner","Contributor","User Access Administrator","Role Based Access Control Administrator")}
                | foreach-Object { $script:privilgedRoles[$_.name] = $_.properties.roleName }
        } 
    }

    # get the role assignements for the resource group
    $res = invoke-azrestmethod -method "GET" -path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    if ($res.StatusCode -ne 200) {
        return
    }
    # returned columns
    # roleId,role,principalId,principalType,scope,source,resourceType,resourceName
    $assignments = @($res.Content | ConvertFrom-Json | Select-Object -ExpandProperty value | Select-Object -ExpandProperty properties `
        | Where-Object { ($_.roleDefinitionId -split "/")[-1] -in $privilgedRoles.Keys } `
        | Select-Object `
            @{N="roleId";E={($_.roleDefinitionId -split "/")[-1]}}, `
            @{N="role";E={""}}, `
            principalId, `
            principalType, `
            scope, `
            @{N="source";E={"RBAC"}}, `
            @{N="resourceType";E={""}}, `
            @{N="resourceName";E={($_.scope -split "/")[-1]}}, `
            @{N="link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource$($_.scope)/users"}})
    # expand columns
    foreach($assignment in $assignments) {
        $assignment.role = $script:privilgedRoles[$assignment.roleId]
        if ($assignment.scope -eq "/") {
            $assignment.resourceType = "managementGroups"
            $assignment.resourceName = "root"
            if ($assignment.resourceName -notin $script:managementGroupNames.Keys) {

                $res = Invoke-AzRestMethod -Method GET -Path "/providers/Microsoft.Management/managementGroups/$($context.Tenant.Id)?api-version=2020-05-01"
                if ($res.StatusCode -eq 200) {
                    $script:managementGroupNames[$assignment.resourceName] =  ($res.Content | ConvertFrom-Json).properties.displayName
                }
            } 
            if ($assignment.resourceName -in $script:managementGroupNames.Keys) {
                $assignment.scope = $assignment.scope -replace $assignment.resourceName,$script:managementGroupNames[$assignment.resourceName]
                $assignment.link = "https://portal.azure.com/#@$($context.Tenant.Id)/resource/providers/Microsoft.Management/managementGroups/$($context.Tenant.Id)/users"
                $assignment.resourceName = $script:managementGroupNames[$assignment.resourceName]
            }
        } elseif ($assignment.scope -imatch "/providers/Microsoft.Management/managementGroups/[^/]+") {
            $assignment.resourceType = "managementGroups"
            if ($assignment.resourceName -notin $script:managementGroupNames.Keys) {
                $res = Invoke-AzRestMethod -Method GET -Path "/providers/Microsoft.Management/managementGroups/$($assignment.resourceName)?api-version=2020-05-01"
                if ($res.StatusCode -eq 200) {
                    $script:managementGroupNames[$assignment.resourceName] =  ($res.Content | ConvertFrom-Json).properties.displayName
                }
            } 
            if ($assignment.resourceName -in $script:managementGroupNames.Keys) {
                $assignment.scope = $assignment.scope -replace $assignment.resourceName,$script:managementGroupNames[$assignment.resourceName]
                $assignment.link = $assignment.link -replace $assignment.resourceName,$script:managementGroupNames[$assignment.resourceName]
                $assignment.resourceName = $script:managementGroupNames[$assignment.resourceName]
            }
        } elseif ($assignment.scope -imatch "/subscriptions/[^/]+/resourceGroups/[^/]+/providers/.+") {
            $assignment.resourceType = ($assignment.scope -split "/")[6..7] -join "/"
        } elseif ($assignment.scope -imatch "/subscriptions/[^/]+/resourceGroups/[^/]+") {
            $assignment.resourceType = "resourceGroups"
        } elseif ($assignment.scope -imatch "/subscriptions/[^/]+") {
            $assignment.resourceType = "subscriptions"
            if ($assignment.resourceName -notin $script:subscriptionNames.Keys) {

                $res = Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($assignment.resourceName)?api-version=2016-06-01"
                if ($res.StatusCode -eq 200) {
                    $script:subscriptionNames[$assignment.resourceName] =  ($res.Content | ConvertFrom-Json).displayName
                }
            } 
            if ($assignment.resourceName -in $script:subscriptionNames.Keys) {
                $assignment.resourceName = $script:subscriptionNames[$assignment.resourceName]
            }
        }
    }
    # add inherited roles at resourceGroup level
    $inherits = $assignments | Where-Object { $_.resourceType -iin ("subscriptions","managementGroups")}
    foreach($inherit in $inherits) {
        $copy = $inherit.PsObject.Copy()
        $copy.scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
        $copy.resourceType = "resourceGroups"
        $copy.resourceName = $ResourceGroupName
        $copy.source = "Inherit"
        $copy.link = "https://portal.azure.com/#@$($context.Tenant.Id)/resource$($copy.scope)/users"
        $assignments += $copy
    }
    # add passing down roles to resources
    # get all resources of resourcegroup
    $res = invoke-azrestmethod -method GET -path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/resources?api-version=2021-04-11"
    if ($res.StatusCode -ne 200) {
        return $assignments
    }
    $resources = $res.Content | ConvertFrom-Json | Select-Object -ExpandProperty value | Select-Object id,name,type
    $childassignments = $assignments | Where-Object { $_.resourceType -iin ("subscriptions","managementGroups","resourceGroups") -and $_.source -eq "RBAC"}
    foreach($childassignement in $childassignments) {
        foreach($resource in $resources) {
            $copy = $childassignement.PsObject.Copy()
            $copy.scope = $resource.id
            $copy.resourceType = $resource.type
            $copy.resourceName = $resource.name
            $copy.source = "Inherit"
            $copy.link = "https://portal.azure.com/#@$($context.Tenant.Id)/resource$($copy.scope)/users"
            $assignments += $copy
        }
    }
    $assignments
}