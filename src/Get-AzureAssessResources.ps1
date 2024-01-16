<#
.SYNOPSIS
    Gets the resources to be analysed within specified scope
.EXAMPLE
    PS C:\Get-AzureAssessResourses -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
    # Get all resource in indicated resourcegroup and subscription
.EXAMPLE
    PS C:\Get-AzureAssessResourses -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a
    # Get all resource for all resource groups in subscription
.EXAMPLE
    PS C:\Get-AzureAssessResourse -MamagementGroup "myManagementGroup"
    # Get all ressource in all the subscriptions and resource groups under indicated management group
#>

$defenderforcloudchecks = @{
    "VirtualMachines" = @("Microsoft.Compute/virtualMachines", "Microsoft.HybridCompute/machines")
    "AppServices" = @("Microsoft.Web/sites")
    "SqlServers" = @("Microsoft.Sql/servers", "Microsoft.Sql/sqlManagedInstances", "Microsoft.AzureArcData/sqlServers", "Microsoft.AzureArcData/sqlManagedInstances")
    "SqlServerVirtualMachines" = @("Microsoft.SqlVirtualMachine/sqlVirtualMachines")
    "OpenSourceRelationalDatabases" = @("Microsoft.DBforMySQL/servers","Microsoft.DBforPostgreSQL/servers","Microsoft.DBforMariaDB/servers","Microsoft.AzureArcData/postgresInstances")
    "CosmosDbs" = @("Microsoft.DocumentDB/databaseAccounts") 
    "StorageAccounts" = @("Microsoft.Storage/storageAccounts")
    "ContainerRegistry" = @("Microsoft.ContainerRegistry/registries")
    "KubernetesService" = @("Microsoft.ContainerService/managedCluster", "Microsoft.ContainerService/connectedCluster")
    "Containers" = @("Microsoft.ContainerRegistry/registries", "Microsoft.ContainerService/managedCluster", "Microsoft.ContainerService/connectedCluster")
    "KeyVaults" = @("Microsoft.KeyVault/vaults")
    "DNS" = @()
    "Arm" = @()
}

function Get-AzureAssessResources() {
    [CmdletBinding(DefaultParameterSetName="SubnRg")]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1, ParameterSetName="SubnRg")]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 2, ParameterSetName="SubnRg")]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 2, ParameterSetName="MgmtGrp")]
        [string[]]$ManagementGroupNames,
        [Parameter(Mandatory = $false)]
        [validateSet("Microsoft.Web/sites", "Microsoft.Web/serverFarms", "Microsoft.Network/privateEndpoints","Microsoft.Storage/storageAccounts","Microsoft.Sql/servers","Microsoft.KeyVault/vaults","Microsoft.Compute/virtualMachines")]
        [string[]]$ResourceTypes = ("Microsoft.Web/sites", "Microsoft.Web/serverFarms", "Microsoft.Network/privateEndpoints","Microsoft.Storage/storageAccounts","Microsoft.Sql/servers","Microsoft.KeyVault/vaults","Microsoft.Compute/virtualMachines")
    )

    # Initialize CSV files for collected resources
    $privateendpointscsv = Join-Path -Path "." -ChildPath "privateendpoints.csv"
    $webappscsv = Join-Path -Path "." -ChildPath "webapps.csv"
    $appserviceplanscsv = Join-Path -Path "." -ChildPath "appserviceplans.csv"
    $storagecsv = Join-Path -Path "." -ChildPath "storages.csv"
    $sqlserverscsv = Join-Path -Path "." -ChildPath "sqlservers.csv"
    $keyvaultscsv = Join-Path -Path "." -ChildPath "keyvaults.csv"
    $virtualmachinescsv = Join-Path -Path "." -ChildPath "virtualmachines.csv"
    $managementgroupscsv = Join-Path -Path "." -ChildPath "managementgroups.csv"
    $subscriptionscsv = Join-Path -Path "." -ChildPath "subscriptions.csv"
    $resourcegroupscsv = Join-Path -Path "." -ChildPath "resourcegroups.csv"
    $securityrecommendationscsv = Join-Path -Path "." -ChildPath "securityrecommendations.csv"
    $roleassignmentscsv = Join-Path "." -ChildPath "roleassignments.csv"

    Write-Output "Initializing csv files"

    # Initialize CSV files with headers
    if ($ResourceTypes -contains "Microsoft.Network/privateEndpoints") {
        "Id,ResourceGroupId,Type,Name,Link,Location,ServiceSubscriptionId,ServiceResourceGroupName,ServiceProvider,ServiceName" | Out-File -FilePath $privateendpointscsv -Force
    }
    if ($ResourceTypes -contains "Microsoft.Web/sites") {
        "Id,ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,State,DefaultHostName,HttpsOnly,MinTlsVersion,FtpsState,AppServiceEnvironementInbound" | Out-File -FilePath $webappscsv -Force
    }
    if ($ResourceTypes -contains "Microsoft.Web/serverFarms") {
        "Id,ResourceGroupId,Type,Name,Link,Location,Sku,AppServiceEnvironementInbound" | Out-File -FilePath $appserviceplanscsv -Force
    }
    if ($ResourceTypes -contains "Microsoft.Storage/storageAccounts") {
        "Id,ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,Sku,MinimumTlsVersion,EnableHttpsTrafficOnly,AllowBlobPublicAccess,InfrastructureEncryption,ServiceEncryption" | Out-File -FilePath $storagecsv -Force
    }
    if ($ResourceTypes -contains "Microsoft.Sql/servers") {
        "Id,ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,FullyQualifiedDomainName,MinimalTlsVersion,AdministratorType,EntraOnlyAuth" | Out-File -FilePath $sqlserverscsv -Force
    }
    if ($ResourceTypes -contains "Microsoft.KeyVault/vaults") {
        "Id,ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,VaultUri,EnableSoftDelete,EnablePurgeProtection" | Out-File -FilePath $keyvaultscsv -Force
    }
    if ($ResourceTypes -contains "Microsoft.Compute/virtualMachines") {
        "Id,ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,HasOpenSSHorRDP,VmSize,PublicIp" | Out-File -FilePath $virtualmachinescsv -Force
    }
    "ResourceGroupId,ResourceId,ResourceType,ResourceName,Recommendation,Description,Severity" | Out-File -FilePath $securityrecommendationscsv -Force
    if ($PSCmdlet.ParameterSetName -eq "MgmtGrp") {
        "ManagementGroup" | Out-File -FilePath $managementgroupscsv -Force
    }
    "ManagementGroup,Id,Name,Link,DefenderForVirtualMachines,DefenderForAppServices,DefenderForSqlServers,DefenderForSqlServerVirtualMachines,DefenderForOpenSourceDBs,DefenderForCosmosDbs,DefenderForStorageAccounts,DefenderForContainerRegistry,DefenderForKubernetesService,DefenderForContainers,DefenderForKeyVaults,DefenderForDNS,DefenderForArm,HasVirtualMachines,HasAppServices,HasSqlServers,HasSqlServerVirtualMachines,HasOpenSourceDBs,HasCosmosDbs,HasStorageAccounts,HasContainerRegistry,HasKubernetesService,HasContainers,HasKeyVaults" | Out-File -FilePath $subscriptionscsv -Force
    "SubscriptionId,Id,Name,Link" | Out-File -FilePath $resourcegroupscsv -Force
    "roleId,role,principalId,principalType,scope,source,resourceType,resourceName,link" | Out-File -FilePath $roleassignmentscsv -Force

    Write-Output "Get subscriptions ids"

    $SubscriptionIds = @()
    $context = get-azcontext

    if ($PSCmdlet.ParameterSetName -eq "SubnRg") {
        $SubscriptionIds += "" | Select-Object @{N="ManagementGroup";E={$null}},@{N="SubscriptionId";E={$SubscriptionId}}
    } elseif ($PSCmdlet.ParameterSetName -eq "MgmtGrp") {
        foreach($ManagementGroupName in $ManagementGroupNames) {
            # Expand all management groups and subscriptions under the indicated management group
            $SubscriptionIds += Get-AzManagementGroupSubscription -GroupName $ManagementGroupName | Select-Object @{N="ManagementGroup";E={$ManagementGroupName}},@{N="SubscriptionId";E={($_.Id -split "/")[-1]}}
            "" | Select-Object @{N="ManagementGroup";E={$ManagementGroupName}} | Export-Csv -Path $managementgroupscsv -NoTypeInformation -Append
        }
    }

    # Message that collection is starting for the number of subscriptions
    Write-Output "Perparing collection for $($SubscriptionIds.Count) subscriptions" 

    # Expand all subscriptions and their ressource groups
    $collections = @()
    $resourcegroupinfos = @()
    $subscriptionsinfos = @()
    foreach($CurrentSubscription in $SubscriptionIds) {
        $ManagementGroupName = $CurrentSubscription.ManagementGroup
        $SubscriptionName = (Set-AzContext -Subscription $CurrentSubscription.SubscriptionId).Subscription.Name
        # get defender for cloud informations
        $defenderforcloud = @{}
        $defenderforcloudres = @{}
        $securitypricing = @(Get-AzSecurityPricing)
        foreach($defenderforcloudcheck in $defenderforcloudchecks.Keys) {
            $defenderforcloud[$defenderforcloudcheck] = ($securitypricing | Where-Object {$_.Name -eq $defenderforcloudcheck}).PricingTier -eq "Standard"
            # check resources presences
            $defenderforcloudres[$defenderforcloudcheck] = ($defenderforcloudchecks[$defenderforcloudcheck]).Count -eq 0
            if ($defenderforcloudres[$defenderforcloudcheck] -eq $false) {
                $jobs = @()
                foreach($defenderforcloudreskey in $defenderforcloudchecks[$defenderforcloudcheck]) {
                    $jobs += invoke-azrestmethod -AsJob -method "GET" -path "/subscriptions/$($CurrentSubscription.SubscriptionId)/resources?`$filter=resourceType+eq+'$defenderforcloudreskey'&`$top=1&api-version=2023-07-01" 
                }
                $res = $jobs | Wait-Job | Receive-Job | Where-Object { $_.StatusCode -eq 200 } | ForEach-Object { $_.Content |  ConvertFrom-Json } | Select-Object -ExpandProperty value
                $defenderforcloudres[$defenderforcloudcheck] = $res.Count -gt 0
            }
        }
        $subscriptionsinfos += "" | select-object `
            @{N="ManagementGroup";E={$ManagementGroupName}}, `
            @{N="Id";E={$CurrentSubscription.SubscriptionId}}, `
            @{N="Name";E={$SubscriptionName}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource/subscriptions/$($CurrentSubscription.SubscriptionId)"}}, `
            @{N="DefenderForVirtualMachines";E={$defenderforcloud["VirtualMachines"]}}, `
            @{N="DefenderForAppServices";E={$defenderforcloud["AppServices"]}}, `
            @{N="DefenderForSqlServers";E={$defenderforcloud["SqlServers"]}}, `
            @{N="DefenderForSqlServerVirtualMachines";E={$defenderforcloud["SqlServerVirtualMachines"]}}, `
            @{N="DefenderForOpenSourceDBs";E={$defenderforcloud["OpenSourceRelationalDatabases"]}}, `
            @{N="DefenderForCosmosDbs";E={$defenderforcloud["CosmosDbs"]}}, `
            @{N="DefenderForStorageAccounts";E={$defenderforcloud["StorageAccounts"]}}, `
            @{N="DefenderForContainerRegistry";E={$defenderforcloud["ContainerRegistry"]}}, `
            @{N="DefenderForKubernetesService";E={$defenderforcloud["KubernetesService"]}}, `
            @{N="DefenderForContainers";E={$defenderforcloud["Containers"]}}, `
            @{N="DefenderForKeyVaults";E={$defenderforcloud["KeyVaults"]}}, `
            @{N="DefenderForDNS";E={$defenderforcloud["DNS"]}}, `
            @{N="DefenderForArm";E={$defenderforcloud["Arm"]}}, `
            @{N="HasVirtualMachines";E={$defenderforcloudres["VirtualMachines"]}}, `
            @{N="HasAppServices";E={$defenderforcloudres["AppServices"]}}, `
            @{N="HasSqlServers";E={$defenderforcloudres["SqlServers"]}}, `
            @{N="HasSqlServerVirtualMachines";E={$defenderforcloudres["SqlServerVirtualMachines"]}}, `
            @{N="HasOpenSourceDBs";E={$defenderforcloudres["OpenSourceRelationalDatabases"]}}, `
            @{N="HasCosmosDbs";E={$defenderforcloudres["CosmosDbs"]}}, `
            @{N="HasStorageAccounts";E={$defenderforcloudres["StorageAccounts"]}}, `
            @{N="HasContainerRegistry";E={$defenderforcloudres["ContainerRegistry"]}}, `
            @{N="HasKubernetesService";E={$defenderforcloudres["KubernetesService"]}}, `
            @{N="HasContainers";E={$defenderforcloudres["Containers"]}}, `
            @{N="HasKeyVaults";E={$defenderforcloudres["KeyVaults"]}}
        $ResourceGroupNames = @($ResourceGroupName)
        if (($PSCmdlet.ParameterSetName -eq "SubnRg" -and !$ResourceGroupName) -or $PSCmdlet.ParameterSetName -eq "MgmtGrp") {
            $ResourceGroupNames = Invoke-RetryCommand { Get-AzResourceGroup } | foreach-object { $_.ResourceGroupName }
        }
        foreach($CurrentResourceGroupName in $ResourceGroupNames) {      
            $resourcegroupinfos += "" | select-object @{N="SubscriptionId";E={$CurrentSubscription.SubscriptionId}},@{N="Id";E={"/subscriptions/$($CurrentSubscription.SubscriptionId)/resourceGroups/$CurrentResourceGroupName"}},@{N="Name";E={$CurrentResourceGroupName}},@{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource/subscriptions/$($CurrentSubscription.SubscriptionId)/resourceGroups/$CurrentResourceGroupName"}}
        }
    }
    # save subscriptions infos
    $subscriptionsinfos | Export-Csv -Path $subscriptionscsv -NoTypeInformation -Append
    # save resourcegroup infos
    $resourcegroupinfos | Export-Csv -Path $resourcegroupscsv -NoTypeInformation -Append
    # use job queries 
    $jobs = @()
    $cnt = 0
    foreach($ResourceType in $ResourceTypes) {
        foreach($ResourceGroupInfo in $resourcegroupinfos) {
            $jobs += Invoke-AzRestMethod -AsJob -Method GET -Path "/subscriptions/$($ResourceGroupInfo.SubscriptionId)/resourceGroups/$($ResourceGroupInfo.Name)/resources?`$filter=resourceType+eq+'$($ResourceType)'&`$top=1&api-version=2021-04-01"
            if ($jobs.Count -ge 20) {
                $cnt += $jobs.Count
                $collections += $jobs | wait-job | Receive-Job | Where-Object {($_.StatusCode -eq 200 -and $_.Content -ne "{`"value`":[]}")} | ForEach-Object { ($_.Content | convertfrom-json).Value[0].id  } | Select-Object @{N="SubscriptionId";E={($_ -split "/")[2]}},@{N="ResourceGroupName";E={($_ -split "/")[4]}},@{N="ResourceType";E={($_ -split "/")[6..7] -join "/"}}
                Write-Progress -Activity "checking resources collection" -Status "$cnt of $($ResourceTypes.Count * $ResourceGroupInfos.Count)" -PercentComplete (($cnt / ($ResourceTypes.Count * $ResourceGroupInfos.Count))*100)
                $jobs = @()
            }
        }
    }
    $cnt += $jobs.Count
    $collections += $jobs | wait-job | Receive-Job | Where-Object {($_.StatusCode -eq 200 -and $_.Content -ne "{`"value`":[]}")} | ForEach-Object { ($_.Content | convertfrom-json).Value[0].id  } | Select-Object @{N="SubscriptionId";E={($_ -split "/")[2]}},@{N="ResourceGroupName";E={($_ -split "/")[4]}},@{N="ResourceType";E={($_ -split "/")[6..7] -join "/"}}
    Write-Progress -Activity "checking resources collection" -Status "$cnt of $($ResourceTypes.Count * $ResourceGroupInfos.Count)" -PercentComplete (($cnt / ($ResourceTypes.Count * $ResourceGroupInfos.Count))*100)
    
    # adding role assignement to the collections
    $collections += $resourcegroupinfos | Select-Object SubscriptionId,@{N="ResourceGroupName";E={$_.Name}},@{N="ResourceType";E={"roles"}}

    # sort by subscription id to limit context changes
    $collections = $collections | Sort-Object -Property SubscriptionId

    # Start the collections showing a progress bar
    for($colid = 0; $colid -lt $collections.Count; $colid += 1) {
        $SubscriptionId = $collections[$colid].SubscriptionId
        $ResourceGroupName = $collections[$colid].ResourceGroupName
        $ResourceType = $collections[$colid].ResourceType
        if ($ResourceType -eq "Microsoft.Network/privateEndpoints") {
            # Get all private endpoints job
            Get-AzureAssessResPrivateEndpoints -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $privateendpointscsv -NoTypeInformation -Append
        }
        if ($ResourceType -eq "Microsoft.Web/sites") {
            # Get all webapps job
            Get-AzureAssessResWebApps -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $webappscsv -NoTypeInformation -Append
        }
        if ($ResourceType -eq "Microsoft.Web/serverFarms") {
            # Get all app service plans job
            Get-AzureAssessResAppServicePlans -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $appserviceplanscsv -NoTypeInformation -Append
        }
        if ($ResourceType -eq "Microsoft.Storage/storageAccounts") {
            # Get all storage accounts job
            Get-AzureAssessResStorages -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $storagecsv -NoTypeInformation -Append
        }
        if ($ResourceType -eq "Microsoft.Sql/servers") {
            # Get all sql servers job
            Get-AzureAssessResSqlServers -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $sqlserverscsv -NoTypeInformation -Append
        }
        if ($ResourceType -eq "Microsoft.KeyVault/vaults") {
            # Get all key vaults and export to csv
            Get-AzureAssessResKeyVaults -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $keyvaultscsv -NoTypeInformation -Append
        }
        if ($ResourceType -eq "Microsoft.Compute/virtualMachines") {
            # Get all virualmachines and export to csv
            Get-AzureAssessResVirtualMachines -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $virtualmachinescsv -NoTypeInformation -Append
        }
        if ($ResourceType -eq "roles") {
            # Get all role assignements and export to csv
            Get-AzureAssessPrivilegedRoleAssginments -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName | Export-Csv -Path $roleassignmentscsv -NoTypeInformation -Append
        }
        # Get all Defender for cloud recommendations
        Get-AzureAssessResSecurityRecommendations -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -ResourceType $ResourceType | Export-Csv -Path $securityrecommendationscsv -NoTypeInformation -Append
        Write-Progress -Activity "Collecting resources" -Status "$colid of $($collections.Count)" -PercentComplete ($colid / $collections.Count * 100)
    }

    # Add information about private endpoints
    Join-AzureAssessPrivateEndpoints

    # remove duplicates from role assignements
    $uniqueroleassignments = Get-Content $roleassignmentscsv | ConvertFrom-Csv | Sort-Object | Get-Unique -AsString -CaseInsensitive
    $uniqueroleassignments | Export-Csv -Path $roleassignmentscsv -NoTypeInformation -Force
}
