<#
.SYNOPSIS
    Gets the virtual machines for specified subscription and resource group
.EXAMPLE
    PS C:\Get-AzureAssessResVirtualMachines -SubscriptionId 3395068f-a9b5-41a9-af54-bd362b69e19a -ResourceGroupName "rg-app-service"
#>

function Get-AzureAssessResVirtualMachines() {
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
    $vms = Invoke-RetryCommand -ScriptBlock { Get-AzVM -ResourceGroupName $ResourceGroupName }
    foreach ($vm in $vms) {
        $id = $vm.Id -split "/"
        $Type = $id[6..($id.Count - 2)] -join "/"

        # Check if the VM has a public ip address
        # get all the vmnics that have a public network address
        $nics = @($vm.NetworkProfile.NetworkInterfaces `
            | ForEach-Object { Get-AzNetworkInterface -ResourceId $_.Id } `
            | Where-Object { @($_.IpConfigurations | ForEach-Object { $_.PublicIpAddress | Where-Object {$null -ne $_}}).Count -gt 0 })
        $publicnetworkaccess = $nics.Count -gt 0
        $publicipaddress = @($nics | ForEach-Object { $_.IpConfigurations } | ForEach-Object { $_.PublicIpAddress | Where-Object {$null -ne $_}})[0]
        # check if nics are associated with a network security group
        $hasfirewallrules = $true
        foreach($nic in $nics) {
            if (!$nic.NetworkSecurityGroup.Id) {
                # no network securituy group found
                $hasfirewallrules = $false
            }
        }
        $opensshorrdp = $false
        if ($hasfirewallrules -eq $false) {
            $opensshorrdp = $true
        } elseif ($publicnetworkaccess) {
            $nsgs = @($vmnics | Where-Object { ![string]::IsNullOrEmpty($_.NetworkSecurityGroup.Id) } | ForEach-Object { Get-AzNetworkSecurityGroup -Name @($_.NetworkSecurityGroup.Id -split "/")[8]})
            foreach($nsg in $nsgs) {
                # check that the last inbound rule blocks all
                $lastinbound =  $nsg.DefaultSecurityRules + $nsg.SecurityRules `
                    | Where-Object {  $_.Direction -eq "Inbound"  } | Sort-Object -Property Priority -Descending | Select-Object -First 
                $denyallinislast = $lastinbound.Access -eq "Deny" -and $lastinbound.DestinationPortRange -contains "*" -and $lastinbound.SourceAddressPrefix -contains "*"
                # check if there is a rule allowing internet inbound
                $hasfullinbound = @($nsg.DefaultSecurityRules + $nsg.SecurityRules `
                    | Where-Object { $_.Access -eq "Allow" -and $_.Direction -eq "Inbound" -and $_.DestinationPortRange -contains "*" -and ($_.SourceAddressPrefix -contains "*" -or $_.SourceAddressPrefix -contains "Internet") }).Count -gt 0
                $hasfirewallrules = ($hasfullinbound -eq $false) -and $denyallinislast    
                $opensshorrdp = @($nsg.DefaultSecurityRules + $nsg.SecurityRules | Where-Object { $_.Access -eq "Allow" -and $_.Direction -eq "Inbound" -and ($_.DestinationPortRange -contains "22" -or $_.DestinationPortRange -contains "3389") -and ($_.SourceAddressPrefix -contains "*" -or $_.SourceAddressPrefix -contains "Internet") }).Count -gt 0
            }
        } 
        # columns to output
        # Id,ResourceGroupId,Type,Name,Link,Location,PublicNetworkAccess,HasFirewallRules,HasPrivateEndpoint,HasOpenSSHorRDP,VmSize,PublicIp
        "" | select-object `
            @{N="Id";E={$vm.Id}}, `
            @{N="ResourceGroupId";E={"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"}}, `
            @{N="Type";E={$Type}}, `
            @{N="Name";E={$vm.Name}}, `
            @{N="Link";E={"https://portal.azure.com/#@$($context.Tenant.Id)/resource$($vm.Id)"}}, `
            @{N="Location";E={$vm.Location}}, `
            @{N="PublicNetworkAccess";E={$publicnetworkaccess}}, `
            @{N="HasFirewallRules";E={$hasfirewallrules}}, `
            @{N="HasPrivateEndpoint";E={!$publicnetworkaccess}}, `
            @{N="HasOpenSSHorRDP";E={$opensshorrdp}}, `
            @{N="VmSize";E={$vm.HardwareProfile.VmSize}}, `
            @{N="PublicIp";E={$publicipaddress}}
    }
}