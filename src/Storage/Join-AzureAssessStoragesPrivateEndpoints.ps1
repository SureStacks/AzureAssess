<#
.SYNOPSIS
    Update storage acciybts collected with known private endpoints to determine if they are accessible from the internet
    When public internet access is neither enabled nor disabled ( PublicNetworkAccess = $null ), the web app will determine access in function of the presence of private endpoints
.EXAMPLE
    PS C:\Join-AzureAssessStoragesPrivateEndpoints
#>

function Join-AzureAssessStoragesPrivateEndpoints() {
    # TODO: put all file definition in main script
    # load web apps csv
    $storagescsv = Join-Path -Path "." -ChildPath "storages.csv" 
    $storages = get-content -Path $storagescsv | ConvertFrom-Csv
    # load private endpoints csv
    $privateendpointscsv = Join-Path -Path "." -ChildPath "privateendpoints.csv" 
    $privateendpoints = get-content -Path $privateendpointscsv | ConvertFrom-Csv

    # create a list with private endpoints targeted services (service subscription/resoucegroup/type/name)
    $privateendpointsservices = @()
    foreach($privateendpoint in $privateendpoints) {
        $privateendpointsservices += "/subscriptions/$($privateendpoint.ServiceSubscriptionId)/resourceGroups/$($privateendpoint.ServiceResourceGroupName)/$($privateendpoint.ServiceProvider)/$($privateendpoint.ServiceName)"
    }

    # updqte webapps PublicNetworkAccess property:
    # storage accounts public network access needs to be explicitly enabled/disabled
    # https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal#about-virtual-network-endpoints
    # null would be default to allow public access
    foreach($storage in $storages) {
        if ([string]::IsNullOrWhiteSpace($storage.PublicNetworkAccess)) {
            $storage.PublicNetworkAccess = $true
        }
        if ($privateendpointsservices -contains "$($storage.ResourceGroupId)/$($storage.Type)/$($storage.Name)") {       
            $storage.HasPrivateEndpoint = $true
        } else {
            $storage.HasPrivateEndpoint = $false
        }
    }

    # export updated webapps to csv
    $storages | Export-Csv -Path $storagescsv -NoTypeInformation
}