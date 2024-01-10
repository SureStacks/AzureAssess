<#
<#
.SYNOPSIS
    Update sql severs collected with known private endpoints to determine if they are accessible from the internet
    When public internet access is neither enabled nor disabled ( PublicNetworkAccess = $null ), the web app will determine access in function of the presence of private endpoints
.EXAMPLE
    PS C:\Join-AzureAssessSQLServersPrivateEndpoints
#>

function Join-AzureAssessSQLServersPrivateEndpoints() {
    # TODO: put all file definition in main script
    # load web apps csv
    $sqlserverscsv = Join-Path -Path "." -ChildPath "sqlservers.csv" 
    $sqlservers = get-content -Path $sqlserverscsv | ConvertFrom-Csv
    # load private endpoints csv
    $privateendpointscsv = Join-Path -Path "." -ChildPath "privateendpoints.csv" 
    $privateendpoints = get-content -Path $privateendpointscsv | ConvertFrom-Csv

    # create a list with private endpoints targeted services (service subscription/resoucegroup/type/name)
    $privateendpointsservices = @()
    foreach($privateendpoint in $privateendpoints) {
        $privateendpointsservices += "/subscriptions/$($privateendpoint.ServiceSubscriptionId)/resourceGroups/$($privateendpoint.ServiceResourceGroupName)/$($privateendpoint.ServiceProvider)/$($privateendpoint.ServiceName)"
    }

    # update sql servers PublicNetworkAccess property:
    # https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql&tabs=azure-portal
    # null means that public network access is disabled
    foreach($sqlserver in $sqlservers) {
        if ([string]::IsNullOrWhiteSpace($sqlserver.PublicNetworkAccess)) {
            $sqlserver.PublicNetworkAccess = $false
        }
        if ($privateendpointsservices -contains "$($sqlserver.ResourceGroupId)/$($sqlserver.Type)/$($sqlserver.Name)") {
            $sqlserver.HasPrivateEndpoint = $true
        } else {
            $sqlserver.HasPrivateEndpoint = $false
        }
    }

    # export updated webapps to csv
    $sqlservers | Export-Csv -Path $sqlserverscsv -NoTypeInformation
}
#>