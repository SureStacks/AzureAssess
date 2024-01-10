<#
.SYNOPSIS
    Update web apps collected with known private endpoints to determine if they are accessible from the internet
    When public internet access is neither enabled nor disabled ( PublicNetworkAccess = $null ), the web app will determine access in function of the presence of private endpoints
.EXAMPLE
    PS C:\Join-AzureAssessWebAppsPrivateEndpoints
#>

function Join-AzureAssessWebAppsPrivateEndpoints() {
    # TODO: put all file definition in main script
    # load web apps csv
    $webappscsv = Join-Path -Path "." -ChildPath "webapps.csv" 
    $webapps = get-content -Path $webappscsv | ConvertFrom-Csv
    # load private endpoints csv
    $privateendpointscsv = Join-Path -Path "." -ChildPath "privateendpoints.csv" 
    $privateendpoints = get-content -Path $privateendpointscsv | ConvertFrom-Csv

    # create a list with private endpoints targeted services (service subscription/resoucegroup/type/name)
    $privateendpointsservices = @()
    foreach($privateendpoint in $privateendpoints) {
        $privateendpointsservices += "/subscriptions/$($privateendpoint.ServiceSubscriptionId)/resourceGroups/$($privateendpoint.ServiceResourceGroupName)/$($privateendpoint.ServiceProvider)/$($privateendpoint.ServiceName)"
    }

    # updqte webapps PublicNetworkAccess property:
    # - if a matching private endpoint is found, set PublicNetworkAccess to Disabled*
    # - if no matching private endpoint is found, set PublicNetworkAccess to Enabled*
    # * https://learn.microsoft.com/en-us/answers/questions/684335/how-to-enable-disable-the-publicnetworkaccess-of-a
    foreach($webapp in $webapps) {
        if ($privateendpointsservices -contains "$($webapp.ResourceGroupId)/$($webapp.Type)/$($webapp.Name)") {
            if ([string]::IsNullOrWhiteSpace($webapp.PublicNetworkAccess)) {
                $webapp.PublicNetworkAccess = $false
            }
            $webapp.HasPrivateEndpoint = $true
        } else {
            if ([string]::IsNullOrWhiteSpace($webapp.PublicNetworkAccess)) {
                $webapp.PublicNetworkAccess = $true
            }
            $webapp.HasPrivateEndpoint = $false
        }
    }

    # export updated webapps to csv
    $webapps | Export-Csv -Path $webappscsv -NoTypeInformation
}