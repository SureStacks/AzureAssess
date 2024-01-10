<#
.SYNOPSIS
    Update keyvaults collected with known private endpoints to determine if they are accessible from the internet
    When public internet access is neither enabled nor disabled ( PublicNetworkAccess = $null ), the web app will determine access in function of the presence of private endpoints
.EXAMPLE
    PS C:\Join-AzureAssessKeyvaultsPrivateEndpoints
#>

function Join-AzureAssessKeyvaultsPrivateEndpoints() {
    # TODO: put all file definition in main script
    # load web apps csv
    $keyvaultscsv = Join-Path -Path "." -ChildPath "keyvaults.csv" 
    $keyvaults = get-content -Path $keyvaultscsv | ConvertFrom-Csv
    # load private endpoints csv
    $privateendpointscsv = Join-Path -Path "." -ChildPath "privateendpoints.csv" 
    $privateendpoints = get-content -Path $privateendpointscsv | ConvertFrom-Csv

    # create a list with private endpoints targeted services (service subscription/resoucegroup/type/name)
    $privateendpointsservices = @()
    foreach($privateendpoint in $privateendpoints) {
        $privateendpointsservices += "/subscriptions/$($privateendpoint.ServiceSubscriptionId)/resourceGroups/$($privateendpoint.ServiceResourceGroupName)/$($privateendpoint.ServiceProvider)/$($privateendpoint.ServiceName)"
    }

    # updqte keyvault PublicNetworkAccess property:
    # https://learn.microsoft.com/en-us/answers/questions/1023805/why-ceating-private-endpoint-in-existing-key-vault
    # the presence of private endpoint doesn't influence public network access
    # null value would mean the default where public access is allowed
    foreach($keyvault in $keyvaults) {
        if([string]::IsNullOrWhiteSpace($keyvault.PublicNetworkAccess)) {
            $keyvault.PublicNetworkAccess = $true
        }
        if ($privateendpointsservices -contains "$($keyvault.ResourceGroupId)/$($keyvault.Type)/$($keyvault.Name)") {
            $keyvault.HasPrivateEndpoint = $true
        } else {
            $keyvault.HasPrivateEndpoint = $false
        }
    }

    # export updated webapps to csv
    $keyvaults | Export-Csv -Path $keyvaultscsv -NoTypeInformation
}