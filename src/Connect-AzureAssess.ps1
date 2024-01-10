<#
.SYNOPSIS
    Connects to Azure to run the assessment
.EXAMPLE
    PS C:\Connect-AzureAssesss
#>

function Connect-AzureAssess() {
    # flag for good conneciton
    $valid = $false
    # check context
    $context = get-azcontext
    if ($context) {
        # check token
        $token = Get-AzAccessToken
        if ($token) {
            # check token expiration
            if ($token.ExpiresOn -lt (Get-Date).AddMinutes(-5)) {
                $valid = $true
            }
        }
    }
    if (!$valid) {
        # connect to azure
        Connect-AzAccount
    }
}