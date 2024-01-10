<#
.SYNOPSIS
    Join endpoints to ressources globaly
#>

function Join-AzureAssessPrivateEndpoints {
    Join-AzureAssessKeyvaultsPrivateEndpoints
    Join-AzureAssessSQLServersPrivateEndpoints
    Join-AzureAssessStoragesPrivateEndpoints
    Join-AzureAssessWebAppsPrivateEndpoints
}