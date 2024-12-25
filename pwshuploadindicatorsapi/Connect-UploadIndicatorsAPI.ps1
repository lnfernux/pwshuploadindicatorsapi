<#
.SYNOPSIS
    Connects to the Upload Indicators API using Azure Service Principal credentials.

.DESCRIPTION
    This function authenticates to the Azure environment using the provided Client ID, Client Secret, and Tenant ID.
    It returns an access token that can be used to interact with the Upload Indicators API.

.PARAMETER ClientID
    The Client ID of the Azure Service Principal.

.PARAMETER ClientSecret
    The Client Secret of the Azure Service Principal.

.PARAMETER TenantID
    The Tenant ID of the Azure Active Directory.

.RETURNS
    A secure string containing the access token.

.EXAMPLE
    $token = Connect-UploadIndicatorsAPI -ClientID "your-client-id" -ClientSecret "your-client-secret" -TenantID "your-tenant-id"
    Write-Output $token

.NOTES
    Ensure that the Azure PowerShell module is installed and imported before running this function.
#>
function Connect-UploadIndicatorsAPI {
    param (
        [Parameter(Mandatory = $true)]
        $ClientID,
        [Parameter(Mandatory = $true)]
        $ClientSecret,
        [Parameter(Mandatory = $true)]
        $TenantID
    )
    $SecurePassword = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientID, $SecurePassword
    Connect-AzAccount -Credential $Credential -TenantId $TenantID -ServicePrincipal
    $token = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString
    return $token
}
