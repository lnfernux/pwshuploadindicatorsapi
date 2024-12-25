<#
.SYNOPSIS
Creates a new header for Upload Indicators API with the provided token.

.DESCRIPTION
The New-UploadIndicatorsAPIHeader function generates a header for the Upload Indicators API using the provided token. 
It converts the secure string token to plain text and constructs the header with the Authorization and Content-Type fields.

.PARAMETER token
The secure string token to be used for authorization.

.RETURNS
A hashtable containing the headers for the API request.

.EXAMPLE
$token = Connect-UploadIndicatorsAPI -ClientID "your-client-id" -ClientSecret "your-client-secret" -TenantID "your-tenant-id"
$headers = New-UploadIndicatorsAPIHeader -token $token
Invoke-RestMethod -Uri "https://api.example.com/upload" -Headers $headers -Method Post

.NOTES
Ensure that the token is securely handled and not exposed in plain text unnecessarily.
#>
function New-UploadIndicatorsAPIHeader {
    param(
        [Parameter(Mandatory = $true)]
        $token
    )
    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($($token.Token))
    try {
        $plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
        # Perform operations with the contents of $plaintext in this section.
        $Headers = @{
            "Authorization" = "Bearer $($plainText)"
            "Content-Type" = "application/json"
        }
        return $Headers
    } finally {
        # The following line ensures that sensitive data is not left in memory.
        $plainText = [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
    }
}