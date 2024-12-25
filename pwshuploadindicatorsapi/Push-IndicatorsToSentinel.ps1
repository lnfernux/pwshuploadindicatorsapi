
<#
.SYNOPSIS
    Pushes indicators to Microsoft Sentinel.

.DESCRIPTION
    This script uploads indicators to Microsoft Sentinel. It connects to the Sentinel workspace, formats the indicators, and pushes them to the Sentinel API.

.PARAMETER WorkspaceId
    The ID of the Sentinel workspace where the indicators will be uploaded.

.PARAMETER Token
    The token used to authenticate with the Sentinel API. From the Connect-UploadIndicatorsAPI function.

.PARAMETER Indicators
    A collection of indicators to be uploaded to Sentinel. Follows the Upload Indicators API schema - https://learn.microsoft.com/en-us/azure/sentinel/upload-indicators-api#request-body. 
    An example can be found in the Github repository for this function under /Examples/Indicator.json

.EXAMPLE
    PS C:\> $token = Connect-UploadIndicatorsAPI -ClientID "your-client-id" -ClientSecret "your-client-secret" -TenantID "your-tenant-id"
    PS C:\> Push-IndicatorsToSentinel.ps1 -WorkspaceId "your-workspace-id" -Token $token -Indicators $indicators

.INPUTS
    [string] - WorkspaceId
    [token] - Token
    [array] - Indicators

#>
function Push-IndicatorsToSentinel {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,
        [Parameter(Mandatory = $true)]
        $token,
        [Parameter(Mandatory = $true)]
        [array]$Indicators
    )
    $header = New-UploadIndicatorsAPIHeader -token $token
    $uri = "https://sentinelus.azure-api.net/workspaces/$WorkspaceId/threatintelligenceindicators:upload?api-version=2022-07-01"
    $indicator = $indicators | ConvertFrom-Json

    # Validate required properties
    $requiredProperties = @("id", "type", "labels", "pattern", "valid_from", "created", "modified")
    foreach($property in $requiredProperties) {
        if(-not $indicator.PSObject.Properties.Value.$property) {
            throw "Property $property is required"
        }
    }
    $body = $indicator | ConvertTo-Json -depth 50
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $header -Body $body
    return $response
}

