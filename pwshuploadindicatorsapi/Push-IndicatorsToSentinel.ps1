
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
        $Indicators,
        [switch]$UploadIndicatorsAPI,
        [string]$SourceSystem = "pwshuploadindicatorsapi"
    )
    $header = New-UploadIndicatorsAPIHeader -token $token
    # Upload Indicators API
    if($UploadIndicatorsAPI) {
        $uri = "https://sentinelus.azure-api.net/workspaces/$WorkspaceId/threatintelligenceindicators:upload?api-version=2022-07-01"
    } else {
        $uri = "https://api.ti.sentinel.azure.com/workspaces/$WorkspaceId/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview"
    }
    # Split indicators into batches of 100
    $indicatorBatches = [System.Collections.ArrayList]::new()
    for ($i = 0; $i -lt $Indicators.stixobjects.Count; $i += 100) {
        $indicatorBatches.Add($Indicators.stixobjects[$i..[math]::Min($i + 99, $Indicators.stixobjects.Count - 1)])
    }

    foreach ($batch in $indicatorBatches) {
        # Ensure each indicator in the batch is a valid JSON object
        $validBatch = $batch | ForEach-Object {
            if ($_ -is [PSCustomObject]) {
                $_
            } else {
                ConvertFrom-Json $_
            }
        }

        $body = @{
            sourcesystem = "pwshuploadindicatorsapi"
            stixobjects = $validBatch
        } | ConvertTo-Json -Depth 10

        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $header -Body $body
        Write-Host "Batch of $($validBatch.Count) indicators pushed successfully."
    }
}

