<#
.SYNOPSIS
    Converts MISP event and attributes to Upload Indicators API format.

.DESCRIPTION
    This function takes a MISP event and its attributes and converts them into a format suitable for the Upload Indicators API. 
    It generates indicators with specific expiration dates based on the type of attribute.

.PARAMETER MISPEvent
    The MISP event object containing event details.

.PARAMETER MISPAttributes
    The list of MISP attributes associated with the event.

.PARAMETER DaysToExpire
    The default number of days until the indicator expires. Default is 50 days.

.PARAMETER DaysToExpireStart
    The start date for the expiration period. Default is the current date.

.PARAMETER DaysToExpireIPV4
    The number of days until an IPv4 indicator expires. Default is 180 days.

.PARAMETER DaysToExpireIPV6
    The number of days until an IPv6 indicator expires. Default is 180 days.

.PARAMETER DaysToExpireDomain
    The number of days until a domain indicator expires. Default is 180 days.

.PARAMETER DaysToExpireURL
    The number of days until a URL indicator expires. Default is 365 days.

.RETURNS
    A JSON string representing the converted indicators in the Upload Indicators API format.

.EXAMPLE
    $MISPEvent = Get-MISPEvent -EventId 123
    $MISPAttributes = Get-MISPAttributes -EventId 123
    $result = ConvertTo-UploadIndicatorsAPIFormat -MISPEvent $MISPEvent -MISPAttributes $MISPAttributes
    Write-Output $result

.NOTES
    This function assumes that the MISP attributes contain a 'uuid' and 'value' property.
#>


function ConvertTo-UploadIndicatorsAPIFormat {
    param(
        [Parameter(Mandatory = $true)]
        $MISPEvent,
        [Parameter(Mandatory = $true)]
        $MISPAttributes,
        $DaysToExpire = 50,
        $DaysToExpireStart = (Get-Date).ToString("yyyy-MM-dd"),
        $DaysToExpireIPV4 = 180,
        $DaysToExpireIPV6 = 180,
        $DaysToExpireDomain = 180,
        $DaysToExpireURL = 365
    )
    $indicators = @()

    foreach ($attribute in $MISPAttributes) {
        $indicator = @{
            type = "indicator"
            spec_version = "2.1"
            id = "indicator--$($attribute.uuid)"
            name = $MISPEvent.info
            created = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            modified = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            pattern = "[ipv4-addr:value = '$($attribute.value)']"
            pattern_type = "stix"
            valid_from = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        $indicators += $indicator
    }

    $output = @{
        sourcesystem = "test_2"
        indicators = $indicators
    }

    return $output | ConvertTo-Json -Depth 10
}