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
        $DaysToExpireURL = 365,
        $Confidence,
        $SourceSystem = "pwshuploadindicatorsapi"
    )
    $indicators = @()
    # Set labels from the event - labels should be a list of strings
    $labels = @()
    foreach($tag in $MISPEvent.EventTag) {
        $labels += $tag.Tag.Name.TrimStart()
    }
    # Check event for confidence tag
    foreach($tag in $labels) {
        if($tag -eq 'misp:confidence-level="completely-confident"') {
            $Confidence = 100
        } elseif ($tag -eq 'misp:confidence-level="usually-confident"') {
            $Confidence = 75
        } elseif ($tag -eq 'misp:confidence-level="confidence-cannot-be-evaluated"') {
            $Confidence = 50
        } elseif ($tag -eq 'misp:confidence-level="fairly-confident"') {
            $Confidence = 50
        } elseif ($tag -eq 'misp:confidence-level="rarely-confident"') {
            $Confidence = 25
        } elseif($tag -eq 'misp:confidence-level="unconfident"') {
            $Confidence = 0
        } else {
            # Default confidence level
            if(!$Confidence) {
                $Confidence = 50
            }
        }
    }
    # Set severity level from the event tags
    foreach($tag in $labels) {
        if($tag -like '*misp:threat-level="high-risk"*') {
            $Severity = 100
        } elseif ($tag -like '*misp:threat-level="medium-risk"*') {
            $Severity = 50
        } elseif ($tag -like '*misp:threat-level="low-risk"*') {
            $Severity = 25
        } elseif($tag -like '*misp:threat-level="no-risk"*') {
            $Severity = 0
        }
        elseif (-not $Severity) {
            # Default severity level
            $Severity = $null
        }
    }
    # Set indicatorstypes from the severity and confidence tags
    $indicator_types = @()
    if($Severity -eq 100) {
        $indicator_types += "threatstream-severity-high"
    } elseif ($Severity -eq 50) {
        $indicator_types += "threatstream-severity-medium"
    } elseif ($Severity -eq 25) {
        $indicator_types += "threatstream-severity-low"
    } elseif ($Severity -eq 0) {
        $indicator_types += "threatstream-severity-none"
    }
    if($Confidence -eq 100) {
        $indicator_types += "threatstream-confidence-100"
    } elseif ($Confidence -eq 75) {
        $indicator_types += "threatstream-confidence-75"
    } elseif ($Confidence -eq 50) {
        $indicator_types += "threatstream-confidence-50"
    } elseif ($Confidence -eq 25) {
        $indicator_types += "threatstream-confidence-25"
    } elseif ($Confidence -eq 0) {
        $indicator_types += "threatstream-confidence-0"
    }
    foreach ($attribute in $MISPAttributes) {
        # Set the correct expiration date based on the attribute type
        if($attribute.type -eq "ip-src" -or $attribute.type -eq "ip-dst") {
            $daysToExpire = $DaysToExpireIPV4
        }
        elseif($attribute.type -eq "ipv6-src" -or $attribute.type -eq "ipv6-dst") {
            $daysToExpire = $DaysToExpireIPV6
        }
        elseif($attribute.type -eq "domain") {
            $daysToExpire = $DaysToExpireDomain
        }
        elseif($attribute.type -eq "url") {
            $daysToExpire = $DaysToExpireURL
        }
        else {
            $daysToExpire = $DaysToExpire
        }
        # Set the created timestamp 
        $created_timestamp = [System.DateTimeOffset]::FromUnixTimeSeconds($attribute.timestamp).DateTime
        
        $indicator = @{
            type = "indicator"
            spec_version = "2.1"
            id = "indicator--$($attribute.uuid)"
            name = $MISPEvent.info
            description = $attribute.comment
            created = (Get-Date($created_timestamp)).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            modified = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            pattern = "[ipv4-addr:value = '$($attribute.value)']"
            pattern_type = "stix"
            valid_from = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            valid_until = (Get-Date).AddDays($daysToExpire).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            labels = $labels
            confidence = $Confidence
            indicator_types = $indicator_types
        }
        $indicators += $indicator
    }

    $output = @{
        sourcesystem = $SourceSystem
        indicators = $indicators
    }

    return $output | ConvertTo-Json -Depth 10
}