
# pwshuploadindicatorsapi                                                                                      

This function is for interacting with the Upload Indicators API for Microsoft Sentinel. The idea is to make it easier to upload indicators using this API. 

## Installation

```powershell
Install-Module -Name pwshuploadindicatorsapi
```

## Usage

Assumes you have created an application registration in Entra ID and have the necessary permissions to interact with the API, which is the [`Microsoft Sentinel Contibutor`](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#microsoft-sentinel-contributor) role on the relevant workspace.

### Setting the variables

```powershell
#Import the module
Import-Module pwshuploadindicatorsapi

# Set the variables needed for the function
$tenantId = "yourtenantid"
$clientId = "yourclientid"
$clientSecret = "yourclientsecret"
$workspaceId = "yourworkspaceid"
```

### Pushing indicators to Microsoft Sentinel

*Note*: This example assumes that you have already installed the [`pwshmisp`](https://www.powershellgallery.com/packages/pwshmisp) module and have an event with attributes that you want to push to Microsoft Sentinel.

```powershell
# First, get an event from MISP
$MISPEvent = Get-MISPEvent -MISPAuthHeader $MISPAuthHeader -MISPUrl $MISPUrl -MISPOrg "ORGNAME" -MISPEventName "Test Event 666" -SelfSigned

# Second, get the attributes from the event
$attributes = Get-MISPAttributeFromEvent -MISPUrl $MISPUrl -MISPAuthHeader $MISPAuthHeader -EventID $MISPEvent.id -SelfSigned

# Third, convert the attributes to a format that can be used with the `pwshuploadindicatorsapi` module
$indicators = ConvertTo-UploadIndicatorsAPIFormat -MISPAttributes $attributes.Attribute -MISPEvent $MISPEvent

# Fourth, push the indicators to Microsoft Sentinel
$token = Connect-UploadIndicatorsAPI -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
Push-IndicatorsToSentinel -WorkspaceId $workspaceId -Indicators $indicators -Token $token
```

## Functions

### Connect-UploadIndicatorsAPI

This function is used to connect to the Upload Indicators API. The application registration referenced by the client id and client secret must have the appropriate permissions to interact with the API, which is the [`Microsoft Sentinel Contibutor`](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#microsoft-sentinel-contributor) role on the relevant workspace.

It will output a `$token` object that can be used to authenticate with the API.

```powershell
$token = Connect-UploadIndicatorsAPI -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
```

### New-UploadIndicatorsAPIHeader

This function is used to create the headers needed to interact with the Upload Indicators API. It requires the `$token` object from the `Connect-UploadIndicatorsAPI` function.

```powershell
$headers = New-UploadIndicatorsAPIHeader -Token $token
```

### Push-IndicatorsToSentinel

This function is used to push indicators to Microsoft Sentinel. It requires the `$token` object from the `Connect-UploadIndicatorsAPI` function. It takes a json-formatted string of indicators as input (it uses `UploadIndicatorsAPIHeader` to create the correct header), see the /Example folder for such a sample file.

```powershell
$indicators = Get-Content -Path .\Example\indicators.json 
Push-IndicatorsToSentinel -token $token -WorkspaceId $workspaceId -Indicators $indicators
```

### ConvertTo-UploadIndicatorsAPIFormat

Function for converting output from the `pwshmisp` module to a format that can be used with the `pwshuploadindicatorsapi` module.

```powershell
# First, get an event from MISP
$MISPEvent = Get-MISPEvent -MISPAuthHeader $MISPAuthHeader -MISPUrl $MISPUrl -MISPOrg "ORGNAME" -MISPEventName "Test Event 666" -SelfSigned
$MISPEvent

id                  : 1780
org_id              : 1
date                : 2024-12-23
info                : Test Event 666
uuid                : 1d3264c4-55ca-4300-a19f-e97e9c2cb103
published           : False
analysis            : 0
attribute_count     : 1
orgc_id             : 1
timestamp           : 1734961044
distribution        : 3
sharing_group_id    : 0
proposal_email_lock : False
locked              : False
threat_level_id     : 4
publish_timestamp   : 0
sighting_timestamp  : 0
disable_correlation : False
extends_uuid        : 
protected           : 
Org                 : @{id=1; name=ORGNAME; uuid=987c32b5-be32-4ad8-9ccc-a1dee70fe473}
Orgc                : @{id=1; name=ORGNAME; uuid=987c32b5-be32-4ad8-9ccc-a1dee70fe473}
EventTag            : {@{id=7966; event_id=1780; tag_id=1108; local=False; relationship_type=; Tag=}, @{id=7967; event_id=1780; tag_id=1137; local=False; relationship_type=; Tag=}}

# Second, get the attributes from the event
$attributes = Get-MISPAttributeFromEvent -MISPUrl $MISPUrl -MISPAuthHeader $MISPAuthHeader -EventID $MISPEvent.id -SelfSigned
$attributes.Attribute

id                  : 312469
event_id            : 1780
object_id           : 0
object_relation     : 
category            : Payload delivery
type                : text
to_ids              : False
uuid                : d29f1e3a-d8ac-4a7c-b148-3bec5ed25a45
timestamp           : 1734961044
distribution        : 5
sharing_group_id    : 0
comment             : This is a test attribute
deleted             : False
disable_correlation : False
first_seen          : 
last_seen           : 
value               : malware
Event               : @{org_id=1; distribution=3; publish_timestamp=0; id=1780; info=Test Event 666; orgc_id=1; uuid=1d3264c4-55ca-4300-a19f-e97e9c2cb103}

# Third, convert the attributes to a format that can be used with the `pwshuploadindicatorsapi` module
$indicators = ConvertTo-UploadIndicatorsAPIFormat -MISPAttributes $attributes.Attribute -MISPEvent $MISPEvent
```

You can also use the `Invoke-MISPEventSearch`-function, which will return both event and attribute information.

```powershell
$MISPData = Invoke-MISPEventSearch -MISPUrl $MISPUrl -MISPAuthHeader $MISPAUthHeader -Filter $Filter -SelfSigned
$indicators = @()
foreach($event in $MISPData.response) {
    $indicators += ConvertTo-UploadIndicatorsAPIFormat -MISPAttributes $event.Event.Attribute -MISPEvent $event.Event
}
$indicatorsObject = $indicators | ConvertFrom-Json -Depth 10
$token = Connect-UploadIndicatorsAPI -ClientID $ApplicationId -ClientSecret $ApplicationSecret -TenantID $TenantId
$uploadindicatorheaders = New-UploadIndicatorsAPIHeader -Token $token
foreach($indicator in $indicatorsObject) {
    Push-IndicatorsToSentinel -token $token -WorkspaceId $WorkspaceId -Indicators $indicator -SourceSystem "mysourcesystem"
}
```

## Updates

### March 2025

Updated to v1.0.2:
- Add support for the `SourceSystem` parameter in the `Push-IndicatorsToSentinel` function. 
- Added the `-UploadIndicatorsAPI` parameter to the `ConvertTo-UploadIndicatorsAPIFormat` and `Push-IndicatorsToSentinel` functions to support the new Stix Object API. The functions now default to the new API, but can be changed to the old API by calling the `-UploadIndicatorsAPI`.

## Known issues

- The module is still in development and may contain bugs. Please report any issues you encounter.
- The module does not have proper error handling. This will be added in future versions, first priority is to add rate limiting handling.

## Contributing

Pull requests are welcome. 
