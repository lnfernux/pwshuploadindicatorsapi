<#
.SYNOPSIS
    Converts a STIX attack pattern JSON file to a PowerShell object.

.DESCRIPTION
    This function takes a STIX attack pattern JSON file and converts it into a PowerShell object suitable for the Push-IndicatorsToSentinel function.

.PARAMETER StixAttackPatternJsonFile
    The path to the STIX attack pattern JSON file.

.RETURNS
    A PowerShell object representing the converted STIX attack pattern.

.EXAMPLE
    $result = ConvertFrom-StixAttackPattern -StixAttackPatternJsonFile "path\to\stixattackpattern.json"
    Write-Output $result

.NOTES
    This function assumes that the STIX attack pattern JSON file contains the necessary properties.
#>

function ConvertFrom-StixAttackPattern {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The path to the STIX attack pattern JSON file.")]
        [string]$StixAttackPatternJsonFile,
        $SourceSystem = "pwshuploadindicatorsapi"
    )

    # Read JSON file content
    $StixAttackPatternJson = Get-Content -Path $StixAttackPatternJsonFile -Raw

    # Convert JSON to PowerShell object
    $StixAttackPattern = $StixAttackPatternJson | ConvertFrom-Json

    # Create the PowerShell object
    $attackPattern = @{
        type = "attack-pattern"
        spec_version = "2.1"
        id = $StixAttackPattern.id
        created = $StixAttackPattern.created
        modified = $StixAttackPattern.modified
        created_by_ref = $StixAttackPattern.created_by_ref
        revoked = $StixAttackPattern.revoked
        labels = $StixAttackPattern.labels
        confidence = $StixAttackPattern.confidence
        lang = $StixAttackPattern.lang
        object_marking_refs = $StixAttackPattern.object_marking_refs
        granular_markings = $StixAttackPattern.granular_markings
        extensions = $StixAttackPattern.extensions
        external_references = $StixAttackPattern.external_references
        name = $StixAttackPattern.name
        description = $StixAttackPattern.description
        kill_chain_phases = $StixAttackPattern.kill_chain_phases
        aliases = $StixAttackPattern.aliases
    }

    # Create the output object
    $output = @{
        sourcesystem = $SourceSystem
        stixobjects = @($attackPattern)
    }

    return $output
}
