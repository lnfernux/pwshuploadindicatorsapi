$pwshuploadindicatorsapi  = @(Get-ChildItem -Path $PSScriptRoot\pwshuploadindicatorsapi\*.ps1 -ErrorAction SilentlyContinue)
foreach ($import in @($pwshuploadindicatorsapi))
{
    try
    {
        . $import.FullName
    }
    catch
    {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
    
}