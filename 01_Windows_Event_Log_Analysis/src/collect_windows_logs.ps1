param(
    [int]$Days = 7
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$OutputDirectory = Join-Path $ProjectRoot "01_Windows_Event_Log_Analysis\sample_logs"

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$OutputFile = Join-Path $OutputDirectory "windows_security_logs.csv"

$StartTime = (Get-Date).AddDays(-$Days)

$EventIDs = @(
    4624,
    4625,
    4634,
    4648,
    4672,
    4688,
    4720,
    4728
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "     WINDOWS SECURITY LOG COLLECTOR"
Write-Host "========================================" -ForegroundColor Cyan

try {

    $Events = @(
        Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            ID = $EventIDs
            StartTime = $StartTime
        } -ErrorAction Stop
    )

    if ($Events.Count -eq 0) {
        Write-Host "No matching events found." -ForegroundColor Yellow
        exit 0
    }

    $Results = foreach ($Event in $Events) {

        [xml]$XML = $Event.ToXml()

        $Data = @{}

        foreach ($Item in $XML.Event.EventData.Data) {
            $Data[[string]$Item.Name] = [string]$Item.'#text'
        }

        [PSCustomObject]@{
            TimeCreated    = $Event.TimeCreated.ToString("o")
            Id             = $Event.Id
            Computer       = $Event.MachineName
            TargetUserName = $Data["TargetUserName"]
            IpAddress      = $Data["IpAddress"]
            Workstation    = $Data["WorkstationName"]
            LogonType      = $Data["LogonType"]
            ProcessName    = $Data["NewProcessName"]
            SubjectUser    = $Data["SubjectUserName"]
            MemberName     = $Data["MemberName"]
            Message        = ($Event.Message -replace "[\r\n]+", " ")
        }
    }

    $Results | Export-Csv `
        -Path $OutputFile `
        -NoTypeInformation `
        -Encoding UTF8

    Write-Host "`nCollection successful!" -ForegroundColor Green
    Write-Host "Events collected: $($Results.Count)"
    Write-Host "Output file: $OutputFile"

}
catch {

    Write-Host "`nCollection failed!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow

    exit 1
}