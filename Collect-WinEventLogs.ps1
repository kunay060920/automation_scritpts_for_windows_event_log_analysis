# Collecting windows event logs

[CmdletBinding()]
param(
    [string]   $OutputPath = 'EventLogCollection',
    [int]      $Hours = 24,
    [datetime] $StartTime,
    [datetime] $EndTime = (Get-Date),
    [string[]] $Channels,
    [ValidateSet('EVTX', 'JSONL', 'CSV', 'All')]
    [string]   $Format = 'All',
    [int]      $MaxEventsPerChannel = 50000,
    [switch]   $NoHash
)

$ErrorActionPreference = 'Stop'

# ------------------------------------- defaults ------------------------------

if (-not $Channels) {
    $Channels = @(
        'Security',
        'System',
        'Application',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-PowerShell/Operational',
        'Windows PowerShell',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WinRM/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    )
}

if (-not $PSBoundParameters.ContainsKey('StartTime')) {
    $StartTime = $EndTime.AddHours(-[Math]::Abs($Hours))
}
if ($StartTime -ge $EndTime) {
    throw "StartTime ($StartTime) must be earlier than EndTime ($EndTime)."
}

# ------------------------------- helpers ------------------------------------

function Write-Log {
    param(
        [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')]
        [string] $Level = 'INFO'
    )
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = "[$stamp] [$Level] $Message"
    $colour = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $colour
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 }
}

function Get-SafeName {
    param([string] $Name)
    ($Name -replace '[\\/:*?"<>|\s]', '-') -replace '-+', '-'
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal] $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Flattens <EventData><Data Name="X">v</Data></EventData> into a hashtable.
function ConvertFrom-EventXml {
    param([System.Diagnostics.Eventing.Reader.EventRecord] $Record)

    $data = @{}
    try {
        $xml = [xml] $Record.ToXml()

        foreach ($node in @($xml.Event.EventData.Data)) {
            if (-not $node) { continue }
            $key = if ($node.Name) { [string] $node.Name } else { 'Data' }
            $val = if ($node.'#text') { [string] $node.'#text' } else { [string] $node.InnerText }
            if ($data.ContainsKey($key)) {
                $data[$key] = @($data[$key]) + $val   # duplicate names -> array
            } else {
                $data[$key] = $val
            }
        }

        # Some providers (e.g. WMI-Activity) use UserData instead.
        if ($data.Count -eq 0 -and $xml.Event.UserData) {
            foreach ($child in $xml.Event.UserData.ChildNodes) {
                foreach ($leaf in $child.ChildNodes) {
                    $data[$leaf.LocalName] = [string] $leaf.InnerText
                }
            }
        }
    } catch {
        $data['_XmlParseError'] = $_.Exception.Message
    }
    return $data
}

function ConvertTo-NormalisedEvent {
    param([System.Diagnostics.Eventing.Reader.EventRecord] $Record)

    [ordered] @{
        TimeCreated  = $Record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
        RecordId     = $Record.RecordId
        EventId      = $Record.Id
        Channel      = $Record.LogName
        Provider     = $Record.ProviderName
        Level        = $Record.LevelDisplayName
        Task         = $Record.TaskDisplayName
        Opcode       = $Record.OpcodeDisplayName
        Computer     = $Record.MachineName
        UserSid      = if ($Record.UserId) { $Record.UserId.Value } else { $null }
        ProcessId    = $Record.ProcessId
        ThreadId     = $Record.ThreadId
        Keywords     = @($Record.KeywordsDisplayNames)
        Message      = $Record.Message
        EventData    = (ConvertFrom-EventXml -Record $Record)
    }
}

# --------------------------------- setup ------------------------------------

# A relative OutputPath is anchored to the script's own folder (falling back to
# the current directory if the script is being run from a pasted block, where
# $PSScriptRoot is empty).
if ([System.IO.Path]::IsPathRooted($OutputPath)) {
    $rootPath = $OutputPath
} else {
    $anchor   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $rootPath = Join-Path $anchor $OutputPath
}

# Collapse any '.' / '..' segments into a canonical absolute path. This is not
# cosmetic: the StreamWriter below and the Substring() call in the manifest
# section both need a full path, and .NET resolves relative paths against the
# process working directory, which is not always PowerShell's location.
$rootPath = [System.IO.Path]::GetFullPath($rootPath)

$runStamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$caseRoot  = Join-Path $rootPath "$($env:COMPUTERNAME)_$runStamp"
$evtxDir   = Join-Path $caseRoot 'evtx'
$jsonDir   = Join-Path $caseRoot 'jsonl'
$csvDir    = Join-Path $caseRoot 'csv'

foreach ($dir in @($caseRoot, $evtxDir, $jsonDir, $csvDir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$script:LogFile = Join-Path $caseRoot 'collection.log'

Write-Log "Collection root : $caseRoot"
Write-Log ("Window          : {0:yyyy-MM-dd HH:mm:ss} -> {1:yyyy-MM-dd HH:mm:ss} (local)" -f $StartTime, $EndTime)
Write-Log "Channels        : $($Channels.Count) requested"
Write-Log "Format          : $Format"

if (-not (Test-IsAdmin)) {
    Write-Log 'Not running elevated - Security channel and EVTX export will likely fail.' 'WARN'
}

# XPath fragment used by wevtutil (UTC, per the schema).
$utcStart = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$utcEnd   = $EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$xPath    = "*[System[TimeCreated[@SystemTime>='$utcStart' and @SystemTime<='$utcEnd']]]"

$results = New-Object System.Collections.Generic.List[object]

# --------------------------------- collection -------------------------------

foreach ($channel in $Channels) {

    Write-Log "--- $channel"
    $safe   = Get-SafeName $channel
    $record = [ordered] @{
        Channel      = $channel
        Present      = $false
        EventCount   = 0
        EvtxFile     = $null
        JsonlFile    = $null
        CsvFile      = $null
        Errors       = @()
    }

    # 1. Does the channel exist on this host?
    try {
        $logInfo = Get-WinEvent -ListLog $channel -ErrorAction Stop
        $record.Present   = $true
        $record.IsEnabled = $logInfo.IsEnabled
        if (-not $logInfo.IsEnabled) {
            Write-Log "Channel exists but is disabled." 'WARN'
        }
    } catch {
        Write-Log "Channel not present on this host - skipping." 'WARN'
        $record.Errors += 'Channel not found'
        $results.Add([pscustomobject] $record)
        continue
    }

    # 2. Raw EVTX export.
    if ($Format -in @('EVTX', 'All')) {
        $evtxPath = Join-Path $evtxDir "$safe.evtx"
        try {
            $null = & wevtutil.exe epl "$channel" "$evtxPath" "/q:$xPath" /ow:true 2>&1
            if ($LASTEXITCODE -ne 0) { throw "wevtutil exited with code $LASTEXITCODE" }
            if (Test-Path $evtxPath) {
                $record.EvtxFile = $evtxPath
                Write-Log "EVTX  -> $([IO.Path]::GetFileName($evtxPath))" 'OK'
            }
        } catch {
            Write-Log "EVTX export failed: $($_.Exception.Message)" 'ERROR'
            $record.Errors += "EVTX: $($_.Exception.Message)"
        }
    }

    # 3. Structured export.
    if ($Format -in @('JSONL', 'CSV', 'All')) {

        $filter = @{
            LogName   = $channel
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $events = @()
        try {
            $events = Get-WinEvent -FilterHashtable $filter `
                                   -MaxEvents $MaxEventsPerChannel `
                                   -ErrorAction Stop
        } catch [Exception] {
            if ($_.Exception.Message -match 'No events were found') {
                Write-Log 'No events in the requested window.'
            } else {
                Write-Log "Read failed: $($_.Exception.Message)" 'ERROR'
                $record.Errors += "Read: $($_.Exception.Message)"
            }
        }

        $events = @($events)
        $record.EventCount = $events.Count

        if ($events.Count -gt 0) {
            $normalised = foreach ($e in $events) { ConvertTo-NormalisedEvent -Record $e }

            if ($Format -in @('JSONL', 'All')) {
                $jsonlPath = Join-Path $jsonDir "$safe.jsonl"
                $writer = New-Object System.IO.StreamWriter($jsonlPath, $false,
                                                            (New-Object System.Text.UTF8Encoding($false)))
                try {
                    foreach ($n in $normalised) {
                        $writer.WriteLine((ConvertTo-Json $n -Depth 6 -Compress))
                    }
                } finally {
                    $writer.Dispose()
                }
                $record.JsonlFile = $jsonlPath
                Write-Log "JSONL -> $([IO.Path]::GetFileName($jsonlPath))  ($($events.Count) events)" 'OK'
            }

            if ($Format -in @('CSV', 'All')) {
                $csvPath = Join-Path $csvDir "$safe.csv"
                $normalised |
                    ForEach-Object {
                        [pscustomobject] @{
                            TimeCreated = $_.TimeCreated
                            RecordId    = $_.RecordId
                            EventId     = $_.EventId
                            Channel     = $_.Channel
                            Provider    = $_.Provider
                            Level       = $_.Level
                            Computer    = $_.Computer
                            UserSid     = $_.UserSid
                            EventData   = (ConvertTo-Json $_.EventData -Depth 4 -Compress)
                            Message     = ($_.Message -replace '\r?\n', ' ')
                        }
                    } |
                    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                $record.CsvFile = $csvPath
                Write-Log "CSV   -> $([IO.Path]::GetFileName($csvPath))" 'OK'
            }

            if ($events.Count -eq $MaxEventsPerChannel) {
                Write-Log "Hit MaxEventsPerChannel ($MaxEventsPerChannel) - results are truncated." 'WARN'
                $record.Errors += 'Truncated at MaxEventsPerChannel'
            }
        }
    }

    $results.Add([pscustomobject] $record)
}

# ------------------------------------ manifest ------------------------------

$fileHashes = @()
if (-not $NoHash) {
    Write-Log 'Hashing output files (SHA-256)...'
    $fileHashes = Get-ChildItem -Path $caseRoot -Recurse -File |
        Where-Object { $_.Name -notin @('manifest.json', 'collection.log') } |
        ForEach-Object {
            [pscustomobject] @{
                Path      = $_.FullName.Substring($caseRoot.Length + 1)
                SizeBytes = $_.Length
                SHA256    = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
            }
        }
}

$manifest = [ordered] @{
    CollectionId      = "$($env:COMPUTERNAME)_$runStamp"
    CollectedAtUtc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    CollectedBy       = "$($env:USERDOMAIN)\$($env:USERNAME)"
    Elevated          = (Test-IsAdmin)
    Hostname          = $env:COMPUTERNAME
    OperatingSystem   = (Get-CimInstance Win32_OperatingSystem).Caption
    OSBuild           = [string] [Environment]::OSVersion.Version
    TimeZone          = (Get-TimeZone).Id
    WindowStartUtc    = $utcStart
    WindowEndUtc      = $utcEnd
    Format            = $Format
    MaxEventsPerChannel = $MaxEventsPerChannel
    ToolVersion       = '1.0.0'
    Channels          = $results
    Files             = $fileHashes
}

$manifestPath = Join-Path $caseRoot 'manifest.json'
ConvertTo-Json $manifest -Depth 8 | Set-Content -Path $manifestPath -Encoding UTF8

# ------------------------------------- summary ------------------------------

$totalEvents = ($results | Measure-Object -Property EventCount -Sum).Sum
$collected   = @($results | Where-Object { $_.Present }).Count

Write-Log '======================================================'
Write-Log "Channels collected : $collected / $($Channels.Count)"
Write-Log "Total events       : $totalEvents"
Write-Log "Manifest           : $manifestPath"
Write-Log '======================================================' 'OK'

# Out-Host is deliberate: Format-Table emits formatting objects into the
# success stream, which would contaminate the return value below.
$results | Format-Table Channel, Present, EventCount -AutoSize | Out-Host

# The log is hashed last, into a sidecar, because it is still being appended to
# while the manifest is being built - hashing it inline guaranteed a permanent
# false mismatch. Nothing may write to the log after this point.
if (-not $NoHash) {
    $logHash = (Get-FileHash -Path $script:LogFile -Algorithm SHA256).Hash
    Set-Content -Path "$($script:LogFile).sha256" `
                -Value "$logHash *collection.log" -Encoding UTF8
}

# Return the case folder so the script can be chained into a pipeline.
return $caseRoot