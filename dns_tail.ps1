param(
    [Parameter(Mandatory = $true)][string]$OutCsv,
    [int]$PollSeconds = 2,
    [int]$MaxEvents = 1000
)

$ErrorActionPreference = 'Continue'
$log = 'Microsoft-Windows-DNS-Client/Operational'
$want = @(3006, 3008)
$stateFile = "$OutCsv.watermark"
$errFile = "$OutCsv.err"

function Write-Err([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Add-Content -LiteralPath $errFile -Value $line -Encoding UTF8
}

$water = 0L
if (Test-Path -LiteralPath $stateFile) {
    $raw = (Get-Content -LiteralPath $stateFile -Raw).Trim()
    [void][int64]::TryParse($raw, [ref]$water)
}

$needHeader = $true
if (Test-Path -LiteralPath $OutCsv) {
    if ((Get-Item -LiteralPath $OutCsv).Length -gt 0) { $needHeader = $false }
}

$enc = [Text.UTF8Encoding]::new($true)
$writer = $null

try {
    $dir = Split-Path -Parent $OutCsv
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $writer = [IO.StreamWriter]::new($OutCsv, $true, $enc)
    if ($needHeader) {
        $writer.WriteLine('ts,event,domain,qtype,server,rcode')
        $writer.Flush()
    }
} catch {
    Write-Err "Не удалось открыть CSV: $($_.Exception.Message)"
    exit 1
}

$idle = 0
while ($true) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $want } -MaxEvents $MaxEvents -ErrorAction Stop |
                Where-Object { $_.RecordId -gt $water }
    } catch {
        $idle++
        if ($idle -gt 30) { Write-Err "События не читаются: $($_.Exception.Message)"; exit 2 }
        Start-Sleep -Seconds ([Math]::Min(30, $PollSeconds * $idle))
        continue
    }

    if (-not $evts) {
        Start-Sleep -Seconds $PollSeconds
        continue
    }

    $idle = 0
    foreach ($e in $evts) {
        try {
            $xml = [xml]$e.ToXml()
            $d = @{}
            foreach ($n in $xml.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }

            $ts = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            $domain = ($d['QueryName'] -replace '\s+', ' ')
            $qtype = $d['QueryType']
            $server = $d['ServerList']
            $rcode = $d['QueryStatus']

            $q = '"' + ($domain -replace '"', '""') + '"'
            $s = '"' + (($server -replace '\s+', ' ') -replace '"', '""') + '"'
            $writer.WriteLine(('{0},{1},{2},"{3}",{4}' -f $ts, $e.Id, $q, $qtype, $s))
            $water = $e.RecordId
        } catch {
            continue
        }
    }

    $writer.Flush()
    Set-Content -LiteralPath $stateFile -Value $water -Encoding ascii
    Start-Sleep -Milliseconds 300
}
