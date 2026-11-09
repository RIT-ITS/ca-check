#!/usr/bin/env pwsh
# Usage: ./cacheck.ps1 HOST [PORT]
# Prints one row per IP and certificate. Exit code: 0 pass, 1 warn, 2 fail, 3 request failed.
param(
    [Parameter(Mandatory = $true)][string]$HostName,
    [int]$Port = 0,
    [string]$Server = $(if ($env:CACHECK_URL) { $env:CACHECK_URL } else { 'https://this-server' })
)
$ErrorActionPreference = 'Stop'
$rank = @{ pass = 0; info = 1; warn = 2; fail = 3 }

function Get-Problems($analysis) {
    @($analysis.checks | Where-Object { $_.status -in 'warn', 'fail' } |
        ForEach-Object { "$($_.id) ($($_.status))" }) -join ', '
}

$body = @{ host = $HostName; port = $Port } | ConvertTo-Json
try {
    $r = Invoke-RestMethod -Method Post -Uri "$Server/api/check" -ContentType 'application/json' -Body $body -TimeoutSec 180
} catch {
    $msg = $_.Exception.Message
    if ($_.ErrorDetails.Message) {
        $msg = $_.ErrorDetails.Message
        try { $msg = ($msg | ConvertFrom-Json).error } catch { }
    }
    [Console]::Error.WriteLine("Request failed: $msg")
    exit 3
}

$rows = [System.Collections.Generic.List[object]]::new()
$rows.Add(@('IP', 'KEY', 'TLS', 'RESULT', 'PROBLEMS'))
foreach ($ip in $r.results) {
    if ($ip.analysis) {
        $result = $ip.analysis.overall
        $problems = Get-Problems $ip.analysis
    } else {
        $result = $ip.overall
        $problems = "$($ip.error)$($ip.denyReason)"
    }
    $key = if ($ip.keyType) { $ip.keyType } else { '-' }
    $tls = if ($ip.tls) { $ip.tls.version } else { '-' }
    $rows.Add(@($ip.ip, $key, $tls, $result, $problems))
    if ($ip.alternate) {
        $alt = $ip.alternate
        $rows.Add(@($ip.ip, $alt.keyType, $alt.tls.version, $alt.overall, (Get-Problems $alt.analysis)))
    }
}

# Pad the first four columns to their widest value, like the bash and Python versions.
$widths = foreach ($i in 0..3) { ($rows | ForEach-Object { "$($_[$i])".Length } | Measure-Object -Maximum).Maximum }
foreach ($row in $rows) {
    $line = (0..3 | ForEach-Object { "$($row[$_])".PadRight($widths[$_] + 2) }) -join ''
    ($line + $row[4]).TrimEnd()
}
''

$overall = 'pass'
$statuses = @($r.results | ForEach-Object { $_.overall })
if ($r.consistency) {
    if ($r.consistency.status -in 'warn', 'fail') { $statuses += $r.consistency.status }
    "Consistency: $($r.consistency.status). $($r.consistency.detail)"
}
foreach ($s in $statuses) { if ($rank[$s] -gt $rank[$overall]) { $overall = $s } }
"Overall: $overall"
if ($overall -eq 'fail') { exit 2 }
if ($overall -eq 'warn') { exit 1 }
exit 0
