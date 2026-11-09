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

$rows = foreach ($ip in $r.results) {
    if ($ip.analysis) {
        $result = $ip.analysis.overall
        $problems = Get-Problems $ip.analysis
    } else {
        $result = $ip.overall
        $problems = "$($ip.error)$($ip.denyReason)"
    }
    [pscustomobject]@{ IP = $ip.ip; Key = $(if ($ip.keyType) { $ip.keyType } else { '-' }); TLS = $(if ($ip.tls) { $ip.tls.version } else { '-' }); Result = $result; Problems = $problems }
    if ($ip.alternate) {
        $alt = $ip.alternate
        [pscustomobject]@{ IP = $ip.ip; Key = $alt.keyType; TLS = $alt.tls.version; Result = $alt.overall; Problems = Get-Problems $alt.analysis }
    }
}
($rows | Format-Table -AutoSize -Wrap | Out-String -Width 200).Trim()
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
