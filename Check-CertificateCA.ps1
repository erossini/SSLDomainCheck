<#
.SYNOPSIS
    Checks the TLS certificate chain of every URL in a list and flags chains issued by
    eMudhra / emSign CAs. Writes the results as a Markdown table.

.DESCRIPTION
    Works with Windows PowerShell 5.1 and PowerShell 7+ (Windows, macOS, Linux).
    The input file has one entry per line, with an optional service name after a pipe:
        https://api.example.com/path | Payments API
        api.example.com
        api.example.com:8443 | Admin portal
    Blank lines and lines starting with # are ignored.

.EXAMPLE
    .\Check-CertificateCA.ps1
    .\Check-CertificateCA.ps1 -InputFile .\urls.txt
    .\Check-CertificateCA.ps1 -InputFile .\urls.txt -OutputFile .\report.md -TimeoutSeconds 5
#>
[CmdletBinding()]
param(
    # Defaults to urls.txt in the current folder, or next to this script if not found there.
    [string]$InputFile = 'urls.txt',
    [string]$OutputFile = 'ca-report.md',
    [int]$TimeoutSeconds = 10,
    # Regex matched (case-insensitive) against the subject and issuer of every certificate in the chain.
    # Add the names of further intermediates from the incident advisory here if needed.
    [string]$AffectedPattern = 'emSign|eMudhra'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Target([string]$Entry) {
    $s = $Entry.Trim()
    if ($s -notmatch '^[a-z][a-z0-9+.-]*://') { $s = "https://$s" }
    $uri = [Uri]$s
    # An http:// URL with no explicit port is still checked on 443.
    $port = if ($uri.Scheme -eq 'http' -and $uri.IsDefaultPort) { 443 } else { $uri.Port }
    [pscustomobject]@{ Host = $uri.Host; Port = $port }
}

function Get-CN([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [bool]$Issuer) {
    # SimpleName returns the CN, falling back to OU / O when there is no CN.
    $Cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $Issuer)
}

function Get-CertChain([string]$HostName, [int]$Port, [int]$TimeoutMs) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($HostName, $Port).Wait($TimeoutMs)) { throw 'connection timed out' }
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs

        $script:capturedChain = $null
        # Accept every certificate: we only want to inspect the chain, not enforce trust.
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            $certs = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
            if ($chain -and $chain.ChainElements.Count -gt 0) {
                foreach ($el in $chain.ChainElements) {
                    $certs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $el.Certificate))
                }
            } else {
                $certs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate))
            }
            $script:capturedChain = $certs
            return $true
        }

        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, $callback
        try { $ssl.AuthenticateAsClient($HostName) } finally { $ssl.Dispose() }

        if (-not $script:capturedChain) { throw 'no certificate received' }
        return $script:capturedChain
    } finally {
        $client.Dispose()
    }
}

function Escape-Md([string]$Text) { ($Text -replace '\|', '\|') -replace '[\r\n]+', ' ' }

if (-not (Test-Path -LiteralPath $InputFile) -and -not [IO.Path]::IsPathRooted($InputFile)) {
    $candidate = Join-Path $PSScriptRoot $InputFile
    if (Test-Path -LiteralPath $candidate) { $InputFile = $candidate }
}
if (-not (Test-Path -LiteralPath $InputFile)) { throw "Input file not found: $InputFile" }

$entries = Get-Content -LiteralPath $InputFile |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') }

$rows = New-Object System.Collections.Generic.List[string]
$affectedCount = 0
$errorCount = 0

foreach ($entry in $entries) {
    # Optional service name after a pipe: "https://pypi.org/simple/ | PyPI"
    $parts = $entry -split '\|', 2
    $target = $parts[0].Trim()
    $service = if ($parts.Count -gt 1 -and $parts[1].Trim()) { $parts[1].Trim() } else { '-' }
    $domain = $target
    try {
        $t = Get-Target $target
        $domain = if ($t.Port -eq 443) { $t.Host } else { "$($t.Host):$($t.Port)" }
        Write-Host "Checking $domain ... " -NoNewline

        $chain = @(Get-CertChain -HostName $t.Host -Port $t.Port -TimeoutMs ($TimeoutSeconds * 1000))
        $leaf = $chain[0]
        $top = $chain[-1]

        $issuingCa = Get-CN $leaf $true
        # If the top certificate is self-signed it is the root; otherwise the root is its issuer.
        $rootCa = if ($top.Subject -eq $top.Issuer) { Get-CN $top $false } else { Get-CN $top $true }

        # Only CA names matter: every issuer, plus the subject of every non-leaf certificate.
        # (The leaf subject is the site itself, e.g. *.emsign.com, which is not a CA.)
        $hits = for ($i = 0; $i -lt $chain.Count; $i++) {
            $c = $chain[$i]
            if ($i -gt 0 -and $c.Subject -match $AffectedPattern) { Get-CN $c $false }
            if ($c.Issuer -match $AffectedPattern) { Get-CN $c $true }
        }
        $hits = @($hits | Select-Object -Unique)

        if ($hits.Count -gt 0) {
            $affectedCount++
            $status = "**YES** ($($hits -join ', '))"
            Write-Host 'AFFECTED' -ForegroundColor Red
        } else {
            $status = 'No'
            Write-Host 'ok' -ForegroundColor Green
        }
        $rows.Add("| $(Escape-Md $service) | $(Escape-Md $domain) | $(Escape-Md $issuingCa) | $(Escape-Md $rootCa) | $(Escape-Md $status) |")
    } catch {
        $errorCount++
        $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Host "ERROR: $msg" -ForegroundColor Yellow
        $rows.Add("| $(Escape-Md $service) | $(Escape-Md $domain) | - | - | ERROR: $(Escape-Md $msg) |")
    }
}

$report = @(
    '# TLS Certificate CA Report'
    ''
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  "
    "Affected pattern: ``$AffectedPattern``  "
    "Checked: $($entries.Count) - Affected: $affectedCount - Errors: $errorCount"
    ''
    '| Service | Domain | Issuing CA | Root CA | Affected (eMudhra / emSign) |'
    '|---|---|---|---|---|'
) + $rows

$report | Set-Content -LiteralPath $OutputFile -Encoding UTF8
Write-Host "`nReport written to $OutputFile"
