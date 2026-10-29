<#
.SYNOPSIS
    Diagnoses connectivity from this machine to the Ent platform.

.DESCRIPTION
    Runs, in order: system/proxy info, DNS resolution, TCP connect, TLS handshake,
    and an unauthenticated GET to <url>/health (the same endpoint the agent uses
    for its platform health check). Prints a hint for each failed stage.

.PARAMETER Address
    Platform hostname or IP (the "address" field of a server entry in the agent config).

.PARAMETER Port
    Platform port. Defaults to 443 (same default as the agent).

.PARAMETER ConfigJson
    Optional path to an agent config JSON; Address/Port are read from servers[0].

.PARAMETER TimeoutSec
    Per-stage timeout in seconds. Default 5 (matches the agent health check).

.EXAMPLE
    .\Test-PlatformConnectivity.ps1 -Address platform.example.com
    .\Test-PlatformConnectivity.ps1 -ConfigJson .\test_config.json
#>
[CmdletBinding()]
param(
    [string]$Address,
    [int]$Port = 0,
    [string]$ConfigJson,
    [int]$TimeoutSec = 5
)

$ErrorActionPreference = 'Stop'

if ($ConfigJson) {
    $cfg = Get-Content -Raw -Path $ConfigJson | ConvertFrom-Json
    $server = $cfg.servers[0]
    if (-not $Address) { $Address = $server.address }
    if ($Port -eq 0 -and $server.port) { $Port = [int]$server.port }
}
if (-not $Address) {
    throw "Specify -Address or -ConfigJson."
}
if ($Port -eq 0) { $Port = 443 }

$script:failed = $false

function Write-Result([string]$Stage, [bool]$Ok, [string]$Detail) {
    $tag = if ($Ok) { '[ PASS ]' } else { '[ FAIL ]' }
    $color = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host $tag -ForegroundColor $color -NoNewline
    Write-Host " $Stage - $Detail"
    if (-not $Ok) { $script:failed = $true }
}

function Write-Hint([string]$Text) {
    Write-Host "         hint: $Text" -ForegroundColor Yellow
}

Write-Host "Platform connectivity check: ${Address}:${Port}"
Write-Host "Host: $env:COMPUTERNAME  User: $env:USERNAME  Time: $((Get-Date).ToString('s'))"
Write-Host ''

# --- Proxy / environment ---------------------------------------------------
try {
    $winhttp = (netsh winhttp show proxy) -join ' '
    $winhttp = ($winhttp -replace '\s+', ' ').Trim()
    Write-Host "WinHTTP proxy: $winhttp"
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ie -and $ie.ProxyEnable) {
        Write-Host "User (WinINET) proxy: $($ie.ProxyServer)"
    }
} catch {
    Write-Host "Proxy info unavailable: $($_.Exception.Message)"
}
Write-Host ''

# --- 1. DNS ------------------------------------------------------------------
$ip = $null
$parsed = $null
if ([System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) {
    $ip = $parsed
    Write-Result 'DNS' $true "$Address is an IP literal, skipping resolution"
} else {
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Address)
        $ip = ($addrs | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1)
        if (-not $ip) { $ip = $addrs[0] }
        Write-Result 'DNS' $true "$Address -> $(($addrs | ForEach-Object { $_.ToString() }) -join ', ')"
    } catch {
        Write-Result 'DNS' $false $_.Exception.Message
        Write-Hint 'Check the address for typos, the adapter DNS servers (ipconfig /all), and VPN/split-DNS.'
        try {
            $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 |
                Where-Object { $_.ServerAddresses } |
                ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ',')" }
            Write-Host "         DNS servers: $($dnsServers -join ' | ')"
        } catch { }
    }
}

# --- 2. TCP ------------------------------------------------------------------
if ($ip) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $task = $tcp.ConnectAsync($ip, $Port)
        if (-not $task.Wait($TimeoutSec * 1000)) {
            throw "timed out after ${TimeoutSec}s"
        }
        $sw.Stop()
        Write-Result 'TCP' $true "connected to ${ip}:${Port} in $($sw.ElapsedMilliseconds) ms (local $($tcp.Client.LocalEndPoint))"
    } catch {
        $msg = $_.Exception.InnerException
        if (-not $msg) { $msg = $_.Exception }
        Write-Result 'TCP' $false "${ip}:${Port} - $($msg.Message)"
        Write-Hint 'Timeout usually means a firewall drop; "actively refused" means nothing is listening on that port.'
    }

    # --- 3. TLS ----------------------------------------------------------------
    if ($tcp.Connected) {
        try {
            $validationErrors = [System.Net.Security.SslPolicyErrors]::None
            $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
                param($s, $cert, $chain, $errors)
                $script:validationErrors = $errors
                $true
            }
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
            $ssl.ReadTimeout = $TimeoutSec * 1000
            $ssl.WriteTimeout = $TimeoutSec * 1000
            $ssl.AuthenticateAsClient($Address)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            Write-Result 'TLS' $true "$($ssl.SslProtocol), subject '$($cert.Subject)', expires $($cert.NotAfter.ToString('yyyy-MM-dd'))"
            Write-Host "         issuer: $($cert.Issuer)"
            if ($script:validationErrors -ne 'None') {
                Write-Host "         certificate validation: $($script:validationErrors) (the agent only tolerates this when disableSslVerification is set)" -ForegroundColor Yellow
            } else {
                Write-Host '         certificate validation: trusted by this machine'
            }
            if ($cert.NotAfter -lt (Get-Date)) {
                Write-Host '         server certificate is EXPIRED' -ForegroundColor Red
            }
            $ssl.Dispose()
        } catch {
            Write-Result 'TLS' $false $_.Exception.Message
            Write-Hint 'Port may be plain HTTP, or a TLS-inspecting proxy / old TLS version is in the way.'
        }
    }
    $tcp.Dispose()
}

# --- 4. HTTPS /health --------------------------------------------------------
if ($ip) {
    $url = "https://${Address}:${Port}/health"
    $handler = $null
    $client = $null
    try {
        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        # The agent does not verify the server cert on /health, so neither do we.
        $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $resp = $client.GetAsync($url).GetAwaiter().GetResult()
        $sw.Stop()
        $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($body.Length -gt 300) { $body = $body.Substring(0, 300) + '...' }
        $code = [int]$resp.StatusCode
        $ok = ($code -ge 200 -and $code -lt 300)
        Write-Result 'HEALTH' $ok "GET $url -> $code $($resp.ReasonPhrase) in $($sw.ElapsedMilliseconds) ms"
        if ($body) { Write-Host "         body: $body" }
        if (-not $ok) {
            Write-Hint '5xx/502/503 from a load balancer means the platform service behind it is down or unhealthy; 407 means an authenticating proxy.'
        }
    } catch {
        $msg = $_.Exception
        while ($msg.InnerException) { $msg = $msg.InnerException }
        Write-Result 'HEALTH' $false "GET $url - $($msg.Message)"
    } finally {
        if ($client) { $client.Dispose() }
        if ($handler) { $handler.Dispose() }
    }
}

Write-Host ''
if ($script:failed) {
    Write-Host 'Result: one or more checks FAILED' -ForegroundColor Red
    exit 1
}
Write-Host 'Result: all checks passed' -ForegroundColor Green
exit 0
