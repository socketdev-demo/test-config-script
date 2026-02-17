# generate-and-validate-config.ps1
# Fetches routes from Artifactory, generates simplified nginx location blocks,
# and validates for issues. Use to debug config generation errors locally.
#
# Usage:
#   .\generate-and-validate-config.ps1 -ApiUrl https://artifactory.company.com -AuthToken <token>
#   .\generate-and-validate-config.ps1 -ApiUrl https://artifactory.company.com -AuthToken "user:pass"
#   .\generate-and-validate-config.ps1 -ApiUrl https://artifactory.company.com -AuthToken <token> -UpstreamFqdn artifactory.company.com

param(
    [Parameter(Mandatory=$true, HelpMessage="Artifactory base URL (e.g., https://artifactory.company.com)")]
    [string]$ApiUrl,
    
    [Parameter(Mandatory=$true, HelpMessage="API token or username:password")]
    [string]$AuthToken,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "path-routing-preview.conf",
    
    [Parameter(Mandatory=$false)]
    [string]$UpstreamFqdn = "",
    
    [Parameter(Mandatory=$false)]
    [string]$RewriteScheme = "https",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = "sfw.company.com",
    
    [Parameter(Mandatory=$false)]
    [int]$HttpPort = 8080,
    
    [Parameter(Mandatory=$false)]
    [int]$HttpsPort = 8443,
    
    [Parameter(Mandatory=$false)]
    [string]$IncludePattern = ".*",
    
    [Parameter(Mandatory=$false)]
    [string]$ExcludePattern = "^$",
    
    [Parameter(Mandatory=$false)]
    [switch]$IgnoreSslErrors
)

$ErrorActionPreference = 'Stop'

# --- Nginx-unsafe characters (will break location directives) ---
$InvalidPathChars = @(' ', "`t", '{', '}', ';', '#', '"', "'")

function Test-NginxPath {
    param([string]$Path)
    if (-not $Path -or -not $Path.StartsWith('/')) { return $false }
    foreach ($c in $InvalidPathChars) {
        if ($Path.Contains($c)) { return $false }
    }
    return $true
}

function Get-InvalidChars {
    param([string]$Path)
    $found = @()
    foreach ($c in $InvalidPathChars) {
        if ($Path.Contains($c)) {
            $found += switch ($c) {
                ' '    { 'SPACE' }
                "`t"   { 'TAB' }
                default { $c }
            }
        }
    }
    return $found -join ', '
}

# --- Ecosystem mapping (matches Python ArtifactoryClient) ---
$EcosystemMap = @{
    'maven'  = 'maven'
    'npm'    = 'npm'
    'pypi'   = 'pypi'
    'cargo'  = 'cargo'
    'gems'   = 'rubygems'
    'go'     = 'go'
    'nuget'  = 'nuget'
}

# --- SSL handling ---
if ($IgnoreSslErrors) {
    Write-Host "WARNING: SSL certificate verification disabled" -ForegroundColor Yellow
    # For PowerShell 7+
    $PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
    # For PowerShell 5.1
    if ($PSVersionTable.PSVersion.Major -le 5) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
}

# --- Authentication ---
$headers = @{ 'Content-Type' = 'application/json' }
if ($AuthToken.Contains(':')) {
    Write-Host "Auth: Basic (username:password)"
    $cred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthToken))
    $headers['Authorization'] = "Basic $cred"
} else {
    Write-Host "Auth: API Token"
    $headers['X-JFrog-Art-Api'] = $AuthToken
}

# --- Fetch repositories ---
$repoUrl = "$($ApiUrl.TrimEnd('/'))/api/repositories"
Write-Host "Fetching repositories from: $repoUrl"

try {
    $repos = Invoke-RestMethod -Uri $repoUrl -Headers $headers -Method Get
    Write-Host "Found $($repos.Count) repositories" -ForegroundColor Green
} catch {
    Write-Error "Failed to fetch repositories: $_"
    exit 1
}

# --- Generate routes (same logic as Python ArtifactoryClient) ---
$routes = @()
$skippedUnsupported = 0
$skippedFiltered = 0
$invalidPaths = @()

foreach ($repo in $repos) {
    $repoKey = $repo.key
    $repoType = $repo.type
    $packageType = $repo.packageType.ToLower()
    $repoUrlField = $repo.url

    # Filter by type
    if ($repoType -notin @('VIRTUAL', 'REMOTE', 'LOCAL')) { continue }

    # Apply include/exclude patterns
    if ($repoKey -notmatch $IncludePattern) { $skippedFiltered++; continue }
    if ($ExcludePattern -ne '^$' -and $repoKey -match $ExcludePattern) { $skippedFiltered++; continue }

    # Map ecosystem
    $registry = $EcosystemMap[$packageType]
    if (-not $registry) { $registry = 'passthrough'; $skippedUnsupported++ }

    # Determine path (from repo URL or construct from key)
    if ($repoUrlField) {
        $urlNoScheme = $repoUrlField -replace '^https?://', ''
        if ($urlNoScheme.Contains('/')) {
            $parts = $urlNoScheme.Split('/', 2)
            $path = '/' + $parts[1]
        } else {
            $path = "/artifactory/$repoKey"
        }
    } else {
        $path = "/artifactory/$repoKey"
    }
    $path = $path.TrimEnd('/')

    # Determine upstream
    if ($UpstreamFqdn) {
        $upstream = "$RewriteScheme`://$UpstreamFqdn$path"
    } else {
        if ($repoUrlField) {
            $upstream = $repoUrlField
        } else {
            $upHost = ($ApiUrl -replace '^https?://', '').Split('/')[0]
            $upstream = "$RewriteScheme`://$upHost$path"
        }
    }

    # Determine needs_rewrite
    $upstreamNoScheme = $upstream -replace '^https?://', ''
    if ($upstreamNoScheme.Contains('/')) {
        $upstreamPathComponent = '/' + ($upstreamNoScheme.Split('/', 2)[1])
        $needsRewrite = ($upstreamPathComponent -ne $path)
    } else {
        $needsRewrite = $true
    }

    # Validate path
    $isValid = Test-NginxPath $path
    if (-not $isValid) {
        $badChars = Get-InvalidChars $path
        $invalidPaths += [PSCustomObject]@{
            Path = $path
            RepoKey = $repoKey
            InvalidChars = $badChars
        }
    }

    $routes += [PSCustomObject]@{
        Path = $path
        Upstream = $upstream
        Registry = $registry
        NeedsRewrite = $needsRewrite
        IsValid = $isValid
        RepoKey = $repoKey
    }
}

# --- Report ---
Write-Host ""
Write-Host "=== ROUTE SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total routes:        $($routes.Count)"
Write-Host "Valid routes:        $(($routes | Where-Object { $_.IsValid }).Count)" -ForegroundColor Green
Write-Host "Invalid routes:      $($invalidPaths.Count)" -ForegroundColor $(if ($invalidPaths.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Passthrough (unsupported): $skippedUnsupported"
Write-Host "Filtered out:        $skippedFiltered"
Write-Host ""

if ($invalidPaths.Count -gt 0) {
    Write-Host "=== INVALID PATHS (will be skipped by config generator) ===" -ForegroundColor Red
    foreach ($inv in $invalidPaths) {
        Write-Host "  INVALID: $($inv.Path)" -ForegroundColor Red
        Write-Host "    Repo:  $($inv.RepoKey)" -ForegroundColor Yellow
        Write-Host "    Chars: $($inv.InvalidChars)" -ForegroundColor Yellow
    }
    Write-Host ""
}

# --- Generate nginx config preview ---
$lineNum = 1
$config = [System.Text.StringBuilder]::new()

function Add-Line {
    param([string]$Line)
    $script:lineNum++
    [void]$config.AppendLine($line)
}

# Header
Add-Line "# Auto-generated path-routing.conf preview"
Add-Line "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Line "# Routes: $($routes.Count) total, $(($routes | Where-Object { $_.IsValid }).Count) valid"
Add-Line "# Source: $ApiUrl"
Add-Line ""
Add-Line "server {"
Add-Line "    listen $HttpPort;"
Add-Line "    listen $HttpsPort ssl;"
Add-Line "    server_name $Domain;"
Add-Line ""

$routeLineMap = @{}

foreach ($r in ($routes | Where-Object { $_.IsValid })) {
    $path = $r.Path
    $upstream = $r.Upstream
    $registry = $r.Registry
    $needsRewrite = $r.NeedsRewrite
    
    $routeStartLine = $lineNum + 1  # +1 because Add-Line increments after

    # Generate rewrite rules
    $rewriteBlock = ""
    if ($needsRewrite) {
        $rewriteBlock = @"
        rewrite ^$path`$ / break;
        rewrite ^$path(/.*)`$ `$1 break;
"@
    }

    # Registry-specific location blocks
    switch ($registry) {
        'npm' {
            Add-Line "    location $path {"
            Add-Line "        set `$backend `"$($upstream -replace '^https?://', '')`";"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { npm_parser.proxy_default(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
        }
        'pypi' {
            Add-Line "    location = $path {"
            Add-Line "        return 302 $path/simple/;"
            Add-Line "    }"
            Add-Line ""
            Add-Line "    location $path/simple {"
            Add-Line "        set `$pypi_path_prefix `"$path`";"
            if ($needsRewrite) {
                Add-Line "        rewrite ^$path/simple`$ /simple/ break;"
                Add-Line "        rewrite ^$path/simple/`$ /simple/ break;"
                Add-Line "        rewrite ^$path/simple/(.+)`$ /simple/`$1 break;"
            }
            Add-Line "        content_by_lua_block { pypi_parser.proxy_simple_metadata(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
            Add-Line "    location $path/packages {"
            Add-Line "        content_by_lua_block { pypi_parser.proxy_package_download(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
        }
        'maven' {
            Add-Line "    location ~ ^$path/.*\.(jar|war|aar)`$ {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { maven_parser.proxy_artifact(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
            Add-Line "    location $path {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { maven_parser.proxy_default(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
        }
        'cargo' {
            Add-Line "    location ~ ^$path/api/v1/crates/.*/download`$ {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { cargo_parser.proxy_download(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
            Add-Line "    location $path {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { cargo_parser.proxy_default(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
        }
        'nuget' {
            Add-Line "    location ~ ^$path/.*\.nupkg`$ {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { nuget_parser.proxy_nupkg_download(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
            Add-Line "    location $path {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { nuget_parser.proxy_default(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
        }
        'go' {
            Add-Line "    location ~ ^$path/.*/@v/.*\.zip`$ {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { go_parser.proxy_download(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
            Add-Line "    location $path {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { go_parser.proxy_default(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
        }
        'rubygems' {
            Add-Line "    location $path/gems {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { rubygems_parser.proxy_gem_download(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
            Add-Line "    location $path {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        content_by_lua_block { rubygems_parser.proxy_default(`"$($upstream -replace '^https?://', '')`") }"
            Add-Line "    }"
            Add-Line ""
        }
        default {
            # passthrough / streaming
            Add-Line "    location $path {"
            if ($rewriteBlock) { Add-Line $rewriteBlock }
            Add-Line "        proxy_pass $upstream`$request_uri;"
            Add-Line "        proxy_ssl_server_name on;"
            Add-Line "    }"
            Add-Line ""
        }
    }

    $routeLineMap[$r.RepoKey] = @{ StartLine = $routeStartLine; Path = $path; Registry = $registry }
}

# Fallback location
Add-Line "    # Default - forward unmatched to upstream"
Add-Line "    location / {"
if ($UpstreamFqdn) {
    Add-Line "        proxy_pass $RewriteScheme`://$UpstreamFqdn`$request_uri;"
} else {
    Add-Line "        return 404;"
}
Add-Line "    }"
Add-Line "}"

# Write config
$config.ToString() | Out-File -FilePath $OutputFile -Encoding UTF8
$totalLines = $lineNum

Write-Host "=== CONFIG GENERATED ===" -ForegroundColor Cyan
Write-Host "Output file: $OutputFile"
Write-Host "Total lines: $totalLines"
Write-Host ""

# --- Find route at a specific line number (for debugging errors) ---
Write-Host "=== ROUTE LINE MAP ===" -ForegroundColor Cyan
Write-Host "Use this to find which route is at a specific line number:"
Write-Host ""
$sortedRoutes = $routeLineMap.GetEnumerator() | Sort-Object { $_.Value.StartLine }
foreach ($entry in $sortedRoutes) {
    $info = $entry.Value
    Write-Host ("  Line {0,5}: {1,-60} ({2})" -f $info.StartLine, $info.Path, $info.Registry)
}

Write-Host ""
Write-Host "=== QUICK LOOKUP ===" -ForegroundColor Cyan
Write-Host 'To find the route at a specific line (e.g., line 6822):'
Write-Host '  $content = Get-Content path-routing-preview.conf'
Write-Host '  $content[6820..6825]  # Show lines around 6822'
Write-Host ""

if ($invalidPaths.Count -gt 0) {
    Write-Host "WARNING: $($invalidPaths.Count) routes have invalid paths and would cause nginx errors!" -ForegroundColor Red
    Write-Host "These routes are EXCLUDED from the generated config." -ForegroundColor Yellow
    Write-Host "Fix the repository names in Artifactory or add them to exclude_pattern." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
