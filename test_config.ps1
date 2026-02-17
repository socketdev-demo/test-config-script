# windows-generate-config.ps1
# Fetches repository list from Artifactory API, validates paths, deduplicates routes,
# and generates both a routes YAML file and an nginx config preview for debugging.
#
# Usage:
#   .\windows-generate-config.ps1 -FQDN https://artifactory.company.com/artifactory -AuthToken <token>
#   .\windows-generate-config.ps1 -FQDN https://artifactory.company.com/artifactory -AuthToken "user:pass" -UpstreamFqdn artifactory.company.com
#   .\windows-generate-config.ps1 -FQDN https://artifactory.company.com/artifactory -AuthToken <token> -IgnoreSslErrors

param(
    [Parameter(Mandatory=$true, HelpMessage="Artifactory base URL (e.g., https://mycompany.jfrog.io/artifactory)")]
    [string]$FQDN,
    
    [Parameter(Mandatory=$true, HelpMessage="API token or username:password")]
    [string]$AuthToken,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "artifactory-routes.yml",
    
    [Parameter(Mandatory=$false)]
    [string]$NginxPreviewFile = "path-routing-preview.conf",
    
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

# ============================================================================
# Path Validation — matches Python validate_nginx_path()
# Characters that break nginx config syntax in location directives
# ============================================================================
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

# ============================================================================
# Ecosystem Mapping — matches Python ARTIFACTORY_PACKAGE_TYPE_MAP
# ============================================================================
$EcosystemMap = @{
    'maven'  = 'maven'
    'npm'    = 'npm'
    'pypi'   = 'pypi'
    'cargo'  = 'cargo'
    'gems'   = 'rubygems'
    'go'     = 'go'
    'nuget'  = 'nuget'
}

# ============================================================================
# SSL Configuration
# ============================================================================
if ($IgnoreSslErrors) {
    Write-Host "WARNING: SSL certificate verification disabled" -ForegroundColor Yellow
    # PowerShell 7+
    $PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
    # PowerShell 5.1
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

# ============================================================================
# Authentication
# ============================================================================
$headers = @{ 'Content-Type' = 'application/json' }
if ($AuthToken.Contains(':')) {
    Write-Host "Auth: Basic (username:password)"
    $cred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthToken))
    $headers['Authorization'] = "Basic $cred"
} else {
    Write-Host "Auth: API Token"
    $headers['X-JFrog-Art-Api'] = $AuthToken
}

# ============================================================================
# Fetch Repositories
# ============================================================================
$repoUrl = "$($FQDN.TrimEnd('/'))/api/repositories"
Write-Host "Fetching repositories from: $repoUrl"
Write-Host "Include pattern: $IncludePattern"
Write-Host "Exclude pattern: $ExcludePattern"
Write-Host ""

try {
    $response = Invoke-RestMethod -Uri $repoUrl -Headers $headers -Method Get
    Write-Host "Found $($response.Count) repositories" -ForegroundColor Green
} catch {
    Write-Error "Failed to fetch repositories: $_"
    exit 1
}

# ============================================================================
# Generate Routes — matches Python ArtifactoryClient.generate_routes()
# With path validation + deduplication
# ============================================================================
$allRoutes = @()
$skippedUnsupported = 0
$skippedFiltered = 0
$invalidPaths = @()
$seenPaths = @{}  # path -> index in $allRoutes for deduplication
$skippedDuplicates = 0

foreach ($repo in $response) {
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

    # Validate path for nginx-safe characters
    $isValid = Test-NginxPath $path
    if (-not $isValid) {
        $badChars = Get-InvalidChars $path
        $invalidPaths += [PSCustomObject]@{
            Path = $path
            RepoKey = $repoKey
            InvalidChars = $badChars
        }
        continue  # Skip invalid paths entirely
    }

    # Determine upstream
    if ($UpstreamFqdn) {
        $upstream = "$RewriteScheme`://$UpstreamFqdn$path"
    } else {
        if ($repoUrlField) {
            $upstream = $repoUrlField
        } else {
            $upHost = ($FQDN -replace '^https?://', '').Split('/')[0]
            $upstream = "$RewriteScheme`://$upHost$path"
        }
    }

    # Determine needs_rewrite
    $upstreamNoScheme = $upstream -replace '^https?://', ''
    if ($upstreamNoScheme.Contains('/')) {
        $upstreamPathComponent = '/' + ($upstreamNoScheme.Split('/', 2)[1]).TrimEnd('/')
        $needsRewrite = ($upstreamPathComponent -ne $path)
    } else {
        $needsRewrite = $true
    }

    # Deduplicate: prefer security-checked registries over passthrough
    if ($seenPaths.ContainsKey($path)) {
        $existingIdx = $seenPaths[$path]
        $existingRoute = $allRoutes[$existingIdx]
        if ($existingRoute.Registry -eq 'passthrough' -and $registry -ne 'passthrough') {
            # Upgrade passthrough to real registry
            Write-Verbose "Upgrading $path from passthrough to $registry (repo=$repoKey)"
            $allRoutes[$existingIdx] = [PSCustomObject]@{
                Path = $path
                Upstream = $upstream
                Registry = $registry
                NeedsRewrite = $needsRewrite
                RepoKey = $repoKey
            }
        } else {
            $skippedDuplicates++
            Write-Verbose "Duplicate skipped: $path ($registry) from repo=$repoKey"
        }
        continue
    }

    $seenPaths[$path] = $allRoutes.Count
    $allRoutes += [PSCustomObject]@{
        Path = $path
        Upstream = $upstream
        Registry = $registry
        NeedsRewrite = $needsRewrite
        RepoKey = $repoKey
    }
}

# ============================================================================
# Summary Report
# ============================================================================
Write-Host ""
Write-Host "=== ROUTE SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total repos fetched: $($response.Count)"
Write-Host "Unique routes:       $($allRoutes.Count)" -ForegroundColor Green
Write-Host "  Security-checked:  $(($allRoutes | Where-Object { $_.Registry -ne 'passthrough' }).Count)" -ForegroundColor Green
Write-Host "  Passthrough:       $(($allRoutes | Where-Object { $_.Registry -eq 'passthrough' }).Count)"
Write-Host "Duplicates removed:  $skippedDuplicates" -ForegroundColor Yellow
Write-Host "Invalid paths:       $($invalidPaths.Count)" -ForegroundColor $(if ($invalidPaths.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Unsupported types:   $skippedUnsupported (mapped to passthrough)"
Write-Host "Filtered out:        $skippedFiltered"
Write-Host ""

if ($invalidPaths.Count -gt 0) {
    Write-Host "=== INVALID PATHS (skipped) ===" -ForegroundColor Red
    foreach ($inv in $invalidPaths) {
        Write-Host "  INVALID: '$($inv.Path)'" -ForegroundColor Red
        Write-Host "    Repo:  $($inv.RepoKey)" -ForegroundColor Yellow
        Write-Host "    Chars: $($inv.InvalidChars)" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($allRoutes.Count -eq 0) {
    Write-Warning "No valid routes generated from Artifactory repositories"
    exit 1
}

# ============================================================================
# Registry Breakdown
# ============================================================================
Write-Host "=== REGISTRY BREAKDOWN ===" -ForegroundColor Cyan
$allRoutes | Group-Object Registry | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("  {0,-15} {1,4} routes" -f $_.Name, $_.Count)
}
Write-Host ""

# ============================================================================
# Generate Routes YAML (for socket.yml routes_file)
# ============================================================================
$yamlRoutes = @()
foreach ($r in $allRoutes) {
    $yamlRoutes += "- path: $($r.Path)"
    $yamlRoutes += "  upstream: $($r.Upstream)"
    $yamlRoutes += "  registry: $($r.Registry)"
    $yamlRoutes += ''
}
$yamlRoutes -join "`r`n" | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "Routes YAML written to: $OutputFile" -ForegroundColor Green

# ============================================================================
# Generate Nginx Config Preview (for debugging)
# ============================================================================
$lineNum = 0
$config = [System.Text.StringBuilder]::new()

function Add-Line {
    param([string]$Line)
    $script:lineNum++
    [void]$config.AppendLine($line)
}

Add-Line "# Auto-generated path-routing.conf preview"
Add-Line "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Line "# Unique routes: $($allRoutes.Count) (from $($response.Count) repos, $skippedDuplicates duplicates removed)"
Add-Line "# Source: $FQDN"
Add-Line ""
Add-Line "server {"
Add-Line "    listen $HttpPort;"
Add-Line "    listen $HttpsPort ssl;"
Add-Line "    server_name $Domain;"
Add-Line ""

$routeLineMap = @{}

foreach ($r in $allRoutes) {
    $path = $r.Path
    $upstream = $r.Upstream
    $registry = $r.Registry
    $needsRewrite = $r.NeedsRewrite
    
    $routeStartLine = $lineNum + 1

    # Rewrite rules
    $rewriteBlock = ""
    if ($needsRewrite) {
        $rewriteBlock = @"
        rewrite ^$path`$ / break;
        rewrite ^$path(/.*)`$ `$1 break;
"@
    }

    # Registry-specific location blocks (matches Python builders)
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

# Write nginx preview
$config.ToString() | Out-File -FilePath $NginxPreviewFile -Encoding UTF8
Write-Host "Nginx preview written to: $NginxPreviewFile ($lineNum lines)" -ForegroundColor Green
Write-Host ""

# ============================================================================
# Route Line Map (for debugging nginx errors at specific line numbers)
# ============================================================================
Write-Host "=== ROUTE LINE MAP ===" -ForegroundColor Cyan
$sortedRoutes = $routeLineMap.GetEnumerator() | Sort-Object { $_.Value.StartLine }
foreach ($entry in $sortedRoutes) {
    $info = $entry.Value
    Write-Host ("  Line {0,5}: {1,-60} ({2})" -f $info.StartLine, $info.Path, $info.Registry)
}

Write-Host ""
Write-Host "=== QUICK LOOKUP ===" -ForegroundColor Cyan
Write-Host "To find the route at a specific line (e.g., line 6822):"
Write-Host "  `$content = Get-Content $NginxPreviewFile"
Write-Host '  $content[6820..6825]  # Show lines around 6822'
Write-Host ""

# ============================================================================
# Final Status
# ============================================================================
if ($invalidPaths.Count -gt 0) {
    Write-Host "WARNING: $($invalidPaths.Count) routes had invalid paths and were excluded." -ForegroundColor Red
    Write-Host "Fix the repository names in Artifactory or add them to -ExcludePattern." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "SUCCESS: $($allRoutes.Count) unique routes generated ($skippedDuplicates duplicates removed)" -ForegroundColor Green
exit 0
