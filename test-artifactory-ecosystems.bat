@echo off
REM Test All Ecosystems Artifactory Virtual Repository Flow (Except VSX)
REM Tests: UAT -> SFW -> SaaS complete flow for URL rewriting in middle topology
REM Ecosystems: PyPI, npm, Maven, RubyGems, Go, Cargo, NuGet, Conda
REM Saves verbose output to logs-all-ecosystems.txt

echo Test All Ecosystems Artifactory Virtual Repository Flow > logs-all-ecosystems.txt
echo ============================================================ >> logs-all-ecosystems.txt
echo Started: %date% %time% >> logs-all-ecosystems.txt
echo. >> logs-all-ecosystems.txt

REM ========================================
REM CONFIGURATION - UPDATE THESE VALUES
REM ========================================

set UAT_DOMAIN=artifactory-uat.example.com
set SFW_DOMAIN=sfw.example.com
set SAAS_DOMAIN=example.jfrog.io
set PROXY_ADDRESS=http://proxy.example.com:8080
set AUTH_USER=u358194
set AUTH_PASS=YOUR_PASSWORD_HERE

REM Virtual repository names
set PYPI_VIRTUAL=pypi-external-virtual
set NPM_VIRTUAL=npm-external-virtual
set MAVEN_VIRTUAL=maven-external-virtual
set RUBYGEMS_VIRTUAL=rubygems-external-virtual
set GO_VIRTUAL=go-external-virtual
set CARGO_VIRTUAL=cargo-external-virtual
set NUGET_VIRTUAL=nuget-external-virtual
set CONDA_VIRTUAL=conda-external-virtual

REM Remote repository names (that proxy through SFW)
set PYPI_REMOTE=pypi-EXAMPLE-proxy-proxy-remote
set NPM_REMOTE=npm-EXAMPLE-proxy-proxy-remote
set MAVEN_REMOTE=maven-EXAMPLE-proxy-proxy-remote
set RUBYGEMS_REMOTE=rubygems-EXAMPLE-proxy-proxy-remote
set GO_REMOTE=go-EXAMPLE-proxy-proxy-remote
set CARGO_REMOTE=cargo-EXAMPLE-proxy-proxy-remote
set NUGET_REMOTE=nuget-EXAMPLE-proxy-proxy-remote
set CONDA_REMOTE=conda-EXAMPLE-proxy-proxy-remote

REM Test packages for each ecosystem
set PYPI_PACKAGE=light-s3-client
set NPM_PACKAGE=lodash
set MAVEN_GROUP=org/springframework/spring-core
set MAVEN_VERSION=5.3.9
set RUBYGEMS_PACKAGE=json
set GO_PACKAGE=github.com/gorilla/mux
set CARGO_PACKAGE=serde
set NUGET_PACKAGE=Newtonsoft.Json
set CONDA_PACKAGE=numpy

echo ============================================================ >> logs-all-ecosystems.txt
echo Configuration >> logs-all-ecosystems.txt
echo ============================================================ >> logs-all-ecosystems.txt
echo UAT Domain: %UAT_DOMAIN% >> logs-all-ecosystems.txt
echo SFW Domain: %SFW_DOMAIN% >> logs-all-ecosystems.txt
echo SaaS Domain: %SAAS_DOMAIN% >> logs-all-ecosystems.txt
echo Proxy: %PROXY_ADDRESS% >> logs-all-ecosystems.txt
echo. >> logs-all-ecosystems.txt

REM ========================================
REM PYPI TESTS
REM ========================================

echo.
echo ========================================
echo TESTING PYPI ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING PYPI ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM PyPI Test 1: Direct to UAT
echo [PYPI-1] Fetching from Artifactory UAT (virtual repo)...
echo [PYPI-1] URL: https://%UAT_DOMAIN%/artifactory/api/pypi/%PYPI_VIRTUAL%/simple/%PYPI_PACKAGE%/ >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: pip/24.3.1" ^
  -H "Accept: text/html" ^
  -H "Accept-Encoding: identity" ^
  -o pypi-uat.html ^
  "https://%UAT_DOMAIN%/artifactory/api/pypi/%PYPI_VIRTUAL%/simple/%PYPI_PACKAGE%/" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [PYPI-1] SUCCESS - Saved to pypi-uat.html
) else (
    echo [PYPI-1] FAILED
)

REM PyPI Test 2: Through SFW
echo [PYPI-2] Fetching from Socket Firewall UAT...
echo [PYPI-2] URL: https://%SFW_DOMAIN%/artifactory/api/pypi/%PYPI_REMOTE%/simple/%PYPI_PACKAGE%/ >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: pip/24.3.1" ^
  -H "Accept: text/html" ^
  -H "Accept-Encoding: identity" ^
  -o pypi-sfw.html ^
  "https://%SFW_DOMAIN%/artifactory/api/pypi/%PYPI_REMOTE%/simple/%PYPI_PACKAGE%/" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [PYPI-2] SUCCESS - Saved to pypi-sfw.html
) else (
    echo [PYPI-2] FAILED
)

REM PyPI Test 3: Direct to SaaS
echo [PYPI-3] Fetching from JFrog SaaS (remote repo)...
echo [PYPI-3] URL: https://%SAAS_DOMAIN%/artifactory/api/pypi/%PYPI_REMOTE%/simple/%PYPI_PACKAGE%/ >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: pip/24.3.1" ^
  -H "Accept: text/html" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o pypi-saas.html ^
  "https://%SAAS_DOMAIN%/artifactory/api/pypi/%PYPI_REMOTE%/simple/%PYPI_PACKAGE%/" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [PYPI-3] SUCCESS - Saved to pypi-saas.html
) else (
    echo [PYPI-3] FAILED
)

REM ========================================
REM NPM TESTS
REM ========================================

echo.
echo ========================================
echo TESTING NPM ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING NPM ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM npm Test 1: Direct to UAT
echo [NPM-1] Fetching from Artifactory UAT (virtual repo)...
echo [NPM-1] URL: https://%UAT_DOMAIN%/artifactory/api/npm/%NPM_VIRTUAL%/%NPM_PACKAGE% >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: npm/10.2.3" ^
  -H "Accept: application/vnd.npm.install-v1+json" ^
  -H "Accept-Encoding: identity" ^
  -o npm-uat.json ^
  "https://%UAT_DOMAIN%/artifactory/api/npm/%NPM_VIRTUAL%/%NPM_PACKAGE%" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [NPM-1] SUCCESS - Saved to npm-uat.json
) else (
    echo [NPM-1] FAILED
)

REM npm Test 2: Through SFW
echo [NPM-2] Fetching from Socket Firewall UAT...
echo [NPM-2] URL: https://%SFW_DOMAIN%/artifactory/api/npm/%NPM_REMOTE%/%NPM_PACKAGE% >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: npm/10.2.3" ^
  -H "Accept: application/vnd.npm.install-v1+json" ^
  -H "Accept-Encoding: identity" ^
  -o npm-sfw.json ^
  "https://%SFW_DOMAIN%/artifactory/api/npm/%NPM_REMOTE%/%NPM_PACKAGE%" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [NPM-2] SUCCESS - Saved to npm-sfw.json
) else (
    echo [NPM-2] FAILED
)

REM npm Test 3: Direct to SaaS
echo [NPM-3] Fetching from JFrog SaaS (remote repo)...
echo [NPM-3] URL: https://%SAAS_DOMAIN%/artifactory/api/npm/%NPM_REMOTE%/%NPM_PACKAGE% >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: npm/10.2.3" ^
  -H "Accept: application/vnd.npm.install-v1+json" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o npm-saas.json ^
  "https://%SAAS_DOMAIN%/artifactory/api/npm/%NPM_REMOTE%/%NPM_PACKAGE%" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [NPM-3] SUCCESS - Saved to npm-saas.json
) else (
    echo [NPM-3] FAILED
)

REM ========================================
REM MAVEN TESTS
REM ========================================

echo.
echo ========================================
echo TESTING MAVEN ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING MAVEN ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM Maven Test 1: Direct to UAT (POM file)
echo [MAVEN-1] Fetching from Artifactory UAT (virtual repo)...
echo [MAVEN-1] URL: https://%UAT_DOMAIN%/artifactory/%MAVEN_VIRTUAL%/%MAVEN_GROUP%/%MAVEN_VERSION%/spring-core-%MAVEN_VERSION%.pom >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Apache-Maven/3.8.6" ^
  -H "Accept: text/xml, application/xml, */*" ^
  -H "Accept-Encoding: identity" ^
  -o maven-uat.pom ^
  "https://%UAT_DOMAIN%/artifactory/%MAVEN_VIRTUAL%/%MAVEN_GROUP%/%MAVEN_VERSION%/spring-core-%MAVEN_VERSION%.pom" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [MAVEN-1] SUCCESS - Saved to maven-uat.pom
) else (
    echo [MAVEN-1] FAILED
)

REM Maven Test 2: Through SFW
echo [MAVEN-2] Fetching from Socket Firewall UAT...
echo [MAVEN-2] URL: https://%SFW_DOMAIN%/artifactory/%MAVEN_REMOTE%/%MAVEN_GROUP%/%MAVEN_VERSION%/spring-core-%MAVEN_VERSION%.pom >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Apache-Maven/3.8.6" ^
  -H "Accept: text/xml, application/xml, */*" ^
  -H "Accept-Encoding: identity" ^
  -o maven-sfw.pom ^
  "https://%SFW_DOMAIN%/artifactory/%MAVEN_REMOTE%/%MAVEN_GROUP%/%MAVEN_VERSION%/spring-core-%MAVEN_VERSION%.pom" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [MAVEN-2] SUCCESS - Saved to maven-sfw.pom
) else (
    echo [MAVEN-2] FAILED
)

REM Maven Test 3: Direct to SaaS
echo [MAVEN-3] Fetching from JFrog SaaS (remote repo)...
echo [MAVEN-3] URL: https://%SAAS_DOMAIN%/artifactory/%MAVEN_REMOTE%/%MAVEN_GROUP%/%MAVEN_VERSION%/spring-core-%MAVEN_VERSION%.pom >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Apache-Maven/3.8.6" ^
  -H "Accept: text/xml, application/xml, */*" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o maven-saas.pom ^
  "https://%SAAS_DOMAIN%/artifactory/%MAVEN_REMOTE%/%MAVEN_GROUP%/%MAVEN_VERSION%/spring-core-%MAVEN_VERSION%.pom" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [MAVEN-3] SUCCESS - Saved to maven-saas.pom
) else (
    echo [MAVEN-3] FAILED
)

REM ========================================
REM RUBYGEMS TESTS
REM ========================================

echo.
echo ========================================
echo TESTING RUBYGEMS ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING RUBYGEMS ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM RubyGems Test 1: Direct to UAT
echo [RUBYGEMS-1] Fetching from Artifactory UAT (virtual repo)...
echo [RUBYGEMS-1] URL: https://%UAT_DOMAIN%/artifactory/api/gems/%RUBYGEMS_VIRTUAL%/api/v1/gems/%RUBYGEMS_PACKAGE%.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Ruby, RubyGems/3.4.10" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -o rubygems-uat.json ^
  "https://%UAT_DOMAIN%/artifactory/api/gems/%RUBYGEMS_VIRTUAL%/api/v1/gems/%RUBYGEMS_PACKAGE%.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [RUBYGEMS-1] SUCCESS - Saved to rubygems-uat.json
) else (
    echo [RUBYGEMS-1] FAILED
)

REM RubyGems Test 2: Through SFW
echo [RUBYGEMS-2] Fetching from Socket Firewall UAT...
echo [RUBYGEMS-2] URL: https://%SFW_DOMAIN%/artifactory/api/gems/%RUBYGEMS_REMOTE%/api/v1/gems/%RUBYGEMS_PACKAGE%.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Ruby, RubyGems/3.4.10" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -o rubygems-sfw.json ^
  "https://%SFW_DOMAIN%/artifactory/api/gems/%RUBYGEMS_REMOTE%/api/v1/gems/%RUBYGEMS_PACKAGE%.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [RUBYGEMS-2] SUCCESS - Saved to rubygems-sfw.json
) else (
    echo [RUBYGEMS-2] FAILED
)

REM RubyGems Test 3: Direct to SaaS
echo [RUBYGEMS-3] Fetching from JFrog SaaS (remote repo)...
echo [RUBYGEMS-3] URL: https://%SAAS_DOMAIN%/artifactory/api/gems/%RUBYGEMS_REMOTE%/api/v1/gems/%RUBYGEMS_PACKAGE%.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Ruby, RubyGems/3.4.10" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o rubygems-saas.json ^
  "https://%SAAS_DOMAIN%/artifactory/api/gems/%RUBYGEMS_REMOTE%/api/v1/gems/%RUBYGEMS_PACKAGE%.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [RUBYGEMS-3] SUCCESS - Saved to rubygems-saas.json
) else (
    echo [RUBYGEMS-3] FAILED
)

REM ========================================
REM GO TESTS
REM ========================================

echo.
echo ========================================
echo TESTING GO ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING GO ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM Go Test 1: Direct to UAT (info endpoint)
echo [GO-1] Fetching from Artifactory UAT (virtual repo)...
echo [GO-1] URL: https://%UAT_DOMAIN%/artifactory/api/go/%GO_VIRTUAL%/%GO_PACKAGE%/@v/list >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Go-http-client/1.1" ^
  -H "Accept: */*" ^
  -H "Accept-Encoding: identity" ^
  -o go-uat.txt ^
  "https://%UAT_DOMAIN%/artifactory/api/go/%GO_VIRTUAL%/%GO_PACKAGE%/@v/list" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [GO-1] SUCCESS - Saved to go-uat.txt
) else (
    echo [GO-1] FAILED
)

REM Go Test 2: Through SFW
echo [GO-2] Fetching from Socket Firewall UAT...
echo [GO-2] URL: https://%SFW_DOMAIN%/artifactory/api/go/%GO_REMOTE%/%GO_PACKAGE%/@v/list >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Go-http-client/1.1" ^
  -H "Accept: */*" ^
  -H "Accept-Encoding: identity" ^
  -o go-sfw.txt ^
  "https://%SFW_DOMAIN%/artifactory/api/go/%GO_REMOTE%/%GO_PACKAGE%/@v/list" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [GO-2] SUCCESS - Saved to go-sfw.txt
) else (
    echo [GO-2] FAILED
)

REM Go Test 3: Direct to SaaS
echo [GO-3] Fetching from JFrog SaaS (remote repo)...
echo [GO-3] URL: https://%SAAS_DOMAIN%/artifactory/api/go/%GO_REMOTE%/%GO_PACKAGE%/@v/list >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: Go-http-client/1.1" ^
  -H "Accept: */*" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o go-saas.txt ^
  "https://%SAAS_DOMAIN%/artifactory/api/go/%GO_REMOTE%/%GO_PACKAGE%/@v/list" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [GO-3] SUCCESS - Saved to go-saas.json
) else (
    echo [GO-3] FAILED
)

REM ========================================
REM CARGO TESTS
REM ========================================

echo.
echo ========================================
echo TESTING CARGO ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING CARGO ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM Cargo Test 1: Direct to UAT (crate metadata)
echo [CARGO-1] Fetching from Artifactory UAT (virtual repo)...
echo [CARGO-1] URL: https://%UAT_DOMAIN%/artifactory/api/cargo/%CARGO_VIRTUAL%/se/rd/%CARGO_PACKAGE% >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: cargo/1.75.0" ^
  -H "Accept: */*" ^
  -H "Accept-Encoding: identity" ^
  -o cargo-uat.json ^
  "https://%UAT_DOMAIN%/artifactory/api/cargo/%CARGO_VIRTUAL%/se/rd/%CARGO_PACKAGE%" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [CARGO-1] SUCCESS - Saved to cargo-uat.json
) else (
    echo [CARGO-1] FAILED
)

REM Cargo Test 2: Through SFW
echo [CARGO-2] Fetching from Socket Firewall UAT...
echo [CARGO-2] URL: https://%SFW_DOMAIN%/artifactory/api/cargo/%CARGO_REMOTE%/se/rd/%CARGO_PACKAGE% >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: cargo/1.75.0" ^
  -H "Accept: */*" ^
  -H "Accept-Encoding: identity" ^
  -o cargo-sfw.json ^
  "https://%SFW_DOMAIN%/artifactory/api/cargo/%CARGO_REMOTE%/se/rd/%CARGO_PACKAGE%" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [CARGO-2] SUCCESS - Saved to cargo-sfw.json
) else (
    echo [CARGO-2] FAILED
)

REM Cargo Test 3: Direct to SaaS
echo [CARGO-3] Fetching from JFrog SaaS (remote repo)...
echo [CARGO-3] URL: https://%SAAS_DOMAIN%/artifactory/api/cargo/%CARGO_REMOTE%/se/rd/%CARGO_PACKAGE% >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: cargo/1.75.0" ^
  -H "Accept: */*" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o cargo-saas.json ^
  "https://%SAAS_DOMAIN%/artifactory/api/cargo/%CARGO_REMOTE%/se/rd/%CARGO_PACKAGE%" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [CARGO-3] SUCCESS - Saved to cargo-saas.json
) else (
    echo [CARGO-3] FAILED
)

REM ========================================
REM NUGET TESTS
REM ========================================

echo.
echo ========================================
echo TESTING NUGET ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING NUGET ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM NuGet Test 1: Direct to UAT (service index)
echo [NUGET-1] Fetching from Artifactory UAT (virtual repo)...
echo [NUGET-1] URL: https://%UAT_DOMAIN%/artifactory/api/nuget/%NUGET_VIRTUAL%/v3/index.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: NuGet Command Line/6.4.0" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -o nuget-uat.json ^
  "https://%UAT_DOMAIN%/artifactory/api/nuget/%NUGET_VIRTUAL%/v3/index.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [NUGET-1] SUCCESS - Saved to nuget-uat.json
) else (
    echo [NUGET-1] FAILED
)

REM NuGet Test 2: Through SFW
echo [NUGET-2] Fetching from Socket Firewall UAT...
echo [NUGET-2] URL: https://%SFW_DOMAIN%/artifactory/api/nuget/%NUGET_REMOTE%/v3/index.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: NuGet Command Line/6.4.0" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -o nuget-sfw.json ^
  "https://%SFW_DOMAIN%/artifactory/api/nuget/%NUGET_REMOTE%/v3/index.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [NUGET-2] SUCCESS - Saved to nuget-sfw.json
) else (
    echo [NUGET-2] FAILED
)

REM NuGet Test 3: Direct to SaaS
echo [NUGET-3] Fetching from JFrog SaaS (remote repo)...
echo [NUGET-3] URL: https://%SAAS_DOMAIN%/artifactory/api/nuget/%NUGET_REMOTE%/v3/index.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: NuGet Command Line/6.4.0" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o nuget-saas.json ^
  "https://%SAAS_DOMAIN%/artifactory/api/nuget/%NUGET_REMOTE%/v3/index.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [NUGET-3] SUCCESS - Saved to nuget-saas.json
) else (
    echo [NUGET-3] FAILED
)

REM ========================================
REM CONDA TESTS
REM ========================================

echo.
echo ========================================
echo TESTING CONDA ECOSYSTEM
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo TESTING CONDA ECOSYSTEM >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM Conda Test 1: Direct to UAT (repodata)
echo [CONDA-1] Fetching from Artifactory UAT (virtual repo)...
echo [CONDA-1] URL: https://%UAT_DOMAIN%/artifactory/api/conda/%CONDA_VIRTUAL%/linux-64/repodata.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: conda/23.11.0" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -o conda-uat.json ^
  "https://%UAT_DOMAIN%/artifactory/api/conda/%CONDA_VIRTUAL%/linux-64/repodata.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [CONDA-1] SUCCESS - Saved to conda-uat.json
) else (
    echo [CONDA-1] FAILED
)

REM Conda Test 2: Through SFW
echo [CONDA-2] Fetching from Socket Firewall UAT...
echo [CONDA-2] URL: https://%SFW_DOMAIN%/artifactory/api/conda/%CONDA_REMOTE%/linux-64/repodata.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: conda/23.11.0" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -o conda-sfw.json ^
  "https://%SFW_DOMAIN%/artifactory/api/conda/%CONDA_REMOTE%/linux-64/repodata.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [CONDA-2] SUCCESS - Saved to conda-sfw.json
) else (
    echo [CONDA-2] FAILED
)

REM Conda Test 3: Direct to SaaS
echo [CONDA-3] Fetching from JFrog SaaS (remote repo)...
echo [CONDA-3] URL: https://%SAAS_DOMAIN%/artifactory/api/conda/%CONDA_REMOTE%/linux-64/repodata.json >> logs-all-ecosystems.txt
curl -v -k -u "%AUTH_USER%:%AUTH_PASS%" ^
  -H "User-Agent: conda/23.11.0" ^
  -H "Accept: application/json" ^
  -H "Accept-Encoding: identity" ^
  -x "%PROXY_ADDRESS%" ^
  -o conda-saas.json ^
  "https://%SAAS_DOMAIN%/artifactory/api/conda/%CONDA_REMOTE%/linux-64/repodata.json" ^
  >> logs-all-ecosystems.txt 2>&1

if %ERRORLEVEL% EQU 0 (
    echo [CONDA-3] SUCCESS - Saved to conda-saas.json
) else (
    echo [CONDA-3] FAILED
)

REM ========================================
REM ANALYZE RESULTS
REM ========================================

echo.
echo ========================================
echo ANALYZING RESULTS
echo ========================================
echo. >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt
echo ANALYSIS: URL Patterns in Responses >> logs-all-ecosystems.txt
echo ======================================== >> logs-all-ecosystems.txt

REM PyPI Analysis
if exist pypi-sfw.html (
    echo.
    echo [PYPI] Analyzing URL rewriting...
    echo [PYPI] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/api/pypi/%PYPI_REMOTE%" pypi-sfw.html >nul
    if %ERRORLEVEL% EQU 0 (
        echo [PYPI] ERROR: Found embedded remote repo paths - rewriting failed!
        echo [PYPI] ERROR: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [PYPI] OK: No embedded paths found - rewriting working!
        echo [PYPI] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM npm Analysis
if exist npm-sfw.json (
    echo.
    echo [NPM] Analyzing URL rewriting...
    echo [NPM] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/api/npm/%NPM_REMOTE%" npm-sfw.json >nul
    if %ERRORLEVEL% EQU 0 (
        echo [NPM] ERROR: Found embedded remote repo paths - rewriting failed!
        echo [NPM] ERROR: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [NPM] OK: No embedded paths found - rewriting working!
        echo [NPM] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM Maven Analysis
if exist maven-sfw.pom (
    echo.
    echo [MAVEN] Analyzing URL rewriting...
    echo [MAVEN] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/%MAVEN_REMOTE%" maven-sfw.pom >nul
    if %ERRORLEVEL% EQU 0 (
        echo [MAVEN] WARNING: Found embedded remote repo paths
        echo [MAVEN] WARNING: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [MAVEN] OK: No embedded paths found
        echo [MAVEN] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM RubyGems Analysis
if exist rubygems-sfw.json (
    echo.
    echo [RUBYGEMS] Analyzing URL rewriting...
    echo [RUBYGEMS] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/api/gems/%RUBYGEMS_REMOTE%" rubygems-sfw.json >nul
    if %ERRORLEVEL% EQU 0 (
        echo [RUBYGEMS] ERROR: Found embedded remote repo paths - rewriting failed!
        echo [RUBYGEMS] ERROR: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [RUBYGEMS] OK: No embedded paths found - rewriting working!
        echo [RUBYGEMS] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM Go Analysis
if exist go-sfw.txt (
    echo.
    echo [GO] Analyzing URL rewriting...
    echo [GO] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/api/go/%GO_REMOTE%" go-sfw.txt >nul
    if %ERRORLEVEL% EQU 0 (
        echo [GO] WARNING: Found embedded remote repo paths
        echo [GO] WARNING: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [GO] OK: No embedded paths found
        echo [GO] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM Cargo Analysis
if exist cargo-sfw.json (
    echo.
    echo [CARGO] Analyzing URL rewriting...
    echo [CARGO] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/api/cargo/%CARGO_REMOTE%" cargo-sfw.json >nul
    if %ERRORLEVEL% EQU 0 (
        echo [CARGO] WARNING: Found embedded remote repo paths
        echo [CARGO] WARNING: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [CARGO] OK: No embedded paths found
        echo [CARGO] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM NuGet Analysis
if exist nuget-sfw.json (
    echo.
    echo [NUGET] Analyzing URL rewriting...
    echo [NUGET] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/api/nuget/%NUGET_REMOTE%" nuget-sfw.json >nul
    if %ERRORLEVEL% EQU 0 (
        echo [NUGET] ERROR: Found embedded remote repo paths - rewriting failed!
        echo [NUGET] ERROR: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [NUGET] OK: No embedded paths found - rewriting working!
        echo [NUGET] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM Conda Analysis
if exist conda-sfw.json (
    echo.
    echo [CONDA] Analyzing URL rewriting...
    echo [CONDA] Checking for embedded path stripping... >> logs-all-ecosystems.txt
    findstr /C:"artifactory/api/conda/%CONDA_REMOTE%" conda-sfw.json >nul
    if %ERRORLEVEL% EQU 0 (
        echo [CONDA] ERROR: Found embedded remote repo paths - rewriting failed!
        echo [CONDA] ERROR: Found embedded remote repo paths >> logs-all-ecosystems.txt
    ) else (
        echo [CONDA] OK: No embedded paths found - rewriting working!
        echo [CONDA] OK: No embedded paths found >> logs-all-ecosystems.txt
    )
)

REM ========================================
REM SUMMARY
REM ========================================

echo.
echo ========================================
echo TEST COMPLETE
echo ========================================
echo.
echo Output files created:
echo   PyPI:     pypi-uat.html, pypi-sfw.html, pypi-saas.html
echo   npm:      npm-uat.json, npm-sfw.json, npm-saas.json
echo   Maven:    maven-uat.pom, maven-sfw.pom, maven-saas.pom
echo   RubyGems: rubygems-uat.json, rubygems-sfw.json, rubygems-saas.json
echo   Go:       go-uat.txt, go-sfw.txt, go-saas.json
echo   Cargo:    cargo-uat.json, cargo-sfw.json, cargo-saas.json
echo   NuGet:    nuget-uat.json, nuget-sfw.json, nuget-saas.json
echo   Conda:    conda-uat.json, conda-sfw.json, conda-saas.json
echo.
echo Logs: logs-all-ecosystems.txt
echo.
echo Next steps:
echo   1. Review logs-all-ecosystems.txt for HTTP status codes
echo   2. Check analysis results above for URL rewriting issues
echo   3. Compare *-uat files vs *-sfw files to see rewriting
echo   4. Look for "artifactory/api/{type}/{repo}" patterns in SFW responses
echo.

echo. >> logs-all-ecosystems.txt
echo Test completed: %date% %time% >> logs-all-ecosystems.txt
