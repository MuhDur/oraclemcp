#Requires -Version 5.1
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification = "Script parameters are consumed by nested installer functions after normalization.")]
param(
    [string]$Version = "latest",
    [ValidateSet("x86_64-pc-windows-msvc")]
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$Prefix = "",
    [string]$BinDir = "",
    [string]$Repo = "MuhDur/oraclemcp",
    [string]$Offline = "",
    [switch]$NoCompletions,
    [switch]$Service,
    [string]$ServiceName = "oraclemcp",
    [string]$Listen = "127.0.0.1:7070",
    [Alias("Profile")]
    [string]$ServiceProfile = "",
    [switch]$AllowNoAuth,
    [switch]$ClientCredentials,
    [switch]$SkipLinger,
    [switch]$Yes,
    [switch]$Force,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$OidcIssuer = "https://token.actions.githubusercontent.com"

function Write-InstallFailure {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "oraclemcp installer: $Message"
}

function Test-CommandAvailable {
    param([Parameter(Mandatory = $true)][string]$Name)
    $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-DefaultPrefix {
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Programs\oraclemcp")
    }
    if (-not [string]::IsNullOrWhiteSpace($HOME)) {
        return (Join-Path -Path $HOME -ChildPath ".oraclemcp")
    }
    Write-InstallFailure "LOCALAPPDATA and HOME are unset; pass -Prefix"
}

function Get-NormalizedVersion {
    param([Parameter(Mandatory = $true)][string]$InputVersion)
    if ($InputVersion -eq "latest") {
        return $InputVersion
    }
    $normalized = $InputVersion -replace "^v", ""
    if ($normalized -notmatch "^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$") {
        Write-InstallFailure "unsupported version '$InputVersion' (expected latest, X.Y.Z, or vX.Y.Z)"
    }
    return $normalized
}

function Get-ReleaseTag {
    if ($Version -eq "latest") {
        return "latest"
    }
    return "v$Version"
}

function Get-ReleaseBaseUrl {
    if ($Version -eq "latest") {
        return "https://github.com/$Repo/releases/latest/download"
    }
    return "https://github.com/$Repo/releases/download/$(Get-ReleaseTag)"
}

function Get-ArchiveName {
    return "oraclemcp-$Target.zip"
}

function Get-CosignIdentityArgument {
    if ($Version -eq "latest") {
        return @(
            "--certificate-identity-regexp",
            "https://github[.]com/$Repo/[.]github/workflows/release[.]yml@refs/tags/v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?"
        )
    }
    return @(
        "--certificate-identity",
        "https://github.com/$Repo/.github/workflows/release.yml@refs/tags/v$Version"
    )
}

function Get-CompletionPath {
    return @(
        (Join-Path -Path $Prefix -ChildPath "Completions\oraclemcp.ps1"),
        (Join-Path -Path $Prefix -ChildPath "Completions\om.ps1")
    )
}

function Get-ServiceUnitDescription {
    return "Windows service '$ServiceName'"
}

function Get-ReadyzUrl {
    if ($Listen -match "^https?://") {
        return "$($Listen.TrimEnd("/"))/readyz"
    }
    if ($Listen -match "^0\.0\.0\.0:(?<port>[0-9]+)$") {
        return "http://127.0.0.1:$($Matches.port)/readyz"
    }
    if ($Listen -match "^\[::\]:(?<port>[0-9]+)$") {
        return "http://127.0.0.1:$($Matches.port)/readyz"
    }
    if ($Listen -match "^(?<host>[^:]+):(?<port>[0-9]+)$") {
        $hostName = $Matches.host
        if ($hostName -eq "localhost") {
            $hostName = "127.0.0.1"
        }
        return "http://${hostName}:$($Matches.port)/readyz"
    }
    return "http://$Listen/readyz"
}

function Get-ServiceArgument {
    $arguments = @("service", "install", "--yes", "--name", $ServiceName, "--listen", $Listen)
    if (-not [string]::IsNullOrWhiteSpace($ServiceProfile)) {
        $arguments += @("--profile", $ServiceProfile)
    }
    if ($AllowNoAuth) {
        $arguments += "--allow-no-auth"
    }
    if ($ClientCredentials) {
        $arguments += "--client-credentials"
    }
    if ($SkipLinger) {
        $arguments += "--skip-linger"
    }
    return $arguments
}

function ConvertTo-DisplayArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -match '[\s"]') {
        return '"' + ($Value -replace '"', '\"') + '"'
    }
    return $Value
}

function Format-CommandLine {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [string[]]$Argument = @()
    )
    $items = @($File) + $Argument
    return (($items | ForEach-Object { ConvertTo-DisplayArgument -Value $_ }) -join " ")
}

function Write-InstallPlan {
    $asset = Get-ArchiveName
    $baseUrl = Get-ReleaseBaseUrl
    $mode = "prebuilt"
    if (-not [string]::IsNullOrWhiteSpace($Offline)) {
        $mode = "offline"
    }

    Write-Output "oraclemcp Windows installer plan"
    Write-Output "  mode: $mode"
    Write-Output "  version: $Version"
    Write-Output "  target: $Target"
    Write-Output "  prefix: $Prefix"
    Write-Output "  bin_dir: $BinDir"

    if (-not [string]::IsNullOrWhiteSpace($Offline)) {
        Write-Output "  offline_archive: $Offline"
        Write-Output "  offline_checksum: $Offline.sha256"
        Write-Output "  offline_cosign_signature: $Offline.sig + $Offline.crt"
        Write-Output "  offline_cosign_attestation: $Offline.attestation.sigstore.json"
    } else {
        Write-Output "  archive: $baseUrl/$asset"
        Write-Output "  checksum: $baseUrl/$asset.sha256"
        Write-Output "  cosign_signature: $baseUrl/$asset.sig + $baseUrl/$asset.crt"
        Write-Output "  cosign_attestation: $baseUrl/$asset.attestation.sigstore.json"
    }
    Write-Output "  sha256_note: checksum verifies transport integrity only; cosign verifies authenticity and provenance"

    Write-Output "  files:"
    Write-Output "    $(Join-Path -Path $BinDir -ChildPath "oraclemcp.exe")"
    Write-Output "    $(Join-Path -Path $BinDir -ChildPath "om.exe")"
    if (-not $NoCompletions) {
        Get-CompletionPath | ForEach-Object { Write-Output "    $_" }
    }

    if ($Service) {
        $serviceArguments = @(Get-ServiceArgument)
        $command = Format-CommandLine -File (Join-Path -Path $BinDir -ChildPath "oraclemcp.exe") -Argument $serviceArguments
        Write-Output "  service:"
        Write-Output "    unit: $(Get-ServiceUnitDescription)"
        Write-Output "    command: $command"
        Write-Output "    readyz_gate: Invoke-WebRequest -UseBasicParsing $(Get-ReadyzUrl)"
    } else {
        Write-Output "  service: not requested; no service-manager files or units will be touched"
    }
}

function Invoke-DownloadFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    $parent = Split-Path -Path $OutFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
}

function Get-Sha256DigestFromText {
    param([Parameter(Mandatory = $true)][string]$Text)
    $match = [regex]::Match($Text, "(?i)[a-f0-9]{64}")
    if (-not $match.Success) {
        Write-InstallFailure "checksum file does not contain a SHA-256 digest"
    }
    return $match.Value.ToLowerInvariant()
}

function Get-ChecksumDigest {
    param([Parameter(Mandatory = $true)][string]$ChecksumFile)
    if (-not (Test-Path -LiteralPath $ChecksumFile -PathType Leaf)) {
        Write-InstallFailure "missing checksum file: $ChecksumFile"
    }
    return (Get-Sha256DigestFromText -Text (Get-Content -LiteralPath $ChecksumFile -Raw))
}

function Test-ArchiveChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$ChecksumFile
    )
    if (-not (Test-CommandAvailable -Name "certutil.exe")) {
        Write-InstallFailure "missing required command: certutil.exe"
    }
    $expected = Get-ChecksumDigest -ChecksumFile $ChecksumFile
    $hashOutput = & certutil.exe -hashfile $Archive SHA256
    if ($LASTEXITCODE -ne 0) {
        Write-InstallFailure "certutil SHA-256 verification failed for $Archive"
    }
    $actual = Get-Sha256DigestFromText -Text ($hashOutput | Out-String)
    if ($actual -ne $expected) {
        Write-InstallFailure "checksum mismatch for $Archive (expected $expected, got $actual)"
    }
    Write-Output "oraclemcp installer: SHA-256 verified with certutil"
}

function Test-CosignEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$Signature,
        [Parameter(Mandatory = $true)][string]$Certificate,
        [Parameter(Mandatory = $true)][string]$Attestation
    )
    if (-not (Test-CommandAvailable -Name "cosign")) {
        Write-InstallFailure "missing required command: cosign"
    }
    $identityArguments = @(Get-CosignIdentityArgument)
    & cosign verify-blob --certificate $Certificate --signature $Signature @identityArguments --certificate-oidc-issuer $OidcIssuer $Archive
    if ($LASTEXITCODE -ne 0) {
        Write-InstallFailure "cosign verify-blob failed for $Archive"
    }
    & cosign verify-blob-attestation --bundle $Attestation --type slsaprovenance1 @identityArguments --certificate-oidc-issuer $OidcIssuer $Archive
    if ($LASTEXITCODE -ne 0) {
        Write-InstallFailure "cosign verify-blob-attestation failed for $Archive"
    }
}

function Test-OfflineBundle {
    param([Parameter(Mandatory = $true)][string]$Archive)
    $expected = Get-ArchiveName
    if ((Split-Path -Path $Archive -Leaf) -ne $expected) {
        Write-InstallFailure "ORACLEMCP_INSTALL_OFFLINE_TARGET_MISMATCH: expected offline archive named $expected for target $Target"
    }
    foreach ($path in @($Archive, "$Archive.sha256", "$Archive.sig", "$Archive.crt", "$Archive.attestation.sigstore.json")) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Write-InstallFailure "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING: required offline bundle file is missing: $path"
        }
    }
}

function Invoke-EnsureParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

function Test-ReplaceablePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ((Test-Path -LiteralPath $Path) -and (-not $Force)) {
        Write-InstallFailure "$Path already exists; rerun with -Force to replace it"
    }
}

function Invoke-InstallBinary {
    param([Parameter(Mandatory = $true)][string]$ExtractRoot)
    $dist = Join-Path -Path $ExtractRoot -ChildPath "oraclemcp-$Target"
    $sourceOraclemcp = Join-Path -Path $dist -ChildPath "oraclemcp.exe"
    $sourceOm = Join-Path -Path $dist -ChildPath "om.exe"
    if (-not (Test-Path -LiteralPath $sourceOraclemcp -PathType Leaf)) {
        Write-InstallFailure "release archive did not contain executable $sourceOraclemcp"
    }
    if (-not (Test-Path -LiteralPath $sourceOm -PathType Leaf)) {
        Write-InstallFailure "release archive did not contain executable $sourceOm"
    }

    $destOraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    $destOm = Join-Path -Path $BinDir -ChildPath "om.exe"
    Invoke-EnsureParentDirectory -Path $destOraclemcp
    Test-ReplaceablePath -Path $destOraclemcp
    Test-ReplaceablePath -Path $destOm
    Copy-Item -LiteralPath $sourceOraclemcp -Destination $destOraclemcp -Force
    Copy-Item -LiteralPath $sourceOm -Destination $destOm -Force
}

function Invoke-InstallCompletion {
    param(
        [Parameter(Mandatory = $true)][string]$CommandPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Invoke-EnsureParentDirectory -Path $Destination
    Test-ReplaceablePath -Path $Destination
    $completion = & $CommandPath completions powershell
    if ($LASTEXITCODE -ne 0) {
        Write-InstallFailure "failed to generate PowerShell completion from $CommandPath"
    }
    Set-Content -LiteralPath $Destination -Value $completion -Encoding UTF8
}

function Invoke-InstallCompletionSet {
    if ($NoCompletions) {
        return
    }
    $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    $om = Join-Path -Path $BinDir -ChildPath "om.exe"
    $completionPaths = @(Get-CompletionPath)
    Invoke-InstallCompletion -CommandPath $oraclemcp -Destination $completionPaths[0]
    Invoke-InstallCompletion -CommandPath $om -Destination $completionPaths[1]
}

function Invoke-PrebuiltInstall {
    if (-not [string]::IsNullOrWhiteSpace($Offline)) {
        Test-OfflineBundle -Archive $Offline
    }

    $asset = Get-ArchiveName
    $baseUrl = Get-ReleaseBaseUrl
    $workRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("oraclemcp-install-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    try {
        if (-not [string]::IsNullOrWhiteSpace($Offline)) {
            $archive = $Offline
            $checksum = "$archive.sha256"
            $signature = "$archive.sig"
            $certificate = "$archive.crt"
            $attestation = "$archive.attestation.sigstore.json"
        } else {
            $archive = Join-Path -Path $workRoot -ChildPath $asset
            $checksum = "$archive.sha256"
            $signature = "$archive.sig"
            $certificate = "$archive.crt"
            $attestation = "$archive.attestation.sigstore.json"
            Invoke-DownloadFile -Uri "$baseUrl/$asset" -OutFile $archive
            Invoke-DownloadFile -Uri "$baseUrl/$asset.sha256" -OutFile $checksum
            Invoke-DownloadFile -Uri "$baseUrl/$asset.sig" -OutFile $signature
            Invoke-DownloadFile -Uri "$baseUrl/$asset.crt" -OutFile $certificate
            Invoke-DownloadFile -Uri "$baseUrl/$asset.attestation.sigstore.json" -OutFile $attestation
        }

        Test-ArchiveChecksum -Archive $archive -ChecksumFile $checksum
        Test-CosignEvidence -Archive $archive -Signature $signature -Certificate $certificate -Attestation $attestation
        Expand-Archive -LiteralPath $archive -DestinationPath $workRoot -Force
        Invoke-InstallBinary -ExtractRoot $workRoot
    } finally {
        if (Test-Path -LiteralPath $workRoot) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force
        }
    }
}

function Invoke-ServiceInstall {
    if (-not $Service) {
        Write-Output "oraclemcp installer: service install skipped"
        return
    }
    if (-not $Yes) {
        Write-InstallFailure "service install requires -Service -Yes or -DryRun"
    }
    $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    $serviceArguments = @(Get-ServiceArgument)
    & $oraclemcp @serviceArguments
    if ($LASTEXITCODE -ne 0) {
        Write-InstallFailure "service install failed"
    }

    $readyz = Get-ReadyzUrl
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            Invoke-WebRequest -Uri $readyz -UseBasicParsing -TimeoutSec 2 | Out-Null
            Write-Output "oraclemcp installer: service ready at $readyz"
            return
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    Write-InstallFailure "service installed but /readyz did not become healthy at $readyz"
}

function Invoke-Main {
    $script:Version = Get-NormalizedVersion -InputVersion $Version
    if ([string]::IsNullOrWhiteSpace($Prefix)) {
        $script:Prefix = Get-DefaultPrefix
    }
    if ([string]::IsNullOrWhiteSpace($BinDir)) {
        $script:BinDir = Join-Path -Path $Prefix -ChildPath "bin"
    }

    if ($DryRun) {
        Write-InstallPlan
        return
    }

    Invoke-PrebuiltInstall
    Invoke-InstallCompletionSet
    Invoke-ServiceInstall
    Write-Output "oraclemcp installer: installed $(Join-Path -Path $BinDir -ChildPath "oraclemcp.exe") and $(Join-Path -Path $BinDir -ChildPath "om.exe")"
}

Invoke-Main
