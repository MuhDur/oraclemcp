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
    [string]$Verify = "",
    [string]$TrustedRoot = "",
    [switch]$Update,
    [switch]$Uninstall,
    [switch]$NoCompletions,
    [switch]$Service,
    [switch]$NoService,
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
$script:VerifyPosture = "prefer"

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
    $pattern = "^(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:-(?<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+(?<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
    $match = [regex]::Match($normalized, $pattern)
    if (-not $match.Success) {
        Write-InstallFailure "unsupported version '$InputVersion' (expected latest or strict SemVer, optionally prefixed with v)"
    }
    $prerelease = $match.Groups["prerelease"].Value
    if (-not [string]::IsNullOrEmpty($prerelease)) {
        foreach ($identifier in ($prerelease -split "\.")) {
            if ($identifier -match "^[0-9]+$" -and $identifier.Length -gt 1 -and $identifier.StartsWith("0")) {
                Write-InstallFailure "unsupported version '$InputVersion' (numeric prerelease identifiers cannot have leading zeroes)"
            }
        }
    }
    return $normalized
}

function Assert-CanonicalRepository {
    param([Parameter(Mandatory = $true)][string]$Repository)
    $match = [regex]::Match(
        $Repository,
        "^(?<owner>[A-Za-z0-9][A-Za-z0-9-]{0,38})/(?<name>[A-Za-z0-9][A-Za-z0-9._-]{0,99})$"
    )
    if (-not $match.Success) {
        Write-InstallFailure "unsupported repository '$Repository' (expected one canonical GitHub owner/repository slug)"
    }
    $owner = $match.Groups["owner"].Value
    if ($owner.EndsWith("-") -or $owner.Contains("--")) {
        Write-InstallFailure "unsupported repository '$Repository' (GitHub owner contains a non-canonical hyphen)"
    }
}

function Get-NormalizedVerifyPosture {
    param([string]$InputPosture)
    $candidate = $InputPosture
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = $env:ORACLEMCP_INSTALL_VERIFY
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = "prefer"
    }
    $candidate = $candidate.ToLowerInvariant()
    if ($candidate -notin @("require", "prefer", "checksum-only")) {
        Write-InstallFailure "unsupported -Verify posture '$InputPosture' (expected require, prefer, or checksum-only)"
    }
    return $candidate
}

function Get-SemverPart {
    param([Parameter(Mandatory = $true)][string]$InputVersion)
    $normalized = Get-NormalizedVersion -InputVersion $InputVersion
    if ($normalized -eq "latest") {
        Write-InstallFailure "unsupported semantic version '$InputVersion'"
    }
    $withoutBuild = ($normalized -split "\+", 2)[0]
    $segments = $withoutBuild -split "-", 2
    $core = $segments[0] -split "\."
    $prerelease = @()
    if ($segments.Count -eq 2) {
        $prerelease = @($segments[1] -split "\.")
    }
    return [PSCustomObject]@{
        Core = @($core)
        Prerelease = @($prerelease)
    }
}

function Compare-DecimalIdentifier {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )
    if ($Left.Length -gt $Right.Length) { return 1 }
    if ($Left.Length -lt $Right.Length) { return -1 }
    return [Math]::Sign([string]::CompareOrdinal($Left, $Right))
}

function Compare-Semver {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )
    $leftParts = Get-SemverPart -InputVersion $Left
    $rightParts = Get-SemverPart -InputVersion $Right
    for ($index = 0; $index -lt 3; $index++) {
        $comparison = Compare-DecimalIdentifier -Left $leftParts.Core[$index] -Right $rightParts.Core[$index]
        if ($comparison -ne 0) { return $comparison }
    }
    if ($leftParts.Prerelease.Count -eq 0 -and $rightParts.Prerelease.Count -eq 0) { return 0 }
    if ($leftParts.Prerelease.Count -eq 0) { return 1 }
    if ($rightParts.Prerelease.Count -eq 0) { return -1 }
    $count = [Math]::Max($leftParts.Prerelease.Count, $rightParts.Prerelease.Count)
    for ($index = 0; $index -lt $count; $index++) {
        if ($index -ge $leftParts.Prerelease.Count) { return -1 }
        if ($index -ge $rightParts.Prerelease.Count) { return 1 }
        $leftIdentifier = $leftParts.Prerelease[$index]
        $rightIdentifier = $rightParts.Prerelease[$index]
        if ($leftIdentifier -ceq $rightIdentifier) { continue }
        $leftNumeric = $leftIdentifier -match "^[0-9]+$"
        $rightNumeric = $rightIdentifier -match "^[0-9]+$"
        if ($leftNumeric -and $rightNumeric) {
            return (Compare-DecimalIdentifier -Left $leftIdentifier -Right $rightIdentifier)
        }
        if ($leftNumeric) { return -1 }
        if ($rightNumeric) { return 1 }
        return [Math]::Sign([string]::CompareOrdinal($leftIdentifier, $rightIdentifier))
    }
    return 0
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

function Resolve-LatestVersion {
    if ($Version -ne "latest") {
        return
    }
    if (-not [string]::IsNullOrWhiteSpace($Offline)) {
        Write-InstallFailure "-Offline requires an explicit -Version so signature identity is exact"
    }
    $latestUrl = "https://github.com/$Repo/releases/latest"
    $finalUrl = Resolve-HttpsUri -Uri $latestUrl
    $tagPrefix = "https://github.com/$Repo/releases/tag/v"
    if (-not $finalUrl.StartsWith($tagPrefix, [System.StringComparison]::Ordinal)) {
        Write-InstallFailure "latest release redirected outside the expected HTTPS repository tag URL: $finalUrl"
    }
    $resolved = $finalUrl.Substring($tagPrefix.Length)
    if ($resolved -match "[/\\?#]") {
        Write-InstallFailure "latest release resolved to a malformed tag URL: $finalUrl"
    }
    $script:Version = Get-NormalizedVersion -InputVersion $resolved
}

function Get-ArchiveName {
    return "oraclemcp-$Target.zip"
}

function Get-CosignIdentityArgument {
    if ($Version -eq "latest") {
        Write-InstallFailure "release version must be resolved before constructing the signing identity"
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

function Test-InteractiveInstall {
    return (-not [Console]::IsInputRedirected) -and [Environment]::UserInteractive -and [string]::IsNullOrWhiteSpace($env:CI)
}

function Read-InstallerConsent {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [bool]$DefaultYes = $false,
        [bool]$HonorYes = $true
    )
    if ($HonorYes -and $Yes) {
        return $true
    }
    if (-not (Test-InteractiveInstall)) {
        return $false
    }
    $suffix = "[y/N]"
    if ($DefaultYes) {
        $suffix = "[Y/n]"
    }
    $answer = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $DefaultYes
    }
    return $answer -match "^(?i:y|yes)$"
}

function Test-BinDirOnPath {
    $segments = @()
    if (-not [string]::IsNullOrWhiteSpace($env:PATH)) {
        $segments += ($env:PATH -split ";")
    }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not [string]::IsNullOrWhiteSpace($userPath)) {
        $segments += ($userPath -split ";")
    }
    $normalizedBin = [System.IO.Path]::GetFullPath($BinDir).TrimEnd("\")
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }
        try {
            if ([System.IO.Path]::GetFullPath($segment).TrimEnd("\") -ieq $normalizedBin) {
                return $true
            }
        } catch {
            Write-Verbose ("oraclemcp installer: ignoring invalid PATH segment '{0}': {1}" -f $segment, $_.Exception.Message)
        }
    }
    return $false
}

function Get-PathAppendCommand {
    $escapedBinDir = $BinDir -replace "'", "''"
    return "[Environment]::SetEnvironmentVariable('Path', '$escapedBinDir;' + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
}

function Add-BinDirToUserPath {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        [Environment]::SetEnvironmentVariable("Path", $BinDir, "User")
    } elseif (-not (Test-BinDirOnPath)) {
        [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
    }
    Write-Output "oraclemcp installer: appended $BinDir to the user PATH"
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
    Write-Output "  update: $([bool]$Update)"
    Write-Output "  verify: $VerifyPosture"

    if (-not [string]::IsNullOrWhiteSpace($Offline)) {
        Write-Output "  offline_archive: $Offline"
        Write-Output "  offline_checksum: $Offline.sha256"
        Write-Output "  offline_cosign_signature: $Offline.sigstore.json"
        Write-Output "  offline_cosign_attestation: $Offline.attestation.sigstore.json"
        if (-not [string]::IsNullOrWhiteSpace($TrustedRoot)) {
            Write-Output "  offline_sigstore_trusted_root: $TrustedRoot"
        } elseif ($VerifyPosture -ne "checksum-only") {
            Write-Output "  offline_sigstore_trusted_root: required for cosign verification; pass -TrustedRoot or ORACLEMCP_SIGSTORE_TRUSTED_ROOT"
        }
    } else {
        Write-Output "  archive: $baseUrl/$asset"
        Write-Output "  checksum: $baseUrl/$asset.sha256"
        Write-Output "  cosign_signature: $baseUrl/$asset.sigstore.json"
        Write-Output "  cosign_attestation: $baseUrl/$asset.attestation.sigstore.json"
    }
    if ($VerifyPosture -eq "require") {
        Write-Output "  sha256_note: checksum verifies transport integrity; cosign authenticity/provenance verification is required"
    } elseif ($VerifyPosture -eq "checksum-only") {
        Write-Output "  sha256_note: checksum verifies transport integrity only; cosign authenticity/provenance is intentionally skipped"
    } else {
        Write-Output "  sha256_note: checksum verifies transport integrity; cosign verifies authenticity/provenance when available"
    }
    # Keep the plan honest about what the real run will do: without cosign the
    # run soft-skips the authenticity check (prefer) or fails closed (require).
    if (-not (Test-CommandAvailable -Name "cosign")) {
        if ($VerifyPosture -eq "require") {
            Write-Output "  cosign: not installed - the real run will fail closed (ORACLEMCP_INSTALL_COSIGN_REQUIRED); install cosign before rerunning"
        } elseif ($VerifyPosture -eq "prefer") {
            Write-Output "  cosign: not installed - authenticity check will be skipped (SHA-256 still enforced); install cosign or use -Verify require to change this"
        }
    }

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

function Write-UninstallPlan {
    Write-Output "oraclemcp Windows uninstall plan"
    Write-Output "  prefix: $Prefix"
    Write-Output "  bin_dir: $BinDir"
    Write-Output "  files:"
    Write-Output "    $(Join-Path -Path $BinDir -ChildPath "oraclemcp.exe")"
    Write-Output "    $(Join-Path -Path $BinDir -ChildPath "om.exe")"
    if (-not $NoCompletions) {
        Get-CompletionPath | ForEach-Object { Write-Output "    $_" }
    }
    if ($Service) {
        Write-Output "  service:"
        Write-Output "    unit: $(Get-ServiceUnitDescription)"
        $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
        $uninstallArguments = @("service", "uninstall", "--yes", "--name", $ServiceName)
        $command = Format-CommandLine -File $oraclemcp -Argument $uninstallArguments
        Write-Output "    command: $command"
    } else {
        Write-Output "  service: not requested; no service-manager files or units will be touched"
    }
}

function Assert-HttpsUri {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $parsed = $null
    if (-not [System.Uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref]$parsed) -or $parsed.Scheme -ne "https") {
        Write-InstallFailure "download URI must use HTTPS: $Uri"
    }
}

function Get-ResponseFinalUri {
    param([Parameter(Mandatory = $true)]$Response)
    $baseResponse = $Response.BaseResponse
    $responseUriProperty = $baseResponse.PSObject.Properties["ResponseUri"]
    if ($null -ne $responseUriProperty -and $null -ne $responseUriProperty.Value) {
        return $responseUriProperty.Value.AbsoluteUri
    }
    $requestMessageProperty = $baseResponse.PSObject.Properties["RequestMessage"]
    if ($null -ne $requestMessageProperty -and $null -ne $requestMessageProperty.Value.RequestUri) {
        return $requestMessageProperty.Value.RequestUri.AbsoluteUri
    }
    Write-InstallFailure "downloader did not expose the final response URI"
}

function Resolve-HttpsUri {
    param([Parameter(Mandatory = $true)][string]$Uri)
    Assert-HttpsUri -Uri $Uri
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 30
            $finalUri = Get-ResponseFinalUri -Response $response
            Assert-HttpsUri -Uri $finalUri
            return $finalUri
        } catch {
            if ($attempt -eq 4) {
                Write-InstallFailure "HTTPS resolution failed after 4 bounded attempts: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds $attempt
        }
    }
}

function Invoke-DownloadFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    $finalUri = Resolve-HttpsUri -Uri $Uri
    $parent = Split-Path -Path $OutFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            Invoke-WebRequest -Uri $finalUri -OutFile $OutFile -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 120
            return
        } catch {
            if ($attempt -eq 4) {
                Write-InstallFailure "HTTPS download failed after 4 bounded attempts: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds $attempt
        }
    }
}

function Get-ChecksumDigest {
    param(
        [Parameter(Mandatory = $true)][string]$ChecksumFile,
        [Parameter(Mandatory = $true)][string]$Archive
    )
    if (-not (Test-Path -LiteralPath $ChecksumFile -PathType Leaf)) {
        Write-InstallFailure "missing checksum file: $ChecksumFile"
    }
    $lines = @(Get-Content -LiteralPath $ChecksumFile)
    if ($lines.Count -ne 1) {
        Write-InstallFailure "checksum sidecar must contain exactly one record"
    }
    $match = [regex]::Match($lines[0], "^(?<digest>[0-9A-Fa-f]{64}) [ *](?<name>[^\s]+)$")
    if (-not $match.Success) {
        Write-InstallFailure "checksum sidecar record is malformed"
    }
    $archiveName = [System.IO.Path]::GetFileName($Archive)
    if ($match.Groups["name"].Value -cne $archiveName) {
        Write-InstallFailure "checksum sidecar must name the selected archive $archiveName"
    }
    return $match.Groups["digest"].Value.ToLowerInvariant()
}

function Test-ArchiveChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$ChecksumFile
    )
    $expected = Get-ChecksumDigest -ChecksumFile $ChecksumFile -Archive $Archive
    $actual = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -notmatch "^[0-9a-f]{64}$") {
        Write-InstallFailure "SHA-256 command returned malformed output for $Archive"
    }
    if ($actual -ne $expected) {
        Write-InstallFailure "checksum mismatch for $Archive (expected $expected, got $actual)"
    }
    Write-Output "oraclemcp installer: SHA-256 verified"
}

function Test-CosignEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$SignatureBundle,
        [Parameter(Mandatory = $true)][string]$AttestationBundle
    )
    if ($VerifyPosture -eq "checksum-only") {
        Write-Output "oraclemcp installer: cosign verification intentionally skipped by -Verify checksum-only"
        return
    }
    if (-not (Test-CommandAvailable -Name "cosign")) {
        if ($VerifyPosture -eq "require") {
            Write-InstallFailure "cosign is required by -Verify require; install cosign or rerun with -Verify prefer/checksum-only"
        }
        Write-Output "oraclemcp installer: authenticity unverified: cosign not installed; SHA-256 checksum verified"
        return
    }
    if (-not [string]::IsNullOrWhiteSpace($Offline) -and [string]::IsNullOrWhiteSpace($TrustedRoot)) {
        Write-InstallFailure "ORACLEMCP_INSTALL_TRUSTED_ROOT_REQUIRED: offline cosign verification requires -TrustedRoot or ORACLEMCP_SIGSTORE_TRUSTED_ROOT"
    }
    $trustedRootArguments = @()
    if (-not [string]::IsNullOrWhiteSpace($TrustedRoot)) {
        if (-not (Test-Path -LiteralPath $TrustedRoot -PathType Leaf)) {
            Write-InstallFailure "required Sigstore trusted root is missing: $TrustedRoot"
        }
        $trustedRootArguments = @("--trusted-root", $TrustedRoot)
    }
    $identityArguments = @(Get-CosignIdentityArgument)
    & cosign verify-blob --bundle $SignatureBundle @trustedRootArguments @identityArguments --certificate-oidc-issuer $OidcIssuer $Archive
    if ($LASTEXITCODE -ne 0) {
        Write-InstallFailure "cosign verify-blob failed for $Archive"
    }
    & cosign verify-blob-attestation --bundle $AttestationBundle --type slsaprovenance1 @trustedRootArguments @identityArguments --certificate-oidc-issuer $OidcIssuer $Archive
    if ($LASTEXITCODE -ne 0) {
        Write-InstallFailure "cosign verify-blob-attestation failed for $Archive"
    }
}

function Test-ShouldFetchCosignEvidence {
    if ($VerifyPosture -eq "require") {
        return $true
    }
    if ($VerifyPosture -eq "checksum-only") {
        return $false
    }
    return (Test-CommandAvailable -Name "cosign")
}

function Test-OfflineBundle {
    param([Parameter(Mandatory = $true)][string]$Archive)
    $expected = Get-ArchiveName
    if ((Split-Path -Path $Archive -Leaf) -ne $expected) {
        Write-InstallFailure "ORACLEMCP_INSTALL_OFFLINE_TARGET_MISMATCH: expected offline archive named $expected for target $Target"
    }
    $required = @($Archive, "$Archive.sha256")
    if (Test-ShouldFetchCosignEvidence) {
        if ([string]::IsNullOrWhiteSpace($TrustedRoot)) {
            Write-InstallFailure "ORACLEMCP_INSTALL_TRUSTED_ROOT_REQUIRED: offline cosign verification requires -TrustedRoot or ORACLEMCP_SIGSTORE_TRUSTED_ROOT"
        }
        $required += @($TrustedRoot, "$Archive.sigstore.json", "$Archive.attestation.sigstore.json")
    }
    foreach ($path in $required) {
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

function Get-InstalledVersion {
    $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    if (-not (Test-Path -LiteralPath $oraclemcp -PathType Leaf)) {
        return ""
    }
    try {
        $output = & $oraclemcp --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            return ""
        }
        $text = ($output | Select-Object -First 1).ToString()
        if ($text -match "^oraclemcp\s+(?<version>\S+)") {
            return $Matches.version
        }
    } catch {
        return ""
    }
    return ""
}

function Get-SafeBackupVersion {
    param([AllowEmptyString()][string]$InstalledVersion = "")
    if ([string]::IsNullOrWhiteSpace($InstalledVersion) -or
        $InstalledVersion -in @("latest", ".", "..") -or
        $InstalledVersion.Contains("/") -or
        $InstalledVersion.Contains("\")) {
        return "unknown"
    }
    try {
        $normalized = Get-NormalizedVersion -InputVersion $InstalledVersion
        if ($normalized -cne $InstalledVersion) {
            return "unknown"
        }
        return $normalized
    } catch {
        return "unknown"
    }
}

function Assert-NotDowngrade {
    if ($Force -or $Version -eq "latest") {
        return
    }
    $installed = Get-InstalledVersion
    if ([string]::IsNullOrWhiteSpace($installed)) {
        return
    }
    if ((Compare-Semver -Left $installed -Right $Version) -gt 0) {
        Write-InstallFailure "ORACLEMCP_INSTALL_DOWNGRADE_REFUSED: installed oraclemcp $installed is newer than target $Version; rerun with -Force only if you intentionally want to downgrade"
    }
}

function Backup-ExistingFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    $installed = Get-SafeBackupVersion -InstalledVersion (Get-InstalledVersion)
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $backupDir = Join-Path -Path $Prefix -ChildPath "backups"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $backupPath = Join-Path -Path $backupDir -ChildPath "$Name-$installed-$stamp"
    Copy-Item -LiteralPath $Path -Destination $backupPath -Force
    Write-Output "oraclemcp installer: backed up previous $Name to $backupPath"
}

function Install-ExecutableAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Name
    )
    Invoke-EnsureParentDirectory -Path $Destination
    if ((Test-Path -LiteralPath $Destination -PathType Leaf) -and
        ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash)) {
        Write-Output "oraclemcp installer: already current: $Destination matches release archive"
        return
    }
    Backup-ExistingFile -Path $Destination -Name $Name
    $tmp = Join-Path -Path (Split-Path -Path $Destination -Parent) -ChildPath ".$Name.tmp.$PID"
    Copy-Item -LiteralPath $Source -Destination $tmp -Force
    Move-Item -LiteralPath $tmp -Destination $Destination -Force
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
    Assert-NotDowngrade
    Install-ExecutableAtomically -Source $sourceOraclemcp -Destination $destOraclemcp -Name "oraclemcp.exe"
    Install-ExecutableAtomically -Source $sourceOm -Destination $destOm -Name "om.exe"
}

function Invoke-InstallCompletion {
    param(
        [Parameter(Mandatory = $true)][string]$CommandPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Invoke-EnsureParentDirectory -Path $Destination
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
    Resolve-LatestVersion
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
            $signatureBundle = "$archive.sigstore.json"
            $attestationBundle = "$archive.attestation.sigstore.json"
        } else {
            $archive = Join-Path -Path $workRoot -ChildPath $asset
            $checksum = "$archive.sha256"
            $signatureBundle = "$archive.sigstore.json"
            $attestationBundle = "$archive.attestation.sigstore.json"
            Invoke-DownloadFile -Uri "$baseUrl/$asset" -OutFile $archive
            Invoke-DownloadFile -Uri "$baseUrl/$asset.sha256" -OutFile $checksum
            if (Test-ShouldFetchCosignEvidence) {
                Invoke-DownloadFile -Uri "$baseUrl/$asset.sigstore.json" -OutFile $signatureBundle
                Invoke-DownloadFile -Uri "$baseUrl/$asset.attestation.sigstore.json" -OutFile $attestationBundle
            }
        }

        Test-ArchiveChecksum -Archive $archive -ChecksumFile $checksum
        Test-CosignEvidence -Archive $archive -SignatureBundle $signatureBundle -AttestationBundle $attestationBundle
        Expand-Archive -LiteralPath $archive -DestinationPath $workRoot -Force
        Invoke-InstallBinary -ExtractRoot $workRoot
    } finally {
        if (Test-Path -LiteralPath $workRoot) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force
        }
    }
}

function Invoke-ServiceInstall {
    $promptedService = $false
    if ((-not $Service) -and (-not $NoService)) {
        $promptedService = Read-InstallerConsent -Prompt "Install and start the local oraclemcp service now?" -DefaultYes $false -HonorYes $false
    }
    if ((-not $Service) -and (-not $promptedService)) {
        Write-Output "oraclemcp installer: service install skipped"
        return
    }
    if ($Service -and (-not $Yes)) {
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

function Invoke-Uninstall {
    if (-not $Yes) {
        Write-InstallFailure "uninstall requires -Yes or -DryRun"
    }
    if ($Service) {
        $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
        if (Test-Path -LiteralPath $oraclemcp -PathType Leaf) {
            & $oraclemcp service uninstall --yes --name $ServiceName
            if ($LASTEXITCODE -ne 0) {
                Write-InstallFailure "service uninstall failed"
            }
        } else {
            Write-Output "oraclemcp installer: service uninstall requested but $oraclemcp is absent"
        }
    }
    foreach ($path in @(
            (Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"),
            (Join-Path -Path $BinDir -ChildPath "om.exe")
        )) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
            Write-Output "oraclemcp installer: removed $path"
        }
    }
    if (-not $NoCompletions) {
        foreach ($path in @(Get-CompletionPath)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force
                Write-Output "oraclemcp installer: removed $path"
            }
        }
    }
}

function Write-PathGuidance {
    if (Test-BinDirOnPath) {
        return
    }
    $command = Get-PathAppendCommand
    Write-Output "oraclemcp installer: $BinDir is not on PATH"
    Write-Output "oraclemcp installer: add it for future PowerShell sessions:"
    Write-Output "  $command"
    if (Read-InstallerConsent -Prompt "Add $BinDir to the user PATH?" -DefaultYes $false) {
        Add-BinDirToUserPath
    } else {
        Write-Output "oraclemcp installer: PATH update skipped"
    }
}

function Invoke-OptionalDoctor {
    if (-not (Read-InstallerConsent -Prompt "Run oraclemcp doctor now?" -DefaultYes $true)) {
        Write-Output "oraclemcp installer: doctor skipped"
        return
    }
    $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    & $oraclemcp --json doctor
    if ($LASTEXITCODE -ne 0) {
        Write-Output "oraclemcp installer: doctor reported issues; continue with the next-step commands below"
    }
}

# Offer zero-config TNS discovery, defaulting to No. The installer never scans
# or parses tnsnames.ora itself: it delegates to `oraclemcp setup --discover`,
# which carries the fail-closed consent gate and writes READ_ONLY profiles
# through config-ops. Parity with the Unix installer's maybe_offer_discovery.
function Invoke-OptionalDiscovery {
    if (-not (Test-InteractiveInstall)) {
        Write-Output "oraclemcp installer: discovery skipped (run 'oraclemcp setup --discover' anytime)"
        return
    }
    if (-not (Read-InstallerConsent -Prompt "Discover databases from tnsnames.ora now?" -DefaultYes $false)) {
        Write-Output "oraclemcp installer: discovery skipped (run 'oraclemcp setup --discover' anytime)"
        return
    }
    $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    & $oraclemcp setup --discover
    if ($LASTEXITCODE -ne 0) {
        Write-Output "oraclemcp installer: discovery reported issues; re-run 'oraclemcp setup --discover'"
    }
}

function Write-ClientSnippet {
    $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    Write-Output "oraclemcp installer: MCP client snippet (stdio)"
    Write-Output "{"
    Write-Output '  "mcpServers": {'
    Write-Output '    "oracle": {'
    Write-Output "      `"command`": `"$oraclemcp`","
    Write-Output '      "args": ["serve", "--profile", "db_ro"]'
    Write-Output '    }'
    Write-Output '  }'
    Write-Output "}"
}

function Invoke-OptionalClientSnippet {
    if (Read-InstallerConsent -Prompt "Print an MCP client wiring snippet now?" -DefaultYes $true) {
        Write-ClientSnippet
    } else {
        Write-Output "oraclemcp installer: MCP client snippet skipped"
    }
}

function Write-NextStep {
    $oraclemcp = Join-Path -Path $BinDir -ChildPath "oraclemcp.exe"
    Write-Output "oraclemcp installer: next steps"
    Write-Output "  * Fastest path: discover databases from tnsnames.ora: $oraclemcp setup --discover"
    Write-Output "  1. Run doctor: $oraclemcp --json doctor"
    Write-Output "  2. Write a starter profile: $oraclemcp --json setup --write --profile db_ro"
    Write-Output "  3. Generate MCP client snippets: $oraclemcp --json setup --profile db_ro"
}

function Invoke-Main {
    $script:Version = Get-NormalizedVersion -InputVersion $Version
    $script:VerifyPosture = Get-NormalizedVerifyPosture -InputPosture $Verify
    if ([string]::IsNullOrWhiteSpace($TrustedRoot) -and -not [string]::IsNullOrWhiteSpace($env:ORACLEMCP_SIGSTORE_TRUSTED_ROOT)) {
        $script:TrustedRoot = $env:ORACLEMCP_SIGSTORE_TRUSTED_ROOT
    }
    Assert-CanonicalRepository -Repository $Repo
    if (-not [string]::IsNullOrWhiteSpace($Offline) -and $Version -eq "latest") {
        Write-InstallFailure "-Offline requires an explicit -Version so signature identity is exact"
    }
    if ([string]::IsNullOrWhiteSpace($Prefix)) {
        $script:Prefix = Get-DefaultPrefix
    }
    if ([string]::IsNullOrWhiteSpace($BinDir)) {
        $script:BinDir = Join-Path -Path $Prefix -ChildPath "bin"
    }

    if ($Uninstall -and $Update) {
        Write-InstallFailure "-Uninstall cannot be combined with -Update"
    }
    if ($NoService) {
        $script:Service = $false
    }

    if ($DryRun) {
        if ($Uninstall) {
            Write-UninstallPlan
            return
        }
        Write-InstallPlan
        return
    }

    if ($Uninstall) {
        Invoke-Uninstall
        return
    }

    Invoke-PrebuiltInstall
    Invoke-InstallCompletionSet
    Write-PathGuidance
    Invoke-OptionalDoctor
    Invoke-OptionalDiscovery
    Invoke-OptionalClientSnippet
    Invoke-ServiceInstall
    Write-NextStep
    Write-Output "oraclemcp installer: installed $(Join-Path -Path $BinDir -ChildPath "oraclemcp.exe") and $(Join-Path -Path $BinDir -ChildPath "om.exe")"
}

Invoke-Main
