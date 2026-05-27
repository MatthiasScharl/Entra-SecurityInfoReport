<#
===============================================================================
  DISCLAIMER
===============================================================================
  This script is provided by a Microsoft Security Cloud Solution Architect
  Matthias Scharl (matthias.scharl@microsoft.com) for informational and guidance purposes only.

  It is provided "AS IS" without warranty of any kind, express or implied,
  including but not limited to warranties of merchantability, fitness for a
  particular purpose, or non-infringement. Microsoft and the author assume no
  liability for any damages arising from the use of this script.

  The CUSTOMER is solely responsible for:
    - Reviewing and understanding the script before execution.
    - Testing the script in a non-production environment first.
    - Ensuring compliance with their organisation's security policies.
    - Any consequences resulting from running this script.

  Use of this script in a production environment is at the customer's own risk.

-------------------------------------------------------------------------------
  AI TRANSPARENCY NOTICE
-------------------------------------------------------------------------------
  This script was generated with the assistance of GitHub Copilot, powered by
  GitHub Copilot, as part of a Microsoft-assisted engagement.

  In line with Microsoft's Responsible AI principles — particularly the
  principle of Transparency — this notice is included to ensure you are aware
  that AI tooling contributed to the creation of this artifact.

  All AI-generated output should be reviewed by a qualified professional before
  use. The author has reviewed this script; however, independent verification
  by the customer is strongly recommended.

  Learn more: https://www.microsoft.com/en-us/ai/responsible-ai
===============================================================================
#>

#Requires -Version 7.2

<#
.SYNOPSIS
    Collects authentication method / security info data from Microsoft Graph and generates
    a self-contained, filterable HTML report.

.DESCRIPTION
    Get-SecurityInfoReport.ps1 operates in two modes:

    COLLECT MODE (default — no -JsonPath)
      Connects to Microsoft Graph, enumerates users, and retrieves each user's
      registered authentication methods. Results are saved to a timestamped
      JSON file and an HTML report is generated in the same step.

    REPORT MODE (-JsonPath)
      Reads an existing JSON snapshot produced by a previous collect run and
      regenerates the HTML report without re-querying the tenant. Useful for
      re-running report generation with a different title or sharing the
      report file.

    The HTML report includes:
      - Summary cards: total users, MFA registered %, no-MFA count, and a
        per-method-type breakdown.
      - Quick filter buttons: All, No MFA, Registered, and per method type.
      - Sortable, searchable DataTable showing principal, account details,
        MFA status, and method badges with hover detail (device names, phone
        numbers, FIDO2 vendor/model, etc.).
      - Export to CSV and Excel.

    Method types reported:
      Microsoft Authenticator  — device name, authentication type
      Software OATH / TOTP     — registered only (app not identifiable via API)
      FIDO2 Security Key       — display name, AAGUID mapped to vendor/model
      Phone (SMS / Voice)      — phone number, type, SMS sign-in state
      Email OTP                — email address
      Windows Hello for Business — device name
      Temporary Access Pass    — usability status, lifetime in minutes
      Password                 — presence only (not counted as MFA)

.PARAMETER TenantId
    [Collect mode] Entra ID / Azure AD tenant GUID. If omitted, the identity
    picker will present the tenants available to the signed-in account.

.PARAMETER ExcludeGuestUsers
    [Collect mode] Exclude guest accounts from the report. By default both
    member and guest accounts are included.

.PARAMETER ExcludeDisabledAccounts
    [Collect mode] Exclude disabled accounts from the report. By default both
    enabled and disabled accounts are included.

.PARAMETER JsonOutputPath
    [Collect mode] Full file path for the JSON snapshot.
    Default: SecurityInfoReport-<timestamp>.json in the script directory.

.PARAMETER ThrottleLimit
    [Collect mode] Accepted for backward compatibility. Per-user Graph requests
    are processed sequentially with exponential-backoff retry (up to 3 attempts).
    Valid range: 1–20. Default: 10.

.PARAMETER JsonPath
    [Report mode] Path to an existing JSON snapshot. When provided, no Graph
    connection is required and no new JSON is written.

.PARAMETER Title
    Report title shown in the browser tab and page header.
    Default: 'Security Info Report'.

.PARAMETER OutputPath
    Destination for the HTML report. Accepts:
      - A folder path  → HTML is auto-named SecurityInfoReport-<timestamp>.html
      - A .html path   → used as the exact output file path
    Default: script directory.

.PARAMETER NoOpen
    Suppresses automatically opening the HTML report in the default browser.

.EXAMPLE
    .\Get-SecurityInfoReport.ps1

    Collect from the tenant of the currently signed-in account and open the report.

.EXAMPLE
    .\Get-SecurityInfoReport.ps1 -TenantId '<tenant-id>' -ExcludeDisabledAccounts

    Collect enabled accounts only (guests and members).

.EXAMPLE
    .\Get-SecurityInfoReport.ps1 -TenantId '<tenant-id>' -ExcludeGuestUsers -ExcludeDisabledAccounts

    Collect enabled member accounts only.

.EXAMPLE
    .\Get-SecurityInfoReport.ps1 -JsonPath '.\SecurityInfoReport-20260423-120000.json'

    Regenerate the HTML report from an existing JSON snapshot.

.EXAMPLE
    .\Get-SecurityInfoReport.ps1 -NoOpen

    Collect and generate the report without opening the browser (e.g. for unattended runs).

.EXAMPLE
    .\Get-SecurityInfoReport.ps1 -JsonPath '.\SecurityInfoReport-20260423-120000.json' `
                        -Title 'Contoso — Security Info Report' `
                        -OutputPath 'C:\Reports\security-info-report.html'

    Custom title and output path from a JSON snapshot.

.EXAMPLE
    .\Get-SecurityInfoReport.ps1 -TenantId '<tenant-id>' -ThrottleLimit 20

    Collect from a large tenant using the maximum parallelism (20 concurrent Graph requests).
    Recommended for tenants with 10 000+ users to reduce overall collection time.

.NOTES
    Minimum required role  : Authentication Administrator or Global Reader
    Microsoft Graph scopes : User.Read.All, UserAuthenticationMethod.Read.All

    Internet access is required to render the HTML report (CDN assets):
      Bootstrap 5  : https://getbootstrap.com
      DataTables   : https://datatables.net
      jQuery       : https://jquery.com

    References:
      Authentication methods API : https://learn.microsoft.com/en-us/graph/api/authentication-list-methods
      User.Read.All permission   : https://learn.microsoft.com/en-us/graph/permissions-reference#userreadall
      UserAuthenticationMethod.Read.All : https://learn.microsoft.com/en-us/graph/permissions-reference#userauthenticationmethodreadall
      Authentication Administrator role : https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#authentication-administrator
#>

#region PARAMETERS & INITIALISATION
[CmdletBinding(DefaultParameterSetName = 'Collect')]
param (
    # ── Collect mode ──────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = 'Collect')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $TenantId,

    [Parameter(ParameterSetName = 'Collect')]
    [switch] $ExcludeGuestUsers,

    [Parameter(ParameterSetName = 'Collect')]
    [switch] $ExcludeDisabledAccounts,

    [Parameter(ParameterSetName = 'Collect')]
    [string] $JsonOutputPath,

    [Parameter(ParameterSetName = 'Collect')]
    [ValidateRange(1, 20)]
    [int] $ThrottleLimit = 10,

    # ── Report mode ───────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = 'FromJson', Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string] $JsonPath,

    # ── Common ────────────────────────────────────────────────────────────────
    [Parameter()]
    [string] $Title = 'Security Info Report',

    [Parameter()]
    [string] $OutputPath,

    [Parameter()]
    [switch] $NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure required modules are available — install from PSGallery if missing
foreach ($moduleName in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Host "Module '$moduleName' not found. Installing from PSGallery..." -ForegroundColor Yellow
        Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
        Write-Host "Module '$moduleName' installed." -ForegroundColor Green
    }
}

Add-Type -AssemblyName System.Web

#endregion

#region HELPER FUNCTIONS
# ── FIDO2 AAGUID → vendor/model map ──────────────────────────────────────────
# Source: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor
$script:Fido2VendorMap = @{
    'cb69481e-8ff7-4039-93ec-0a2729a154a8' = 'YubiKey 5 Series'
    'ee882879-721c-4913-9775-3dfcce97072a' = 'YubiKey 5 FIPS Series'
    'fa2b99dc-9e39-4257-8f92-4a30d23c4118' = 'YubiKey 5Ci'
    '149a2021-8ef6-4133-96b8-81f8d5b7f1f5' = 'Security Key NFC by Yubico'
    '73402251-f2a8-4f03-873e-3cb6db604b03' = 'YubiKey Bio'
    'b92c3f9a-c014-4056-887f-140a2501163b' = 'Security Key by Yubico'
    'f8a011f3-8c0a-4d15-8006-17111f9edc7d' = 'Security Key NFC by Yubico'
    '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73' = 'Security Key NFC by Yubico — Enterprise'
    'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd' = 'YubiKey 5 NFC FIPS'
    'a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa' = 'Security Key by Feitian'
    '12ded745-4bed-47d4-abaa-e713f51d6393' = 'Feitian BioPass FIDO2'
    '3e078ffd-4c54-4586-8baa-a77da113aec5' = 'Feitian ePass FIDO'
    '77010bd7-212a-4fc9-b236-d2ca5e9d4084' = 'Feitian BioPass FIDO2 Plus'
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9' = 'Windows Hello (VBS HW)'
    '08987058-cadc-4b81-b6e1-30de50dcbe96' = 'Windows Hello (HW)'
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2' = 'Windows Hello'
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2' = 'Android Authenticator (Credential Manager)'
    'adce0002-35bc-c60a-648b-0b25f1f05503' = 'Chrome on Mac'
    'adce0003-35bc-c60a-648b-0b25f1f05503' = 'Chrome on Windows'
    '17290f1e-baa4-4d56-81c2-8f53d28f455b' = 'IDMELON'
    'be727034-574a-f799-5c76-0929e0430973' = 'Crayonic KeyVault K1'
}

# ── Helper: map one raw Graph method hashtable to a normalised record ─────────
function ConvertTo-MethodDetail {
    param ([object] $Method)

    # Handle both hashtable (collect mode) and PSCustomObject (JSON load mode)
    $get  = { param($k) if ($Method -is [hashtable]) { $Method[$k] } else { $Method.$k } }
    $type = & $get '@odata.type'

    switch ($type) {
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
            $device = (& $get 'displayName') ?? ''
            $authType = (& $get 'authenticationType') ?? ''
            $detail = if ($device) { "Device: $device" } else { '(no device name)' }
            if ($authType) { $detail += " | Mode: $authType" }
            return [pscustomobject]@{ Type = 'Authenticator'; Label = 'Authenticator'; Color = 'primary';   Detail = $detail }
        }
        '#microsoft.graph.phoneAuthenticationMethod' {
            $phoneType = switch ((& $get 'phoneType')) {
                'mobile'          { 'Mobile' }
                'alternateMobile' { 'Alt Mobile' }
                'office'          { 'Office' }
                default           { (& $get 'phoneType') ?? 'Phone' }
            }
            $detail = "${phoneType}: $((& $get 'phoneNumber') ?? '(unknown)')"
            $smsState = (& $get 'smsSignInState')
            if ($smsState -and $smsState -ne 'notSupported') { $detail += " | SMS: $smsState" }
            return [pscustomobject]@{ Type = 'Phone';         Label = 'Phone';         Color = 'info';      Detail = $detail }
        }
        '#microsoft.graph.fido2AuthenticationMethod' {
            $aaguid = (& $get 'aaGuid') ?? ''
            $vendor  = if ($aaguid -and $script:Fido2VendorMap.ContainsKey($aaguid.ToLower())) {
                $script:Fido2VendorMap[$aaguid.ToLower()]
            } elseif ($aaguid) { "FIDO2 (AAGUID: $aaguid)" }
            else { 'FIDO2 Key' }
            $keyName = (& $get 'displayName') ?? ''
            $detail  = if ($keyName) { "$keyName | $vendor" } else { $vendor }
            return [pscustomobject]@{ Type = 'Fido2';         Label = 'FIDO2';         Color = 'success';   Detail = $detail }
        }
        '#microsoft.graph.emailAuthenticationMethod' {
            $detail = (& $get 'emailAddress') ?? '(unknown)'
            return [pscustomobject]@{ Type = 'Email';         Label = 'Email OTP';     Color = 'warning';   Detail = $detail }
        }
        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
            $device = (& $get 'displayName') ?? '(unknown)'
            return [pscustomobject]@{ Type = 'WHFB';          Label = 'Windows Hello'; Color = 'dark';      Detail = "Device: $device" }
        }
        '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
            $usable   = (& $get 'isUsable') ? 'Usable' : 'Not Usable'
            $lifetime = (& $get 'lifetimeInMinutes')
            $detail   = "Status: $usable" + $(if ($lifetime) { " | Lifetime: ${lifetime}min" } else { '' })
            return [pscustomobject]@{ Type = 'TAP';           Label = 'TAP';           Color = 'secondary'; Detail = $detail }
        }
        '#microsoft.graph.softwareOathAuthenticationMethod' {
            return [pscustomobject]@{ Type = 'SoftwareOath';  Label = 'TOTP';          Color = 'warning';   Detail = 'Software OATH/TOTP (specific app not identifiable via API)' }
        }
        '#microsoft.graph.passwordAuthenticationMethod' {
            return [pscustomobject]@{ Type = 'Password';      Label = 'Password';      Color = 'secondary'; Detail = 'Password registered' }
        }
        default {
            return [pscustomobject]@{ Type = 'Unknown';       Label = 'Unknown';       Color = 'secondary'; Detail = $type ?? 'Unknown method' }
        }
    }
}

# ── Helper: build normalised user record from raw Graph user + methods ─────────
function Build-UserRecord {
    param (
        [object]   $User,
        [object[]] $RawMethods
    )

    $getU = { param($k) if ($User -is [hashtable]) { $User[$k] } else { $User.$k } }

    $methods         = @()
    $hasAuthenticator = $false; $hasFido2 = $false; $hasPhone = $false
    $hasEmail         = $false; $hasWHFB  = $false; $hasTap   = $false
    $hasSoftwareOath  = $false

    foreach ($m in $RawMethods) {
        $detail = ConvertTo-MethodDetail -Method $m
        $methods += $detail
        switch ($detail.Type) {
            'Authenticator' { $hasAuthenticator = $true }
            'Fido2'         { $hasFido2         = $true }
            'Phone'         { $hasPhone         = $true }
            'Email'         { $hasEmail         = $true }
            'WHFB'          { $hasWHFB          = $true }
            'TAP'           { $hasTap           = $true }
            'SoftwareOath'  { $hasSoftwareOath  = $true }
        }
    }

    $hasMFA = $hasAuthenticator -or $hasFido2 -or $hasPhone -or $hasEmail -or
              $hasWHFB -or $hasTap -or $hasSoftwareOath

    # SSPR-capable methods: Authenticator, Phone (SMS/voice), Email OTP, Software OATH
    # Source: https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication
    $ssprCount = ([int]$hasAuthenticator) + ([int]$hasPhone) + ([int]$hasEmail) + ([int]$hasSoftwareOath)

    return [pscustomobject]@{
        UserId            = & $getU 'id'
        DisplayName       = (& $getU 'displayName')       ?? ''
        UserPrincipalName = (& $getU 'userPrincipalName') ?? ''
        UserType          = (& $getU 'userType')          ?? 'Unknown'
        AccountEnabled    = [bool](& $getU 'accountEnabled')
        HasMFA            = $hasMFA
        HasAuthenticator  = $hasAuthenticator
        HasFido2          = $hasFido2
        HasPhone          = $hasPhone
        HasEmail          = $hasEmail
        HasWHFB           = $hasWHFB
        HasSoftwareOath   = $hasSoftwareOath
        HasTap            = $hasTap
        SsprCount         = $ssprCount
        MethodCount       = @($methods | Where-Object { $_.Type -ne 'Password' }).Count
        Methods           = $methods
    }
}

# ── Resolve HTML output path ───────────────────────────────────────────────────
$timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
$reportDir  = Join-Path $scriptDir 'Report'

if ($OutputPath -and $OutputPath.EndsWith('.html', [System.StringComparison]::OrdinalIgnoreCase)) {
    $htmlFile  = $OutputPath
    $parentDir = Split-Path $htmlFile -Parent
    if ($parentDir -and -not (Test-Path $parentDir -PathType Container)) {
        Write-Error "Output directory '$parentDir' does not exist."
        exit 1
    }
} elseif ($OutputPath) {
    if (-not (Test-Path $OutputPath -PathType Container)) {
        Write-Error "OutputPath '$OutputPath' is not a valid directory."
        exit 1
    }
    $htmlFile = Join-Path $OutputPath "SecurityInfoReport-$timestamp.html"
} else {
    if (-not (Test-Path $reportDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $reportDir -Force
        Write-Host "  Created output folder: $reportDir" -ForegroundColor DarkGray
    }
    $htmlFile = Join-Path $reportDir "SecurityInfoReport-$timestamp.html"
}

# ── Import helpers ─────────────────────────────────────────────────────────────
Import-Module "$PSScriptRoot\Entra-Helpers.psm1" -Force

#endregion

#region COLLECT MODE
# ══════════════════════════════════════════════════════════════════════════════
#  COLLECT MODE
# ══════════════════════════════════════════════════════════════════════════════
if ($PSCmdlet.ParameterSetName -eq 'Collect') {

    Write-Step 'Connecting to Microsoft Graph'
    $requiredScopes = @('User.Read.All', 'UserAuthenticationMethod.Read.All')
    Initialize-GraphSession -TenantId $TenantId -RequiredScopes $requiredScopes

    $mgCtx = Get-MgContext
    Write-Host "  Identity : $($mgCtx.Account)" -ForegroundColor DarkGray
    Write-Host "  Tenant   : $($mgCtx.TenantId)" -ForegroundColor DarkGray

    # Build user query URI
    Write-Step 'Enumerating users'
    $filterParts = @()
    if ($ExcludeGuestUsers)            { $filterParts += "userType eq 'Member'" }
    if ($ExcludeDisabledAccounts)      { $filterParts += 'accountEnabled eq true' }

    $queryParts = @()
    if ($filterParts.Count -gt 0) { $queryParts += '$filter=' + ($filterParts -join ' and ') }
    $queryParts += '$select=id,displayName,userPrincipalName,userType,accountEnabled'
    $queryParts += '$top=999'
    $usersUri = 'https://graph.microsoft.com/v1.0/users?' + ($queryParts -join '&')

    $rawUsers = Invoke-GraphPagedRequest -Uri $usersUri
    Write-Success "  Found $($rawUsers.Count) user(s)."

    # Collect authentication methods per user — parallel with exponential-backoff retry
    Write-Step 'Collecting authentication methods'

    # Capture function bodies as strings so they can be recreated in each parallel runspace
    $convertFnDef = "function ConvertTo-MethodDetail { $((Get-Command ConvertTo-MethodDetail).Definition) }"
    $buildFnDef   = "function Build-UserRecord { $((Get-Command Build-UserRecord).Definition) }"
    $fido2MapRef  = $script:Fido2VendorMap
    $totalUsers   = $rawUsers.Count
    $progressBag  = [System.Collections.Concurrent.ConcurrentBag[byte]]::new()

    $userRecords = $rawUsers | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        # Recreate helper functions and shared state in this runspace
        . ([scriptblock]::Create($using:convertFnDef))
        . ([scriptblock]::Create($using:buildFnDef))
        $script:Fido2VendorMap = $using:fido2MapRef

        $rawUser    = $_
        $rawMethods = @()
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $response   = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/users/$($rawUser['id'])/authentication/methods" `
                    -OutputType HashTable -ErrorAction Stop
                $rawMethods = $response['value'] ?? @()
                break
            }
            catch {
                if ($attempt -ge 3) {
                    Write-Warning "  Could not retrieve methods for '$($rawUser['userPrincipalName'])': $_"
                }
                else {
                    Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
                }
            }
        }

        ($using:progressBag).Add(0)
        $done = ($using:progressBag).Count
        Write-Progress -Activity 'Collecting authentication methods' `
                       -Status "$done / $($using:totalUsers)" `
                       -PercentComplete ([int](($done / $($using:totalUsers)) * 100))

        Build-UserRecord -User $rawUser -RawMethods $rawMethods
    }
    Write-Progress -Activity 'Collecting authentication methods' -Completed
    Write-Success "  Collected methods for $(@($userRecords).Count) user(s)."

    # Save JSON snapshot
    Write-Step 'Saving JSON snapshot'
    if (-not $JsonOutputPath -and -not (Test-Path $reportDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $reportDir -Force
        Write-Host "  Created output folder: $reportDir" -ForegroundColor DarkGray
    }
    $jsonFile = if ($JsonOutputPath) { $JsonOutputPath } else { Join-Path $reportDir "SecurityInfoReport-$timestamp.json" }
    @{
        CollectedAt             = (Get-Date -Format 'o')
        TenantId                = $mgCtx.TenantId
        CollectedBy             = $mgCtx.Account
        ExcludeDisabledAccounts = [bool]$ExcludeDisabledAccounts
        ExcludeGuestUsers       = [bool]$ExcludeGuestUsers
        Users                   = $userRecords
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFile -Encoding UTF8
    Write-Success "  JSON: $jsonFile"

    $users    = $userRecords
    $metadata = @{
        CollectedAt             = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        TenantId                = $mgCtx.TenantId
        CollectedBy             = $mgCtx.Account
        ExcludeDisabledAccounts = [bool]$ExcludeDisabledAccounts
        ExcludeGuestUsers       = [bool]$ExcludeGuestUsers
    }
}

#endregion

#region REPORT MODE
# ══════════════════════════════════════════════════════════════════════════════
#  REPORT MODE (load from existing JSON)
# ══════════════════════════════════════════════════════════════════════════════
else {
    Write-Step "Loading data from '$JsonPath'"
    $jsonData = Get-Content $JsonPath -Raw | ConvertFrom-Json
    $users    = $jsonData.Users
    $metadata = @{
        CollectedAt             = $jsonData.CollectedAt
        TenantId                = $jsonData.TenantId
        CollectedBy             = $jsonData.CollectedBy
        ExcludeDisabledAccounts = [bool]$jsonData.ExcludeDisabledAccounts
        ExcludeGuestUsers       = [bool]$jsonData.ExcludeGuestUsers
    }
    Write-Success "  Loaded $($users.Count) user(s)."
}

#endregion

#region GENERATE HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════
#  GENERATE HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════
Write-Step 'Generating HTML report'

# Summary statistics
$stats = @{
    Total        = $users.Count
    MFA          = @($users | Where-Object { $_.HasMFA }).Count
    NoMFA        = @($users | Where-Object { -not $_.HasMFA }).Count
    Authenticator = @($users | Where-Object { $_.HasAuthenticator }).Count
    Fido2        = @($users | Where-Object { $_.HasFido2 }).Count
    Phone        = @($users | Where-Object { $_.HasPhone }).Count
    Email        = @($users | Where-Object { $_.HasEmail }).Count
    WHFB         = @($users | Where-Object { $_.HasWHFB }).Count
    SoftwareOath = @($users | Where-Object { $_.HasSoftwareOath }).Count
    Tap          = @($users | Where-Object { $_.HasTap }).Count
    Disabled     = @($users | Where-Object { -not $_.AccountEnabled }).Count
    Guest        = @($users | Where-Object { $_.UserType -eq 'Guest' }).Count
}
$stats['MFAPct'] = if ($stats.Total -gt 0) { [int](($stats.MFA / $stats.Total) * 100) } else { 0 }

# Build table rows
$tableRows = foreach ($u in $users) {
    $name     = [System.Web.HttpUtility]::HtmlEncode($u.DisplayName  -ne '' ? $u.DisplayName  : '(no display name)')
    $upn      = [System.Web.HttpUtility]::HtmlEncode($u.UserPrincipalName -ne '' ? $u.UserPrincipalName : '')
    $typeClr  = if ($u.UserType -eq 'Guest') { 'warning' } else { 'primary' }
    $typeLabel= [System.Web.HttpUtility]::HtmlEncode($u.UserType)
    $accClr   = if ($u.AccountEnabled) { 'success' } else { 'secondary' }
    $accLabel = if ($u.AccountEnabled) { 'Enabled' } else { 'Disabled' }
    $mfaClr   = if ($u.HasMFA) { 'success' } else { 'danger' }
    $mfaLabel = if ($u.HasMFA) { 'Registered' } else { 'Not Registered' }
    $ssprClr  = if ($u.SsprCount -gt 0) { 'success' } else { 'danger' }
    $ssprLabel = if ($u.SsprCount -gt 0) { "Capable ($($u.SsprCount))" } else { 'Not Capable' }

    # SSPR-capable method chips — show which registered methods qualify for SSPR
    $ssprTypes  = @('Authenticator', 'Phone', 'Email', 'SoftwareOath')
    $ssprChips  = ($u.Methods | Where-Object { $_.Type -in $ssprTypes } | ForEach-Object {
        $lbl = [System.Web.HttpUtility]::HtmlEncode($_.Label)
        $clr = $_.Color
        "<span class=`"fl-method fl-method-$clr`">$lbl</span>"
    }) -join ''
    $ssprDiv  = if ($ssprChips) { '<div class="sspr-chips">' + $ssprChips + '</div>' } else { '' }
    $ssprCell = "<span class=`"fl-pill fl-pill-$ssprClr`">$ssprLabel</span>$ssprDiv"

    # Method badges — summary (badges only) + collapsible detail (badges + device/detail text)
    $nonPwdMethods = @($u.Methods | Where-Object { $_.Type -ne 'Password' })
    if ($nonPwdMethods.Count -gt 0) {
        $summaryBadges = ($nonPwdMethods | ForEach-Object {
            $lbl = [System.Web.HttpUtility]::HtmlEncode($_.Label)
            $clr = $_.Color
            "<span class=`"fl-method fl-method-$clr`">$lbl</span>"
        }) -join ''
        $detailBadges = ($nonPwdMethods | ForEach-Object {
            $lbl = [System.Web.HttpUtility]::HtmlEncode($_.Label)
            $dtl = [System.Web.HttpUtility]::HtmlEncode($_.Detail)
            $clr = $_.Color
            "<span class=`"fl-method fl-method-$clr`">$lbl</span><small class=`"text-muted d-block ms-1 mb-1`" style=`"font-size:.71em`">$dtl</small>"
        }) -join ''
        $methodCell = "<div class=`"methods-summary`">$summaryBadges<span class=`"methods-toggle`">&#9660;</span></div><div class=`"methods-detail`">$detailBadges</div>"
    } else {
        $methodCell = '<span class="text-muted small">—</span>'
    }

    # CSV-friendly method list for DataTable search
    $methodTypesCsv    = ($u.Methods | Where-Object { $_.Type -ne 'Password' } | ForEach-Object { $_.Type }) -join ','
    $hasMfaAttr        = ($u.HasMFA).ToString().ToLower()
    $accountEnabledAttr = ($u.AccountEnabled).ToString().ToLower()
    $userTypeAttr       = ($u.UserType).ToLower()

    @"
            <tr data-hasmfa="$hasMfaAttr" data-methods="$methodTypesCsv" data-accountenabled="$accountEnabledAttr" data-usertype="$userTypeAttr" data-name="$name" data-upn="$upn">
              <td>$name$(if ($upn) { "<br><small class=`"text-muted`">$upn</small>" })</td>
              <td><span class="fl-pill fl-pill-$typeClr">$typeLabel</span></td>
              <td><span class="fl-pill fl-pill-$accClr">$accLabel</span></td>
              <td><span class="fl-pill fl-pill-$mfaClr">$mfaLabel</span></td>
              <td>$ssprCell</td>
              <td>$methodCell</td>
            </tr>
"@
}

$tableRowsHtml = $tableRows -join ''
$generatedAt   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$html = @"
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$Title</title>
  <link  rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link  rel="stylesheet" href="https://cdn.datatables.net/1.13.8/css/dataTables.bootstrap5.min.css">
  <link  rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css">
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/dataTables.bootstrap5.min.js"></script>
  <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
  <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.bootstrap5.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
  <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
  <style>
    /* ── Fluent UI colour tokens ───────────────────────────────── */
    :root {
      --f-bg:         #141414;
      --f-surface:    #1b1a19;
      --f-border:     #484644;
      --f-border2:    #3b3a39;
      --f-text:       #f3f2f1;
      --f-text2:      #d2d0ce;
      --f-blue:       #0078d4;
      --f-green:      #6dd36d;
      --f-green-bg:   #0a3d0a;
      --f-red:        #f47474;
      --f-red-bg:     #420c0c;
      --f-amber:      #ffcc87;
      --f-amber-bg:   #3d1f00;
      --f-teal:       #6decec;
      --f-teal-bg:    #003333;
      --f-neutral:    #d2d0ce;
      --f-neutral-bg: #3b3a39;
    }
    /* ── Base ──────────────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px;
      background: var(--f-bg);
      color: var(--f-text);
      margin: 0; padding: 0;
    }
    /* ── Page header ────────────────────────────────────────────  */
    .page-header {
      background: var(--f-surface);
      border-bottom: 1px solid var(--f-border);
      padding: 16px 24px 14px;
    }
    .page-breadcrumb { font-size: 12px; color: var(--f-text2); margin-bottom: 6px; }
    .page-breadcrumb a { color: var(--f-blue); text-decoration: none; }
    .page-breadcrumb a:hover { text-decoration: underline; }
    .page-title { font-size: 20px; font-weight: 600; color: var(--f-text); margin: 0 0 6px; }
    .page-meta { font-size: 12px; color: var(--f-text2); display: flex; flex-wrap: wrap; gap: 4px 12px; }
    /* ── Content area ───────────────────────────────────────────  */
    .content-area { padding: 20px 24px; }
    /* ── Stat cards ─────────────────────────────────────────────  */
    .stat-card { background: var(--f-surface); border: 1px solid var(--f-border); border-radius: 4px; padding: 16px; height: 100%; }
    .stat-label { font-size: 12px; color: var(--f-text2); margin-bottom: 4px; }
    .stat-value { font-size: 28px; font-weight: 600; line-height: 1.2; color: var(--f-text); }
    .stat-sub   { font-size: 13px; font-weight: 400; color: var(--f-text2); margin-left: 4px; }
    .v-green  { color: var(--f-green) !important; }
    .v-red    { color: var(--f-red) !important; }
    .v-blue   { color: var(--f-blue) !important; }
    .v-teal   { color: var(--f-teal) !important; }
    .v-amber  { color: var(--f-amber) !important; }
    /* ── Status pills ───────────────────────────────────────────  */
    .fl-pill {
      display: inline-flex; align-items: center; padding: 2px 10px;
      border-radius: 12px; font-size: 12px; white-space: nowrap;
    }
    .fl-pill-success   { background: var(--f-green-bg);   color: var(--f-green); }
    .fl-pill-danger    { background: var(--f-red-bg);     color: var(--f-red); }
    .fl-pill-primary   { background: #0a2a5a;             color: #6ab7f5; }
    .fl-pill-warning   { background: var(--f-amber-bg);   color: var(--f-amber); }
    .fl-pill-secondary { background: var(--f-neutral-bg); color: var(--f-neutral); }
    /* ── Method chips ───────────────────────────────────────────  */
    .fl-method {
      display: inline-flex; align-items: center; padding: 2px 8px;
      border-radius: 12px; font-size: 11px; margin: 1px 2px 1px 0; white-space: nowrap;
    }
    .fl-method-primary   { background: #0a2a5a;             color: #6ab7f5; }
    .fl-method-info      { background: var(--f-teal-bg);    color: var(--f-teal); }
    .fl-method-success   { background: var(--f-green-bg);   color: var(--f-green); }
    .fl-method-warning   { background: var(--f-amber-bg);   color: var(--f-amber); }
    .fl-method-dark      { background: var(--f-neutral-bg); color: var(--f-neutral); }
    .fl-method-secondary { background: var(--f-neutral-bg); color: var(--f-neutral); }
    /* ── Filter card ────────────────────────────────────────────  */
    .filter-card { background: var(--f-surface); border: 1px solid var(--f-border); border-radius: 4px; padding: 14px 16px; margin-bottom: 16px; }
    .filter-row  { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-bottom: 8px; }
    .filter-row:last-child { margin-bottom: 0; }
    .filter-group-label {
      font-size: 11px; font-weight: 600; color: var(--f-text2);
      text-transform: uppercase; letter-spacing: 0.05em; min-width: 58px;
    }
    .fl-filter-btn {
      display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 4px;
      font-size: 13px; border: 1px solid var(--f-border2); background: var(--f-surface);
      color: var(--f-text); cursor: pointer; font-family: inherit; transition: background .1s;
    }
    .fl-filter-btn:hover  { background: var(--f-bg); border-color: #9b9b9b; }
    .fl-filter-btn.active { background: var(--f-blue); border-color: var(--f-blue); color: #fff; font-weight: 600; }
    .fl-filter-btn::before { content: none !important; }
    /* ── Advanced identity filter ───────────────────────────────  */
    .adv-input {
      padding: 4px 10px; border-radius: 4px; border: 1px solid var(--f-border2);
      background: var(--f-surface); color: var(--f-text); font-family: inherit;
      font-size: 13px; width: 180px;
    }
    .adv-input:focus { outline: none; border-color: var(--f-blue); box-shadow: 0 0 0 1px var(--f-blue); }
    .adv-apply { background: var(--f-blue) !important; border-color: var(--f-blue) !important; color: #fff !important; }
    .adv-apply:hover { filter: brightness(1.1); }
    .adv-conn-btn {
      padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;
      border: 1px solid var(--f-border2); background: var(--f-surface);
      color: var(--f-text2); cursor: pointer; font-family: inherit; letter-spacing: 0.04em;
    }
    .adv-conn-btn.active { background: var(--f-blue); border-color: var(--f-blue); color: #fff; }
    /* ── Table card ─────────────────────────────────────────────  */
    .table-card { background: var(--f-surface); border: 1px solid var(--f-border); border-radius: 4px; overflow: hidden; margin-bottom: 20px; }
    .table-toolbar { padding: 10px 16px; border-bottom: 1px solid var(--f-border); display: flex; justify-content: flex-start; gap: 8px; }
    .fl-btn {
      display: inline-flex; align-items: center; padding: 5px 12px; border-radius: 4px;
      font-size: 13px; border: 1px solid var(--f-border2); background: var(--f-surface);
      color: var(--f-text); cursor: pointer; font-family: inherit;
    }
    .fl-btn:hover { background: var(--f-bg); border-color: #9b9b9b; }
    /* ── DataTable overrides ────────────────────────────────────  */
    table#mfaTable.dataTable { font-size: 13px; border-collapse: collapse !important; }
    table#mfaTable.dataTable thead th {
      background: var(--f-bg) !important; color: var(--f-text) !important;
      font-weight: 600 !important; border-bottom: 2px solid var(--f-border) !important;
      border-top: none !important; padding: 10px 12px !important; font-size: 13px !important;
    }
    table#mfaTable.dataTable tbody td {
      padding: 10px 12px !important; border-bottom: 1px solid var(--f-border) !important;
      vertical-align: middle; background: var(--f-surface) !important; color: var(--f-text);
    }
    table#mfaTable.dataTable tbody tr:hover td { background: var(--f-bg) !important; }
    table#mfaTable.dataTable tbody tr:last-child td { border-bottom: none !important; }
    .dataTables_wrapper .dataTables_filter input,
    .dataTables_wrapper .dataTables_length select {
      background: var(--f-surface); border: 1px solid var(--f-border2) !important;
      border-radius: 4px; padding: 4px 8px; font-size: 13px;
      color: var(--f-text); font-family: inherit; box-shadow: none !important;
    }
    .dataTables_wrapper .dataTables_filter input:focus,
    .dataTables_wrapper .dataTables_length select:focus {
      outline: none; border-color: var(--f-blue) !important; box-shadow: 0 0 0 1px var(--f-blue) !important;
    }
    .dataTables_wrapper .dataTables_info { font-size: 12px; color: var(--f-text2); }
    .dt-filter-bar { padding: 8px 0 4px; }
    .dt-filter-bar .dataTables_filter { text-align: left !important; float: none !important; }
    .dt-filter-bar .dataTables_filter label { display: inline-flex; align-items: center; gap: 8px; }
    .dataTables_wrapper .dataTables_paginate .paginate_button { border-radius: 4px !important; font-size: 13px !important; color: var(--f-text) !important; }
    .dataTables_wrapper .dataTables_paginate .paginate_button.current,
    .dataTables_wrapper .dataTables_paginate .paginate_button.current:hover {
      background: var(--f-blue) !important; border-color: var(--f-blue) !important; color: #fff !important;
    }
    .dataTables_wrapper .dataTables_paginate .paginate_button:hover {
      background: var(--f-bg) !important; border-color: var(--f-border2) !important; color: var(--f-text) !important;
    }
    /* ── Expand toggle ──────────────────────────────────────────  */
    .methods-detail { display: none; margin-top: 4px; }
    .sspr-chips    { display: none; margin-top: 4px; }
    .methods-toggle {
      background: none; border: none; padding: 0 2px; margin-left: 3px;
      font-size: .7em; color: var(--f-blue); cursor: pointer; opacity: 0.7;
      vertical-align: baseline; font-family: inherit;
    }
    .methods-toggle:hover { opacity: 1; }
    #mfaTable tbody tr:has(.methods-summary) { cursor: pointer; }
    /* ── Utilities ──────────────────────────────────────────────  */
    .text-muted, .text-secondary { color: var(--f-text2) !important; }
    td small { font-size: 0.77em; }
    /* ── Footer ─────────────────────────────────────────────────  */
    .page-footer { font-size: 12px; color: var(--f-text2); padding: 8px 0 20px; }
  </style>
</head>
<body>

  <!-- Page header -->
  <div class="page-header">
    <div class="page-breadcrumb">
      <a href="#">Protection</a> &rsaquo; <a href="#">Authentication methods</a> &rsaquo; Security Info registration
    </div>
    <h1 class="page-title">$Title</h1>
    <div class="page-meta">
      <span>Generated $generatedAt</span>
      <span>&middot; Collected $($metadata.CollectedAt)</span>
      <span>&middot; $($metadata.CollectedBy)</span>
      <span>&middot; Tenant: $($metadata.TenantId)</span>
      $(if ($metadata.ExcludeGuestUsers)       { '<span>&middot; <span class="fl-pill fl-pill-warning" style="font-size:11px">Guests excluded</span></span>' })
      $(if ($metadata.ExcludeDisabledAccounts) { '<span>&middot; <span class="fl-pill fl-pill-secondary" style="font-size:11px">Disabled excluded</span></span>' })
    </div>
  </div>

  <div class="content-area">

    <!-- Summary cards -->
    <div class="row g-3 mb-4">
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">Total Users</div>
          <div class="stat-value">$($stats.Total)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">Security Info Registered</div>
          <div class="stat-value v-green">$($stats.MFA)<span class="stat-sub">$($stats.MFAPct)%</span></div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">No Security Info</div>
          <div class="stat-value v-red">$($stats.NoMFA)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">Authenticator</div>
          <div class="stat-value v-blue">$($stats.Authenticator)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">FIDO2</div>
          <div class="stat-value v-green">$($stats.Fido2)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">Phone</div>
          <div class="stat-value v-teal">$($stats.Phone)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">Email OTP</div>
          <div class="stat-value v-amber">$($stats.Email)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">Windows Hello</div>
          <div class="stat-value">$($stats.WHFB)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">TOTP</div>
          <div class="stat-value v-amber">$($stats.SoftwareOath)</div>
        </div>
      </div>
      <div class="col-6 col-md-3 col-xl-2">
        <div class="stat-card">
          <div class="stat-label">Temp. Access Pass</div>
          <div class="stat-value">$($stats.Tap)</div>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filter-card">
      <div class="filter-row">
        <span class="filter-group-label">Security Info</span>
        <button class="fl-filter-btn filter-btn active" data-filter="all">All ($($stats.Total))</button>
        <button class="fl-filter-btn filter-btn" data-filter="nomfa">No Security Info ($($stats.NoMFA))</button>
        <button class="fl-filter-btn filter-btn" data-filter="hasmfa">Registered ($($stats.MFA))</button>
      </div>
      <div class="filter-row">
        <span class="filter-group-label">Method</span>
        <button class="fl-filter-btn filter-btn" data-filter="Authenticator">Authenticator ($($stats.Authenticator))</button>
        <button class="fl-filter-btn filter-btn" data-filter="Fido2">FIDO2 ($($stats.Fido2))</button>
        <button class="fl-filter-btn filter-btn" data-filter="Phone">Phone ($($stats.Phone))</button>
        <button class="fl-filter-btn filter-btn" data-filter="Email">Email OTP ($($stats.Email))</button>
        <button class="fl-filter-btn filter-btn" data-filter="WHFB">Windows Hello ($($stats.WHFB))</button>
        <button class="fl-filter-btn filter-btn" data-filter="SoftwareOath">TOTP ($($stats.SoftwareOath))</button>
        <button class="fl-filter-btn filter-btn" data-filter="TAP">TAP ($($stats.Tap))</button>
      </div>
      <div class="filter-row">
        <span class="filter-group-label">Account</span>
        <button class="fl-filter-btn filter-btn" data-filter="disabled">Disabled ($($stats.Disabled))</button>
        <button class="fl-filter-btn filter-btn" data-filter="guest">Guest ($($stats.Guest))</button>
        <button id="advToggle" class="fl-filter-btn">Advanced filter</button>
      </div>
      <div id="advPanel" style="display:none;border-top:1px solid var(--f-border);padding-top:10px;margin-top:2px;padding-bottom:2px">
        <div id="advRows"></div>
        <div style="display:flex;gap:6px;margin-top:4px">
          <button id="advAddRow" class="fl-filter-btn">&#43;&nbsp;Add condition</button>
          <button id="advApply" class="fl-filter-btn adv-apply">Apply</button>
          <button id="advClear" class="fl-filter-btn">Clear</button>
        </div>
      </div>
    </div>

    <!-- Users table -->
    <div class="table-card">
      <div class="table-toolbar">
        <button id="btnCsv"   class="fl-btn">&#8659;&nbsp;Export CSV</button>
        <button id="btnExcel" class="fl-btn">&#8659;&nbsp;Export Excel</button>
      </div>
      <div class="px-3 pt-2 pb-3">
        <table id="mfaTable" class="table w-100">
          <thead>
            <tr>
              <th>Principal</th>
              <th>Type</th>
              <th>Account</th>
              <th>Security Info Status</th>
              <th>SSPR Status</th>
              <th>Methods</th>
            </tr>
          </thead>
          <tbody>
$tableRowsHtml
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <script>
    let table;
    let currentFilter = 'all';
    let advFilters    = [];   // [{pattern, action, conn}]

    `$.fn.dataTable.ext.search.push(function (settings, data, dataIndex) {
      if (settings.nTable.id !== 'mfaTable') { return true; }
      let api = new `$.fn.dataTable.Api(settings);
      let row = `$(api.row(dataIndex).node());
      let hasMfa         = row.attr('data-hasmfa') === 'true';
      let methods        = (row.attr('data-methods') || '').split(',').filter(Boolean);
      let accountEnabled = row.attr('data-accountenabled') === 'true';
      let userType       = (row.attr('data-usertype') || '').toLowerCase();

      let switchResult;
      switch (currentFilter) {
        case 'all':      switchResult = true;                           break;
        case 'nomfa':    switchResult = !hasMfa;                        break;
        case 'hasmfa':   switchResult = hasMfa;                         break;
        case 'disabled': switchResult = !accountEnabled;                break;
        case 'guest':    switchResult = userType === 'guest';           break;
        default:         switchResult = methods.includes(currentFilter); break;
      }
      if (!switchResult) { return false; }

      if (advFilters.length > 0) {
        let nm  = (row.attr('data-name') || '').toLowerCase();
        let upn = (row.attr('data-upn')  || '').toLowerCase();
        let result = null;
        for (let f of advFilters) {
          let match  = nm.includes(f.pattern) || upn.includes(f.pattern);
          let passes = f.action === 'include' ? match : !match;
          if (result === null) {
            result = passes;
          } else if (f.conn === 'or') {
            result = result || passes;
          } else {
            result = result && passes;
          }
        }
        if (!result) { return false; }
      }
      return true;
    });

    function addAdvRow(pattern, action) {
      pattern = pattern || '';
      action  = action  || 'include';
      if (`$('#advRows .adv-row').length > 0) {
        `$('#advRows').append(
          '<div class="adv-connector" style="display:flex;align-items:center;gap:4px;margin:0 0 6px 0">' +
          '<button class="adv-conn-btn active" data-conn="and">AND</button>' +
          '<button class="adv-conn-btn" data-conn="or">OR</button>' +
          '</div>'
        );
      }
      `$('#advRows').append(
        '<div class="adv-row" style="display:flex;gap:6px;margin-bottom:6px;align-items:center">' +
        '<input type="text" class="adv-input adv-row-input" placeholder="UPN or displayname" value="' + pattern + '" autocomplete="off">' +
        '<button class="fl-filter-btn adv-row-action' + (action === 'include' ? ' active' : '') + '" data-action="include">Include</button>' +
        '<button class="fl-filter-btn adv-row-action' + (action === 'exclude' ? ' active' : '') + '" data-action="exclude">Exclude</button>' +
        '<button class="fl-filter-btn adv-row-remove" style="padding:4px 8px" title="Remove">&times;</button>' +
        '</div>'
      );
    }

    `$(document).ready(function () {
      addAdvRow();

      table = `$('#mfaTable').DataTable({
        pageLength: 25,
        order: [[3, 'asc'], [0, 'asc']],
        dom: '<"dt-filter-bar"f>rtip',
        buttons: [
          { extend: 'csvHtml5',   text: 'Export CSV' },
          { extend: 'excelHtml5', text: 'Export Excel' }
        ],
        columnDefs: [
          { orderable: false, targets: [1, 2, 4] }
        ]
      });

      `$('.filter-btn').on('click', function () {
        `$('.filter-btn').removeClass('active');
        `$(this).addClass('active');
        currentFilter = `$(this).data('filter');
        table.draw();
      });

      `$('.adv-logic').on('click', function () {
        `$('.adv-logic').removeClass('active');
        `$(this).addClass('active');
      });

      `$('#advRows').on('click', '.adv-conn-btn', function () {
        `$(this).closest('.adv-connector').find('.adv-conn-btn').removeClass('active');
        `$(this).addClass('active');
      });

      `$('#advRows').on('click', '.adv-row-action', function () {
        let row = `$(this).closest('.adv-row');
        row.find('.adv-row-action').removeClass('active');
        `$(this).addClass('active');
      });

      `$('#advRows').on('click', '.adv-row-remove', function () {
        let row  = `$(this).closest('.adv-row');
        let prev = row.prev('.adv-connector');
        let next = row.next('.adv-connector');
        if (prev.length) { prev.remove(); } else if (next.length) { next.remove(); }
        row.remove();
        if (`$('#advRows .adv-row').length === 0) { addAdvRow(); }
      });

      `$('#advRows').on('keydown', '.adv-row-input', function (e) {
        if (e.key === 'Enter') { `$('#advApply').trigger('click'); }
      });

      `$('#advAddRow').on('click', function () { addAdvRow(); });

      `$('#advApply').on('click', function () {
        advFilters = [];
        `$('#advRows .adv-row').each(function () {
          let pattern  = `$(this).find('.adv-row-input').val().trim().toLowerCase();
          let action   = `$(this).find('.adv-row-action.active').data('action') || 'include';
          let connNode = `$(this).prev('.adv-connector');
          let conn     = connNode.length ? (connNode.find('.adv-conn-btn.active').data('conn') || 'and') : 'and';
          if (pattern) { advFilters.push({ pattern: pattern, action: action, conn: conn }); }
        });
        table.draw();
      });

      `$('#advClear').on('click', function () {
        advFilters = [];
        `$('#advRows').empty();
        addAdvRow();
        table.draw();
      });

      `$('#advToggle').on('click', function () {
        let panel = `$('#advPanel');
        let visible = panel.is(':visible');
        panel.toggle();
        `$(this).toggleClass('active', !visible);
        if (visible) {
          advFilters = [];
          `$('#advRows').empty();
          addAdvRow();
          table.draw();
        }
      });

      `$('#btnCsv').on('click',   function () { table.button('.buttons-csv').trigger(); });
      `$('#btnExcel').on('click', function () { table.button('.buttons-excel').trigger(); });

      // Collapse/expand method details — click anywhere on the row
      `$('#mfaTable tbody').on('click', 'tr', function (e) {
        var `$row = `$(this);
        if (`$row.find('.methods-summary').length) {
          `$row.find('.methods-summary, .methods-detail, .sspr-chips').toggle();
        }
      });
    });
  </script>
</body>
</html>
"@

$html | Set-Content -Path $htmlFile -Encoding UTF8
Write-Success "  HTML : $htmlFile"

if (-not $NoOpen) {
    if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        Start-Process $htmlFile
    } elseif ($IsMacOS) {
        & open $htmlFile
    } else {
        & xdg-open $htmlFile
    }
}

#endregion

Write-Host "`nDone. $($users.Count) user(s) reported." -ForegroundColor Green
