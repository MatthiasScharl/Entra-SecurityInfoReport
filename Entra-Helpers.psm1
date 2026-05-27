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

  Entra-Helpers.psm1
  ------------------
  Shared helper module for the MFA-Report scripts.
  Import in each script with:

      Import-Module "$PSScriptRoot\Entra-Helpers.psm1" -Force

  Exported functions:
    Write-Step              — Timestamped step header
    Write-Success           — Green status line
    Write-Warn              — Yellow warning line
    Initialize-GraphSession — Connect-MgGraph with scope/tenant validation
    Invoke-GraphPagedRequest — Paginated GET against Microsoft Graph
#>

#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param ([string] $Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] --- $Message ---" -ForegroundColor Cyan
}

function Write-Success {
    param ([string] $Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warn {
    param ([string] $Message)
    Write-Host "WARNING: $Message" -ForegroundColor Yellow
}

function Initialize-GraphSession {
    <#
    .SYNOPSIS
        Ensures an active Microsoft Graph connection with the required scopes.
    .PARAMETER TenantId
        Optional tenant ID. If the current connection targets a different tenant, reconnects.
    .PARAMETER RequiredScopes
        Array of Graph permission scopes needed by the calling script.
    #>
    [CmdletBinding()]
    param (
        [string]   $TenantId,
        [string[]] $RequiredScopes
    )

    $ctx = $null
    try { $ctx = Get-MgContext } catch {}

    $needConnect = $null -eq $ctx
    if (-not $needConnect -and -not [string]::IsNullOrWhiteSpace($TenantId) -and
        $ctx.TenantId -ne $TenantId) {
        Write-Warn "Connected to tenant $($ctx.TenantId) — reconnecting to $TenantId..."
        $needConnect = $true
    }

    if ($needConnect) {
        $params = @{ Scopes = $RequiredScopes }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $params['TenantId'] = $TenantId }
        Connect-MgGraph @params | Out-Null
        Write-Success 'Connected to Microsoft Graph.'
    } else {
        Write-Host "  Already connected (tenant: $($ctx.TenantId), account: $($ctx.Account))" -ForegroundColor DarkGray
    }
}

function Invoke-GraphPagedRequest {
    <#
    .SYNOPSIS
        Performs a paginated GET request against Microsoft Graph and returns all results.
    .PARAMETER Uri
        Initial Graph API URI (may include $filter, $select, $top, etc.)
    .OUTPUTS
        System.Collections.Generic.List[object] containing all returned items.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Uri
    )

    $results = [System.Collections.Generic.List[object]]::new()
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable
        foreach ($item in $response['value']) { $results.Add($item) }
        $Uri = $response['@odata.nextLink']
    } while (-not [string]::IsNullOrEmpty($Uri))

    return $results
}

Export-ModuleMember -Function `
    Write-Step, Write-Success, Write-Warn, `
    Initialize-GraphSession, Invoke-GraphPagedRequest
