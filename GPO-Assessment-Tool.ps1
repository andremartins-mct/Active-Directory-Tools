<#
##################################################################################################

    DISCLAIMER - PLEASE READ BEFORE USING THIS SCRIPT

    THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED,
    INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
    PARTICULAR PURPOSE, AND NONINFRINGEMENT.

    NO SUPPORT OF ANY KIND IS PROVIDED. The author does not provide, and is under no obligation
    to provide, installation assistance, troubleshooting, maintenance, updates, bug fixes, or
    any other form of support related to this script. This script is not supported by Microsoft
    Corporation or by any Microsoft support program or service, and it is not endorsed by or
    affiliated with the author's employer or any of its clients.

    THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SCRIPT REMAINS WITH YOU. You
    are solely responsible for reviewing, testing, and validating this script in a non-production
    environment before running it against any production Active Directory infrastructure, and for
    ensuring that its use complies with the policies of your organization.

    IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT
    LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS
    INFORMATION, DATA LOSS, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR THE INABILITY
    TO USE THIS SCRIPT, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

    By executing this script, you acknowledge and accept the terms stated above.

##################################################################################################
#>

#Requires -Version 5.1
#Requires -Modules GroupPolicy, ActiveDirectory

<#
.SYNOPSIS
    Read-only assessment of Group Policy Objects in an Active Directory domain.

.DESCRIPTION
    Collects Group Policy configuration, delegation, link topology and SYSVOL state from a single
    pinned domain controller, evaluates a fixed set of checks, and produces an HTML report plus
    machine-readable JSON and CSV output.

    The script performs read operations only. It never creates, modifies, links, unlinks or
    deletes any Active Directory or SYSVOL object.

    Findings are grouped in three classes:

      RISK       Integrity or security findings that can break policy application or expose
                 a privilege escalation path.
      HYGIENE    Configuration debt and precedence findings.
      INVENTORY  Descriptive data with no severity attached.

    The class assigned to each check is an editorial convention of this report used for
    prioritization. It does not correspond to any formal severity rating published by Microsoft.

.PARAMETER DomainName
    FQDN of the domain to assess. Defaults to the domain of the current user context.

.PARAMETER Server
    Domain controller to pin every read to. Pinning matters: reading the Group Policy Container
    from one DC and the Group Policy Template from another produces false orphan and false
    version-mismatch findings while replication has not converged. Defaults to the PDC emulator
    of the target domain.

.PARAMETER OutputPath
    Root folder for the generated artifacts. Defaults to C:\GPO-Assessment.

    Inside that root a subfolder is created per domain and per run, so consecutive runs and
    different domains never overwrite each other:

        C:\GPO-Assessment\<domain>\<yyyyMMdd-HHmmss>\

    The account running the script must be able to create and write that path. Note that on a
    default installation the first user to create a folder directly under C:\ becomes its owner
    and other users receive read access only, so a shared collection station may require the
    folder to be pre-created with appropriate permissions.

.PARAMETER ClientName
    Client or organization name recorded in the report header. Optional.

.PARAMETER Assessor
    Name of the person who ran the collection, recorded in the report header. Optional.

.PARAMETER StaleGpoThresholdDays
    A GPO whose last modification is older than this value is reported as stale. Default 730.

.PARAMETER LargeGptThresholdMB
    A SYSVOL Group Policy Template folder larger than this value is reported. Default 25.

.PARAMETER IncludeForestDomains
    Enumerate linked containers in every domain of the forest instead of the target domain only.
    Required for cross-domain link detection to be meaningful. Increases runtime and requires
    read access in the other domains.

.PARAMETER SkipIndividualHtmlReports
    Do not export one HTML report per GPO. Roughly halves the runtime of the collection phase.

.PARAMETER SkipPermissionChecks
    Skip delegation collection. Disables the MS16-072, delegation, unresolved SID and
    no-effective-target checks.

.PARAMETER SkipSysvolContentScan
    Skip reading files inside the SYSVOL Group Policy Templates. Disables the Group Policy
    Preferences cpassword check, the loopback processing check and the template size check.

.PARAMETER PassThru
    Emit the result object on the pipeline in addition to writing the report files.

.EXAMPLE
    .\GPO_Assessment_Tool.ps1

    Assesses the current domain against its PDC emulator and writes the report to the default
    output folder.

.EXAMPLE
    .\GPO_Assessment_Tool.ps1 -DomainName contoso.com -Server dc01.contoso.com -ClientName 'Contoso' -Assessor 'A. Martins'

    Assesses contoso.com against a specific domain controller and stamps the report header with
    engagement metadata.

.EXAMPLE
    .\GPO_Assessment_Tool.ps1 -IncludeForestDomains -SkipIndividualHtmlReports -PassThru

    Enumerates linked containers across the whole forest, skips the per-GPO HTML export and
    returns the finding set on the pipeline.

.INPUTS
    None.

.OUTPUTS
    System.Management.Automation.PSCustomObject when -PassThru is specified.

.NOTES
    Author      : Andre Martins
    Version     : 2.1.0
    Permissions : Read access to the domain naming context, to the Configuration naming context
                  and to SYSVOL. Local administrator rights are NOT required.
    Exit codes  : 0 completed, no collection errors
                  1 prerequisite or fatal error
                  2 completed with collection errors (findings may be incomplete)

.DISCLAIMER
    Provided "AS IS", without warranty and without any form of support from its author.
    See the full disclaimer at the top of this file.

.LINK
    https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $DomainName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Server,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = 'C:\GPO-Assessment',

    [Parameter()]
    [string] $ClientName,

    [Parameter()]
    [string] $Assessor,

    [Parameter()]
    [ValidateRange(1, 36500)]
    [int] $StaleGpoThresholdDays = 730,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int] $LargeGptThresholdMB = 25,

    [Parameter()]
    [switch] $IncludeForestDomains,

    [Parameter()]
    [switch] $SkipIndividualHtmlReports,

    [Parameter()]
    [switch] $SkipPermissionChecks,

    [Parameter()]
    [switch] $SkipSysvolContentScan,

    [Parameter()]
    [switch] $PassThru
)

# ============================================================================================
#  SCRIPT METADATA AND CONSTANTS
# ============================================================================================

# Errors are NOT suppressed globally. A suppressed collection error renders as "0 findings",
# which is indistinguishable from "checked and compliant" in the report. Every collection step
# handles its own failures explicitly and records them in $script:CollectionIssues.
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'Continue'

$script:ScriptVersion = '2.1.0'
$script:StartTime     = Get-Date

# Well-known SIDs that are absolute (not domain-relative).
$script:SidAuthenticatedUsers = 'S-1-5-11'
$script:SidEveryone           = 'S-1-1-0'
$script:SidLocalSystem        = 'S-1-5-18'
$script:SidBuiltinAdmins      = 'S-1-5-32-544'
$script:SidEnterpriseDCs      = 'S-1-5-9'
$script:SidCreatorOwner       = 'S-1-3-0'

# Domain-relative identifiers (RIDs). Resolving well-known groups by RID rather than by display
# name is mandatory: group names are localized and a name comparison fails on any domain that was
# not installed in English.
$script:RidDomainAdmins      = 512
$script:RidDomainComputers   = 515
$script:RidDomainControllers = 516
$script:RidEnterpriseAdmins  = 519
$script:RidGpCreatorOwners   = 520

# Well-known GPO identifiers.
$script:GuidDefaultDomainPolicy     = '31B2F340-016D-11D2-945F-00C04FB984F9'
$script:GuidDefaultDomainCtrlPolicy = '6AC1786C-016F-11D2-945F-00C04FB984F9'

# Client-side extension categories expected in the two default GPOs. Microsoft guidance is to
# restrict the Default Domain Policy to account policies and the Default Domain Controllers
# Policy to user rights assignment and audit policy, and to place everything else in dedicated
# GPOs. Anything outside the Security extension in either GPO is reported for manual review.
$script:DefaultGpoExpectedExtensions = @('Security')

# Group Policy Preferences files that may carry a cpassword attribute (MS14-025).
$script:PreferenceFilePattern = '*.xml'

# Permissions that allow a trustee to change the content or the security of a GPO.
$script:WritePermissions = @('GpoEdit', 'GpoEditDeleteModifySecurity')

$script:CollectionIssues = [System.Collections.Generic.List[object]]::new()
$script:LogLines         = [System.Collections.Generic.List[string]]::new()

# ============================================================================================
#  LOGGING
# ============================================================================================

function Write-GpaLog {
    <#
        .SYNOPSIS
            Writes a formatted line to the console and to the in-memory log buffer.
        .DESCRIPTION
            Write-Host is used for the operator-facing banner only. Everything else is routed
            through this function so the run can be reconstructed from the log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'OK', 'WARN', 'FAIL', 'STEP')]
        [string] $Level,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Message
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $script:LogLines.Add(('{0} [{1,-4}] {2}' -f $stamp, $Level, $Message))

    switch ($Level) {
        'STEP' {
            Write-Host ''
            Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkCyan
            Write-Host ('  ' + $Message) -ForegroundColor White
            Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkCyan
        }
        'INFO' { Write-Host "  [INFO]  $Message" -ForegroundColor Cyan }
        'OK'   { Write-Host "  [ OK ]  $Message" -ForegroundColor Green }
        'WARN' { Write-Host "  [WARN]  $Message" -ForegroundColor Yellow }
        'FAIL' { Write-Host "  [FAIL]  $Message" -ForegroundColor Red }
    }
}

function Add-GpaCollectionIssue {
    <#
        .SYNOPSIS
            Records a collection failure so the report can state which checks are incomplete.
        .DESCRIPTION
            A check whose input could not be collected must not be presented as "0 findings".
            Every issue recorded here is rendered in a dedicated section of the report and
            drives the process exit code.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Stage,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $Reason,
        [Parameter()] [string] $Impact = ''
    )

    $script:CollectionIssues.Add([pscustomobject]@{
        Stage  = $Stage
        Target = $Target
        Reason = $Reason
        Impact = $Impact
    })
    Write-GpaLog -Level WARN -Message ('{0} | {1} | {2}' -f $Stage, $Target, $Reason)
}

# ============================================================================================
#  GENERIC HELPERS
# ============================================================================================

function ConvertTo-GpaHtmlText {
    <#
        .SYNOPSIS
            HTML-encodes a value.
        .DESCRIPTION
            System.Net.WebUtility is part of the shared runtime on .NET Framework 4.0 and later
            and on .NET Core, so no Add-Type call is needed and the function cannot silently
            degrade the way [System.Web.HttpUtility] does when its assembly fails to load.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()] [AllowNull()] [object] $Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-GpaNormalizedGuid {
    <#
        .SYNOPSIS
            Normalizes a GPO identifier to an uppercase braceless GUID string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()] [AllowNull()] [object] $Value)

    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim().Trim('{', '}')
    $parsed = [guid]::Empty
    if ([guid]::TryParse($text, [ref]$parsed)) {
        return $parsed.ToString().ToUpperInvariant()
    }
    return $null
}

function Get-GpaSafeFileName {
    <#
        .SYNOPSIS
            Builds a collision-free, length-bounded file name for a GPO export.
        .DESCRIPTION
            The display name alone is not unique after character substitution and can exceed the
            maximum path length, so the GUID is always appended.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $DisplayName,
        [Parameter(Mandatory)] [string] $Guid
    )

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean   = ($DisplayName.ToCharArray() | ForEach-Object {
        if ($invalid -contains $_) { '_' } else { $_ }
    }) -join ''
    $clean = $clean.Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'unnamed' }
    if ($clean.Length -gt 80) { $clean = $clean.Substring(0, 80) }
    return ('{0}_{1}' -f $clean, $Guid)
}

function Test-GpaXmlHasSettings {
    <#
        .SYNOPSIS
            Determines whether a configuration node of a GPO XML report contains extension data.
        .DESCRIPTION
            The node is wrapped in an array before the count is read. A single XmlElement exposes
            the synthetic Count member inconsistently, which makes a bare .Count comparison an
            unreliable emptiness test.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()] [AllowNull()] [object] $ConfigurationNode)

    if ($null -eq $ConfigurationNode) { return $false }
    # @($null).Count evaluates to 1, so the null elements must be filtered out before counting.
    # Without this filter every GPO reports as having settings and the emptiness checks silently
    # return nothing.
    $nodes = @(@($ConfigurationNode.ExtensionData) | Where-Object { $null -ne $_ })
    return ($nodes.Count -gt 0)
}

function Get-GpaExtensionNames {
    <#
        .SYNOPSIS
            Returns the client-side extension names configured in a GPO configuration node.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter()] [AllowNull()] [object] $ConfigurationNode)

    if ($null -eq $ConfigurationNode) { return @() }
    $names = foreach ($extension in @($ConfigurationNode.ExtensionData)) {
        if ($null -ne $extension -and $null -ne $extension.Name) { [string]$extension.Name }
    }
    return @($names | Where-Object { $_ } | Sort-Object -Unique)
}

# ============================================================================================
#  CONTEXT RESOLUTION
# ============================================================================================

function Resolve-GpaContext {
    <#
        .SYNOPSIS
            Resolves the target domain, pins a domain controller and collects the identifiers
            that every later step depends on.
        .DESCRIPTION
            All subsequent reads are directed at the returned domain controller. Reading the
            Group Policy Container and the Group Policy Template from different domain
            controllers is the single most common cause of false orphan findings in this class
            of tool, because DFS Namespace resolves the SYSVOL share to an arbitrary replica.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [string] $DomainName,
        [Parameter()] [AllowNull()] [string] $Server
    )

    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        $domain = Get-ADDomain -Current LoggedOnUser
    }
    else {
        $domain = Get-ADDomain -Identity $DomainName
    }

    if ([string]::IsNullOrWhiteSpace($Server)) {
        $targetServer = $domain.PDCEmulator
        if ([string]::IsNullOrWhiteSpace($targetServer)) {
            throw "Unable to determine the PDC emulator of $($domain.DNSRoot). Specify -Server explicitly."
        }
    }
    else {
        $targetServer = $Server
    }

    # Re-read the domain through the pinned domain controller so that every attribute used later
    # originates from the same replica as the SYSVOL content.
    $domain   = Get-ADDomain -Identity $domain.DNSRoot -Server $targetServer
    $rootDse  = Get-ADRootDSE -Server $targetServer
    $forest   = Get-ADForest -Server $targetServer

    [pscustomobject]@{
        DomainFQDN        = $domain.DNSRoot
        DomainNetBIOS     = $domain.NetBIOSName
        DomainDN          = $domain.DistinguishedName
        DomainSID         = $domain.DomainSID.Value
        ForestFQDN        = $forest.Name
        ForestDomains     = @($forest.Domains)
        Server            = $targetServer
        ConfigurationNC   = $rootDse.configurationNamingContext
        PoliciesContainer = "CN=Policies,CN=System,$($domain.DistinguishedName)"
        SysvolPolicyPath  = "\\$targetServer\SYSVOL\$($domain.DNSRoot)\Policies"
        RunAsAccount      = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
    }
}

function Get-GpaWellKnownPrincipals {
    <#
        .SYNOPSIS
            Builds the set of SIDs that are expected to hold write permissions on a GPO.
        .DESCRIPTION
            Domain-relative principals are resolved from the domain SID by RID, never by display
            name, because those names are localized.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object] $Context)

    $domainSid = $Context.DomainSID
    $rootSid   = $null
    try {
        $rootDomain = Get-ADDomain -Identity $Context.ForestFQDN -Server $Context.Server
        $rootSid    = $rootDomain.DomainSID.Value
    }
    catch {
        Add-GpaCollectionIssue -Stage 'Well-known principals' -Target $Context.ForestFQDN `
            -Reason $_.Exception.Message `
            -Impact 'Enterprise Admins is not treated as an expected delegation holder.'
    }

    $privileged = [System.Collections.Generic.List[string]]::new()
    $privileged.Add($script:SidLocalSystem)
    $privileged.Add($script:SidBuiltinAdmins)
    $privileged.Add($script:SidEnterpriseDCs)
    $privileged.Add($script:SidCreatorOwner)
    $privileged.Add("$domainSid-$($script:RidDomainAdmins)")
    $privileged.Add("$domainSid-$($script:RidGpCreatorOwners)")
    if ($rootSid) { $privileged.Add("$rootSid-$($script:RidEnterpriseAdmins)") }

    [pscustomobject]@{
        AuthenticatedUsers  = $script:SidAuthenticatedUsers
        Everyone            = $script:SidEveryone
        DomainComputers     = "$domainSid-$($script:RidDomainComputers)"
        DomainControllers   = "$domainSid-$($script:RidDomainControllers)"
        GpCreatorOwners     = "$domainSid-$($script:RidGpCreatorOwners)"
        PrivilegedWriteSids = @($privileged)
    }
}

# ============================================================================================
#  COLLECTION
# ============================================================================================

function Get-GpaGpoInventory {
    <#
        .SYNOPSIS
            Retrieves every GPO readable by the current account from the pinned domain controller.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object] $Context)

    $gpos = Get-GPO -All -Domain $Context.DomainFQDN -Server $Context.Server
    Write-GpaLog -Level OK -Message "GPOs retrieved: $(@($gpos).Count)"
    Write-GpaLog -Level INFO -Message 'Only GPOs readable by the running account are returned; a permission-trimmed result is silently smaller.'
    return @($gpos)
}

function Get-GpaGpoReportMap {
    <#
        .SYNOPSIS
            Generates the XML report of every GPO and returns a GUID-keyed hashtable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Context,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Gpos
    )

    $map   = @{}
    $total = @($Gpos).Count
    $index = 0

    foreach ($gpo in $Gpos) {
        $index++
        Write-Progress -Activity 'Collecting GPO XML reports' -Status $gpo.DisplayName `
            -PercentComplete (($index / [Math]::Max($total, 1)) * 100)
        try {
            $xmlText = Get-GPOReport -Guid $gpo.Id -ReportType Xml `
                -Domain $Context.DomainFQDN -Server $Context.Server
            $map[(Get-GpaNormalizedGuid $gpo.Id)] = [xml]$xmlText
        }
        catch {
            Add-GpaCollectionIssue -Stage 'GPO XML report' -Target $gpo.DisplayName `
                -Reason $_.Exception.Message `
                -Impact 'Settings-based checks skip this GPO.'
        }
    }
    Write-Progress -Activity 'Collecting GPO XML reports' -Completed
    Write-GpaLog -Level OK -Message "XML reports collected: $($map.Count) of $total"
    return $map
}

function Export-GpaIndividualReport {
    <#
        .SYNOPSIS
            Exports one HTML report per GPO.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Context,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Gpos,
        [Parameter(Mandatory)] [string] $Destination
    )

    $exported = 0
    $total    = @($Gpos).Count
    $index    = 0

    foreach ($gpo in $Gpos) {
        $index++
        Write-Progress -Activity 'Exporting individual GPO reports' -Status $gpo.DisplayName `
            -PercentComplete (($index / [Math]::Max($total, 1)) * 100)
        $guid = Get-GpaNormalizedGuid $gpo.Id
        $file = [System.IO.Path]::Combine($Destination, ((Get-GpaSafeFileName -DisplayName $gpo.DisplayName -Guid $guid) + '.html'))
        try {
            Get-GPOReport -Guid $gpo.Id -ReportType Html -Path $file `
                -Domain $Context.DomainFQDN -Server $Context.Server
            $exported++
        }
        catch {
            Add-GpaCollectionIssue -Stage 'Individual HTML export' -Target $gpo.DisplayName `
                -Reason $_.Exception.Message -Impact 'The per-GPO report is missing from the export folder.'
        }
    }
    Write-Progress -Activity 'Exporting individual GPO reports' -Completed
    Write-GpaLog -Level OK -Message "Individual HTML reports exported: $exported of $total"
    return $exported
}

function ConvertFrom-GpaGPLink {
    <#
        .SYNOPSIS
            Parses the gPLink attribute of a container into structured link objects.
        .DESCRIPTION
            The attribute holds a concatenation of [LDAP://<GPO DN>;<flags>] entries. The flags
            are a bit field: bit 0 set means the link is disabled, bit 1 set means the link is
            enforced.

            Link order convention used here: the LAST entry of the gPLink string corresponds to
            link order 1 in the Group Policy Management Console, that is, the highest precedence.
            Validate this against GPMC in a lab before relying on the LinkOrder column.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $GPLink,
        [Parameter(Mandatory)] [string] $ContainerDN,
        [Parameter(Mandatory)] [string] $ContainerType,
        [Parameter(Mandatory)] [string] $ContainerDomain
    )

    if ([string]::IsNullOrWhiteSpace($GPLink)) { return }

    $entries = [regex]::Matches($GPLink, '\[LDAP://(?<dn>[^;\]]+);(?<flags>\d+)\]')
    $count   = $entries.Count

    for ($i = 0; $i -lt $count; $i++) {
        $dn    = $entries[$i].Groups['dn'].Value
        $flags = [int]$entries[$i].Groups['flags'].Value

        $guid = $null
        $guidMatch = [regex]::Match($dn, '\{(?<g>[0-9A-Fa-f\-]{36})\}')
        if ($guidMatch.Success) { $guid = Get-GpaNormalizedGuid $guidMatch.Groups['g'].Value }

        $gpoDomainDN = $null
        $dcMatch = [regex]::Match($dn, '(?<dc>DC=.+)$')
        if ($dcMatch.Success) { $gpoDomainDN = $dcMatch.Groups['dc'].Value }

        [pscustomobject]@{
            GpoGuid         = $guid
            GpoDN           = $dn
            GpoDomainDN     = $gpoDomainDN
            ContainerDN     = $ContainerDN
            ContainerType   = $ContainerType
            ContainerDomain = $ContainerDomain
            LinkEnabled     = -not [bool]($flags -band 1)
            Enforced        = [bool]($flags -band 2)
            LinkOrder       = $count - $i
        }
    }
}

function Get-GpaLinkTopology {
    <#
        .SYNOPSIS
            Collects every container that carries a gPLink, plus inheritance blocking.
        .DESCRIPTION
            One LDAP query per naming context returns all linked containers directly. This
            replaces the pattern of enumerating every organizational unit and calling
            Get-GPInheritance on each of them, which is orders of magnitude more expensive and
            still cannot see containers outside the queried domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Context,
        [Parameter()] [switch] $IncludeForestDomains
    )

    $links      = [System.Collections.Generic.List[object]]::new()
    $blocked    = [System.Collections.Generic.List[object]]::new()
    $searchList = [System.Collections.Generic.List[object]]::new()

    $searchList.Add([pscustomobject]@{
        Domain = $Context.DomainFQDN
        Server = $Context.Server
        BaseDN = $Context.DomainDN
        Scope  = 'Domain'
    })

    if ($IncludeForestDomains) {
        foreach ($otherDomain in $Context.ForestDomains) {
            if ($otherDomain -eq $Context.DomainFQDN) { continue }
            $searchList.Add([pscustomobject]@{
                Domain = $otherDomain
                Server = $otherDomain
                BaseDN = $null
                Scope  = 'Domain'
            })
        }
    }

    foreach ($target in $searchList) {
        $baseDN = $target.BaseDN
        try {
            if (-not $baseDN) {
                $baseDN = (Get-ADDomain -Identity $target.Domain -Server $target.Server).DistinguishedName
            }

            $containers = Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $baseDN `
                -SearchScope Subtree -Server $target.Server -Properties gPLink, gPOptions, objectClass

            foreach ($container in $containers) {
                $type = switch ($container.objectClass) {
                    'domainDNS'             { 'Domain' }
                    'organizationalUnit'    { 'OU' }
                    default                 { [string]$container.objectClass }
                }

                foreach ($link in (ConvertFrom-GpaGPLink -GPLink $container.gPLink `
                                    -ContainerDN $container.DistinguishedName `
                                    -ContainerType $type -ContainerDomain $target.Domain)) {
                    $links.Add($link)
                }

                if ($null -ne $container.gPOptions -and ([int]$container.gPOptions -band 1)) {
                    $blocked.Add([pscustomobject]@{
                        Container     = $container.DistinguishedName
                        ContainerType = $type
                        Domain        = $target.Domain
                    })
                }
            }
        }
        catch {
            Add-GpaCollectionIssue -Stage 'Link topology' -Target $target.Domain `
                -Reason $_.Exception.Message `
                -Impact 'Links and inheritance blocking in this domain are missing from the report.'
        }
    }

    # Sites live in the Configuration naming context and are forest-wide, so they are queried once.
    try {
        $siteContainers = Get-ADObject -LDAPFilter '(&(objectClass=site)(gPLink=*))' `
            -SearchBase $Context.ConfigurationNC -SearchScope Subtree `
            -Server $Context.Server -Properties gPLink, gPOptions, name

        foreach ($site in $siteContainers) {
            foreach ($link in (ConvertFrom-GpaGPLink -GPLink $site.gPLink `
                                -ContainerDN $site.DistinguishedName `
                                -ContainerType 'Site' -ContainerDomain $Context.ForestFQDN)) {
                $links.Add($link)
            }
            if ($null -ne $site.gPOptions -and ([int]$site.gPOptions -band 1)) {
                $blocked.Add([pscustomobject]@{
                    Container     = $site.DistinguishedName
                    ContainerType = 'Site'
                    Domain        = $Context.ForestFQDN
                })
            }
        }
    }
    catch {
        Add-GpaCollectionIssue -Stage 'Link topology' -Target 'Configuration naming context' `
            -Reason $_.Exception.Message -Impact 'Site-level links are missing from the report.'
    }

    Write-GpaLog -Level OK -Message "Links collected: $($links.Count) across $($searchList.Count) domain(s) plus sites"
    Write-GpaLog -Level OK -Message "Containers with inheritance blocked: $($blocked.Count)"

    [pscustomobject]@{
        Links           = @($links)
        BlockedInherit  = @($blocked)
        SearchedDomains = @($searchList | ForEach-Object { $_.Domain })
    }
}

function Get-GpaPermissionMap {
    <#
        .SYNOPSIS
            Collects the delegation of every GPO and returns a GUID-keyed hashtable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Context,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Gpos
    )

    $map   = @{}
    $total = @($Gpos).Count
    $index = 0

    foreach ($gpo in $Gpos) {
        $index++
        Write-Progress -Activity 'Collecting GPO delegation' -Status $gpo.DisplayName `
            -PercentComplete (($index / [Math]::Max($total, 1)) * 100)
        try {
            $map[(Get-GpaNormalizedGuid $gpo.Id)] = @(Get-GPPermission -Guid $gpo.Id -All `
                -Domain $Context.DomainFQDN -Server $Context.Server)
        }
        catch {
            Add-GpaCollectionIssue -Stage 'GPO delegation' -Target $gpo.DisplayName `
                -Reason $_.Exception.Message `
                -Impact 'Delegation-based checks skip this GPO.'
        }
    }
    Write-Progress -Activity 'Collecting GPO delegation' -Completed
    Write-GpaLog -Level OK -Message "Delegation collected for $($map.Count) of $total GPOs"
    return $map
}

function Read-GpaRegistryPol {
    <#
        .SYNOPSIS
            Parses a Registry.pol file into key/value/type/data records.
        .DESCRIPTION
            The format is documented in [MS-GPREG]: a "PReg" signature, a version DWORD, then a
            sequence of [key;value;type;size;data] records where the delimiters are UTF-16
            characters and type and size are little-endian DWORDs.

            Parsing the file directly is language independent, which reading policy names out of
            the GPO XML report is not: those names are localized by the console that generated
            the report.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    $result = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $Path)) { return @($result) }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 8) { return @($result) }
    if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') { return @($result) }

    $unicode = [System.Text.Encoding]::Unicode
    $pos     = 8

    while (($pos + 2) -le $bytes.Length) {
        if ([BitConverter]::ToUInt16($bytes, $pos) -ne 0x5B) { break }   # '['
        $pos += 2

        # Key name, NUL terminated.
        $start = $pos
        while (($pos + 2) -le $bytes.Length -and [BitConverter]::ToUInt16($bytes, $pos) -ne 0) { $pos += 2 }
        $key = $unicode.GetString($bytes, $start, $pos - $start)
        $pos += 2
        if (($pos + 2) -gt $bytes.Length) { break }
        $pos += 2   # ';'

        # Value name, NUL terminated.
        $start = $pos
        while (($pos + 2) -le $bytes.Length -and [BitConverter]::ToUInt16($bytes, $pos) -ne 0) { $pos += 2 }
        $value = $unicode.GetString($bytes, $start, $pos - $start)
        $pos += 2
        if (($pos + 2) -gt $bytes.Length) { break }
        $pos += 2   # ';'

        if (($pos + 4) -gt $bytes.Length) { break }
        $type = [int][BitConverter]::ToUInt32($bytes, $pos); $pos += 4
        if (($pos + 2) -gt $bytes.Length) { break }
        $pos += 2   # ';'

        if (($pos + 4) -gt $bytes.Length) { break }
        $size = [int][BitConverter]::ToUInt32($bytes, $pos); $pos += 4
        if (($pos + 2) -gt $bytes.Length) { break }
        $pos += 2   # ';'

        if ($size -lt 0 -or ($pos + $size) -gt $bytes.Length) { break }
        $data = [byte[]]::new($size)
        if ($size -gt 0) { [Array]::Copy($bytes, [int]$pos, $data, [int]0, [int]$size) }
        $pos += $size

        if (($pos + 2) -le $bytes.Length) { $pos += 2 }   # ']'

        $result.Add([pscustomobject]@{
            Key   = $key
            Value = $value
            Type  = $type
            Data  = $data
        })
    }

    return @($result)
}

function Get-GpaSysvolInventory {
    <#
        .SYNOPSIS
            Enumerates the Group Policy Templates in SYSVOL and scans their content.
        .DESCRIPTION
            SYSVOL is read through the pinned domain controller rather than through the DFS
            Namespace root, so the Group Policy Container and the Group Policy Template come from
            the same replica.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Context,
        [Parameter()] [switch] $ScanContent,
        [Parameter(Mandatory)] [int] $LargeGptThresholdMB
    )

    $templates  = [System.Collections.Generic.List[object]]::new()
    $cpasswords = [System.Collections.Generic.List[object]]::new()
    $loopback   = [System.Collections.Generic.List[object]]::new()

    if (-not (Test-Path -LiteralPath $Context.SysvolPolicyPath)) {
        Add-GpaCollectionIssue -Stage 'SYSVOL inventory' -Target $Context.SysvolPolicyPath `
            -Reason 'Path is not accessible.' `
            -Impact 'Orphan, version-mismatch, cpassword, loopback and template-size checks are unavailable.'
        return [pscustomobject]@{
            Templates = @(); CPasswords = @(); Loopback = @(); Available = $false
        }
    }

    try {
        $folders = @(Get-ChildItem -LiteralPath $Context.SysvolPolicyPath -Directory |
            Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' })
    }
    catch {
        Add-GpaCollectionIssue -Stage 'SYSVOL inventory' -Target $Context.SysvolPolicyPath `
            -Reason $_.Exception.Message `
            -Impact 'Orphan and version-mismatch checks are unavailable.'
        return [pscustomobject]@{
            Templates = @(); CPasswords = @(); Loopback = @(); Available = $false
        }
    }

    $total = $folders.Count
    $index = 0

    foreach ($folder in $folders) {
        $index++
        Write-Progress -Activity 'Scanning SYSVOL Group Policy Templates' -Status $folder.Name `
            -PercentComplete (($index / [Math]::Max($total, 1)) * 100)

        $guid    = Get-GpaNormalizedGuid $folder.Name
        $sizeMB  = $null
        $fileCnt = $null

        if ($ScanContent) {
            try {
                $files   = @(Get-ChildItem -LiteralPath $folder.FullName -Recurse -File)
                $fileCnt = $files.Count
                $sum     = ($files | Measure-Object -Property Length -Sum).Sum
                if ($null -eq $sum) { $sum = 0 }
                $sizeMB  = [Math]::Round($sum / 1MB, 2)

                # MS14-025: Group Policy Preferences stored credentials. The AES key used to
                # protect the cpassword attribute was published by Microsoft, so any principal
                # with read access to SYSVOL can recover the plaintext.
                foreach ($file in ($files | Where-Object { $_.Extension -eq '.xml' })) {
                    $content = [System.IO.File]::ReadAllText($file.FullName)
                    if ($content -match 'cpassword\s*=\s*"[^"]+"') {
                        $cpasswords.Add([pscustomobject]@{
                            Guid          = $guid
                            PreferenceXml = $file.Name
                            RelativePath  = $file.FullName.Substring($folder.FullName.Length).TrimStart('\')
                            Occurrences   = ([regex]::Matches($content, 'cpassword\s*=\s*"[^"]+"')).Count
                        })
                    }
                }

                # Loopback processing is stored as UserPolicyMode under the System policy key.
                $polPath = [System.IO.Path]::Combine($folder.FullName, 'Machine', 'Registry.pol')
                foreach ($entry in (Read-GpaRegistryPol -Path $polPath)) {
                    if ($entry.Value -eq 'UserPolicyMode') {
                        $mode = 'Enabled (mode not determined)'
                        if ($entry.Data -and $entry.Data.Length -ge 4) {
                            switch ([BitConverter]::ToUInt32($entry.Data, 0)) {
                                1 { $mode = 'Merge' }
                                2 { $mode = 'Replace' }
                            }
                        }
                        $loopback.Add([pscustomobject]@{ Guid = $guid; Mode = $mode })
                    }
                }
            }
            catch {
                Add-GpaCollectionIssue -Stage 'SYSVOL content scan' -Target $folder.Name `
                    -Reason $_.Exception.Message `
                    -Impact 'cpassword, loopback and size data are missing for this template.'
            }
        }

        $templates.Add([pscustomobject]@{
            Guid    = $guid
            Path    = $folder.FullName
            SizeMB  = $sizeMB
            Files   = $fileCnt
            IsLarge = ($null -ne $sizeMB -and $sizeMB -gt $LargeGptThresholdMB)
        })
    }
    Write-Progress -Activity 'Scanning SYSVOL Group Policy Templates' -Completed
    Write-GpaLog -Level OK -Message "Group Policy Templates found in SYSVOL: $($templates.Count)"

    [pscustomobject]@{
        Templates  = @($templates)
        CPasswords = @($cpasswords)
        Loopback   = @($loopback)
        Available  = $true
    }
}

function Get-GpaContainerInventory {
    <#
        .SYNOPSIS
            Enumerates the Group Policy Container objects registered in Active Directory.
        .DESCRIPTION
            Get-ADObject is used rather than an ADSI child enumeration because it pages results
            correctly above the LDAP server-side limit.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object] $Context)

    try {
        $objects = @(Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' `
            -SearchBase $Context.PoliciesContainer -SearchScope OneLevel `
            -Server $Context.Server -Properties cn, displayName, whenCreated, whenChanged)

        $result = foreach ($object in $objects) {
            $guid = Get-GpaNormalizedGuid $object.cn
            if ($guid) {
                [pscustomobject]@{
                    Guid        = $guid
                    DisplayName = $object.displayName
                    WhenCreated = $object.whenCreated
                    WhenChanged = $object.whenChanged
                }
            }
        }
        Write-GpaLog -Level OK -Message "Group Policy Containers in Active Directory: $(@($result).Count)"
        return @($result)
    }
    catch {
        Add-GpaCollectionIssue -Stage 'GPC inventory' -Target $Context.PoliciesContainer `
            -Reason $_.Exception.Message -Impact 'Orphan checks are unavailable.'
        return @()
    }
}

# ============================================================================================
#  ANALYSIS
# ============================================================================================

function New-GpaFinding {
    <#
        .SYNOPSIS
            Builds a finding definition consumed by the renderer and by the exporters.
        .DESCRIPTION
            Every check is described as data rather than as inline markup, so the navigation,
            the summary tiles, the remediation plan, the report sections and the CSV exports are
            all generated from one source.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Ref,
        [Parameter(Mandatory)] [string] $Anchor,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $NavLabel,
        [Parameter(Mandatory)] [ValidateSet('risk', 'hygiene', 'inventory')] [string] $Class,
        [Parameter(Mandatory)] [string] $Observation,
        [Parameter()] [string] $Remediation = '',
        [Parameter()] [string] $ReferenceLabel = '',
        [Parameter()] [string] $ReferenceUrl = '',
        [Parameter()] [AllowNull()] [object[]] $Data = @(),
        [Parameter()] [string] $EmptyMessage = 'No items found.',
        [Parameter()] [bool] $Available = $true,
        [Parameter()] [string] $UnavailableMessage = 'This check did not run.'
    )

    # A check that produced no output assigns $null, and @($null) is an array of ONE null
    # element, not an empty array. Without this filter an empty check reports "1 finding",
    # renders a blank table row and breaks Export-Csv with a null InputObject.
    $rows = @(@($Data) | Where-Object { $null -ne $_ })

    [pscustomobject]@{
        Ref                = $Ref
        Anchor             = $Anchor
        Title              = $Title
        NavLabel           = $NavLabel
        Class              = $Class
        Observation        = $Observation
        Remediation        = $Remediation
        ReferenceLabel     = $ReferenceLabel
        ReferenceUrl       = $ReferenceUrl
        Data               = $rows
        Count              = $rows.Count
        EmptyMessage       = $EmptyMessage
        Available          = $Available
        UnavailableMessage = $UnavailableMessage
    }
}

function Get-GpaFindingSeverity {
    <#
        .SYNOPSIS
            Maps a finding class and count to a severity token used by the stylesheet.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    if (-not $Finding.Available)     { return 'unknown' }
    if ($Finding.Class -eq 'inventory') { return 'info' }
    if ($Finding.Count -eq 0)        { return 'ok' }
    if ($Finding.Class -eq 'risk')   { return 'crit' }
    return 'warn'
}

function Get-GpaFindings {
    <#
        .SYNOPSIS
            Evaluates every check against the collected data and returns the finding set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Context,
        [Parameter(Mandatory)] [object] $Principals,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Gpos,
        [Parameter(Mandatory)] [hashtable] $ReportMap,
        [Parameter(Mandatory)] [object] $Topology,
        [Parameter(Mandatory)] [AllowNull()] [hashtable] $PermissionMap,
        [Parameter(Mandatory)] [object] $Sysvol,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Containers,
        [Parameter(Mandatory)] [int] $StaleGpoThresholdDays,
        [Parameter(Mandatory)] [int] $LargeGptThresholdMB,
        [Parameter()] [bool] $ForestScope = $false
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    $permissionsAvailable = ($null -ne $PermissionMap -and $PermissionMap.Count -gt 0)
    $sysvolAvailable      = [bool]$Sysvol.Available
    $contentAvailable     = $sysvolAvailable -and (@($Sysvol.Templates | Where-Object { $null -ne $_.SizeMB }).Count -gt 0)

    # ---- Indexes -----------------------------------------------------------------------
    $gpoByGuid = @{}
    foreach ($gpo in $Gpos) { $gpoByGuid[(Get-GpaNormalizedGuid $gpo.Id)] = $gpo }

    $linksByGuid = @{}
    foreach ($link in $Topology.Links) {
        if (-not $link.GpoGuid) { continue }
        if (-not $linksByGuid.ContainsKey($link.GpoGuid)) { $linksByGuid[$link.GpoGuid] = [System.Collections.Generic.List[object]]::new() }
        $linksByGuid[$link.GpoGuid].Add($link)
    }

    $templateByGuid = @{}
    foreach ($template in $Sysvol.Templates) { $templateByGuid[$template.Guid] = $template }

    $containerGuids = @{}
    foreach ($container in $Containers) { $containerGuids[$container.Guid] = $container }

    $tier0Dns = @(
        $Context.DomainDN.ToLowerInvariant(),
        ("ou=domain controllers," + $Context.DomainDN).ToLowerInvariant()
    )

    function Get-GpaLinksFor {
        <#
            .SYNOPSIS
                Returns the links of a GPO as a real array.
            .DESCRIPTION
                Indexing a hashtable with an absent key yields $null, and @($null) has a Count
                of 1. Every link lookup goes through this function so that a GPO with no link
                reports zero links rather than one phantom link.
        #>
        param([Parameter()] [AllowNull()] [string] $Guid)
        if (-not $Guid) { return @() }
        if (-not $linksByGuid.ContainsKey($Guid)) { return @() }
        return @($linksByGuid[$Guid])
    }

    function Test-GpaTier0Link {
        param([Parameter()] [AllowNull()] [object[]] $LinkSet)
        foreach ($item in @($LinkSet)) {
            if ($tier0Dns -contains $item.ContainerDN.ToLowerInvariant()) { return $true }
        }
        return $false
    }

    function Get-GpaLinkSummary {
        param([Parameter()] [AllowNull()] [object[]] $LinkSet)
        $set = @($LinkSet)
        if ($set.Count -eq 0) { return '(not linked)' }
        return (($set | ForEach-Object {
            $flags = @()
            if ($_.Enforced)       { $flags += 'ENFORCED' }
            if (-not $_.LinkEnabled) { $flags += 'DISABLED' }
            if ($flags.Count -gt 0) { '{0} [{1}]' -f $_.ContainerDN, ($flags -join ',') }
            else                    { $_.ContainerDN }
        }) -join ' ; ')
    }

    # ---- R1  MS16-072 read permission -------------------------------------------------
    $r1 = @()
    if ($permissionsAvailable) {
        $r1 = foreach ($gpo in $Gpos) {
            $guid = Get-GpaNormalizedGuid $gpo.Id
            if (-not $PermissionMap.ContainsKey($guid)) { continue }

            $readers = @($PermissionMap[$guid] | Where-Object {
                (-not $_.Denied) -and (([string]$_.Permission) -in @('GpoRead', 'GpoApply', 'GpoEdit', 'GpoEditDeleteModifySecurity'))
            })
            $readerSids = @($readers | ForEach-Object { if ($_.Trustee.Sid) { $_.Trustee.Sid.Value } })

            $hasAuthUsers = $readerSids -contains $Principals.AuthenticatedUsers
            $hasEveryone  = $readerSids -contains $Principals.Everyone
            $hasComputers = $readerSids -contains $Principals.DomainComputers
            $hasDCs       = $readerSids -contains $Principals.DomainControllers

            if (-not ($hasAuthUsers -or $hasEveryone -or $hasComputers -or $hasDCs)) {
                [pscustomobject]@{
                    GPOName        = $gpo.DisplayName
                    GUID           = $guid
                    LinkCount      = (Get-GpaLinksFor $guid).Count
                    GpoStatus      = [string]$gpo.GpoStatus
                    ReadTrustees   = (($readers | ForEach-Object { $_.Trustee.Name }) -join '; ')
                    Impact         = 'User policy may fail to apply on domain-joined computers.'
                }
            }
        }
    }
    $findings.Add((New-GpaFinding -Ref 'R1' -NavLabel 'MS16-072' -Anchor 'ms16072' -Class 'risk' `
        -Title 'GPOs without a read permission usable by the computer account (MS16-072)' `
        -Observation 'After MS16-072 / KB3163622, user Group Policy is retrieved in the security context of the computer. A GPO that grants read neither to Authenticated Users nor to Everyone, Domain Computers or Domain Controllers cannot be retrieved by the computer account, and its user settings may stop applying. This is a factual permission observation; whether the removal was intentional must be confirmed with the domain owner.' `
        -Remediation 'Grant read permission to Authenticated Users, or to Domain Computers when security filtering on user objects is required. Apply Group Policy is not needed for the computer account.' `
        -ReferenceLabel 'MS16-072 / KB3163622 (Microsoft Support)' `
        -ReferenceUrl 'https://support.microsoft.com/en-us/topic/ms16-072-security-update-for-group-policy-june-14-2016-7570425d-d460-3003-b2ac-a464c874725d' `
        -Data $r1 -EmptyMessage 'Every GPO grants read to a principal that includes the computer account.' `
        -Available $permissionsAvailable -UnavailableMessage 'Delegation was not collected.'))

    # ---- R2  Group Policy Preferences cpassword ---------------------------------------
    $r2 = foreach ($item in $Sysvol.CPasswords) {
        $gpo = $gpoByGuid[$item.Guid]
        [pscustomobject]@{
            GPOName       = if ($gpo) { $gpo.DisplayName } else { '(no matching GPO object)' }
            GUID          = $item.Guid
            PreferenceXml = $item.PreferenceXml
            RelativePath  = $item.RelativePath
            Occurrences   = $item.Occurrences
        }
    }
    $findings.Add((New-GpaFinding -Ref 'R2' -NavLabel 'cpassword' -Anchor 'cpassword' -Class 'risk' `
        -Title 'Credentials stored in Group Policy Preferences (MS14-025)' `
        -Observation 'Group Policy Preferences XML files containing a cpassword attribute were found in SYSVOL. The AES key protecting that attribute was published by Microsoft, so any principal able to read SYSVOL can recover the plaintext credential. The stored value is deliberately not reproduced in this report.' `
        -Remediation 'Remove the affected preference items, rotate every credential they contained, and replace the mechanism with LAPS or a Group Managed Service Account as appropriate.' `
        -ReferenceLabel 'MS14-025 / KB2962486 (Microsoft Support)' `
        -ReferenceUrl 'https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30' `
        -Data $r2 -EmptyMessage 'No cpassword attribute was found in the scanned Group Policy Templates.' `
        -Available $contentAvailable -UnavailableMessage 'The SYSVOL content scan did not run.'))

    # ---- R3  Non-standard write delegation --------------------------------------------
    $r3 = @()
    if ($permissionsAvailable) {
        $r3 = foreach ($gpo in $Gpos) {
            $guid = Get-GpaNormalizedGuid $gpo.Id
            if (-not $PermissionMap.ContainsKey($guid)) { continue }

            $nonStandard = @($PermissionMap[$guid] | Where-Object {
                (-not $_.Denied) -and (([string]$_.Permission) -in $script:WritePermissions) -and
                ($null -ne $_.Trustee.Sid) -and
                ($Principals.PrivilegedWriteSids -notcontains $_.Trustee.Sid.Value)
            })

            if ($nonStandard.Count -gt 0) {
                $linkSet = Get-GpaLinksFor $guid
                [pscustomobject]@{
                    GPOName     = $gpo.DisplayName
                    GUID        = $guid
                    Tier0Linked = if (Test-GpaTier0Link $linkSet) { 'Yes' } else { 'No' }
                    Trustees    = (($nonStandard | ForEach-Object {
                                        '{0} [{1}]' -f $_.Trustee.Name, $_.Permission
                                    }) -join '; ')
                    LinkedTo    = Get-GpaLinkSummary $linkSet
                }
            }
        }
    }
    $findings.Add((New-GpaFinding -Ref 'R3' -NavLabel 'Delegation' -Anchor 'delegation' -Class 'risk' `
        -Title 'Write delegation held by non-default principals' `
        -Observation 'GPOs on which Edit settings or Edit settings, delete, modify security is granted to a principal outside the default privileged set (SYSTEM, Administrators, Domain Admins, Enterprise Admins, Enterprise Domain Controllers, Creator Owner, Group Policy Creator Owners). Where Tier0Linked is Yes the GPO is linked to the domain root or to the Domain Controllers organizational unit, which makes the delegation a direct path to Tier 0. Whether each delegation is legitimate is a decision for the domain owner; this report only states that it is non-default.' `
        -Remediation 'Review each entry against the delegation model. Remove write delegation from any principal that does not require it, with priority on GPOs linked to Tier 0 containers.' `
        -ReferenceLabel 'Securing Group Policy delegation (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn579255(v=ws.11)' `
        -Data $r3 -EmptyMessage 'No write delegation outside the default privileged principals was found.' `
        -Available $permissionsAvailable -UnavailableMessage 'Delegation was not collected.'))

    # ---- R4  Unresolved SIDs in delegation --------------------------------------------
    $r4 = @()
    if ($permissionsAvailable) {
        $r4 = foreach ($gpo in $Gpos) {
            $guid = Get-GpaNormalizedGuid $gpo.Id
            if (-not $PermissionMap.ContainsKey($guid)) { continue }

            $unresolved = @($PermissionMap[$guid] | Where-Object {
                $null -ne $_.Trustee.Sid -and (
                    [string]::IsNullOrWhiteSpace($_.Trustee.Name) -or
                    $_.Trustee.Name -match '^S-\d-\d+' -or
                    $_.Trustee.Name -eq $_.Trustee.Sid.Value
                )
            })

            if ($unresolved.Count -gt 0) {
                [pscustomobject]@{
                    GPOName    = $gpo.DisplayName
                    GUID       = $guid
                    Unresolved = (($unresolved | ForEach-Object {
                                      '{0} [{1}]' -f $_.Trustee.Sid.Value, $_.Permission
                                  }) -join '; ')
                }
            }
        }
    }
    $findings.Add((New-GpaFinding -Ref 'R4' -NavLabel 'Unresolved SIDs' -Anchor 'sids' -Class 'risk' `
        -Title 'Unresolved SIDs in the delegation of a GPO' `
        -Observation 'Delegation entries whose trustee name could not be resolved and is displayed as a raw SID. The usual causes are a deleted principal or a trust that cannot currently be traversed.' `
        -Remediation 'Confirm whether the principal was deleted. Remove the stale access control entries after confirming that the SID does not belong to a trusted domain that is temporarily unreachable.' `
        -ReferenceLabel 'Get-GPPermission (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gppermission' `
        -Data $r4 -EmptyMessage 'No unresolved SIDs were found in GPO delegation.' `
        -Available $permissionsAvailable -UnavailableMessage 'Delegation was not collected.'))

    # ---- R5 / R6  Orphaned objects -----------------------------------------------------
    $r5 = @()
    $r6 = @()
    if ($sysvolAvailable -and @($Containers).Count -gt 0) {
        $r5 = foreach ($container in $Containers) {
            if (-not $templateByGuid.ContainsKey($container.Guid)) {
                [pscustomobject]@{
                    GUID        = $container.Guid
                    GPOName     = if ($container.DisplayName) { $container.DisplayName } else { '(no displayName attribute)' }
                    WhenCreated = $container.WhenCreated
                    WhenChanged = $container.WhenChanged
                    Issue       = 'Group Policy Container present in Active Directory with no Group Policy Template in SYSVOL.'
                }
            }
        }
        $r6 = foreach ($template in $Sysvol.Templates) {
            if (-not $containerGuids.ContainsKey($template.Guid)) {
                [pscustomobject]@{
                    GUID    = $template.Guid
                    GPOName = '(no Group Policy Container in Active Directory)'
                    Path    = $template.Path
                    Issue   = 'Group Policy Template present in SYSVOL with no Group Policy Container in Active Directory.'
                }
            }
        }
    }
    $orphanNote = 'Both sides of this comparison were read from the same domain controller, so a divergence is not an artifact of DFS Namespace resolving SYSVOL to a different replica. It can still reflect replication that has not converged; confirm against a second domain controller before deleting anything.'
    $findings.Add((New-GpaFinding -Ref 'R5' -NavLabel 'Orphan GPC' -Anchor 'orphan-gpc' -Class 'risk' `
        -Title 'Orphaned Group Policy Container (no template in SYSVOL)' `
        -Observation ("A groupPolicyContainer object exists under CN=Policies,CN=System with no matching folder in SYSVOL. $orphanNote") `
        -Remediation 'Confirm the state on a second domain controller. If the divergence persists, delete the orphaned container through the Group Policy Management Console.' `
        -ReferenceLabel 'Group Policy architecture (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)' `
        -Data $r5 -EmptyMessage 'Every Group Policy Container has a matching template in SYSVOL.' `
        -Available ($sysvolAvailable -and @($Containers).Count -gt 0) `
        -UnavailableMessage 'SYSVOL or the Policies container could not be enumerated.'))
    $findings.Add((New-GpaFinding -Ref 'R6' -NavLabel 'Orphan GPT' -Anchor 'orphan-gpt' -Class 'risk' `
        -Title 'Orphaned Group Policy Template (no container in Active Directory)' `
        -Observation ("A GUID-named folder exists under the SYSVOL Policies path with no matching groupPolicyContainer object. $orphanNote") `
        -Remediation 'Confirm the state on a second domain controller. If the divergence persists, remove the folder from SYSVOL after backing it up.' `
        -ReferenceLabel 'Group Policy architecture (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)' `
        -Data $r6 -EmptyMessage 'Every Group Policy Template has a matching container in Active Directory.' `
        -Available ($sysvolAvailable -and @($Containers).Count -gt 0) `
        -UnavailableMessage 'SYSVOL or the Policies container could not be enumerated.'))

    # ---- R7  Version mismatch between container and template ---------------------------
    $r7 = foreach ($gpo in $Gpos) {
        $computerMismatch = ($gpo.Computer.DSVersion -ne $gpo.Computer.SysvolVersion)
        $userMismatch     = ($gpo.User.DSVersion     -ne $gpo.User.SysvolVersion)
        if ($computerMismatch -or $userMismatch) {
            [pscustomobject]@{
                GPOName          = $gpo.DisplayName
                GUID             = Get-GpaNormalizedGuid $gpo.Id
                ComputerAD       = $gpo.Computer.DSVersion
                ComputerSysvol   = $gpo.Computer.SysvolVersion
                UserAD           = $gpo.User.DSVersion
                UserSysvol       = $gpo.User.SysvolVersion
                ModificationTime = $gpo.ModificationTime
            }
        }
    }
    $findings.Add((New-GpaFinding -Ref 'R7' -NavLabel 'Versions' -Anchor 'version' -Class 'risk' `
        -Title 'Version mismatch between Active Directory and SYSVOL' `
        -Observation 'The version number recorded on the Group Policy Container does not match the version recorded in the Group Policy Template on the same domain controller. This is a direct indicator that SYSVOL replication has not converged or has failed for this policy.' `
        -Remediation 'Investigate DFS Replication or FRS health for SYSVOL. Compare the values across all domain controllers before editing the affected GPOs.' `
        -ReferenceLabel 'DFS Replication of SYSVOL (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/troubleshoot-missing-sysvol-and-netlogon-shares' `
        -Data $r7 -EmptyMessage 'Container and template versions match for every GPO.'))

    # ---- R8  Cross-domain links --------------------------------------------------------
    $domainDnLower = $Context.DomainDN.ToLowerInvariant()
    $r8 = foreach ($link in $Topology.Links) {
        if (-not $link.GpoDomainDN) { continue }
        $containerDomainDN = $null
        $match = [regex]::Match($link.ContainerDN, '(?<dc>DC=.+)$')
        if ($match.Success) { $containerDomainDN = $match.Groups['dc'].Value }
        if (-not $containerDomainDN) { continue }
        if ($link.GpoDomainDN.ToLowerInvariant() -ne $containerDomainDN.ToLowerInvariant()) {
            $gpo = $gpoByGuid[$link.GpoGuid]
            [pscustomobject]@{
                GPOName       = if ($gpo) { $gpo.DisplayName } else { '(GPO hosted in another domain)' }
                GUID          = $link.GpoGuid
                GPODomain     = $link.GpoDomainDN
                ContainerDN   = $link.ContainerDN
                ContainerType = $link.ContainerType
                LinkEnabled   = $link.LinkEnabled
                Enforced      = $link.Enforced
            }
        }
    }
    $crossDomainScope = if ($ForestScope) {
        'Linked containers were enumerated in every domain of the forest, so a link hosted in another domain is visible to this check.'
    }
    else {
        "Only containers in $($Context.DomainFQDN) were enumerated. A link created in another domain that points to a GPO of this domain is NOT visible to this check; re-run with -IncludeForestDomains for full coverage."
    }
    $findings.Add((New-GpaFinding -Ref 'R8' -NavLabel 'Cross-domain' -Anchor 'crossdomain' -Class 'risk' `
        -Title 'Links that cross a domain boundary' `
        -Observation ("A container is linked to a GPO hosted in a different domain. Cross-domain links add latency to policy processing, depend on an available trust path, and are not recommended outside specific scenarios. $crossDomainScope") `
        -Remediation 'Replicate the policy content into a GPO of the target domain and remove the cross-domain link, unless the design explicitly requires it.' `
        -ReferenceLabel 'Linking GPOs (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)' `
        -Data $r8 -EmptyMessage 'No cross-domain link was found within the enumerated scope.'))

    # ---- R9  Linked GPOs with no principal able to apply them --------------------------
    $r9 = @()
    if ($permissionsAvailable) {
        $r9 = foreach ($gpo in $Gpos) {
            $guid    = Get-GpaNormalizedGuid $gpo.Id
            $linkSet = @((Get-GpaLinksFor $guid) | Where-Object { $_.LinkEnabled })
            if ($linkSet.Count -eq 0) { continue }
            if ($gpo.GpoStatus -eq 'AllSettingsDisabled') { continue }
            if (-not $PermissionMap.ContainsKey($guid)) { continue }

            $applyTrustees = @($PermissionMap[$guid] | Where-Object {
                (-not $_.Denied) -and ([string]$_.Permission) -eq 'GpoApply'
            })
            if ($applyTrustees.Count -eq 0) {
                [pscustomobject]@{
                    GPOName   = $gpo.DisplayName
                    GUID      = $guid
                    GpoStatus = [string]$gpo.GpoStatus
                    LinkedTo  = Get-GpaLinkSummary $linkSet
                }
            }
        }
    }
    $findings.Add((New-GpaFinding -Ref 'R9' -NavLabel 'No apply target' -Anchor 'noapply' -Class 'risk' `
        -Title 'Enabled links on GPOs that no principal can apply' `
        -Observation 'The GPO is linked with the link enabled and its settings are not fully disabled, but no principal holds the Apply Group Policy permission. The policy is therefore inert while appearing active in the console.' `
        -Remediation 'Either restore the intended security filtering or remove the link, so that the console reflects the effective configuration.' `
        -ReferenceLabel 'Security filtering (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)' `
        -Data $r9 -EmptyMessage 'Every enabled link resolves to at least one principal that can apply the GPO.' `
        -Available $permissionsAvailable -UnavailableMessage 'Delegation was not collected.'))

    # ---- H1 / H2 / H3 / H4  Settings distribution --------------------------------------
    $h1 = @(); $h2 = @(); $h3 = @(); $h4 = @()

    foreach ($gpo in $Gpos) {
        $guid = Get-GpaNormalizedGuid $gpo.Id
        if (-not $ReportMap.ContainsKey($guid)) { continue }

        $xml         = $ReportMap[$guid]
        $hasComputer = Test-GpaXmlHasSettings $xml.GPO.Computer
        $hasUser     = Test-GpaXmlHasSettings $xml.GPO.User
        $linkSet     = Get-GpaLinksFor $guid
        $status      = [string]$gpo.GpoStatus

        if (-not $hasComputer -and -not $hasUser) {
            $h1 += [pscustomobject]@{
                GPOName          = $gpo.DisplayName
                GUID             = $guid
                GpoStatus        = $status
                LinkCount        = $linkSet.Count
                ComputerVersion  = $gpo.Computer.DSVersion
                UserVersion      = $gpo.User.DSVersion
                CreationTime     = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
            }
        }
        elseif ($linkSet.Count -eq 0) {
            $h2 += [pscustomobject]@{
                GPOName          = $gpo.DisplayName
                GUID             = $guid
                GpoStatus        = $status
                CreationTime     = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
            }
        }

        if ($hasUser -and -not $hasComputer -and $status -notin @('ComputerSettingsDisabled', 'AllSettingsDisabled')) {
            $h3 += [pscustomobject]@{
                GPOName     = $gpo.DisplayName
                GUID        = $guid
                GpoStatus   = $status
                Recommended = 'Set the GPO Status to Computer Settings Disabled.'
            }
        }
        if ($hasComputer -and -not $hasUser -and $status -notin @('UserSettingsDisabled', 'AllSettingsDisabled')) {
            $h4 += [pscustomobject]@{
                GPOName     = $gpo.DisplayName
                GUID        = $guid
                GpoStatus   = $status
                Recommended = 'Set the GPO Status to User Settings Disabled.'
            }
        }
    }

    $emptyNote = 'Emptiness is determined from the extension data of the XML report. The container version numbers are shown alongside: a GPO whose settings were added and later removed keeps a version above zero, so the two indicators can legitimately disagree.'
    $findings.Add((New-GpaFinding -Ref 'H1' -NavLabel 'Empty' -Anchor 'empty' -Class 'hygiene' `
        -Title 'GPOs with no configured settings' `
        -Observation ("No extension data is present in either Computer Configuration or User Configuration. $emptyNote") `
        -Remediation 'Confirm the GPO is not a documented placeholder, then back it up and delete it.' `
        -ReferenceLabel 'Get-GPOReport (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo' `
        -Data $h1 -EmptyMessage 'No empty GPO was found.'))
    $findings.Add((New-GpaFinding -Ref 'H2' -NavLabel 'Unlinked' -Anchor 'unlinked' -Class 'hygiene' `
        -Title 'GPOs with settings but no link' `
        -Observation 'The GPO contains settings but is not linked to any domain, organizational unit or site within the enumerated scope. It has no effect on the environment but represents unfinished or abandoned configuration.' `
        -Remediation 'Link the GPO where it is required, or back it up and delete it.' `
        -ReferenceLabel 'Linking GPOs (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)' `
        -Data $h2 -EmptyMessage 'Every GPO with settings is linked somewhere in the enumerated scope.'))
    $findings.Add((New-GpaFinding -Ref 'H3' -NavLabel 'User only' -Anchor 'useronly' -Class 'hygiene' `
        -Title 'User Configuration only, with the Computer node still enabled' `
        -Observation 'Settings exist only in User Configuration while the Computer Configuration section remains enabled, so clients evaluate a section that carries nothing.' `
        -Remediation 'Set the GPO Status to Computer Settings Disabled to shorten policy processing.' `
        -ReferenceLabel 'Set-GPO GpoStatus (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpo' `
        -Data $h3 -EmptyMessage 'No GPO matches this condition.'))
    $findings.Add((New-GpaFinding -Ref 'H4' -NavLabel 'Computer only' -Anchor 'componly' -Class 'hygiene' `
        -Title 'Computer Configuration only, with the User node still enabled' `
        -Observation 'Settings exist only in Computer Configuration while the User Configuration section remains enabled.' `
        -Remediation 'Set the GPO Status to User Settings Disabled.' `
        -ReferenceLabel 'Set-GPO GpoStatus (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpo' `
        -Data $h4 -EmptyMessage 'No GPO matches this condition.'))

    # ---- H5  All settings disabled -----------------------------------------------------
    $h5 = foreach ($gpo in ($Gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' })) {
        $guid = Get-GpaNormalizedGuid $gpo.Id
        [pscustomobject]@{
            GPOName          = $gpo.DisplayName
            GUID             = $guid
            LinkCount        = (Get-GpaLinksFor $guid).Count
            CreationTime     = $gpo.CreationTime
            ModificationTime = $gpo.ModificationTime
        }
    }
    $findings.Add((New-GpaFinding -Ref 'H5' -NavLabel 'All disabled' -Anchor 'alldisabled' -Class 'hygiene' `
        -Title 'GPOs with GPO Status set to All Settings Disabled' `
        -Observation 'The GPO is completely inert even where it is linked.' `
        -Remediation 'Confirm that the deactivation is intentional and documented; otherwise re-enable it or remove the GPO.' `
        -ReferenceLabel 'Set-GPO GpoStatus (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpo' `
        -Data $h5 -EmptyMessage 'No GPO has all settings disabled.'))

    # ---- H6  Enforced links ------------------------------------------------------------
    $h6 = foreach ($link in ($Topology.Links | Where-Object { $_.Enforced })) {
        $gpo = $gpoByGuid[$link.GpoGuid]
        [pscustomobject]@{
            GPOName       = if ($gpo) { $gpo.DisplayName } else { '(GPO hosted in another domain)' }
            GUID          = $link.GpoGuid
            ContainerDN   = $link.ContainerDN
            ContainerType = $link.ContainerType
            LinkEnabled   = $link.LinkEnabled
            LinkOrder     = $link.LinkOrder
        }
    }
    $findings.Add((New-GpaFinding -Ref 'H6' -NavLabel 'Enforced' -Anchor 'enforced' -Class 'hygiene' `
        -Title 'Links configured as Enforced' `
        -Observation 'An enforced link overrides inheritance blocking and takes precedence over links applied closer to the object. Enforcement is a legitimate design choice; undocumented enforcement is a common source of unexplained precedence.' `
        -Remediation 'Document each enforced link, or remove enforcement where the precedence can be achieved through link order.' `
        -ReferenceLabel 'Group Policy processing and precedence (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)' `
        -Data $h6 -EmptyMessage 'No enforced link was found.'))

    # ---- H7  Inheritance blocking ------------------------------------------------------
    $h7 = foreach ($item in $Topology.BlockedInherit) {
        [pscustomobject]@{
            ContainerDN   = $item.Container
            ContainerType = $item.ContainerType
            Domain        = $item.Domain
        }
    }
    $findings.Add((New-GpaFinding -Ref 'H7' -NavLabel 'Block inherit' -Anchor 'blockinherit' -Class 'hygiene' `
        -Title 'Containers with inheritance blocked' `
        -Observation 'Block Inheritance is set on the container, so GPOs linked higher in the hierarchy do not apply unless their links are enforced. Together with the enforced links above, this determines the effective precedence of the environment.' `
        -Remediation 'Document each blocked container. Inheritance blocking combined with enforcement produces precedence that is difficult to reason about and should be minimized.' `
        -ReferenceLabel 'Group Policy processing and precedence (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)' `
        -Data $h7 -EmptyMessage 'No container blocks inheritance within the enumerated scope.'))

    # ---- H8  Stale GPOs ----------------------------------------------------------------
    $staleBefore = (Get-Date).AddDays(-1 * $StaleGpoThresholdDays)
    $h8 = foreach ($gpo in ($Gpos | Where-Object { $_.ModificationTime -lt $staleBefore })) {
        $guid = Get-GpaNormalizedGuid $gpo.Id
        [pscustomobject]@{
            GPOName          = $gpo.DisplayName
            GUID             = $guid
            LinkCount        = (Get-GpaLinksFor $guid).Count
            ModificationTime = $gpo.ModificationTime
            DaysSinceChange  = [int]((Get-Date) - $gpo.ModificationTime).TotalDays
        }
    }
    $findings.Add((New-GpaFinding -Ref 'H8' -NavLabel 'Stale' -Anchor 'stale' -Class 'hygiene' `
        -Title "GPOs not modified in more than $StaleGpoThresholdDays days" `
        -Observation 'Age alone is not a defect: a stable policy is expected to be stable. The list exists to drive a review of whether the content still matches the current operating system estate and security baseline.' `
        -Remediation 'Review the listed GPOs against the current baseline and record a review date.' `
        -ReferenceLabel 'Get-GPO (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo' `
        -Data $h8 -EmptyMessage 'Every GPO was modified within the configured window.'))

    # ---- H9  Default GPO scope deviation -----------------------------------------------
    $h9 = @()
    foreach ($defaultGuid in @($script:GuidDefaultDomainPolicy, $script:GuidDefaultDomainCtrlPolicy)) {
        if (-not $ReportMap.ContainsKey($defaultGuid)) { continue }
        $gpo = $gpoByGuid[$defaultGuid]
        $xml = $ReportMap[$defaultGuid]

        $computerExtensions = @(Get-GpaExtensionNames $xml.GPO.Computer)
        $userExtensions     = @(Get-GpaExtensionNames $xml.GPO.User)
        $unexpected         = @(@($computerExtensions + $userExtensions) |
                                Where-Object { $script:DefaultGpoExpectedExtensions -notcontains $_ } |
                                Sort-Object -Unique)

        if ($unexpected.Count -gt 0 -or $userExtensions.Count -gt 0) {
            $h9 += [pscustomobject]@{
                GPOName            = if ($gpo) { $gpo.DisplayName } else { '(not readable)' }
                GUID               = $defaultGuid
                ComputerExtensions = ($computerExtensions -join ', ')
                UserExtensions     = ($userExtensions -join ', ')
                Unexpected         = ($unexpected -join ', ')
            }
        }
    }
    $findings.Add((New-GpaFinding -Ref 'H9' -NavLabel 'Default GPOs' -Anchor 'defaultgpo' -Class 'hygiene' `
        -Title 'Default GPOs configured beyond their recommended scope' `
        -Observation 'Microsoft guidance is to restrict the Default Domain Policy to account, password, lockout and Kerberos policy, and the Default Domain Controllers Policy to user rights assignment and audit policy, placing everything else in purpose-built GPOs. This check reports the client-side extensions present in those two GPOs; the contents of the Security extension itself still require manual review, so a listed GPO is a candidate for review rather than a confirmed deviation.' `
        -Remediation 'Move settings outside the recommended scope into dedicated GPOs, then restore the default GPOs to their intended content.' `
        -ReferenceLabel 'Default GPO recommendations (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/create-and-manage-central-store' `
        -Data $h9 -EmptyMessage 'The default GPOs contain only the expected extension.'))

    # ---- H10  Loopback processing ------------------------------------------------------
    $h10 = foreach ($item in $Sysvol.Loopback) {
        $gpo     = $gpoByGuid[$item.Guid]
        $linkSet = Get-GpaLinksFor $item.Guid
        [pscustomobject]@{
            GPOName  = if ($gpo) { $gpo.DisplayName } else { '(no matching GPO object)' }
            GUID     = $item.Guid
            Mode     = $item.Mode
            LinkedTo = Get-GpaLinkSummary $linkSet
        }
    }
    $findings.Add((New-GpaFinding -Ref 'H10' -NavLabel 'Loopback' -Anchor 'loopback' -Class 'hygiene' `
        -Title 'GPOs enabling user Group Policy loopback processing' `
        -Observation 'Loopback processing changes which user settings apply on the computers in scope. Replace discards the user-linked settings entirely; Merge applies them first and lets the loopback GPO override. The mode is read directly from the Registry.pol file of the template, which makes the detection independent of the console language.' `
        -Remediation 'Confirm the mode is intentional and that the scope of the GPO is limited to the computers that require it.' `
        -ReferenceLabel 'Loopback processing of Group Policy (Microsoft Support)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/loopback-processing-of-group-policy' `
        -Data $h10 -EmptyMessage 'No GPO enables loopback processing.' `
        -Available $contentAvailable -UnavailableMessage 'The SYSVOL content scan did not run.'))

    # ---- I1  Link map ------------------------------------------------------------------
    $i1 = foreach ($gpo in $Gpos) {
        $guid    = Get-GpaNormalizedGuid $gpo.Id
        $linkSet = @((Get-GpaLinksFor $guid) | Sort-Object LinkOrder)
        [pscustomobject]@{
            GPOName   = $gpo.DisplayName
            GUID      = $guid
            GpoStatus = [string]$gpo.GpoStatus
            LinkCount = $linkSet.Count
            LinkedTo  = Get-GpaLinkSummary $linkSet
        }
    }
    $findings.Add((New-GpaFinding -Ref 'I1' -NavLabel 'Link map' -Anchor 'links' -Class 'inventory' `
        -Title 'Link map' `
        -Observation 'Where every GPO is applied, with the enforced and disabled state of each link. Link order is derived from the position of the entry in the gPLink attribute, where the last entry corresponds to link order 1 in the console.' `
        -ReferenceLabel 'gPLink attribute (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/windows/win32/adschema/a-gplink' `
        -Data $i1 -EmptyMessage 'No GPO was returned.'))

    # ---- I2  WMI filters ---------------------------------------------------------------
    $i2 = foreach ($gpo in ($Gpos | Where-Object { $null -ne $_.WmiFilter })) {
        [pscustomobject]@{
            GPOName       = $gpo.DisplayName
            GUID          = Get-GpaNormalizedGuid $gpo.Id
            WMIFilterName = $gpo.WmiFilter.Name
            Description   = $gpo.WmiFilter.Description
        }
    }
    $findings.Add((New-GpaFinding -Ref 'I2' -NavLabel 'WMI filters' -Anchor 'wmi' -Class 'inventory' `
        -Title 'GPOs with a WMI filter' `
        -Observation 'A WMI filter is evaluated on every client at every policy refresh, so each filter adds processing cost. Filters should be documented and periodically revalidated against the operating system estate.' `
        -ReferenceLabel 'WMI filtering (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc779036(v=ws.10)' `
        -Data $i2 -EmptyMessage 'No GPO uses a WMI filter.'))

    # ---- I3  Disabled links ------------------------------------------------------------
    $i3 = foreach ($link in ($Topology.Links | Where-Object { -not $_.LinkEnabled })) {
        $gpo = $gpoByGuid[$link.GpoGuid]
        [pscustomobject]@{
            GPOName       = if ($gpo) { $gpo.DisplayName } else { '(GPO hosted in another domain)' }
            GUID          = $link.GpoGuid
            ContainerDN   = $link.ContainerDN
            ContainerType = $link.ContainerType
            Enforced      = $link.Enforced
        }
    }
    $findings.Add((New-GpaFinding -Ref 'I3' -NavLabel 'Disabled links' -Anchor 'disabled-links' -Class 'inventory' `
        -Title 'Links with Link Enabled set to No' `
        -Observation 'The GPO is linked to the container but the link is not processed.' `
        -ReferenceLabel 'gPLink attribute (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/windows/win32/adschema/a-gplink' `
        -Data $i3 -EmptyMessage 'No disabled link was found.'))

    # ---- I4  Group Policy Creator Owners -----------------------------------------------
    $i4 = @()
    $i4Available = $true
    try {
        $gpcoGroup = Get-ADGroup -Identity $Principals.GpCreatorOwners -Server $Context.Server
        $i4 = foreach ($member in (Get-ADGroupMember -Identity $gpcoGroup -Recursive -Server $Context.Server)) {
            [pscustomobject]@{
                Name              = $member.Name
                SamAccountName    = $member.SamAccountName
                ObjectClass       = $member.objectClass
                DistinguishedName = $member.DistinguishedName
            }
        }
    }
    catch {
        $i4Available = $false
        Add-GpaCollectionIssue -Stage 'Group Policy Creator Owners' -Target $Principals.GpCreatorOwners `
            -Reason $_.Exception.Message -Impact 'Membership of the group is missing from the report.'
    }
    $findings.Add((New-GpaFinding -Ref 'I4' -NavLabel 'GPCO' -Anchor 'gpco' -Class 'inventory' `
        -Title 'Members of Group Policy Creator Owners' `
        -Observation 'Members of this group can create GPOs in the domain and hold full control over the GPOs they create. The group is resolved by its well-known relative identifier (RID 520) rather than by display name, so the check works on domains installed in any language.' `
        -ReferenceLabel 'Well-known security identifiers (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers' `
        -Data $i4 -EmptyMessage 'The group has no members.' `
        -Available $i4Available -UnavailableMessage 'The group could not be read.'))

    # ---- I5  Large Group Policy Templates ----------------------------------------------
    $i5 = foreach ($template in ($Sysvol.Templates | Where-Object { $_.IsLarge })) {
        $gpo = $gpoByGuid[$template.Guid]
        [pscustomobject]@{
            GPOName = if ($gpo) { $gpo.DisplayName } else { '(no matching GPO object)' }
            GUID    = $template.Guid
            SizeMB  = $template.SizeMB
            Files   = $template.Files
            Path    = $template.Path
        }
    }
    $findings.Add((New-GpaFinding -Ref 'I5' -NavLabel 'Large templates' -Anchor 'largegpt' -Class 'inventory' `
        -Title "Group Policy Templates larger than $LargeGptThresholdMB MB" `
        -Observation 'Large templates increase SYSVOL replication volume and can extend logon time when the content is downloaded by clients. Scripts and installation payloads stored inside a template are the usual cause.' `
        -ReferenceLabel 'DFS Replication of SYSVOL (Microsoft Learn)' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/troubleshoot-missing-sysvol-and-netlogon-shares' `
        -Data $i5 -EmptyMessage 'No template exceeds the configured size threshold.' `
        -Available $contentAvailable -UnavailableMessage 'The SYSVOL content scan did not run.'))

    return @($findings)
}

# ============================================================================================
#  REPORT RENDERING
# ============================================================================================

$script:ReportCss = @'
  :root{
    --ink:#10151c; --slate:#3d4956; --muted:#5a6672;
    --paper:#f5f6f8; --surface:#ffffff; --line:#e4e8ed; --line-strong:#c7d0d9;
    --accent:#1d5570; --accent-soft:#eaf1f5;
    --crit:#a81f26; --crit-soft:#fbeaea;
    --warn:#7d5107; --warn-soft:#fbf1de;
    --ok:#1f6340;   --ok-soft:#e7f2ec;
    --info:#414e60; --info-soft:#eef1f4;
    --unknown:#5a6672; --unknown-soft:#eceff2;
    --mono:"Cascadia Code","Cascadia Mono",Consolas,ui-monospace,monospace;
    --sans:"Segoe UI Variable","Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --ink:#e8ecf1; --slate:#c2ccd6; --muted:#9aa7b4;
      --paper:#12161b; --surface:#1a1f26; --line:#2b323b; --line-strong:#3d4650;
      --accent:#7fb8d4; --accent-soft:#1e2b34;
      --crit:#f0868c; --crit-soft:#3a1f21;
      --warn:#e3b567; --warn-soft:#382d19;
      --ok:#79c9a1;   --ok-soft:#182c22;
      --info:#a9b6c4; --info-soft:#222831;
      --unknown:#9aa7b4; --unknown-soft:#232931;
    }
    thead th{background:#232a33 !important}
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  html{scroll-behavior:smooth}
  body{font-family:var(--sans);font-size:13px;line-height:1.5;color:var(--ink);background:var(--paper);-webkit-font-smoothing:antialiased}
  code.mono,.mono{font-family:var(--mono);font-size:.82em;color:var(--slate);word-break:break-all}
  .muted-txt{color:var(--muted)}
  a{color:var(--accent)}
  a:focus-visible,summary:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}

  .masthead{background:var(--ink);color:#fff;padding:30px 40px 24px}
  @media (prefers-color-scheme: dark){.masthead{background:#0b0e12}}
  .masthead .kicker{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#93a3b2;font-weight:600}
  .masthead h1{font-size:26px;font-weight:700;letter-spacing:-.01em;margin-top:8px;color:#fff}
  .masthead .meta{margin-top:15px;display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:5px 26px;font-size:12px;color:#c9d3dc}
  .masthead .meta b{color:#fff;font-weight:600}

  .posture{display:flex;flex-wrap:wrap;align-items:center;gap:14px 22px;padding:14px 40px;background:var(--surface);border-bottom:1px solid var(--line)}
  .verdict{display:flex;align-items:center;gap:10px;font-weight:700;font-size:14px}
  .verdict .dot{width:11px;height:11px;border-radius:50%;flex:none}
  .verdict.sev-crit{color:var(--crit)} .verdict.sev-crit .dot{background:var(--crit)}
  .verdict.sev-warn{color:var(--warn)} .verdict.sev-warn .dot{background:var(--warn)}
  .verdict.sev-ok{color:var(--ok)}     .verdict.sev-ok .dot{background:var(--ok)}
  .legend{display:flex;gap:15px;margin-left:auto;font-size:11.5px;color:var(--muted)}
  .legend span{display:flex;align-items:center;gap:6px}
  .legend i{width:9px;height:9px;border-radius:50%;display:inline-block}
  .lg-risk{background:var(--crit)} .lg-hyg{background:var(--warn)} .lg-info{background:var(--line-strong)}

  /* Navigation chips: same severity language as the tiles, at roughly a third of the height.
     The count badge carries the colour so the strip can be scanned without reading labels. */
  .nav{position:sticky;top:0;z-index:30;background:var(--surface);border-bottom:1px solid var(--line);padding:7px 40px;display:flex;flex-wrap:wrap;gap:4px;align-items:center}
  .navchip{display:inline-flex;align-items:center;gap:5px;font-size:10.5px;line-height:1;letter-spacing:.01em;text-decoration:none;color:var(--slate);background:var(--surface);border:1px solid var(--line);border-left-width:3px;border-left-color:var(--line-strong);border-radius:6px;padding:4px 6px 4px 5px;transition:transform .12s ease,box-shadow .12s ease,border-color .12s ease,color .12s ease}
  .navchip .lbl{white-space:nowrap;font-weight:500}
  .navchip .cnt{font-family:var(--mono);font-size:9.5px;font-weight:700;min-width:16px;height:14px;padding:0 4px;display:inline-flex;align-items:center;justify-content:center;border-radius:7px;background:var(--info-soft);color:var(--info);font-variant-numeric:tabular-nums}
  .navchip:hover{transform:translateY(-1px);box-shadow:0 2px 7px rgba(16,21,28,.14)}
  .navchip.sev-crit{border-left-color:var(--crit)}
  .navchip.sev-crit .cnt{background:var(--crit);color:#fff}
  .navchip.sev-crit:hover{border-color:var(--crit);color:var(--crit)}
  .navchip.sev-warn{border-left-color:var(--warn)}
  .navchip.sev-warn .cnt{background:var(--warn);color:#fff}
  .navchip.sev-warn:hover{border-color:var(--warn);color:var(--warn)}
  .navchip.sev-ok{border-left-color:var(--ok)}
  .navchip.sev-ok .cnt{background:var(--ok-soft);color:var(--ok)}
  .navchip.sev-ok:hover{border-color:var(--ok);color:var(--ok)}
  .navchip.sev-info{border-left-color:var(--line-strong)}
  .navchip.sev-unknown{border-left-color:var(--unknown);border-style:dashed;border-left-style:solid}
  .navchip.sev-unknown .cnt{background:var(--unknown-soft);color:var(--unknown)}
  .navchip.sev-unknown:hover{border-color:var(--unknown);color:var(--unknown)}
  .navchip.plain{border-left-color:var(--accent);color:var(--accent);font-weight:700;text-transform:uppercase;font-size:10px;letter-spacing:.06em;padding:5px 8px}
  .navchip.plain:hover{border-color:var(--accent);background:var(--accent-soft)}
  .nav .spacer{margin-left:auto;display:flex;gap:5px}
  @media (prefers-color-scheme: dark){
    .navchip.sev-crit .cnt,.navchip.sev-warn .cnt{color:#12161b}
    .navchip:hover{box-shadow:0 2px 7px rgba(0,0,0,.5)}
  }

  /* The navigation strip is sticky, so anchors need clearance or the heading lands under it. */
  .finding,#summary,#plan{scroll-margin-top:78px}
  .finding:target{border-color:var(--accent)}
  .btn{font-size:11px;font-family:inherit;color:var(--slate);background:var(--surface);border:1px solid var(--line-strong);border-radius:5px;padding:4px 10px;cursor:pointer}
  .btn:hover{color:var(--accent);border-color:var(--accent)}

  .wrap{max-width:1180px;margin:0 auto;padding:28px 40px 20px}
  .block-title{font-size:12px;letter-spacing:.13em;text-transform:uppercase;color:var(--muted);font-weight:600;margin:6px 0 13px}

  .tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:11px;margin-bottom:14px}
  .tile{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:14px 15px 13px}
  .tile::before{content:"";position:absolute;left:0;top:13px;bottom:13px;width:3px;border-radius:3px;background:var(--line-strong)}
  .tile.sev-crit::before{background:var(--crit)} .tile.sev-warn::before{background:var(--warn)}
  .tile.sev-ok::before{background:var(--ok)}     .tile.sev-info::before{background:var(--line-strong)}
  .tile.sev-unknown::before{background:var(--unknown)}
  .tile .num{font-size:27px;font-weight:700;line-height:1;padding-left:11px;font-variant-numeric:tabular-nums;color:var(--ink)}
  .tile.sev-crit .num{color:var(--crit)} .tile.sev-warn .num{color:var(--warn)} .tile.sev-ok .num{color:var(--ok)}
  .tile.sev-unknown .num{color:var(--unknown)}
  .tile .lbl{font-size:11.5px;color:var(--muted);margin-top:7px;padding-left:11px;line-height:1.35}

  .note{font-size:12px;color:var(--muted);border-left:2px solid var(--line-strong);padding-left:11px;margin-top:6px}

  .plan{background:var(--surface);border:1px solid var(--line);border-radius:9px;overflow:hidden;margin-bottom:22px}
  .plan table{width:100%;border-collapse:collapse;font-size:12.5px}
  .plan td,.plan th{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
  .plan tbody tr:last-child td{border-bottom:none}
  .plan .r{font-family:var(--mono);font-weight:700;color:var(--muted);white-space:nowrap}

  .finding{background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--line-strong);border-radius:9px;margin-bottom:14px;overflow:hidden}
  .finding.sev-crit{border-left-color:var(--crit)} .finding.sev-warn{border-left-color:var(--warn)}
  .finding.sev-ok{border-left-color:var(--ok)}     .finding.sev-info{border-left-color:var(--line-strong)}
  .finding.sev-unknown{border-left-color:var(--unknown)}
  .finding>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;padding:14px 20px;user-select:none}
  .finding>summary::-webkit-details-marker{display:none}
  .finding>summary::after{content:"";margin-left:auto;width:7px;height:7px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .2s;flex:none}
  .finding[open]>summary::after{transform:rotate(-135deg)}
  .finding .ref{font-family:var(--mono);font-size:11px;color:var(--muted);font-weight:700;min-width:32px}
  .finding h2{font-size:15px;font-weight:600;flex:1}
  .finding .body{padding:0 20px 20px;border-top:1px solid var(--line)}
  .desc{font-size:12.5px;color:var(--slate);margin:14px 0;padding-left:12px;border-left:2px solid var(--accent-soft)}
  .desc .tag-obs,.desc .tag-rem{display:inline-block;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--accent);margin-right:6px}
  .desc p+p{margin-top:8px}
  .srcref{font-size:11.5px;color:var(--muted);margin:0 0 12px 12px}

  .chip{font-size:11px;font-weight:600;padding:3px 11px;border-radius:20px;white-space:nowrap;font-variant-numeric:tabular-nums}
  .chip-crit{background:var(--crit-soft);color:var(--crit)}
  .chip-warn{background:var(--warn-soft);color:var(--warn)}
  .chip-ok{background:var(--ok-soft);color:var(--ok)}
  .chip-info{background:var(--info-soft);color:var(--info)}
  .chip-unknown{background:var(--unknown-soft);color:var(--unknown)}

  .toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px}
  .toolbar input{font-family:inherit;font-size:12px;color:var(--ink);background:var(--surface);border:1px solid var(--line-strong);border-radius:6px;padding:5px 10px;min-width:230px}
  .toolbar .rowcount{font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums}

  .table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  caption{text-align:left;font-size:11px;color:var(--muted);padding:0 0 6px}
  thead th{background:#eef1f4;color:var(--slate);text-align:left;font-weight:600;font-size:10.5px;letter-spacing:.04em;text-transform:uppercase;padding:9px 13px;border-bottom:1px solid var(--line-strong);white-space:nowrap}
  table.sortable thead th{cursor:pointer}
  table.sortable thead th::after{content:"";display:inline-block;width:0;height:0;margin-left:6px;vertical-align:middle;border-left:4px solid transparent;border-right:4px solid transparent;border-top:4px solid var(--line-strong)}
  table.sortable thead th.asc::after{border-top:none;border-bottom:4px solid var(--accent)}
  table.sortable thead th.desc::after{border-top:4px solid var(--accent)}
  tbody td{padding:9px 13px;border-bottom:1px solid var(--line);vertical-align:top}
  tbody tr:last-child td{border-bottom:none}
  tbody tr:hover{background:var(--accent-soft)}

  .ok-note{font-size:12.5px;color:var(--ok);background:var(--ok-soft);border:1px solid var(--ok);border-radius:7px;padding:11px 14px;display:flex;gap:9px;align-items:center}
  .ok-note::before{content:"\2713";font-weight:700}
  .unknown-note{font-size:12.5px;color:var(--unknown);background:var(--unknown-soft);border:1px solid var(--line-strong);border-radius:7px;padding:11px 14px}

  .foot{border-top:1px solid var(--line);padding:20px 40px;font-size:11.5px;color:var(--muted);text-align:center;line-height:1.7}
  .foot strong{color:var(--slate)}

  @media (max-width:640px){
    .masthead,.posture,.nav,.wrap,.foot{padding-left:18px;padding-right:18px}
    .masthead h1{font-size:21px} .legend{margin-left:0}
  }
  @media (prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
  @page{size:A4;margin:14mm}
  @media print{
    body{background:#fff;color:#000;font-size:10.5px}
    .nav,.toolbar,.btn{display:none!important}
    .masthead{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .tile,.chip,thead th,.finding,.plan{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .finding{break-inside:avoid;box-shadow:none}
    .finding>summary::after{display:none}
    .finding .body{display:block!important}
    tr{break-inside:avoid}
  }
'@

$script:ReportJs = @'
document.addEventListener('DOMContentLoaded', function () {
  var sections = Array.prototype.slice.call(document.querySelectorAll('details.finding'));

  function setAll(state) { sections.forEach(function (d) { d.open = state; }); }
  var expandBtn = document.getElementById('expand-all');
  var collapseBtn = document.getElementById('collapse-all');
  if (expandBtn) { expandBtn.addEventListener('click', function () { setAll(true); }); }
  if (collapseBtn) { collapseBtn.addEventListener('click', function () { setAll(false); }); }

  Array.prototype.slice.call(document.querySelectorAll('input.tfilter')).forEach(function (input) {
    input.addEventListener('input', function () {
      var term = input.value.toLowerCase();
      var table = document.getElementById(input.getAttribute('data-target'));
      if (!table) { return; }
      var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));
      var shown = 0;
      rows.forEach(function (row) {
        var hit = row.textContent.toLowerCase().indexOf(term) !== -1;
        row.style.display = hit ? '' : 'none';
        if (hit) { shown += 1; }
      });
      var counter = document.getElementById(input.getAttribute('data-target') + '-count');
      if (counter) { counter.textContent = shown + ' / ' + rows.length + ' rows'; }
    });
  });

  function cellValue(row, index) {
    var cell = row.cells[index];
    return cell ? cell.textContent.trim() : '';
  }

  function compare(a, b, index, numeric) {
    var x = cellValue(a, index);
    var y = cellValue(b, index);
    if (numeric) { return parseFloat(x.replace(/[^0-9.\-]/g, '') || '0') - parseFloat(y.replace(/[^0-9.\-]/g, '') || '0'); }
    return x.localeCompare(y, undefined, { numeric: true, sensitivity: 'base' });
  }

  Array.prototype.slice.call(document.querySelectorAll('table.sortable')).forEach(function (table) {
    var headers = Array.prototype.slice.call(table.querySelectorAll('thead th'));
    headers.forEach(function (th, index) {
      th.setAttribute('tabindex', '0');
      function run() {
        var body = table.tBodies[0];
        if (!body) { return; }
        var rows = Array.prototype.slice.call(body.rows);
        var descending = th.classList.contains('asc');
        var numeric = rows.every(function (r) {
          var v = cellValue(r, index).replace(/[^0-9.\-]/g, '');
          return v.length > 0 && !isNaN(parseFloat(v));
        });
        rows.sort(function (a, b) { return descending ? compare(b, a, index, numeric) : compare(a, b, index, numeric); });
        headers.forEach(function (h) { h.classList.remove('asc', 'desc'); });
        th.classList.add(descending ? 'desc' : 'asc');
        rows.forEach(function (r) { body.appendChild(r); });
      }
      th.addEventListener('click', run);
      th.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); run(); } });
    });
  });
});
'@

function ConvertTo-GpaHtmlTable {
    <#
        .SYNOPSIS
            Renders a collection as a sortable, filterable HTML table.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] [object[]] $Data,
        [Parameter(Mandatory)] [string] $TableId,
        [Parameter(Mandatory)] [string] $Caption,
        [Parameter(Mandatory)] [string] $EmptyMessage
    )

    $rows = @($Data)
    if ($rows.Count -eq 0) {
        return ("<p class='ok-note'>{0}</p>" -f (ConvertTo-GpaHtmlText $EmptyMessage))
    }

    $monoColumns = @('GUID', 'Id', 'DistinguishedName', 'ContainerDN', 'GpoDN', 'GPODomain',
                     'SID', 'Sid', 'Unresolved', 'Path', 'RelativePath', 'LinkedTo')

    $properties = @($rows[0].PSObject.Properties.Name)
    $header = ($properties | ForEach-Object {
        "<th scope='col'>{0}</th>" -f (ConvertTo-GpaHtmlText $_)
    }) -join ''

    $bodyRows = foreach ($row in $rows) {
        $cells = ($properties | ForEach-Object {
            $encoded = ConvertTo-GpaHtmlText $row.$_
            if ($monoColumns -contains $_) { "<td><code class='mono'>$encoded</code></td>" }
            else                           { "<td>$encoded</td>" }
        }) -join ''
        "<tr>$cells</tr>"
    }

    $toolbar = @"
<div class="toolbar">
  <input class="tfilter" type="search" data-target="$TableId" placeholder="Filter rows" aria-label="Filter rows of $TableId">
  <span class="rowcount" id="$TableId-count">$($rows.Count) / $($rows.Count) rows</span>
</div>
"@

    $table = @"
<div class="table-wrap">
  <table class="sortable" id="$TableId">
    <caption>$(ConvertTo-GpaHtmlText $Caption)</caption>
    <thead><tr>$header</tr></thead>
    <tbody>$($bodyRows -join '')</tbody>
  </table>
</div>
"@

    return ($toolbar + $table)
}

function New-GpaFindingSection {
    <#
        .SYNOPSIS
            Renders one finding as a collapsible report section.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [object] $Finding)

    $severity = Get-GpaFindingSeverity -Finding $Finding

    $chip = switch ($severity) {
        'unknown' { "<span class='chip chip-unknown'>not assessed</span>" }
        'info'    { "<span class='chip chip-info'>$($Finding.Count)</span>" }
        'ok'      { "<span class='chip chip-ok'>0 findings</span>" }
        default   {
            $word = if ($Finding.Count -eq 1) { 'finding' } else { 'findings' }
            "<span class='chip chip-$severity'>$($Finding.Count) $word</span>"
        }
    }

    $reference = ''
    if ($Finding.ReferenceUrl) {
        $reference = "<p class='srcref'>Reference: <a href='$(ConvertTo-GpaHtmlText $Finding.ReferenceUrl)'>$(ConvertTo-GpaHtmlText $Finding.ReferenceLabel)</a></p>"
    }

    $remediation = ''
    if ($Finding.Remediation) {
        $remediation = "<p><span class='tag-rem'>Recommendation</span>$(ConvertTo-GpaHtmlText $Finding.Remediation)</p>"
    }

    if (-not $Finding.Available) {
        $content = "<p class='unknown-note'>$(ConvertTo-GpaHtmlText $Finding.UnavailableMessage) The result of this check is unknown and must not be read as compliance.</p>"
    }
    else {
        $content = ConvertTo-GpaHtmlTable -Data $Finding.Data -TableId "t-$($Finding.Anchor)" `
            -Caption "$($Finding.Ref) - $($Finding.Title)" -EmptyMessage $Finding.EmptyMessage
    }

    $open = if ($severity -in @('crit', 'unknown')) { ' open' } else { '' }

    return @"
<details id="$($Finding.Anchor)" class="finding sev-$severity"$open>
  <summary><span class="ref">$(ConvertTo-GpaHtmlText $Finding.Ref)</span><h2>$(ConvertTo-GpaHtmlText $Finding.Title)</h2>$chip</summary>
  <div class="body">
    <div class="desc">
      <p><span class="tag-obs">Observation</span>$(ConvertTo-GpaHtmlText $Finding.Observation)</p>
      $remediation
    </div>
    $reference
    $content
  </div>
</details>
"@
}

function New-GpaReport {
    <#
        .SYNOPSIS
            Assembles the complete HTML report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object] $Context,
        [Parameter(Mandatory)] [object] $Metadata,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Issues,
        [Parameter(Mandatory)] [int] $TotalGpos
    )

    $riskOpen    = @($Findings | Where-Object { $_.Class -eq 'risk'    -and $_.Available -and $_.Count -gt 0 }).Count
    $hygieneOpen = @($Findings | Where-Object { $_.Class -eq 'hygiene' -and $_.Available -and $_.Count -gt 0 }).Count
    $notAssessed = @($Findings | Where-Object { -not $_.Available }).Count

    if     ($riskOpen    -gt 0) { $postureSev = 'crit'; $postureLabel = 'Attention required - integrity or security findings present' }
    elseif ($hygieneOpen -gt 0) { $postureSev = 'warn'; $postureLabel = 'No risk findings - hygiene items pending' }
    else                        { $postureSev = 'ok';   $postureLabel = 'No risk or hygiene findings within the assessed scope' }

    # Incompleteness is stated on the posture strip whatever the finding counts are: a report
    # that omits it invites the reader to treat an unrun check as a clean one.
    if ($notAssessed -gt 0) {
        if ($postureSev -eq 'ok') { $postureSev = 'warn' }
        $postureLabel = '{0} - assessment incomplete, {1} check(s) not assessed' -f $postureLabel, $notAssessed
    }

    # --- navigation ---
    # Each check becomes a chip whose left edge and count badge use the severity of the finding,
    # so the strip doubles as a heat map. The reference and the full title stay in the tooltip
    # rather than on the chip, which keeps the strip to a fraction of the height of the tiles.
    $navItems = foreach ($finding in $Findings) {
        $severity = Get-GpaFindingSeverity -Finding $finding
        $count    = if ($finding.Available) { $finding.Count } else { '?' }
        $tooltip  = ConvertTo-GpaHtmlText ('{0} - {1}' -f $finding.Ref, $finding.Title)
        "<a class='navchip sev-$severity' href='#$($finding.Anchor)' title='$tooltip'><span class='lbl'>$(ConvertTo-GpaHtmlText $finding.NavLabel)</span><span class='cnt'>$count</span></a>"
    }

    $issueCount = @($Issues).Count
    $issueSev   = if ($issueCount -gt 0) { 'warn' } else { 'ok' }

    $navHtml = @"
<a class="navchip plain" href="#summary">Summary</a>
<a class="navchip plain" href="#plan">Plan</a>
$($navItems -join "`n")
<a class="navchip sev-$issueSev" href="#collection" title="C0 - Collection completeness"><span class="lbl">Collection</span><span class="cnt">$issueCount</span></a>
<div class="spacer">
  <button type="button" class="btn" id="expand-all">Expand all</button>
  <button type="button" class="btn" id="collapse-all">Collapse all</button>
</div>
"@

    # --- tiles ---
    $tiles = [System.Collections.Generic.List[string]]::new()
    $tiles.Add("<div class='tile sev-info'><div class='num'>$TotalGpos</div><div class='lbl'>GPOs assessed</div></div>")
    foreach ($finding in $Findings) {
        $severity = Get-GpaFindingSeverity -Finding $finding
        $value    = if ($finding.Available) { $finding.Count } else { '?' }
        $tiles.Add("<div class='tile sev-$severity'><div class='num'>$value</div><div class='lbl'>$($finding.Ref) $(ConvertTo-GpaHtmlText $finding.Title)</div></div>")
    }

    # --- remediation plan ---
    $planItems = @($Findings |
        Where-Object { $_.Available -and $_.Count -gt 0 -and $_.Class -ne 'inventory' } |
        Sort-Object @{ Expression = { if ($_.Class -eq 'risk') { 0 } else { 1 } } }, @{ Expression = 'Count'; Descending = $true })

    if ($planItems.Count -eq 0) {
        $planHtml = "<div class='plan'><table><tbody><tr><td>No risk or hygiene finding requires action within the assessed scope.</td></tr></tbody></table></div>"
    }
    else {
        $planRows = foreach ($item in $planItems) {
            $severity = Get-GpaFindingSeverity -Finding $item
            @"
<tr>
  <td class="r">$(ConvertTo-GpaHtmlText $item.Ref)</td>
  <td><a href="#$($item.Anchor)">$(ConvertTo-GpaHtmlText $item.Title)</a></td>
  <td><span class="chip chip-$severity">$($item.Count)</span></td>
  <td>$(ConvertTo-GpaHtmlText $item.Remediation)</td>
</tr>
"@
        }
        $planHtml = @"
<div class="plan">
  <table>
    <caption class="muted-txt">Findings with a non-zero count, ordered by class and volume.</caption>
    <thead><tr><th scope="col">Ref</th><th scope="col">Finding</th><th scope="col">Count</th><th scope="col">Recommended action</th></tr></thead>
    <tbody>$($planRows -join '')</tbody>
  </table>
</div>
"@
    }

    $sectionsHtml = ($Findings | ForEach-Object { New-GpaFindingSection -Finding $_ }) -join "`n"

    $issuesHtml = ConvertTo-GpaHtmlTable -Data $Issues -TableId 't-collection' `
        -Caption 'Steps that failed during collection' `
        -EmptyMessage 'Every collection step completed without error.'

    $metaRows = @(
        "<span>Domain&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Context.DomainFQDN)</b></span>"
        "<span>Domain controller&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Context.Server)</b></span>"
        "<span>Collected by&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Context.RunAsAccount)</b></span>"
        "<span>Generated&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Metadata.Timestamp)</b></span>"
        "<span>GPOs assessed&nbsp;&nbsp;<b>$TotalGpos</b></span>"
        "<span>Link scope&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Metadata.LinkScope)</b></span>"
        "<span>Script version&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Metadata.ScriptVersion)</b></span>"
        "<span>Script SHA-256&nbsp;&nbsp;<b class='mono'>$(ConvertTo-GpaHtmlText $Metadata.ScriptHash)</b></span>"
    )
    if ($Metadata.ClientName) { $metaRows = @("<span>Client&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Metadata.ClientName)</b></span>") + $metaRows }
    if ($Metadata.Assessor)   { $metaRows += "<span>Assessor&nbsp;&nbsp;<b>$(ConvertTo-GpaHtmlText $Metadata.Assessor)</b></span>" }

    return @"
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPO Assessment - $(ConvertTo-GpaHtmlText $Context.DomainFQDN)</title>
<style>
$($script:ReportCss)
</style>
</head>
<body>

<div class="masthead">
  <div class="kicker">Group Policy Assessment &middot; Active Directory</div>
  <h1>GPO Assessment Report</h1>
  <div class="meta">
$($metaRows -join "`n")
  </div>
</div>

<div class="posture">
  <div class="verdict sev-$postureSev"><span class="dot"></span>$postureLabel</div>
  <div class="legend">
    <span><i class="lg-risk"></i>Risk / integrity</span>
    <span><i class="lg-hyg"></i>Hygiene / precedence</span>
    <span><i class="lg-info"></i>Inventory</span>
  </div>
</div>

<div class="nav">
$navHtml
</div>

<div class="wrap">

<div id="summary">
  <div class="block-title">Executive summary</div>
  <div class="tiles">$($tiles -join "`n")</div>
  <p class="note">The classification into risk, hygiene and inventory is an editorial convention of this report used for prioritization. It does not correspond to any formal severity rating published by Microsoft. Each section separates the observation, which is a statement of the collected data, from the recommendation, which is an interpretation to be validated against the design of the environment. A tile showing "?" means the check did not run; see the collection section.</p>
</div>

<div id="plan">
  <div class="block-title">Recommended actions</div>
  $planHtml
</div>

<div class="block-title" style="margin-top:24px">Detailed findings</div>

$sectionsHtml

<details id="collection" class="finding sev-$(if (@($Issues).Count -gt 0) { 'warn' } else { 'ok' })">
  <summary><span class="ref">C0</span><h2>Collection completeness</h2><span class="chip chip-$(if (@($Issues).Count -gt 0) { 'warn' } else { 'ok' })">$(@($Issues).Count)</span></summary>
  <div class="body">
    <div class="desc">
      <p><span class="tag-obs">Observation</span>Steps that failed while collecting data. Any check that depended on a failed step is marked as not assessed and its result is unknown rather than compliant.</p>
    </div>
    $issuesHtml
  </div>
</details>

</div>

<div class="foot">
  <strong>GPO Assessment Report</strong> &nbsp;&middot;&nbsp; $(ConvertTo-GpaHtmlText $Context.DomainFQDN) &nbsp;&middot;&nbsp; $(ConvertTo-GpaHtmlText $Metadata.Timestamp)<br>
  Read-only assessment. No Active Directory or SYSVOL object was created, modified or deleted.<br>
  Provided AS IS, without warranty and without support.
</div>

<script>
$($script:ReportJs)
</script>
</body>
</html>
"@
}

# ============================================================================================
#  MAIN
# ============================================================================================

$exitCode = 0

try {
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '   GPO ASSESSMENT - Active Directory' -ForegroundColor Cyan
    Write-Host "   Version $($script:ScriptVersion) - read-only" -ForegroundColor Cyan
    Write-Host '   Provided AS IS. No support is provided.' -ForegroundColor DarkCyan
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host ''

    # ---- Context -------------------------------------------------------------------
    Write-GpaLog -Level STEP -Message 'CONTEXT'
    $context = Resolve-GpaContext -DomainName $DomainName -Server $Server
    Write-GpaLog -Level OK -Message "Domain           : $($context.DomainFQDN)"
    Write-GpaLog -Level OK -Message "Domain controller: $($context.Server)"
    Write-GpaLog -Level OK -Message "SYSVOL path      : $($context.SysvolPolicyPath)"
    Write-GpaLog -Level INFO -Message 'All reads are pinned to this domain controller so that Active Directory and SYSVOL come from the same replica.'

    $principals = Get-GpaWellKnownPrincipals -Context $context

    # ---- Output layout -------------------------------------------------------------
    # Everything this run produces stays under one folder: <OutputPath>\<domain>\<timestamp>.
    # The per-run subfolder means a second execution never overwrites the previous evidence,
    # which matters when the report is a client deliverable.
    $runStamp  = $script:StartTime.ToString('yyyyMMdd-HHmmss')
    # [System.IO.Path]::Combine is used instead of Join-Path throughout: Join-Path resolves the
    # leading segment through the PowerShell provider and fails when the current location is on a
    # provider that does not expose the target drive.
    $runFolder = [System.IO.Path]::Combine($OutputPath, $context.DomainFQDN, $runStamp)
    $exportDir = [System.IO.Path]::Combine($runFolder, 'GPO-Exports')
    $csvDir    = [System.IO.Path]::Combine($runFolder, 'csv')

    try {
        foreach ($folder in @($runFolder, $csvDir)) {
            if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        }
        if (-not $SkipIndividualHtmlReports -and -not (Test-Path -LiteralPath $exportDir)) {
            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        }
    }
    catch {
        throw ("Unable to create the output folder '{0}': {1} Specify a writable location with -OutputPath." -f $runFolder, $_.Exception.Message)
    }
    Write-GpaLog -Level OK -Message "Output root      : $OutputPath"
    Write-GpaLog -Level OK -Message "Run folder       : $runFolder"

    # ---- Collection ----------------------------------------------------------------
    Write-GpaLog -Level STEP -Message 'COLLECTION'
    $gpos       = Get-GpaGpoInventory -Context $context
    $reportMap  = Get-GpaGpoReportMap -Context $context -Gpos $gpos
    $topology   = Get-GpaLinkTopology -Context $context -IncludeForestDomains:$IncludeForestDomains
    $containers = Get-GpaContainerInventory -Context $context
    $sysvol     = Get-GpaSysvolInventory -Context $context -ScanContent:(-not $SkipSysvolContentScan) `
                    -LargeGptThresholdMB $LargeGptThresholdMB

    $permissionMap = $null
    if ($SkipPermissionChecks) {
        Write-GpaLog -Level WARN -Message 'Delegation collection skipped by parameter; four checks will report as not assessed.'
        $permissionMap = @{}
    }
    else {
        $permissionMap = Get-GpaPermissionMap -Context $context -Gpos $gpos
    }

    $exportedReports = 0
    if ($SkipIndividualHtmlReports) {
        Write-GpaLog -Level INFO -Message 'Individual per-GPO HTML export skipped by parameter.'
    }
    else {
        $exportedReports = Export-GpaIndividualReport -Context $context -Gpos $gpos -Destination $exportDir
    }

    # ---- Analysis ------------------------------------------------------------------
    Write-GpaLog -Level STEP -Message 'ANALYSIS'
    $findings = Get-GpaFindings -Context $context -Principals $principals -Gpos $gpos `
        -ReportMap $reportMap -Topology $topology -PermissionMap $permissionMap `
        -Sysvol $sysvol -Containers $containers `
        -StaleGpoThresholdDays $StaleGpoThresholdDays -LargeGptThresholdMB $LargeGptThresholdMB `
        -ForestScope ([bool]$IncludeForestDomains)
    Write-GpaLog -Level OK -Message "Checks evaluated: $(@($findings).Count)"

    # ---- Reporting -----------------------------------------------------------------
    Write-GpaLog -Level STEP -Message 'REPORTING'

    $scriptHash = 'not available'
    if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
        $scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    }

    $metadata = [pscustomobject]@{
        Timestamp     = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss K')
        ClientName    = $ClientName
        Assessor      = $Assessor
        ScriptVersion = $script:ScriptVersion
        ScriptHash    = $scriptHash
        LinkScope     = if ($IncludeForestDomains) { "Forest ($($context.ForestFQDN))" } else { "Domain ($($context.DomainFQDN))" }
    }

    $html       = New-GpaReport -Context $context -Metadata $metadata -Findings $findings `
                    -Issues @($script:CollectionIssues) -TotalGpos (@($gpos).Count)
    $reportFile = [System.IO.Path]::Combine($runFolder, ('GPO-Assessment-Report_{0}.html' -f $runStamp))

    # WriteAllText with an explicit encoding keeps the output byte-identical between
    # Windows PowerShell 5.1 and PowerShell 7, unlike Out-File -Encoding UTF8.
    [System.IO.File]::WriteAllText($reportFile, $html, ([System.Text.UTF8Encoding]::new($false)))
    Write-GpaLog -Level OK -Message "HTML report : $reportFile"

    $jsonFile = [System.IO.Path]::Combine($runFolder, 'findings.json')
    $jsonBody = [pscustomobject]@{
        Metadata         = $metadata
        Context          = $context
        TotalGpos        = @($gpos).Count
        ExportedReports  = $exportedReports
        Findings         = @($findings | Select-Object Ref, Title, Class, Count, Available, Observation, Remediation, ReferenceUrl, Data)
        CollectionIssues = @($script:CollectionIssues)
    } | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($jsonFile, $jsonBody, ([System.Text.UTF8Encoding]::new($false)))
    Write-GpaLog -Level OK -Message "JSON export : $jsonFile"

    foreach ($finding in $findings) {
        $rows = @($finding.Data | Where-Object { $null -ne $_ })
        if ($rows.Count -eq 0) { continue }
        $csvFile = [System.IO.Path]::Combine($csvDir, ('{0}_{1}.csv' -f $finding.Ref, $finding.Anchor))
        $rows | Export-Csv -LiteralPath $csvFile -NoTypeInformation -Encoding UTF8
    }
    if (@($script:CollectionIssues).Count -gt 0) {
        $script:CollectionIssues | Export-Csv -LiteralPath ([System.IO.Path]::Combine($csvDir, 'C0_collection-issues.csv')) `
            -NoTypeInformation -Encoding UTF8
    }
    Write-GpaLog -Level OK -Message "CSV export  : $csvDir"

    # ---- Summary -------------------------------------------------------------------
    Write-GpaLog -Level STEP -Message 'SUMMARY'
    foreach ($finding in $findings) {
        $value = if ($finding.Available) { $finding.Count } else { 'not assessed' }
        $line  = '  {0,-4} {1,-62} : {2}' -f $finding.Ref, $finding.Title, $value
        $colour = 'Cyan'
        if ($finding.Available -and $finding.Count -gt 0 -and $finding.Class -eq 'risk')    { $colour = 'Red' }
        elseif ($finding.Available -and $finding.Count -gt 0 -and $finding.Class -eq 'hygiene') { $colour = 'Yellow' }
        elseif (-not $finding.Available) { $colour = 'DarkYellow' }
        Write-Host $line -ForegroundColor $colour
        $script:LogLines.Add($line)
    }

    $elapsed = (Get-Date) - $script:StartTime
    Write-Host ''
    Write-GpaLog -Level OK -Message ('Elapsed: {0:hh\:mm\:ss}' -f $elapsed)

    if (@($script:CollectionIssues).Count -gt 0) {
        $exitCode = 2
        Write-GpaLog -Level WARN -Message ('Collection issues: {0}. Findings that depended on them are marked as not assessed.' -f @($script:CollectionIssues).Count)
    }
    else {
        Write-GpaLog -Level OK -Message 'Collection completed with no errors.'
    }

    if ($PassThru) {
        [pscustomobject]@{
            Metadata         = $metadata
            Context          = $context
            Gpos             = @($gpos)
            Findings         = @($findings)
            CollectionIssues = @($script:CollectionIssues)
            ReportFile       = $reportFile
            JsonFile         = $jsonFile
            OutputFolder     = $runFolder
        }
    }
}
catch {
    $exitCode = 1
    Write-GpaLog -Level FAIL -Message ('Fatal error: {0}' -f $_.Exception.Message)
    Write-GpaLog -Level FAIL -Message ('At: {0}' -f $_.InvocationInfo.PositionMessage)
}
finally {
    if ($runFolder -and (Test-Path -LiteralPath $runFolder)) {
        $logFile = [System.IO.Path]::Combine($runFolder, 'assessment.log')
        [System.IO.File]::WriteAllLines($logFile, [string[]]@($script:LogLines), ([System.Text.UTF8Encoding]::new($false)))
        Write-Host "  [ OK ]  Log file    : $logFile" -ForegroundColor Green
    }
    Write-Host ''
}

exit $exitCode
