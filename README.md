================================================================================
GPO ASSESSMENT TOOL - REQUIREMENTS
Version 1.0
================================================================================

Read-only assessment of Group Policy Objects in an Active Directory domain.
Produces an HTML report, a JSON finding set and one CSV per finding.

DISCLAIMER

    This script is provided "AS IS", without warranty of any kind, and without
    any form of support from its author. See the disclaimer at the top of
    GPO_Assessment_Tool.ps1 and the LICENSE file.

================================================================================
1. POWERSHELL VERSION
================================================================================

MINIMUM ................ Windows PowerShell 5.1
DECLARED IN SCRIPT ..... #Requires -Version 5.1
RECOMMENDED HOST ....... Windows PowerShell 5.1 (the version shipped with
                         Windows Server 2016 and later, and with Windows 10
                         and later)

Why 5.1 and not lower
---------------------
The binding constraint is the .NET constructor syntax [Type]::new(), which was
introduced in PowerShell 5.0 and is used 17 times in the script. Get-FileHash
requires PowerShell 4.0. Everything else in the script (the [pscustomobject]
cast, the -in and -notin operators, Get-ChildItem -Directory and -File,
ConvertTo-Json, $PSCommandPath) requires PowerShell 3.0.

The script therefore runs on 5.0, but 5.1 is declared because it is the version
present on every currently supported Windows release and is the reference host
for this tool. Running on 5.0 is untested.

The script uses no PowerShell 7 exclusive syntax. It contains no classes, no
using statements, no ternary operator, no null-coalescing operator, no pipeline
chain operators and no ForEach-Object -Parallel. This was verified by scanning
the parsed token stream: zero PowerShell 7 only operator tokens are present
outside string literals.

PowerShell 7.x
--------------
The script parses cleanly under PowerShell 7.4.6 and its analysis and rendering
layers were exercised there against synthetic data.

However, PowerShell 7 does NOT load the GroupPolicy and ActiveDirectory modules
natively. Both are Windows PowerShell modules and are imported through the
Windows PowerShell compatibility layer, which proxies the cmdlets through a
background Windows PowerShell session and deserializes their output. Objects
returned that way lose their original types and their methods.

This has not been tested end to end against a domain. Until it has been, run
the script under Windows PowerShell 5.1.


================================================================================
2. REQUIRED MODULES
================================================================================

GroupPolicy
    Cmdlets used: Get-GPO, Get-GPOReport, Get-GPPermission
    Source: Group Policy Management Console (GPMC)

ActiveDirectory
    Cmdlets used: Get-ADDomain, Get-ADForest, Get-ADRootDSE, Get-ADObject,
                  Get-ADGroup, Get-ADGroupMember
    Source: RSAT Active Directory module for Windows PowerShell

Both are declared with #Requires -Modules GroupPolicy, ActiveDirectory. The
script refuses to start if either is missing.

Installation
------------
Windows Server (any supported version):

    Install-WindowsFeature -Name GPMC
    Install-WindowsFeature -Name RSAT-AD-PowerShell

Windows 10 / Windows 11 (Features on Demand):

    Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

Verification
------------

    Get-Module -ListAvailable GroupPolicy, ActiveDirectory


================================================================================
3. OPERATING SYSTEM
================================================================================

Windows only. The script depends on the GroupPolicy and ActiveDirectory
modules, on SMB access to SYSVOL and on Windows path semantics. It does not run
on Linux or macOS.

The collection station must be joined to the target domain, or to a domain with
a trust path to it, and must be able to resolve and reach the target domain
controller.


================================================================================
4. PERMISSIONS
================================================================================

REQUIRED
    Read access to the domain naming context of the target domain
    Read access to the Configuration naming context of the forest
    Read access to the SYSVOL share of the target domain controller
    Read access to the security descriptor of every GPO (for the delegation
    checks)

NOT REQUIRED
    Local administrator rights on the collection station. Elevation grants
    nothing that this script needs. The script declares no
    #Requires -RunAsAdministrator.

    Domain Admin membership. An account with read access across the domain is
    sufficient.

WRITE ACCESS
    The account must be able to create and write the output folder. See
    section 6.

IMPORTANT
    Get-GPO -All returns only the GPOs that the running account is allowed to
    read. If the account cannot read every GPO, the result is silently smaller
    and the report will assess fewer objects than exist. Run the collection
    with an account that can read every GPO in the domain.

    With -IncludeForestDomains the same read access is required in every other
    domain of the forest.


================================================================================
5. NETWORK AND FIREWALL
================================================================================

From the collection station to the target domain controller:

    TCP 389     LDAP                    directory queries
    TCP 3268    LDAP Global Catalog     forest scope operations
    TCP 445     SMB                     SYSVOL access
    TCP/UDP 88  Kerberos                authentication
    TCP/UDP 53  DNS                     name resolution
    TCP 135 + dynamic RPC range         used by some GroupPolicy operations

SYSVOL is read as \\<domain controller>\SYSVOL\<domain>\Policies, addressing
the pinned domain controller directly rather than the DFS Namespace root. This
is deliberate: reading the Group Policy Container from one replica and the
Group Policy Template from another produces false orphan and false version
mismatch findings.


================================================================================
6. OUTPUT LOCATION
================================================================================

DEFAULT ROOT ........... C:\GPO-Assessment
OVERRIDE ............... -OutputPath <path>

Layout produced by one run:

    C:\GPO-Assessment\<domain>\<yyyyMMdd-HHmmss>\
        GPO-Assessment-Report_<stamp>.html    the report
        findings.json                         full finding set, machine readable
        assessment.log                        collection log
        csv\                                  one CSV per non-empty finding
        GPO-Exports\                          one HTML report per GPO

The per-domain and per-run subfolders mean consecutive executions never
overwrite each other.

PERMISSION NOTE
    On a default Windows installation the first user to create a folder
    directly under C:\ becomes its owner, and other users receive read access
    only. On a collection station shared between accounts, pre-create
    C:\GPO-Assessment with permissions that allow every operator to write to
    it, or point -OutputPath somewhere else.


================================================================================
7. DISK SPACE AND RUNTIME
================================================================================

The dominant cost is one Get-GPOReport call per GPO for the XML report, plus a
second one per GPO for the individual HTML export, plus one Get-GPPermission
call per GPO.

    -SkipIndividualHtmlReports   removes one full pass over every GPO
    -SkipPermissionChecks        removes one full pass; disables checks
                                 R1, R3, R4 and R9
    -SkipSysvolContentScan       removes the recursive SYSVOL read; disables
                                 checks R2, H10 and I5

Disk space is driven by the per-GPO HTML exports, which are a few tens of
kilobytes each.

No runtime figures are given here because none were measured against a
production domain.


================================================================================
8. EXIT CODES
================================================================================

    0    Completed, no collection errors
    1    Prerequisite or fatal error
    2    Completed with collection errors; some findings are incomplete and
         are marked "not assessed" in the report rather than reported as zero


================================================================================
9. WHAT THE SCRIPT DOES NOT DO
================================================================================

The script performs read operations only. It never creates, modifies, links,
unlinks or deletes any Active Directory or SYSVOL object, and it never changes
a GPO, a link, a permission or a WMI filter.

It does not evaluate the content of individual policy settings against a
security baseline. It assesses structure, delegation, link topology and
integrity.


================================================================================
10. KNOWN LIMITATIONS
================================================================================

- Cross-domain link detection only sees containers inside the enumerated
  scope. Without -IncludeForestDomains, a link created in another domain that
  points to a GPO of the target domain is not visible. The report states which
  scope was used.

- Emptiness is derived from the extension data of the XML report. A GPO whose
  settings were added and later removed keeps a version number above zero, so
  the version columns shown alongside can legitimately disagree with the
  emptiness verdict.

- Check H9 reports the client-side extensions present in the two default GPOs.
  The contents of the Security extension itself are not parsed, so a listed GPO
  is a candidate for manual review rather than a confirmed deviation.

- Link order is derived from the position of the entry inside the gPLink
  attribute, where the last entry is taken to be link order 1. Validate this
  against the Group Policy Management Console in a lab before relying on the
  LinkOrder column.

- Orphan and version findings can still reflect replication that has not yet
  converged. Confirm against a second domain controller before deleting
  anything.

- The classification of findings into risk, hygiene and inventory is an
  editorial convention of this report used for prioritization. It does not
  correspond to any formal severity rating published by Microsoft.


================================================================================
11. QUICK START
================================================================================

    # Current domain, PDC emulator, default output folder
    .\GPO_Assessment_Tool.ps1

    # Explicit target and engagement metadata in the report header
    .\GPO_Assessment_Tool.ps1 -DomainName contoso.com -Server dc01.contoso.com `
                              -ClientName 'Contoso' -Assessor 'A. Martins'

    # Forest-wide link enumeration, faster collection, result on the pipeline
    .\GPO_Assessment_Tool.ps1 -IncludeForestDomains -SkipIndividualHtmlReports -PassThru

    # Full parameter documentation
    Get-Help .\GPO_Assessment_Tool.ps1 -Full


================================================================================
12. VALIDATION PERFORMED ON THIS RELEASE
================================================================================

DONE
    Syntax validated with the PowerShell language parser (7.4.6): no errors.
    Offline test suite over synthetic data covering all 24 checks, the gPLink
    parser, the Registry.pol parser, the degraded collection paths and the
    HTML and JSON rendering.
    Generated HTML checked for well-formedness.

NOT DONE
    No execution against a production domain.
    No execution under Windows PowerShell 5.1 (only the 7.4.6 parser and
    runtime were available in the build environment).
    PSScriptAnalyzer was not run.

Run PSScriptAnalyzer and a full lab execution before using this in a client
engagement:

    Install-Module PSScriptAnalyzer -Scope CurrentUser
    Invoke-ScriptAnalyzer -Path .\GPO_Assessment_Tool.ps1


================================================================================
LICENSE
================================================================================

MIT. See the LICENSE file. The license grants permission to use and modify the
software. It creates no obligation for the author to provide support,
maintenance, updates or bug fixes, and no such support is offered.
