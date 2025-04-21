<#
.SYNOPSIS
    Performs a comprehensive assessment of Group Policy Objects in the current domain.
.DESCRIPTION
    This script analyzes GPOs in the Active Directory domain, identifying various issues and configurations,
    then generates a detailed HTML report.
.NOTES
    File Name      : GPO-Assessment.ps1
    Author         : André Martins
    Prerequisite   : PowerShell 5.1 or later, Active Directory module, Group Policy module
#>

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Error "Failed to load required modules. Please ensure Active Directory and Group Policy modules are installed."
    exit 1
}

# Create output directory if it doesn't exist
$outputDir = "C:\GPO-Assessment"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Get current date for report
$reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to check AD Recycle Bin status
function Test-ADRecycleBinEnabled {
    try {
        $rootDSE = Get-ADRootDSE
        $searchBase = "CN=Partitions,$($rootDSE.configurationNamingContext)"
        $partitions = Get-ADObject -Identity $searchBase -Properties msDS-EnabledFeature
        
        if ($partitions.'msDS-EnabledFeature' -like "*Recycle Bin Feature*") {
            return $true
        } else {
            return $false
        }
    } catch {
        Write-Warning "Error checking AD Recycle Bin status: $_"
        return $false
    }
}

# 1. Get Active Directory information
$domain = Get-ADDomain
$domainFQDN = $domain.DNSRoot
$domainDN = $domain.DistinguishedName
$forestInfo = Get-ADForest
$recycleBinStatus = if (Test-ADRecycleBinEnabled) { "Enabled" } else { "Disabled" }

# Calculate SYSVOL size
$sysvolPath = "\\$domainFQDN\SYSVOL\$domainFQDN"
$sysvolSize = (Get-ChildItem -Path $sysvolPath -Recurse | Measure-Object -Property Length -Sum).Sum
$sysvolSizeMB = [math]::Round($sysvolSize / 1MB, 2)

# Get Group Policy Creator Owners members
$gpcMembers = try {
    Get-ADGroupMember "Group Policy Creator Owners" -ErrorAction Stop | Select-Object Name, SamAccountName
} catch {
    "Could not retrieve Group Policy Creator Owners group: $_"
}

# HTML report header
$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>GPO Assessment Report - $domainFQDN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { padding: 8px; border: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning { background-color: #fff3cd; }
        .error { background-color: #f8d7da; }
        .success { background-color: #d4edda; }
        .summary { margin-bottom: 30px; padding: 15px; background-color: #f8f9fa; border-left: 5px solid #6c757d; }
        .timestamp { font-size: 0.9em; color: #6c757d; text-align: right; }
        .unlinked { background-color: #ffcccc; }
        .info { background-color: #e7f4ff; }
        .enforced { background-color: #d4e6ff; }
    </style>
</head>
<body>
    <h1>Group Policy Objects Assessment Report</h1>
    <div class="timestamp">Report generated: $reportDate</div>
    <div class="summary">
        <strong>Domain:</strong> $domainFQDN<br>
        <strong>Domain DN:</strong> $domainDN<br>
        <strong>Domain Functional Level:</strong> $($domain.DomainMode)<br>
        <strong>Forest Functional Level:</strong> $($forestInfo.ForestMode)<br>
        <strong>SYSVOL Size:</strong> $sysvolSizeMB MB<br>
        <strong>AD Recycle Bin:</strong> $recycleBinStatus
    </div>

    <h2>Group Policy Creator Owners Members</h2>
"@

# Add Group Policy Creator Owners members to the report
if ($gpcMembers -is [array]) {
    $htmlHeader += "<table><tr><th>Member Name</th><th>SamAccountName</th></tr>"
    foreach ($member in $gpcMembers) {
        $htmlHeader += "<tr><td>$($member.Name)</td><td>$($member.SamAccountName)</td></tr>"
    }
    $htmlHeader += "</table>"
} else {
    $htmlHeader += "<p class='error'>$gpcMembers</p>"
}

# Initialize HTML content
$htmlContent = $htmlHeader

# Get all GPOs in the domain
$allGPOs = Get-GPO -All

# Function to get all GPO links in the domain
function Get-GPOLinksInDomain {
    param (
        [string]$DomainDN
    )
    
    $links = @()
    
    # Get domain links
    $domainLinks = Get-ADObject -Identity $DomainDN -Properties gPLink, gPOptions
    if ($domainLinks.gPLink) {
        $links += [PSCustomObject]@{
            Target = $DomainDN
            GPOs = $domainLinks.gPLink -split '\[' | Where-Object { $_ -match '^LDAP://CN=\{([A-F0-9-]+)\},CN=Policies,CN=System,' }
            Enforced = [bool]($domainLinks.gPOptions -band 1)
        }
    }
    
    # Get OU links
    $ous = Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions
    foreach ($ou in $ous) {
        if ($ou.gPLink) {
            $links += [PSCustomObject]@{
                Target = $ou.DistinguishedName
                GPOs = $ou.gPLink -split '\[' | Where-Object { $_ -match '^LDAP://CN=\{([A-F0-9-]+)\},CN=Policies,CN=System,' }
                Enforced = [bool]($ou.gPOptions -band 1)
            }
        }
    }
    
    return $links
}

# Get all GPO links in the domain
$allLinks = Get-GPOLinksInDomain -DomainDN $domainDN

# Create hashtable to map GPO GUIDs to display names
$gpoMap = @{}
foreach ($gpo in $allGPOs) {
    $gpoMap[$gpo.Id.ToString()] = $gpo.DisplayName
}

# Create hashtable to store GPO link information
$gpoLinkInfo = @{}
$gpoEnforcedInfo = @{}
foreach ($gpo in $allGPOs) {
    $gpoLinkInfo[$gpo.Id.ToString()] = @()
    $gpoEnforcedInfo[$gpo.Id.ToString()] = @()
}

# Process all links
foreach ($link in $allLinks) {
    foreach ($gpoRef in $link.GPOs) {
        if ($gpoRef -match 'CN=\{(.+?)\}') {
            $gpoGuid = $matches[1]
            if ($gpoRef -match ';0\)$') {
                $enabled = $false
            } else {
                $enabled = $true
            }
            $gpoLinkInfo[$gpoGuid] += [PSCustomObject]@{
                Target = $link.Target
                Enabled = $enabled
            }
            $gpoEnforcedInfo[$gpoGuid] += [PSCustomObject]@{
                Target = $link.Target
                Enforced = $link.Enforced
            }
        }
    }
}

# 2. List all GPOs by name and where they are linked
$htmlContent += "<h2>All Group Policy Objects and Their Links</h2>"
$htmlContent += "<table><tr><th>GPO Name</th><th>GPO ID</th><th>Linked To</th><th>Link Enabled</th><th>Enforced</th></tr>"

foreach ($gpo in $allGPOs) {
    $gpoId = $gpo.Id.ToString()
    if ($gpoLinkInfo[$gpoId].Count -gt 0) {
        foreach ($link in $gpoLinkInfo[$gpoId]) {
            $enforcedStatus = ($gpoEnforcedInfo[$gpoId] | Where-Object { $_.Target -eq $link.Target }).Enforced
            $htmlContent += "<tr><td>$($gpo.DisplayName)</td><td>$gpoId</td><td>$($link.Target)</td><td>$($link.Enabled)</td><td>$enforcedStatus</td></tr>"
        }
    } else {
        $htmlContent += "<tr><td>$($gpo.DisplayName)</td><td>$gpoId</td><td>Not linked</td><td class='unlinked'>FALSE</td><td>N/A</td></tr>"
    }
}

$htmlContent += "</table>"

# 3. Identify truly empty GPOs (no settings at all)
$htmlContent += "<h2>Empty Group Policy Objects (No Settings Configured)</h2>"
$emptyGPOs = @()

foreach ($gpo in $allGPOs) {
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    $xmlReport = [xml]$report
    
    $hasComputerSettings = $false
    $hasUserSettings = $false
    
    # Check computer configuration
    if ($xmlReport.GPO.Computer.ExtensionData -ne $null) {
        foreach ($extension in $xmlReport.GPO.Computer.ExtensionData.Extension) {
            if ($extension.ChildNodes.Count -gt 0) {
                $hasComputerSettings = $true
                break
            }
        }
    }
    
    # Check user configuration
    if ($xmlReport.GPO.User.ExtensionData -ne $null) {
        foreach ($extension in $xmlReport.GPO.User.ExtensionData.Extension) {
            if ($extension.ChildNodes.Count -gt 0) {
                $hasUserSettings = $true
                break
            }
        }
    }
    
    if (-not $hasComputerSettings -and -not $hasUserSettings) {
        $emptyGPOs += $gpo
    }
}

if ($emptyGPOs.Count -gt 0) {
    $htmlContent += "<table><tr><th>GPO Name</th><th>GPO ID</th><th>Status</th></tr>"
    foreach ($gpo in $emptyGPOs) {
        $htmlContent += "<tr class='warning'><td>$($gpo.DisplayName)</td><td>$($gpo.Id)</td><td>Completely empty (no settings in either section)</td></tr>"
    }
    $htmlContent += "</table>"
} else {
    $htmlContent += "<p class='success'>No completely empty GPOs found.</p>"
}

# 4. Identify GPOs with empty Computer Configuration but section enabled
$htmlContent += "<h2>GPOs with Empty Computer Configuration (but section enabled)</h2>"
$emptyComputerGPOs = @()

foreach ($gpo in $allGPOs) {
    if ($gpo.ComputerEnabled -or $gpo.GpoStatus -eq "AllSettingsEnabled" -or $gpo.GpoStatus -eq "ComputerSettingsEnabled") {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $xmlReport = [xml]$report
        
        $hasComputerSettings = $false
        
        if ($xmlReport.GPO.Computer.ExtensionData -ne $null) {
            foreach ($extension in $xmlReport.GPO.Computer.ExtensionData.Extension) {
                if ($extension.ChildNodes.Count -gt 0) {
                    $hasComputerSettings = $true
                    break
                }
            }
        }
        
        if (-not $hasComputerSettings) {
            $emptyComputerGPOs += $gpo
        }
    }
}

if ($emptyComputerGPOs.Count -gt 0) {
    $htmlContent += "<table><tr><th>GPO Name</th><th>GPO ID</th><th>Computer Enabled</th><th>Status</th></tr>"
    foreach ($gpo in $emptyComputerGPOs) {
        $htmlContent += "<tr class='warning'>"
        $htmlContent += "<td>$($gpo.DisplayName)</td>"
        $htmlContent += "<td>$($gpo.Id)</td>"
        $htmlContent += "<td>$($gpo.ComputerEnabled)</td>"
        $htmlContent += "<td>Computer section enabled but contains no settings</td>"
        $htmlContent += "</tr>"
    }
    $htmlContent += "</table>"
} else {
    $htmlContent += "<p class='success'>No GPOs with empty Computer Configuration found.</p>"
}

# 5. Identify GPOs with empty User Configuration but section enabled
$htmlContent += "<h2>GPOs with Empty User Configuration (but section enabled)</h2>"
$emptyUserGPOs = @()

foreach ($gpo in $allGPOs) {
    if ($gpo.UserEnabled -or $gpo.GpoStatus -eq "AllSettingsEnabled" -or $gpo.GpoStatus -eq "UserSettingsEnabled") {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $xmlReport = [xml]$report
        
        $hasUserSettings = $false
        
        if ($xmlReport.GPO.User.ExtensionData -ne $null) {
            foreach ($extension in $xmlReport.GPO.User.ExtensionData.Extension) {
                if ($extension.ChildNodes.Count -gt 0) {
                    $hasUserSettings = $true
                    break
                }
            }
        }
        
        if (-not $hasUserSettings) {
            $emptyUserGPOs += $gpo
        }
    }
}

if ($emptyUserGPOs.Count -gt 0) {
    $htmlContent += "<table><tr><th>GPO Name</th><th>GPO ID</th><th>User Enabled</th><th>Status</th></tr>"
    foreach ($gpo in $emptyUserGPOs) {
        $htmlContent += "<tr class='warning'>"
        $htmlContent += "<td>$($gpo.DisplayName)</td>"
        $htmlContent += "<td>$($gpo.Id)</td>"
        $htmlContent += "<td>$($gpo.UserEnabled)</td>"
        $htmlContent += "<td>User section enabled but contains no settings</td>"
        $htmlContent += "</tr>"
    }
    $htmlContent += "</table>"
} else {
    $htmlContent += "<p class='success'>No GPOs with empty User Configuration found.</p>"
}

# 6. Identify unlinked GPOs
$htmlContent += "<h2>Unlinked Group Policy Objects</h2>"
$unlinkedGPOs = @()

foreach ($gpo in $allGPOs) {
    $gpoId = $gpo.Id.ToString()
    if ($gpoLinkInfo[$gpoId].Count -eq 0) {
        $unlinkedGPOs += $gpo
    }
}

if ($unlinkedGPOs.Count -gt 0) {
    $htmlContent += "<table><tr><th>GPO Name</th><th>GPO ID</th><th>Status</th></tr>"
    foreach ($gpo in $unlinkedGPOs) {
        $htmlContent += "<tr class='warning'><td>$($gpo.DisplayName)</td><td>$($gpo.Id)</td><td>Not linked anywhere</td></tr>"
    }
    $htmlContent += "</table>"
} else {
    $htmlContent += "<p class='success'>No unlinked GPOs found.</p>"
}

# 7. Corrected: Identify truly orphaned GPTs (GPOs with GPT but no GPC)
$htmlContent += "<h2>GPOs with Orphaned Group Policy Template (GPT)</h2>"
$sysvolPath = "\\$domainFQDN\SYSVOL\$domainFQDN\Policies\"
$orphanedGPTs = @()

# Get all GPCs from AD
$gpcGuids = (Get-ADObject -SearchBase "CN=Policies,CN=System,$domainDN" -LDAPFilter "(objectClass=groupPolicyContainer)" -Properties displayName | Select-Object -ExpandProperty Name)

# Get all GPT folders
$gptFolders = Get-ChildItem -Path $sysvolPath -Directory | Where-Object { $_.Name -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$' }

foreach ($folder in $gptFolders) {
    $guid = $folder.Name.Trim('{}')
    # Only consider orphaned if the GPT folder exists but there's no corresponding GPC
    # AND the GPO doesn't exist in the $allGPOs collection
    if ($guid -notin $gpcGuids -and $guid -notin $allGPOs.Id.Guid) {
        $gpoName = "Unknown (missing GPC and GPO)"
        try {
            $gptIni = Get-Content "$($folder.FullName)\GPT.ini" -ErrorAction Stop
            $nameLine = $gptIni | Where-Object { $_ -match '^displayName=' }
            if ($nameLine) {
                $gpoName = $nameLine.Split('=')[1]
            }
        } catch {
            # Couldn't read GPT.ini
        }
        $orphanedGPTs += [PSCustomObject]@{
            Name = $gpoName
            Guid = $guid
            Path = $folder.FullName
        }
    }
}

if ($orphanedGPTs.Count -gt 0) {
    $htmlContent += "<table><tr><th>GPO Name</th><th>GUID</th><th>Path</th><th>Status</th></tr>"
    foreach ($gpt in $orphanedGPTs) {
        $htmlContent += "<tr class='error'><td>$($gpt.Name)</td><td>$($gpt.Guid)</td><td>$($gpt.Path)</td><td>GPT exists but GPC and GPO are missing</td></tr>"
    }
    $htmlContent += "</table>"
} else {
    $htmlContent += "<p class='success'>No truly orphaned GPTs found.</p>"
}

# 8. Corrected: Identify enforced GPOs (both link-level and GPO-level enforcement)
$htmlContent += "<h2>Enforced Group Policy Objects</h2>"
$enforcedGPOs = @()

# Process each GPO to check for enforcement
foreach ($gpo in $allGPOs) {
    $gpoId = $gpo.Id.ToString()
    
    # Get XML report to check for GPO-level enforcement
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    $xmlReport = [xml]$report
    
    # Check for GPO-level enforcement (NoOverride flag)
    $gpoLevelEnforced = $false
    if ($xmlReport.GPO.LinksTo -ne $null) {
        $gpoLevelEnforced = $xmlReport.GPO.LinksTo.NoOverride -eq "true"
    }
    
    # Check for link-level enforcement
    $linkLevelEnforced = $gpoEnforcedInfo[$gpoId] | Where-Object { $_.Enforced -eq $true }
    
    if ($gpoLevelEnforced -or $linkLevelEnforced) {
        $enforcedGPOs += [PSCustomObject]@{
            GpoName = $gpo.DisplayName
            GpoId = $gpoId
            EnforcementType = if ($gpoLevelEnforced) { "GPO-level enforcement" } else { "Link-level enforcement" }
            EnforcementTarget = if ($gpoLevelEnforced) { "GPO itself" } else { ($linkLevelEnforced.Target -join ", ") }
        }
    }
}

if ($enforcedGPOs.Count -gt 0) {
    $htmlContent += "<table><tr><th>GPO Name</th><th>GPO ID</th><th>Enforcement Type</th><th>Enforcement Target</th></tr>"
    foreach ($gpo in $enforcedGPOs) {
        $htmlContent += "<tr class='enforced'>"
        $htmlContent += "<td>$($gpo.GpoName)</td>"
        $htmlContent += "<td>$($gpo.GpoId)</td>"
        $htmlContent += "<td>$($gpo.EnforcementType)</td>"
        $htmlContent += "<td>$($gpo.EnforcementTarget)</td>"
        $htmlContent += "</tr>"
    }
    $htmlContent += "</table>"
} else {
    $htmlContent += "<p class='success'>No enforced GPOs found.</p>"
}

# 9. NEW: Verification of Obsolete Settings
$htmlContent += "<h2>GPOs with Obsolete Settings</h2>"
$obsoleteGPOs = foreach ($gpo in $allGPOs) {
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    if ($report -match "Internet Explorer|Windows XP|Windows 7|\.msc") {
        [PSCustomObject]@{
            Name = $gpo.DisplayName
            Id = $gpo.Id
            ObsoleteSettings = @(
                if ($report -match "Internet Explorer") { "Internet Explorer" }
                if ($report -match "Windows XP") { "Windows XP" }
                if ($report -match "Windows 7") { "Windows 7" }
                if ($report -match "\.msc") { "Legacy MMC snap-ins" }
            ) -join ", "
        }
    }
}

if ($obsoleteGPOs) {
    $htmlContent += "<table><tr><th>GPO Name</th><th>GPO ID</th><th>Obsolete Settings</th></tr>"
    foreach ($gpo in $obsoleteGPOs) {
        $htmlContent += "<tr class='warning'><td>$($gpo.Name)</td><td>$($gpo.Id)</td><td>$($gpo.ObsoleteSettings)</td></tr>"
    }
    $htmlContent += "</table>"
} else {
    $htmlContent += "<p class='success'>No GPOs with obsolete settings found.</p>"
}

# 10. NEW: Verification of GPO Auditing
$htmlContent += "<h2>GPO Auditing Status</h2>"
try {
    $auditPolicy = auditpol /get /subcategory:"Audit Authorization Policy Change" /r | ConvertFrom-Csv
    if ($auditPolicy."Inclusion Setting" -match "Success") {
        $gpoAuditEnabled = "Yes"
        $htmlContent += "<p class='success'>GPO change auditing enabled: <strong>$gpoAuditEnabled</strong></p>"
    } else {
        $gpoAuditEnabled = "No"
        $htmlContent += "<p class='error'>GPO change auditing enabled: <strong>$gpoAuditEnabled</strong></p>"
    }
} catch {
    $htmlContent += "<p class='error'>Could not determine GPO auditing status: $_</p>"
}

# Close HTML
$htmlContent += @"
</body>
</html>
"@

# Save the report
$reportPath = "$outputDir\GPO-Assessment-Report-$((Get-Date).ToString('yyyyMMdd-HHmmss')).html"
$htmlContent | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "GPO assessment report generated at: $reportPath" -ForegroundColor Green

# Open the report in default browser
try {
    Start-Process $reportPath
}
catch {
    Write-Warning "Could not open the report automatically. Please open it manually from: $reportPath"
}
