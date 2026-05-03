export const groupPolicyEvents = [
  {
    id: 1030,
    source: 'Userenv',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Group Policy: Cannot Query GPO List',
    short_desc: 'Windows could not retrieve the list of Group Policy Objects — network or domain connectivity problem.',
    description: 'Event 1030 from source Userenv means Windows could not query Active Directory to get the list of Group Policy Objects that should apply to the user or computer. This is typically a domain controller connectivity problem: the machine cannot reach a DC over the network, DNS is not resolving the domain, or the Netlogon service is unavailable. As a result, Group Policy is not applied at all, and users may see stale cached policy or no policy enforcement. Event 1030 is often paired with Event 1058 (cannot access gpt.ini) from the same session.',
    why_it_happens: 'Group Policy processing starts by querying Active Directory for the list of GPOs linked to the computer\'s OU, site, and domain. If the machine cannot reach a DC — because of a network issue, LDAP failure, or DNS not resolving the domain — it cannot build the GPO list and logs Event 1030.',
    what_good_looks_like: 'No Event 1030. This event should never appear in a healthy, connected domain environment.',
    common_mistakes: [
      'Treating this as a Group Policy problem when it is actually a network/DNS problem — fix connectivity first',
      'Not checking if DNS resolves the domain name: Resolve-DnsName <domain> should return DC IPs',
      'Forgetting to check if the machine has a valid IP and can reach a DC on the network',
      'Missing that Event 1030 often clusters with 1058 from the same Group Policy processing cycle'
    ],
    causes: [
      'Machine cannot reach a domain controller (network issue, VLAN, firewall blocking LDAP port 389)',
      'DNS not resolving the domain name to a valid DC IP',
      'Netlogon service stopped or not running',
      'Machine account expired or disabled in Active Directory',
      'Time skew too large between client and DC — Kerberos requires time within 5 minutes'
    ],
    steps: [
      'Check DNS resolves the domain: Resolve-DnsName <domain.com>',
      'Check DC connectivity: nltest /dsgetdc:<domain.com>',
      'Check Netlogon service: Get-Service Netlogon',
      'Check network path to DC: Test-NetConnection <DC-IP> -Port 389',
      'Check time sync: w32tm /query /status — ensure time is within 5 minutes of DC',
      'Review System log for any network or Netlogon errors at the same timestamp',
      'Force a GP refresh after fixing connectivity: gpupdate /force'
    ],
    symptoms: [
      'group policy not applying',
      'gpo not applying',
      'group policy failed',
      'cannot retrieve group policy objects',
      'gpo list query failed',
      'group policy not working',
      'policy not applied at logon',
      'group policy error on login',
      'gpo not loading',
      'user policy not applied',
      'computer policy not applied',
      'group policy connectivity error'
    ],
    tags: ['group-policy', 'gpo', 'error', 'domain', 'connectivity', 'netlogon', 'userenv'],
    powershell: `# Group Policy connectivity and error check
# Eventful

# Check DC is reachable and Netlogon is running
nltest /dsgetdc:$env:USERDNSDOMAIN
Get-Service Netlogon | Select-Object Name, Status

# Check DNS resolves the domain
Resolve-DnsName $env:USERDNSDOMAIN -ErrorAction SilentlyContinue | Select-Object Name, IPAddress

# Check time sync
w32tm /query /status

# Recent Group Policy errors in System log
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Userenv'
    Id           = @(1030, 1058)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1058, 1085, 7017],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/event-id-1030-1058-group-policy'
  },

  {
    id: 1058,
    source: 'Userenv',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Group Policy: Cannot Access gpt.ini (SYSVOL Issue)',
    short_desc: 'Windows cannot access the gpt.ini file for a GPO — typically a SYSVOL replication or network share problem.',
    description: 'Event 1058 from Userenv means Windows found the list of GPOs that should apply but cannot access the gpt.ini file for one of them. The gpt.ini file lives in SYSVOL on the domain controller (\\\\domain\\SYSVOL\\domain\\Policies\\{GUID}\\gpt.ini). Failure to access this file means Group Policy cannot read the GPO version number and cannot apply the policy. The most common cause on domain controllers is a SYSVOL replication fault — one or more DCs have a SYSVOL folder that is not in sync. Event 1058 is almost always paired with Event 1030.',
    why_it_happens: 'Group Policy reads GPO settings from SYSVOL — a shared folder on DCs that is synchronized by DFS-R (or the older FRS). If SYSVOL replication is broken, if SYSVOL is not shared (the share went missing), or if permissions on SYSVOL are incorrect, Windows cannot reach the gpt.ini files and logs Event 1058.',
    what_good_looks_like: 'No Event 1058. Any occurrence should trigger an immediate SYSVOL health check on all DCs.',
    common_mistakes: [
      'Running gpupdate /force on the client before fixing SYSVOL on the DC — the update will fail again',
      'Only checking SYSVOL on one DC when the client may be authenticating to a different DC',
      'Not checking whether the SYSVOL share itself exists on the DCs: net share SYSVOL',
      'Confusing SYSVOL replication issues with network connectivity issues — the path in the error message tells you which DC is being contacted'
    ],
    causes: [
      'SYSVOL replication broken — DFS-R or FRS not syncing SYSVOL between DCs',
      'SYSVOL share missing from a DC (net share SYSVOL returns not found)',
      'Permissions on SYSVOL folder changed, blocking access',
      'Network path to SYSVOL blocked by firewall',
      'DC SYSVOL not yet initialized after promotion (usually self-resolves after initial sync)',
      'AD replication failure causing GPO objects in AD to be out of sync with SYSVOL files'
    ],
    steps: [
      'Note which DC and GPO GUID appears in the Event 1058 message',
      'Verify SYSVOL share exists on the contacted DC: net use \\\\<DC>\\SYSVOL',
      'Check DFS-R SYSVOL replication health: dfsrdiag ReplicationState /member:<DC>',
      'Check SYSVOL replication on all DCs: repadmin /replsummary',
      'If SYSVOL is not shared, check DFS-R service on the DC: Get-Service DFSR',
      'Check Event Viewer → DFS Replication log on the DC for replication errors',
      'After fixing SYSVOL: force GP reapplication on clients: gpupdate /force'
    ],
    symptoms: [
      'group policy cannot access sysvol',
      'gpt.ini not found',
      'group policy sysvol error',
      'sysvol not accessible',
      'group policy gpo file missing',
      'gpo version check failed',
      'group policy not applying sysvol',
      'dfsr sysvol not syncing',
      'group policy sysvol replication issue',
      'cannot read gpo settings',
      'sysvol share missing',
      'group policy broken after dc demotion'
    ],
    tags: ['group-policy', 'gpo', 'sysvol', 'dfsr', 'replication', 'error', 'userenv'],
    powershell: `# SYSVOL and Group Policy health check
# Eventful

# Test SYSVOL accessibility from this machine
Test-Path "\\\\$env:USERDNSDOMAIN\\SYSVOL"

# Check SYSVOL share on all DCs (run on a DC)
# net share SYSVOL

# DFS-R replication state
dfsrdiag ReplicationState /member:$env:COMPUTERNAME

# Recent gpt.ini errors
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Userenv'
    Id           = 1058
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1030, 1085, 7017],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/event-id-1030-1058-group-policy'
  },

  {
    id: 1085,
    source: 'Microsoft-Windows-GroupPolicy',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Group Policy: Failed to Apply a Setting',
    short_desc: 'Windows successfully retrieved a GPO but failed to apply a specific setting within it — the policy name and error are recorded.',
    description: 'Event 1085 is more specific than 1030 or 1058: Group Policy connected to AD and retrieved the GPO, but when trying to apply a particular extension (Security, Software Installation, Scripts, Folder Redirection, etc.), the application failed. The event message names the extension that failed (e.g. "Security" means security settings within the GPO failed to apply). This means most of the policy may have applied, but a specific category did not. The error code in the message points to the specific cause.',
    why_it_happens: 'Group Policy applies different setting types through separate CSEs (Client-Side Extensions). If a CSE encounters an error — missing folder path for Folder Redirection, incorrect permissions for Software Installation, a corrupt policy file — it fails independently and logs Event 1085 for that extension.',
    what_good_looks_like: 'No Event 1085. A specific GPO failing repeatedly for a specific extension means there is a misconfiguration in that GPO or a dependency issue on the client.',
    common_mistakes: [
      'Trying to fix the computer without reading which extension failed — the extension name in the event tells you exactly which part of the GPO to check',
      'Not running gpresult /h to see which specific setting within the failed extension was the problem',
      'Forgetting that 1085 for "Software Installation" commonly means the distribution point share is unreachable'
    ],
    causes: [
      'Folder Redirection target path missing or permission denied',
      'Software Installation distribution point share unavailable',
      'Security template referencing a missing or invalid account',
      'Scripts CSE: logon/logoff script path unreachable',
      'Drive Map CSE: target path or credentials invalid',
      'Missing prerequisite (e.g. software deployment requires .NET Framework not installed)'
    ],
    steps: [
      'Read the extension name in Event 1085 — this tells you which category of policy failed',
      'Run gpresult /h C:\\gpresult.html to get the full GP result with failure details',
      'Open gpresult and find the failed GPO under the named extension',
      'For Folder Redirection failures: verify the target path is accessible from the client',
      'For Software Installation failures: verify the distribution share is reachable (net use \\\\server\\share)',
      'For Security failures: check for references to deleted accounts or invalid SIDs in the GPO',
      'Edit the GPO in GPMC to correct the misconfiguration, then gpupdate /force'
    ],
    symptoms: [
      'group policy failed to apply setting',
      'gpo setting not applying',
      'group policy partial failure',
      'folder redirection not working',
      'software deployment gpo failing',
      'drive map not applying',
      'logon script not running from gpo',
      'security policy not applied',
      'gpo extension failed',
      'group policy applied with errors',
      'gpo not fully applying',
      'specific gpo setting not working'
    ],
    tags: ['group-policy', 'gpo', 'error', 'cse', 'extension', 'folder-redirection', 'software'],
    powershell: `# Group Policy result and extension failure report
# Eventful

# Generate HTML GP result report
gpresult /h C:\\Temp\\gpresult.html /f
Write-Host "Report saved to C:\\Temp\\gpresult.html — open in a browser"

# GP result summary in console
gpresult /r

# Recent Group Policy apply failures
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-GroupPolicy'
    Id           = 1085
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1030, 1058, 7017, 5312],
    ms_docs: null
  },

  {
    id: 7017,
    source: 'Microsoft-Windows-GroupPolicy',
    channel: 'Microsoft-Windows-GroupPolicy/Operational',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Group Policy Processing Time Exceeded',
    short_desc: 'Group Policy took longer than expected to process — typically causing slow login or slow startup for users.',
    description: 'Event 7017 in the Group Policy Operational log means GP processing exceeded the expected time threshold. This is the primary diagnostic event when users complain about slow logins or slow computer startup. The event logs how long processing actually took and which components were slow. The most common culprits are software deployment (MSI packages over slow links), folder redirection to slow/distant file servers, or simply too many GPOs linked at too many levels. On laptops connecting over VPN, slow GP is extremely common.',
    why_it_happens: 'Group Policy applies synchronously at startup (computer policy) and at logon (user policy) before the desktop appears. If any CSE — especially Software Installation, Folder Redirection, or Scripts — is slow to complete because of network latency, large MSI packages, or a large number of GPOs, total processing time increases and Event 7017 is generated.',
    what_good_looks_like: 'No Event 7017. Logon times under 30 seconds are generally acceptable. Investigate if users regularly report logon times over 60 seconds.',
    common_mistakes: [
      'Applying the fix to only one GPO when the problem is the accumulated total of many GPOs',
      'Not running gpresult /h to see which specific CSE is consuming the most time',
      'Enabling "Always wait for network" Group Policy without understanding it forces synchronous processing and increases logon time'
    ],
    causes: [
      'Software Installation GPO deploying large MSI packages at logon',
      'Folder Redirection to a file server over a slow link',
      'Too many GPOs linked at domain, site, and OU level — total processing time adds up',
      'Slow domain controller LDAP response',
      'VPN or WAN latency between client and SYSVOL/DC'
    ],
    steps: [
      'Run gpresult /h C:\\Temp\\gpresult.html — the HTML report shows per-CSE processing times',
      'Check the Operational log for which CSE had the longest duration: Event Viewer → Microsoft → Windows → GroupPolicy → Operational',
      'For Software Installation delays: consider moving large deployments to a software deployment tool (Intune, SCCM)',
      'For Folder Redirection delays: consider caching options or moving the file server closer',
      'Run gpresult /z for a verbose text report showing all applied policies',
      'Consider enabling loopback processing or reducing GPO links to flatten the processing chain'
    ],
    symptoms: [
      'slow login',
      'logon takes too long',
      'slow startup from group policy',
      'login slow windows',
      'group policy processing slow',
      'taking ages to log in',
      'long logon time',
      'desktop takes minutes to appear',
      'slow user login domain',
      'applying group policy slow',
      'login screen stuck on applying settings',
      'slow to get to desktop after login'
    ],
    tags: ['group-policy', 'gpo', 'performance', 'slow-logon', 'warning', 'latency'],
    powershell: `# Group Policy processing time and slow CSE report
# Eventful

# Generate full GP result with timing
gpresult /h C:\\Temp\\gpresult.html /f
Write-Host "Open C:\\Temp\\gpresult.html in a browser to view per-CSE timings"

# GP processing time events — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-GroupPolicy/Operational'
    Id           = @(7017, 8004)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1030, 1058, 1085, 5312],
    ms_docs: null
  },

  {
    id: 5312,
    source: 'Microsoft-Windows-GroupPolicy',
    channel: 'Microsoft-Windows-GroupPolicy/Operational',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Group Policy: List of Applied GPOs',
    short_desc: 'Records the complete list of GPOs that were applied during this GP processing cycle — the definitive record of what policy was active.',
    description: 'Event 5312 in the Group Policy Operational log is generated at the end of each GP processing cycle and lists every GPO that was successfully applied to the user or computer. This is the authoritative record of what Group Policy was in effect at a given time. It is the first event to check when a tech needs to confirm whether a specific GPO actually applied, when troubleshooting policy not behaving as expected, or when auditing which policies were active at a particular date and time.',
    why_it_happens: 'Group Policy writes Event 5312 at the end of every successful processing cycle — at computer startup and at user logon — listing all GPOs that were applied. If GP processing failed entirely, this event may not appear (check for 1030 or 1058 instead).',
    what_good_looks_like: 'Event 5312 at every logon and startup, listing the expected set of GPOs. Missing GPOs in the list require investigation — check if the GPO is linked to the correct OU and that the security filtering/WMI filter is correct.',
    common_mistakes: [
      'Checking GPMC to see which GPOs are linked without checking Event 5312 to see which actually applied — linked does not mean applied',
      'Not checking the security filtering on a GPO — a GPO may be linked but the computer or user account may not be in the "Apply Group Policy" security group',
      'Confusing computer policy GPO list (at startup) with user policy GPO list (at logon) — they are separate events'
    ],
    causes: [
      'Normal Group Policy processing cycle at computer startup or user logon',
      'gpupdate /force manually triggered',
      'GP refresh interval elapsed (default 90 minutes)'
    ],
    steps: [
      'Filter Event Viewer for Event 5312 in the Group Policy Operational log',
      'Find the event that matches the logon/startup time you are investigating',
      'Read the list of GPO names — any GPO you expected to see but is missing needs investigation',
      'For a missing GPO: check GPMC to confirm it is linked to the correct OU',
      'Check security filtering on the GPO: is the computer or user account in the allowed group?',
      'Check WMI filter if one is applied — the filter may be excluding this machine',
      'Run gpresult /r for a quick on-screen summary of applied policies'
    ],
    symptoms: [
      'which gpos applied',
      'what group policies are active',
      'list of applied group policies',
      'gpo not showing as applied',
      'check which policies applied',
      'confirm gpo applied',
      'group policy audit',
      'which policies were active at logon',
      'gpo applied list',
      'group policy result',
      'what gpos are applied to this computer',
      'policy audit log'
    ],
    tags: ['group-policy', 'gpo', 'audit', 'info', 'applied', 'list', 'compliance'],
    powershell: `# Applied GPO list and GP result
# Eventful

# Quick GP result summary
gpresult /r

# Applied GPO events — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-GroupPolicy/Operational'
    Id           = 5312
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending |
    Select-Object -First 5 | Format-List`,
    related_ids: [1030, 1058, 1085, 7017],
    ms_docs: null
  }
];
