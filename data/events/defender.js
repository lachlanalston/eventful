export const defenderEvents = [
  {
    id: 1116,
    source: 'Microsoft-Windows-Windows Defender',
    channel: 'Microsoft-Windows-Windows Defender/Operational',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Windows Defender Detected Malware',
    short_desc: 'Windows Defender detected a threat — malware name, path, and user account captured.',
    description: 'Event 1116 from Windows Defender is generated when real-time protection, a scheduled scan, or an on-demand scan detects a threat. The event records the threat name (e.g., Trojan:Win32/AgentTesla), severity, detected file path, and the user account associated with the process. This is the primary detection event — it should always be followed by Event 1117 (action taken). If 1116 is not followed by 1117, the threat was detected but not remediated.',
    why_it_happens: 'Defender detects threats through signature matching, behavioral analysis, and cloud protection. Detection fires when a file is written to disk, executed, downloaded, or accessed. Detections can be true positives (actual malware) or false positives (legitimate software flagged by a signature).',
    what_good_looks_like: 'Event 1116 immediately followed by Event 1117 (Quarantined or Removed). No repeated detections of the same threat on the same machine after remediation. No detection in sensitive locations (System32, ProgramData) which may indicate deeper compromise.',
    common_mistakes: [
      'Assuming quarantine = fully remediated — check for related detections on other machines and for persistence mechanisms',
      'Not investigating where the malware came from — the detected path usually shows the attack vector (Downloads, Temp, email attachment)',
      'Not checking 1117 to confirm the action actually succeeded — detection without successful removal is still a live threat',
      'Treating all 1116 events the same — severity field (Critical, High, Moderate, Low) matters significantly'
    ],
    causes: [
      'User downloaded or executed a malicious file',
      'Email attachment executed by user',
      'Malware downloaded by another malicious process (staged payload)',
      'Infected USB drive or network share',
      'Browser exploit dropping a malicious file',
      'False positive — legitimate software incorrectly flagged'
    ],
    steps: [
      'Note the Threat Name — search it online for threat intelligence',
      'Note the Path — this is where the file was found; check parent directory for related files',
      'Check Event 1117 immediately after — was it Quarantined or Removed?',
      'Check the Action Status in 1117 — "Failed" means the threat is still active',
      'Review other machines for the same threat: scan the environment',
      'If sensitive detection path (System32, startup, scheduled tasks): escalate and investigate lateral movement',
      'Check Event 4688 (process create) for the parent process that spawned the malicious file'
    ],
    symptoms: [
      'malware detected',
      'virus found',
      'Windows Defender alert',
      'threat detected',
      'antivirus detection',
      'malware on computer',
      'trojan detected',
      'ransomware detected',
      'malicious file found',
      'Defender found virus'
    ],
    tags: ['defender', 'antivirus', 'malware', 'threat', 'security', 'detection'],
    powershell: `# Windows Defender Threat Detection History
# Eventful

$startTime = (Get-Date).AddDays(-7)

# Detections (1116) and actions taken (1117)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-Windows Defender/Operational'
    Id           = @(1116, 1117)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        EventId      = $_.Id
        ThreatName   = ($data | Where-Object Name -eq 'Threat Name').'#text'
        Severity     = ($data | Where-Object Name -eq 'Severity Name').'#text'
        Path         = ($data | Where-Object Name -eq 'Path').'#text'
        ActionName   = ($data | Where-Object Name -eq 'Action Name').'#text'
        ActionStatus = ($data | Where-Object Name -eq 'Action Status').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1117, 1119, 5001, 4688],
    ms_docs: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus'
  },

  {
    id: 1117,
    source: 'Microsoft-Windows-Windows Defender',
    channel: 'Microsoft-Windows-Windows Defender/Operational',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Windows Defender Took Action on Malware',
    short_desc: 'Defender attempted to quarantine, remove, or clean a detected threat — records success or failure.',
    description: 'Event 1117 records the remediation action Windows Defender took in response to a detection (Event 1116). The event captures the action type (Quarantine, Remove, Clean, Allow, Block) and critically the Action Status — whether the action succeeded or failed. A failed action means the threat is still active. This event should be checked immediately after every 1116 to confirm the threat was actually removed.',
    why_it_happens: 'After detecting a threat, Defender attempts to quarantine or remove it based on its configured policy and the threat category. Quarantine moves the file to a protected holding area. Removal deletes the file. Actions can fail if the file is locked by a running process, if the file is in a read-only location, or if the process associated with the threat is still running.',
    what_good_looks_like: 'Action Status = "Succeeded" with Action = "Quarantine" or "Remove". No repeat detection of the same threat after successful action.',
    common_mistakes: [
      'Not reading the Action Status field — "Failed" means Defender found it but could not remove it',
      'Assuming Quarantine = safe — quarantined files are isolated but the machine may still be compromised if the malware ran first',
      'Not following up on failed remediations with manual investigation'
    ],
    causes: [
      'Threat successfully quarantined (normal outcome)',
      'Remediation failed because threat process is still running',
      'File locked by another process at remediation time',
      'Defender policy configured to Allow (if file is in an exclusion)',
      'Defender needs a reboot to complete removal'
    ],
    steps: [
      'Check Action Status field — Succeeded means clean, Failed means still active',
      'If Failed: run a full offline scan — Defender → Virus & threat protection → Scan options → Microsoft Defender Offline scan',
      'Check Quarantine history: Get-MpThreat | Where-Object IsActive -eq $false',
      'For persistent threats: boot to WinPE or use Defender offline scan to clean',
      'After remediation: check startup items, scheduled tasks, and services for persistence'
    ],
    symptoms: [
      'malware quarantined',
      'virus removal failed',
      'threat removal status',
      'Defender could not remove virus',
      'malware still active after detection',
      'quarantine failed',
      'Defender remediation failed',
      'threat not removed'
    ],
    tags: ['defender', 'antivirus', 'remediation', 'quarantine', 'malware', 'security'],
    powershell: `# Windows Defender Remediation Status
# Eventful

# Failed remediations (still active threats)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-Windows Defender/Operational'
    Id           = 1117
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        ThreatName   = ($data | Where-Object Name -eq 'Threat Name').'#text'
        ActionName   = ($data | Where-Object Name -eq 'Action Name').'#text'
        ActionStatus = ($data | Where-Object Name -eq 'Action Status').'#text'
        Path         = ($data | Where-Object Name -eq 'Path').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-List

# Active threats (not yet cleaned)
Get-MpThreatDetection | Where-Object { $_.ActionSuccess -eq $false } |
    Select-Object ThreatId, ActionSuccess, Resources | Format-List`,
    related_ids: [1116, 1119, 5001],
    ms_docs: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus'
  },

  {
    id: 5001,
    source: 'Microsoft-Windows-Windows Defender',
    channel: 'Microsoft-Windows-Windows Defender/Operational',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Windows Defender Real-Time Protection Disabled',
    short_desc: 'Real-time protection has been turned off — the system is unprotected against active threats.',
    description: 'Event 5001 is generated when Windows Defender real-time protection is disabled. This leaves the machine unprotected against file execution, download, and behavioral threats until protection is re-enabled. In a managed environment, this should never happen without a legitimate reason. Attackers frequently disable AV as an early step in an intrusion, making this event a high-priority security alert.',
    why_it_happens: 'Real-time protection can be disabled by a user with admin rights from the Windows Security app, by a Group Policy disabling Defender, by another antivirus product taking over (causing Defender to go into passive mode), by a tamper protection bypass, or by malware with sufficient privileges disabling it. Event 5001 is often preceded by an escalation-of-privilege event.',
    what_good_looks_like: 'Real-time protection always enabled. Tamper protection enabled to prevent unauthorized changes. No 5001 events. If another AV is deployed, Defender should be in passive mode (not fully disabled).',
    common_mistakes: [
      'Not correlating 5001 with preceding login events — was it a local admin who disabled it, or did malware escalate?',
      'Not checking Tamper Protection status — if Tamper Protection is off, any admin can disable Defender',
      'Assuming disabling was intentional because it came from a user account — attackers use compromised accounts'
    ],
    causes: [
      'User or admin manually disabled via Windows Security app',
      'Group Policy disabling Defender',
      'Malware or attacker disabling AV as intrusion step',
      'Third-party AV installation triggering Defender passive mode',
      'Tamper protection bypass exploit'
    ],
    steps: [
      'Immediately check current status: Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled',
      'Re-enable if disabled: Set-MpPreference -DisableRealtimeMonitoring $false',
      'Check 4688 (process create) events before 5001 — what process triggered the disable?',
      'Check if this correlates with a malware detection (1116) shortly after — malware disabling AV is a common sequence',
      'Enable Tamper Protection to prevent future unauthorized changes',
      'Review Security log for privilege escalation events (4672) preceding the disable'
    ],
    symptoms: [
      'antivirus disabled',
      'Windows Defender turned off',
      'real-time protection disabled',
      'computer unprotected',
      'Defender protection off',
      'antivirus not running',
      'malware disabled antivirus',
      'Windows Security real-time off'
    ],
    tags: ['defender', 'real-time-protection', 'security', 'disabled', 'malware', 'tamper'],
    powershell: `# Windows Defender Protection Status
# Eventful

# Current Defender status
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled,
    AntivirusEnabled, TamperProtectionSource,
    AntivirusSignatureLastUpdated,
    @{N='SignatureAgeDays'; E={ [int](((Get-Date) - $_.AntivirusSignatureLastUpdated).TotalDays) }} |
    Format-List

# Real-time protection disable events
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-Windows Defender/Operational'
    Id           = @(5001, 5004, 5007)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1116, 5007, 4688, 4672],
    ms_docs: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows'
  },

  {
    id: 2001,
    source: 'Microsoft-Windows-Windows Defender',
    channel: 'Microsoft-Windows-Windows Defender/Operational',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Windows Defender Definition Update Failed',
    short_desc: 'Defender could not download or install updated malware definitions — signatures are out of date.',
    description: 'Event 2001 is generated when Windows Defender fails to update its antivirus signature definitions. Outdated definitions mean new malware strains released after the last successful update will not be detected. In a managed environment, definitions should be no more than 24 hours old. Persistent 2001 events indicate a connectivity, WSUS, or Defender service problem.',
    why_it_happens: 'Definition updates can fail when the machine cannot reach Microsoft Update or a configured WSUS/SCCM server, when the Windows Update service has issues, when disk space is low, or when Defender\'s own service is in a degraded state. Corporate environments that use WSUS must ensure definitions are approved and distributed.',
    what_good_looks_like: 'Definitions updated at least once every 24 hours. No 2001 events. AntivirusSignatureLastUpdated within 1 day. Definitions version matches current Microsoft release.',
    common_mistakes: [
      'Not monitoring signature age — definitions can silently fall weeks behind without 2001 events if partial updates succeed',
      'Not checking WSUS approval — if WSUS manages updates, definitions must be approved to flow to clients',
      'Forgetting that Defender definitions are separate from Windows Update patches'
    ],
    causes: [
      'Internet/WSUS connectivity issue from the endpoint',
      'WSUS not approving or distributing definition updates',
      'Windows Update service (wuauserv) stopped or broken',
      'Disk space insufficient for update staging',
      'Defender service in degraded state'
    ],
    steps: [
      'Check current signature age: Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated',
      'Manually trigger update: Update-MpSignature',
      'Check Windows Update service: Get-Service wuauserv | Select-Object Status',
      'Check network connectivity to update endpoint: Test-NetConnection -ComputerName go.microsoft.com -Port 443',
      'If WSUS managed: verify definitions are approved in WSUS console',
      'Check Windows Update log for errors: Get-WindowsUpdateLog'
    ],
    symptoms: [
      'antivirus definitions out of date',
      'Defender not updating',
      'virus definitions old',
      'Windows Defender update failed',
      'antivirus signatures outdated',
      'Defender definitions not updating',
      'security signatures old',
      'Windows Defender out of date'
    ],
    tags: ['defender', 'definitions', 'signatures', 'update', 'antivirus', 'wsus'],
    powershell: `# Windows Defender Signature Status
# Eventful

# Current signature age and version
Get-MpComputerStatus | Select-Object
    AntivirusSignatureVersion,
    AntivirusSignatureLastUpdated,
    @{N='SignatureAgeDays'; E={ [math]::Round(((Get-Date) - $_.AntivirusSignatureLastUpdated).TotalDays, 1) }} |
    Format-List

# Force update
# Update-MpSignature

# Recent definition update failures
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-Windows Defender/Operational'
    Id           = @(2001, 2002, 2003)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [5001, 1116],
    ms_docs: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-updates'
  },

  {
    id: 3002,
    source: 'Microsoft-Windows-Windows Defender',
    channel: 'Microsoft-Windows-Windows Defender/Operational',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Windows Defender Real-Time Protection Component Failed',
    short_desc: 'A Defender real-time protection component has failed — partial protection only.',
    description: 'Event 3002 indicates that one or more Windows Defender real-time protection components (such as on-access scanning, behavior monitoring, or network inspection) has encountered a failure. Unlike 5001 (protection fully disabled), 3002 means protection is partially degraded — Defender is running but a specific protection layer has malfunctioned. This can result in gaps where certain types of threats are not being scanned.',
    why_it_happens: 'Component failures can occur after Windows updates that change internal Defender APIs, after third-party software conflicts with Defender drivers (minifilter conflicts), when Defender service files are corrupted, or when a required dependency (such as the WdFilter driver) fails to load.',
    what_good_looks_like: 'No 3002 events. All Defender components healthy per Get-MpComputerStatus. No conflicts with other security products.',
    common_mistakes: [
      'Not following up on 3002 because the machine "seems to be working" — partial protection means coverage gaps',
      'Not checking for minifilter driver conflicts with third-party security products'
    ],
    causes: [
      'Defender component driver (WdFilter, WdNisDrv) failed to load',
      'Third-party AV or security driver conflicting with Defender minifilter',
      'Windows Update changed API that Defender component depends on',
      'Corrupted Defender installation files'
    ],
    steps: [
      'Run: Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AMServiceEnabled, AntispywareEnabled, AntivirusEnabled',
      'Restart Defender service: Restart-Service WinDefend',
      'Run Defender self-repair: "%ProgramFiles%\\Windows Defender\\MpCmdRun.exe" -RestoreDefaults',
      'Check for minifilter conflicts: fltmc instances',
      'If persistent: run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth'
    ],
    symptoms: [
      'Windows Defender component failed',
      'antivirus protection partially working',
      'Defender real-time protection error',
      'Windows Defender not fully working',
      'Defender component error',
      'antivirus service failed',
      'Windows Defender broken'
    ],
    tags: ['defender', 'real-time-protection', 'component', 'error', 'antivirus'],
    powershell: `# Defender Component Health Check
# Eventful

Get-MpComputerStatus | Select-Object
    AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
    BehaviorMonitorEnabled, IoavProtectionEnabled,
    RealTimeProtectionEnabled, NISEnabled | Format-List

# Defender component failure events
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-Windows Defender/Operational'
    Id           = @(3002, 3007)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Check for minifilter conflicts
fltmc instances`,
    related_ids: [5001, 3007, 1116],
    ms_docs: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus'
  },

  {
    id: 1119,
    source: 'Microsoft-Windows-Windows Defender',
    channel: 'Microsoft-Windows-Windows Defender/Operational',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Windows Defender Remediation Failed — Threat Still Active',
    short_desc: 'Defender detected and attempted to remediate a threat but the action failed — malware still present.',
    description: 'Event 1119 is a critical escalation from 1117 — it specifically indicates that Defender\'s remediation attempt failed and the threat remains active on the system. This is different from 1117 with a failed action status in that 1119 explicitly flags the machine as potentially compromised. Immediate manual investigation and offline scan are required.',
    why_it_happens: 'Remediation failures occur when the malware is actively running and protecting itself, when the malicious file is locked by a kernel driver, when the threat has modified system policies to prevent removal, or when the malware has infected system files that cannot be replaced while Windows is running.',
    what_good_looks_like: 'No 1119 events. All detections followed by successful 1117 remediation.',
    common_mistakes: [
      'Not treating 1119 as a critical incident — a failed remediation means active malware on the system',
      'Trying to clean the machine while Windows is running when the malware is protecting itself',
      'Not isolating the machine from the network while investigating'
    ],
    causes: [
      'Malware running in memory and blocking file deletion',
      'Rootkit protecting malicious files from removal',
      'Threat has infected system files requiring offline repair',
      'Malware disabled Defender after being detected',
      'File locked by a kernel driver the malware installed'
    ],
    steps: [
      'Isolate the machine from the network immediately',
      'Run Defender Offline Scan: Start-MpScan -ScanType 3 (boots to WinPE for offline scan)',
      'If offline scan also fails: boot from external media for manual investigation',
      'Check for persistence: scheduled tasks, services, registry run keys, startup folder',
      'Consider reimaging if the threat is a rootkit or has infected system files',
      'Preserve evidence (memory dump, disk image) before remediation if incident response is required'
    ],
    symptoms: [
      'malware cannot be removed',
      'virus removal failed',
      'Defender cannot clean virus',
      'threat still active after scan',
      'malware persisting',
      'antivirus failed to remove threat',
      'virus keeps coming back',
      'malware removal failed'
    ],
    tags: ['defender', 'malware', 'remediation-failed', 'active-threat', 'security', 'incident'],
    powershell: `# Active Threat Investigation
# Eventful

# Failed remediations
Get-WinEvent -FilterHashtable @{
    LogName      = 'Microsoft-Windows-Windows Defender/Operational'
    Id           = @(1119, 1120)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Current active threats
Get-MpThreat | Where-Object IsActive -eq $true | Select-Object ThreatName, SeverityID, Resources | Format-List

# Trigger Defender Offline Scan (requires reboot)
# Start-MpScan -ScanType 3`,
    related_ids: [1116, 1117, 5001],
    ms_docs: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus'
  }
];
