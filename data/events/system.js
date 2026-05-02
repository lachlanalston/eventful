export const systemEvents = [
  {
    id: 41,
    source: 'Microsoft-Windows-Kernel-Power',
    channel: 'System',
    severity: 'Critical',
    skill_level: 'Intermediate',
    title: 'Kernel Power: Unexpected Reboot',
    short_desc: 'The system rebooted without a clean shutdown — power loss, crash, or hard reset.',
    description: 'Event ID 41 from the Kernel-Power source is generated on the NEXT boot after an unexpected shutdown. It indicates the system did not go through a normal shutdown sequence — the most likely causes are a power cut, someone hitting the power button, a kernel panic (BSOD), or overheating causing emergency shutdown. The BugcheckCode field is critical: if it\'s 0, there was no BSOD (power loss or hard reset). A non-zero BugcheckCode means there was a crash — look at 1001 for the full minidump analysis.',
    why_it_happens: 'Windows maintains a "clean shutdown flag" in the registry (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PagingFiles and the boot-status driver). If the system loses power, crashes, or is hard-reset before the OS can clear this flag during a normal shutdown, the next boot detects the unexpected condition and logs Event 41. BugcheckCode 0 = no crash occurred (hardware power event). Non-zero = the kernel itself crashed.',
    what_good_looks_like: 'Occasional Event 41 after a power outage is normal. Investigate: repeated Event 41 without an obvious power explanation, BugcheckCode that keeps repeating (same hardware fault), Event 41 with a non-zero BugcheckCode (actual kernel crash), clusters of Event 41 at similar times of day (thermal throttling at peak CPU load).',
    common_mistakes: [
      'Ignoring the BugcheckCode field — 0 means no crash, non-zero means BSOD and you need minidump analysis',
      'Not checking Event 6008 in the same log — it provides the timestamp of the unexpected shutdown',
      'Not checking the system for hardware issues: check SMART on disk, RAM with memtest86, PSU voltage, temperatures',
      'Assuming the OS caused the crash without ruling out hardware first — Event 41 with code 0 is almost always hardware or power'
    ],
    causes: [
      'Power outage or UPS failure',
      'Manual hard reset (power button hold)',
      'Kernel panic (BSOD) — check BugcheckCode',
      'Overheating causing emergency shutdown',
      'Faulty RAM causing memory corruption',
      'Failing power supply delivering inconsistent voltage',
      'Hardware driver crash'
    ],
    steps: [
      'Find Event 41 and note BugcheckCode — if 0, no BSOD occurred',
      'Check Event 6008 nearby to confirm unexpected shutdown timestamp',
      'If BugcheckCode non-zero: check Event 1001 for full minidump details',
      'Check Windows Reliability Monitor for pattern over time (search: perfmon /rel)',
      'Check system temperatures: Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root/wmi',
      'Run hardware diagnostics: memory test, disk SMART, PSU check',
      'If BugcheckCode 0x9F: driver power state failure — check device manager for driver issues',
      'If recurring: consider UPS installation or hardware replacement'
    ],
    symptoms: [
      'computer randomly reboots',
      'pc turns off by itself',
      'unexpected reboot',
      'computer keeps restarting',
      'blue screen then restart',
      'machine shut off randomly',
      'server restarted overnight',
      'sudden shutdown'
    ],
    tags: ['reboot', 'crash', 'kernel-power', 'bsod', 'hardware', 'uptime', 'critical'],
    powershell: `# Unexpected Reboot Investigation (Kernel Power 41)
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)   # Look back further for reboot patterns

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id           = 41
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        BugcheckCode   = ($data | Where-Object Name -eq 'BugcheckCode').'#text'
        PowerButtonOn  = ($data | Where-Object Name -eq 'PowerButtonTimestamp').'#text'
        SleepInProgress= ($data | Where-Object Name -eq 'SleepInProgress').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [1001, 6008, 1074, 6006],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/windows-kernel-event-id-41-error'
  },

  {
    id: 55,
    source: 'Ntfs',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'NTFS File System Corruption',
    short_desc: 'The NTFS driver detected corruption on a volume — could lead to data loss.',
    description: 'Event ID 55 from the Ntfs source indicates that the NTFS file system driver detected on-disk corruption. This can be a corrupt Master File Table (MFT), invalid file records, damaged metadata structures, or bad sectors affecting file system data. This event is serious — it can lead to data loss, application failures, and in severe cases an unbootable system. Corruption can appear without obvious symptoms until a file is accessed.',
    why_it_happens: 'NTFS corruption occurs when writes are interrupted mid-operation (power loss during write), when the storage medium has bad sectors, when the disk controller reports errors that corrupt in-flight data, when storage drivers have bugs, or when RAM errors cause corrupt data to be written to disk. NTFS is transactional and has a journal ($LogFile), but this only protects against metadata corruption from clean failures — bad sectors and RAM corruption can still cause Event 55.',
    what_good_looks_like: 'No Event 55 at all is ideal. Any Event 55 should be investigated. Repeated Event 55 on the same volume is urgent — the drive may be failing. Correlate with disk errors in the Disk event log (Event 7, 11, 15, 51) to see if bad sectors are triggering the corruption.',
    common_mistakes: [
      'Running chkdsk on a running system rather than scheduling it for next boot — chkdsk /f cannot fully repair a mounted volume',
      'Only running chkdsk and not investigating the underlying cause (failing disk, PSU issues, RAM)',
      'Ignoring Event 55 because the user "seems fine" — corruption can be silently expanding',
      'Not checking the disk SMART data alongside Event 55'
    ],
    causes: [
      'Power loss during a write operation',
      'Failing hard disk with bad sectors',
      'Faulty storage controller or cable',
      'RAM errors causing corrupt data to be written',
      'USB drive safely removed while mounted with pending writes',
      'Virtual machine storage issues (snapshot corruption, thin provisioning exhaustion)',
      'RAID array degradation affecting write integrity'
    ],
    steps: [
      'Note which volume is affected from the event message',
      'Schedule chkdsk: chkdsk C: /f /r /b (requires reboot for system volume)',
      'Check disk SMART health: Get-Disk | Get-StorageReliabilityCounter | Select-Object *',
      'Check for disk errors: Get-WinEvent -FilterHashtable @{LogName=\'System\'; ProviderName=\'disk\'} | Select -First 20',
      'Check Event 7, 11, 51 in System log for I/O errors on the same disk',
      'If a VM: check datastore health, free space, snapshot state',
      'If recurring: consider disk replacement and restore from backup',
      'Verify backup is working before running chkdsk /r'
    ],
    symptoms: [
      'file system corruption',
      'ntfs corruption',
      'disk corruption',
      'chkdsk finding errors',
      'files corrupted',
      'cant open files',
      'disk errors',
      'file system errors'
    ],
    tags: ['ntfs', 'corruption', 'disk', 'filesystem', 'data-integrity', 'chkdsk'],
    powershell: `# NTFS Corruption Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)

# Find NTFS corruption events
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Ntfs'
    Id           = 55
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Also check for disk I/O errors
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'disk'
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Select-Object -First 10 | Format-List`,
    related_ids: [41, 1001, 7023],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/troubleshoot-nfs-file-server'
  },

  {
    id: 1001,
    source: 'Microsoft-Windows-WER-SystemErrorReporting',
    channel: 'System',
    severity: 'Critical',
    skill_level: 'Intermediate',
    title: 'Windows Error Reporting: BugCheck (BSOD)',
    short_desc: 'A kernel-mode crash (Blue Screen of Death) was recorded with stop code and parameters.',
    description: 'Event ID 1001 from WER-SystemErrorReporting records the details of a kernel crash — the stop code (BugcheckCode), parameters, and a reference to the minidump file. This event is generated on the next boot after a BSOD. The BugcheckCode is the most important field: common codes include 0x0000007E (driver error), 0x00000050 (PAGE_FAULT_IN_NONPAGED_AREA, often bad RAM or driver), 0x0000009F (DRIVER_POWER_STATE_FAILURE), 0x00000124 (WHEA_UNCORRECTABLE_ERROR, hardware fault).',
    why_it_happens: 'When the Windows kernel encounters an unrecoverable error — typically a driver accessing invalid memory, a hardware fault, or kernel data structure corruption — it halts execution and writes a memory dump. The dump file (usually C:\\Windows\\Minidump\\*.dmp) contains the full call stack at the time of the crash. Event 1001 is the event log representation of this crash, generated after the system reboots.',
    what_good_looks_like: 'A system that never BSODs. If it does crash once, investigate the BugcheckCode. Repeated BSODs with the same code strongly suggest a specific hardware fault or driver bug. Multiple different codes on the same machine suggest bad RAM (random memory corruption causes many different stop codes).',
    common_mistakes: [
      'Reading the bugcheck code without looking up what it means — each code has specific causes',
      'Not analysing the minidump file — the code alone isn\'t enough; you need WinDbg or WhoCrashed to identify the responsible driver',
      'Blaming Windows when the driver shown in WinDbg analysis is a third-party driver (AV, NIC, storage)',
      'Running driver verifier without understanding it can cause additional crashes (use in isolated test environment)',
      'Not checking RAM with memtest86 for at least 8 passes when stop code varies'
    ],
    causes: [
      'Faulty or incompatible device driver (most common)',
      'RAM hardware fault',
      'CPU overheating or overclocking instability',
      'Power supply delivering inconsistent voltage',
      'Failing or corrupt SSD/HDD',
      'Kernel-mode malware or rootkit',
      'Windows system file corruption',
      'Hardware fault (GPU, NIC, storage controller)'
    ],
    steps: [
      'Find BugcheckCode in Event 1001 and look it up: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2',
      'Open minidump: C:\\Windows\\Minidump\\ — open with WinDbg or use WhoCrashed (free tool)',
      'WinDbg: !analyze -v will identify the crashing driver',
      'Update or roll back the identified driver first',
      'If code 0x124 (WHEA): run hardware diagnostics — this is a hardware fault',
      'If variable codes: run memtest86 overnight — likely bad RAM',
      'Check system temperatures and clean dust from fans/heatsinks',
      'If driver-related: check Windows Update and vendor site for driver updates'
    ],
    symptoms: [
      'blue screen',
      'bsod',
      'blue screen of death',
      'stop error',
      'computer crashes with blue screen',
      'windows crash',
      'pc restarts with blue screen',
      'kernel crash',
      'stop code',
      'memory dump'
    ],
    tags: ['bsod', 'crash', 'kernel', 'minidump', 'driver', 'hardware', 'critical'],
    powershell: `# BSOD / BugCheck Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Look back 30 days for crash patterns

# Find all BSOD records
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
    Id           = 1001
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# List minidump files
Write-Host "\n--- Minidump Files ---" -ForegroundColor Cyan
Get-ChildItem -Path "\\\\$computer\\c$\\Windows\\Minidump\\" -Filter "*.dmp" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize`,
    related_ids: [41, 6008, 1074],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2'
  },

  {
    id: 1074,
    source: 'USER32',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'System Shutdown or Restart Initiated by Process',
    short_desc: 'A process or user initiated a shutdown or restart, with reason and initiating process recorded.',
    description: 'Event ID 1074 records when a shutdown or restart is initiated programmatically or via the Windows shutdown dialog. It captures who initiated the shutdown, what process called it, the reason code, and whether it was a shutdown or restart. This is the primary event for determining why a machine was shut down or restarted intentionally. It contrasts with Event 6008 (unexpected shutdown) — if you see 6008 without a preceding 1074, the shutdown was unplanned.',
    why_it_happens: 'Windows generates 1074 whenever ExitWindowsEx() or InitiateSystemShutdown() is called with the shutdown or restart flag. This happens when a user clicks "Restart" or "Shut down", when Windows Update installs patches and requires a reboot, when an administrator runs "shutdown /r", or when management software (RMM, SCCM) triggers a reboot. The Reason Code provides structured information about why the restart occurred (e.g., 0x0 = other, 0x80020003 = OS/reconfiguration/planned).',
    what_good_looks_like: 'Expected: 1074 events from Windows Update (reason code OS: Planned), from users shutting down at end of day, from RMM tools patching. Investigate: 1074 events at unexpected times, restarts initiated by unfamiliar processes, restarts on servers without a corresponding change ticket.',
    common_mistakes: [
      'Not checking 1074 before concluding a reboot was unexpected — always look for 1074 first',
      'Ignoring the "Process" field — knowing whether it was shutdown.exe, wusa.exe, or an unknown binary matters',
      'Not checking for 1074 on servers when investigating unplanned downtime'
    ],
    causes: [
      'User-initiated shutdown or restart',
      'Windows Update requiring reboot after patch installation',
      'RMM tool triggering a managed reboot',
      'Administrator running shutdown command',
      'Application requesting system restart (installer)',
      'Group Policy forcing restart after changes'
    ],
    steps: [
      'Filter System log for Event 1074',
      'Check "Process Name" — was it Windows Update, shutdown.exe, or an RMM tool?',
      'Check "Reason" — does it match expected maintenance?',
      'Check "User" — who was logged on when the restart was triggered?',
      'If on a server: correlate with change records',
      'If Process Name is unexpected: investigate with Event 4688 to trace the process'
    ],
    symptoms: [
      'computer was restarted',
      'who restarted this machine',
      'server rebooted',
      'why did it restart',
      'shutdown reason',
      'machine shut down',
      'reboot reason',
      'windows update reboot'
    ],
    tags: ['shutdown', 'restart', 'reboot', 'maintenance', 'audit', 'uptime'],
    powershell: `# Shutdown/Restart Reason Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'USER32'
    Id           = 1074
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [41, 6006, 6008, 1076],
    ms_docs: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc940437(v=ws.10)'
  },

  {
    id: 1076,
    source: 'USER32',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Unexpected Shutdown Reason Recorded',
    short_desc: 'After an unexpected shutdown (6008), a user provided the reason via the shutdown tracker.',
    description: 'Event ID 1076 is generated when the Windows Shutdown Event Tracker is enabled and a user provides a reason for the previous unexpected shutdown. This event appears after a 6008 (unexpected shutdown was detected) and a user logs in and fills in the reason dialog. Common in server environments where administrators are required to document the cause of unexpected outages. The event captures the user who provided the reason and the reason text they entered.',
    why_it_happens: 'Windows Server has the Shutdown Event Tracker enabled by default. When the system detects that the previous shutdown was unexpected (via 6008), it prompts the next user to log in to provide a reason. This is a governance control to ensure unexpected downtime is documented. The feature can be configured via Group Policy.',
    what_good_looks_like: 'Expected: admins documenting reasons for unexpected server reboots. Investigate: the reason entered does not match known events, the same admin keeps logging reasons suggesting systematic unplanned outages, reasons indicating hardware problems that should be addressed.',
    common_mistakes: [
      'Relying on 1076 alone for root cause — the reason entered is user-supplied and may be generic or incorrect',
      'Not having the Shutdown Event Tracker enabled on servers — it helps with accountability'
    ],
    causes: [
      'Administrator documenting the previous unexpected shutdown',
      'Automatic population by management software',
      'Policy requiring documentation of server downtime'
    ],
    steps: [
      'Correlate 1076 with the preceding 6008 event',
      'Read the reason text — does it provide useful diagnosis information?',
      'Cross-reference with Event 41 or 1001 to find technical root cause',
      'If a pattern of unexpected shutdowns: escalate to hardware investigation'
    ],
    symptoms: [
      'unexpected shutdown explanation',
      'shutdown reason recorded',
      'shutdown tracker',
      'documented reboot reason',
      'server restart explanation'
    ],
    tags: ['shutdown', 'restart', 'accountability', 'audit', 'server'],
    powershell: `# Unexpected Shutdown Reason Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'USER32'
    Id           = 1076
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [6008, 41, 1074, 6006],
    ms_docs: null
  },

  {
    id: 6005,
    source: 'EventLog',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Event Log Service Started (System Boot)',
    short_desc: 'The Windows Event Log service started — marks the beginning of a new boot.',
    description: 'Event ID 6005 is generated by the Event Log service itself when it starts during system boot. It reliably marks the beginning of a new Windows session in the event log. When combined with 6006 (event log stopped, clean shutdown) and 6008 (unexpected shutdown), you can build a complete timeline of system uptime and shutdown history. It is one of the simplest but most useful events for determining when a machine was last booted.',
    why_it_happens: 'The Event Log service is one of the earliest services to start during Windows boot. When it initialises and opens the event log files, it writes Event 6005 to record its own startup. This event has been present since Windows NT.',
    what_good_looks_like: 'Every 6005 should be paired with either a preceding 6006 (clean shutdown) or a preceding 6008 (unexpected shutdown). Missing 6006 before a 6005 means the previous session ended unexpectedly — this is your signal to look for 41, 1001, or other crash indicators.',
    common_mistakes: [
      'Not checking what precedes 6005 — without a 6006, the previous boot ended badly',
      'Confusing 6005 with 6006 — 6005 = start (boot), 6006 = stop (shutdown)'
    ],
    causes: [
      'Normal system boot after clean shutdown',
      'System boot after power restoration',
      'System boot after BSOD or hard reset'
    ],
    steps: [
      'Look for 6005 events to find all boot times',
      'Check what precedes each 6005 — is there a 6006 (clean shutdown) or 6008 (unexpected)?',
      'If no 6006 before 6005: previous session ended unexpectedly, look for 41 and 1001',
      'Calculate uptime between 6005 pairs for availability reporting'
    ],
    symptoms: [
      'when did this computer last start',
      'boot time',
      'system started',
      'when was it turned on',
      'last reboot time',
      'computer started up'
    ],
    tags: ['boot', 'startup', 'uptime', 'availability', 'fundamental'],
    powershell: `# System Boot History Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Adjust time range as needed

# Get boot and shutdown timeline
$boots = Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'EventLog'
    Id           = @(6005, 6006, 6008)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={
            switch ($_.Id) {
                6005 { 'BOOT (Event Log Started)' }
                6006 { 'SHUTDOWN (Clean)' }
                6008 { 'SHUTDOWN (Unexpected)' }
            }
        }} | Sort-Object TimeCreated

$boots | Format-Table -AutoSize`,
    related_ids: [6006, 6008, 41, 1074],
    ms_docs: null
  },

  {
    id: 6006,
    source: 'EventLog',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Event Log Service Stopped (Clean Shutdown)',
    short_desc: 'The Event Log service stopped — marks the end of a clean shutdown sequence.',
    description: 'Event ID 6006 is generated when the Windows Event Log service stops as part of a clean shutdown. It is the last event written before the system shuts down. If you are investigating why a machine rebooted and you see a 6006 followed by a 6005 (next boot), the shutdown was intentional and clean. If 6005 appears without a preceding 6006, the previous session ended unexpectedly.',
    why_it_happens: 'During a clean shutdown, the Event Log service is one of the last services to stop. Before stopping, it writes 6006 to record its own clean termination. This provides a reliable audit trail of clean shutdowns.',
    what_good_looks_like: 'Every 6006 should be followed by a 6005. If you are investigating an unexpected reboot or crash, look for the absence of 6006 before a 6005.',
    common_mistakes: [
      'Confusing 6006 with 6005 — 6006 = clean stop, 6005 = start',
      'Not checking for 6006 when investigating whether a shutdown was clean or unexpected'
    ],
    causes: [
      'User-initiated shutdown',
      'Windows Update restart',
      'Administrator shutdown',
      'RMM-triggered reboot'
    ],
    steps: [
      'Look for 6006 events to confirm clean shutdowns',
      'If missing 6006 before a 6005: unexpected shutdown — investigate Event 41, 6008',
      'Pair with 1074 to find who initiated the clean shutdown'
    ],
    symptoms: [
      'clean shutdown',
      'planned shutdown',
      'machine was shut down cleanly',
      'system shutdown normally'
    ],
    tags: ['shutdown', 'clean-shutdown', 'uptime', 'audit'],
    powershell: `# Clean Shutdown Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'EventLog'
    Id           = 6006
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [6005, 6008, 1074, 41],
    ms_docs: null
  },

  {
    id: 6008,
    source: 'EventLog',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Unexpected Shutdown Recorded',
    short_desc: 'The previous system shutdown was unexpected — generated on the next boot.',
    description: 'Event ID 6008 is generated at boot time when Windows detects that the previous shutdown was not clean. The event message includes the date and time the unexpected shutdown occurred (the time the system last had a clean record). This event is your first indicator of an unplanned outage — the starting point for investigating BSODs, power losses, and hard resets. It does not tell you why the shutdown happened — for that, look at Event 41 and Event 1001.',
    why_it_happens: 'Windows maintains a boot-status file that is updated throughout normal operation and properly closed during a clean shutdown. If the system loses power, crashes, or is hard-reset, this file is not properly closed. On the next boot, Windows checks the file, detects the improper closure, and logs Event 6008 to record the unexpected termination.',
    what_good_looks_like: 'No 6008 events on a healthy, stable machine. A 6008 followed by investigation and resolution is acceptable. Repeated 6008 events — especially on servers — indicate an ongoing problem that must be resolved.',
    common_mistakes: [
      'Reading 6008 and not following up with Event 41 and Event 1001',
      'Assuming 6008 always means BSOD — it also occurs for power loss and hard reset',
      'Not correlating 6008 timestamp with UPS or power monitoring logs'
    ],
    causes: [
      'Power failure (no UPS)',
      'Hard reset (power button)',
      'Kernel crash (BSOD)',
      'Hypervisor force-shutdown of VM',
      'Hardware failure causing abrupt halt'
    ],
    steps: [
      'Find Event 6008 and note the timestamp of the unexpected shutdown',
      'Look for Event 41 (Kernel Power) near the same time',
      'Look for Event 1001 (BugCheck) — if present, a BSOD occurred',
      'If no 41 or 1001: likely hardware power event (check UPS logs)',
      'Check Reliability Monitor for a visual timeline: perfmon /rel'
    ],
    symptoms: [
      'unexpected shutdown',
      'computer shut off unexpectedly',
      'unclean shutdown',
      'power outage reboot',
      'machine crashed',
      'previous session ended unexpectedly',
      'system did not shut down properly'
    ],
    tags: ['shutdown', 'unexpected', 'crash', 'power', 'uptime', 'fundamental'],
    powershell: `# Unexpected Shutdown Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Adjust time range as needed

# Get unexpected shutdown events
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'EventLog'
    Id           = 6008
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [41, 1001, 6005, 6006, 1074],
    ms_docs: null
  },

  {
    id: 6013,
    source: 'EventLog',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'System Uptime',
    short_desc: 'Daily event recording total system uptime in seconds — useful for availability reporting.',
    description: 'Event ID 6013 is generated once per day (usually around midnight or on event log startup) and records the current system uptime in seconds. While simple, it provides a built-in uptime audit trail. If you want to know how long a machine has been up without running a command, you can look for the most recent 6013 event and calculate from its timestamp. It is also useful for confirming SLAs — a server with 6013 showing many days of uptime has been stable.',
    why_it_happens: 'The Event Log service generates 6013 once every 24 hours as a housekeeping record. The uptime value in seconds comes from the system kernel\'s KeQueryTimeIncrement counter, which starts at boot.',
    what_good_looks_like: 'Any 6013 is normal. Use the uptime value to calculate last boot time: (Get-Date).AddSeconds(-[int]$uptimeSeconds). Uptime longer than your patching cycle means the machine has not been rebooted for updates.',
    common_mistakes: [
      'Not realising 6013 fires at log startup too, not just midnight — so a reboot generates a 6013 with low uptime',
      'Using 6013 instead of checking LastBootUpTime directly — Get-CimInstance Win32_OperatingSystem is more reliable'
    ],
    causes: [
      'Automatic daily system heartbeat from Event Log service'
    ],
    steps: [
      'Find the most recent 6013 event',
      'Note the uptime in seconds from the message',
      'Calculate last boot: (Get-Date).AddSeconds(-<uptime_seconds>)',
      'For real-time uptime: (Get-CimInstance Win32_OperatingSystem).LastBootUpTime'
    ],
    symptoms: [
      'check system uptime',
      'how long has this been on',
      'when was last reboot',
      'system runtime',
      'availability check'
    ],
    tags: ['uptime', 'availability', 'sla', 'baseline', 'monitoring'],
    powershell: `# System Uptime Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed

# Direct uptime query (most accurate)
$os = Get-CimInstance -ComputerName $computer -ClassName Win32_OperatingSystem
Write-Host "Last Boot Time: $($os.LastBootUpTime)"
Write-Host "Uptime: $((Get-Date) - $os.LastBootUpTime)"

# Also check recent 6013 events for historical uptime
$startTime = (Get-Date).AddDays(-7)
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'EventLog'
    Id           = 6013
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List`,
    related_ids: [6005, 6006, 6008],
    ms_docs: null
  },

  {
    id: 7000,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Service Failed to Start',
    short_desc: 'The Service Control Manager could not start a service at boot or on demand.',
    description: 'Event ID 7000 is generated by the Service Control Manager (SCM) when a service fails to start. The event includes the service name and an error code that identifies why it failed. This is the primary event for service startup failures. Common error codes: 2 = "The system cannot find the file" (service binary missing), 5 = "Access is denied" (service account lacks permissions), 1053 = "The service did not respond to the start or control request" (service timeout).',
    why_it_happens: 'The SCM attempts to start services during boot or when a dependent service requires them. Startup failures can occur because the service binary was deleted or moved, the service account credentials are wrong, a required dependency service failed first (see 7001), the service binary threw an exception immediately on start, or the service account was locked out or disabled.',
    what_good_looks_like: 'No 7000 events on a healthy system. Any 7000 should be investigated — even for non-critical services, failed services can indicate a broken application. On a server, a failed critical service may mean the server is partially or fully non-functional.',
    common_mistakes: [
      'Trying to start the service without reading the error code — the code tells you exactly what went wrong',
      'Not checking Event 7001 for dependency failures — if a dependency failed, fix that first',
      'Resetting the service account password without also updating it in the service configuration',
      'Not checking that the service binary executable actually exists at the path configured'
    ],
    causes: [
      'Service binary file missing or corrupt',
      'Service account credentials invalid or account locked/disabled',
      'Dependency service not running',
      'Insufficient permissions for service account',
      'Service crashed immediately on start',
      'Antivirus blocking service binary',
      'Registry configuration corrupt for the service'
    ],
    steps: [
      'Filter System log for Event 7000',
      'Note the service name and error code',
      'Error 2 (file not found): check if binary exists at configured path',
      'Error 5 (access denied): check service account permissions',
      'Error 1053 (timeout): check Event 7009 and investigate why service is not responding',
      'Check Event 7001 for dependency failures first',
      'Check service configuration: Get-Service <name> | Select-Object *',
      'Check service account status in AD if it uses a domain account'
    ],
    symptoms: [
      'service wont start',
      'service failed to start',
      'service not starting',
      'service startup failure',
      'service is stopped',
      'application service failed',
      'windows service error',
      'service does not start on boot'
    ],
    tags: ['service', 'startup', 'scm', 'fundamental', 'reliability'],
    powershell: `# Service Startup Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

# Find service startup failures
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = @(7000, 7001, 7009, 7023)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Sort-Object TimeCreated -Descending |
    Format-List`,
    related_ids: [7001, 7009, 7023, 7031, 7045],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/client-management/troubleshoot-service-startup-errors'
  },

  {
    id: 7001,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Service Dependency Failed',
    short_desc: 'A service could not start because a service it depends on failed or did not start.',
    description: 'Event ID 7001 records that a service failed to start because one of its dependencies failed. Windows services can declare dependencies on other services — the SCM tries to start dependencies first. If a dependency fails (7000), all dependent services will also fail with 7001. This creates a cascade: one failed core service can trigger dozens of 7001 events. Always trace back to find the root cause failure (the 7000 event) rather than trying to fix each 7001 individually.',
    why_it_happens: 'Service dependencies are configured in the service registry key under DependOnService or DependOnGroup. When the SCM starts the system, it topologically sorts services by dependency and starts them in order. A failure in a low-level service propagates to all services above it in the dependency tree.',
    what_good_looks_like: 'A 7001 that follows a 7000 for the dependency is expected cascade behavior. Find and fix the 7000 first. If you see 7001 without a corresponding 7000 for the dependency service, the dependency may have started but then crashed (check 7031).',
    common_mistakes: [
      'Fixing each 7001 service individually without finding the root 7000 cause',
      'Not understanding that a single dependency failure can cascade to many 7001 events',
      'Not checking the dependency chain: Get-Service -ComputerName <host> <servicename> -RequiredServices'
    ],
    causes: [
      'Root dependency service failed to start (Event 7000)',
      'Root dependency service crashed after starting (Event 7031)',
      'Dependency service disabled',
      'Circular dependency (unusual)'
    ],
    steps: [
      'Find Event 7001 and note which dependency failed',
      'Find the 7000 event for the failing dependency service',
      'Fix the root cause dependency first',
      'Once dependency is fixed, restart dependent services: Start-Service <name>',
      'Check dependency chain: (Get-Service <name>).RequiredServices'
    ],
    symptoms: [
      'service dependency failed',
      'dependent service failed',
      'service cant start because of dependency',
      'multiple services not starting',
      'service dependency error'
    ],
    tags: ['service', 'dependency', 'startup', 'scm', 'reliability'],
    powershell: `# Service Dependency Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-3)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7001
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [7000, 7009, 7023, 7031],
    ms_docs: null
  },

  {
    id: 7009,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Service Start Timeout',
    short_desc: 'A service did not respond to a start request within the timeout period (typically 30s).',
    description: 'Event ID 7009 records that a service was started but failed to report "running" status within the SCM timeout period (default 30 seconds, configurable via HKLM\\SYSTEM\\CurrentControlSet\\Control\\ServicesPipeTimeout). This typically means the service binary is hung during initialization — perhaps waiting for a network resource, deadlocked in its startup code, or taking longer than expected to load. The service may eventually start or may time out and fail with a 7000.',
    why_it_happens: 'The SCM sends a "start" control code to the service and waits for the service to call SetServiceStatus() with SERVICE_RUNNING within the timeout window. If the service is doing heavy initialization work (database connections, loading large files, network calls) it may exceed the timeout. Timeout errors during boot are common after power failure when disks or networks are slow.',
    what_good_looks_like: 'No 7009 events. If 7009 appears: check if the service eventually started, investigate what is blocking it during initialization.',
    common_mistakes: [
      'Increasing ServicesPipeTimeout as the fix without investigating why the service is slow to start',
      'Not checking whether the service is doing network calls during startup that may be failing',
      'Treating 7009 and 7000 as the same — 7009 is timeout specifically, 7000 is general failure'
    ],
    causes: [
      'Service doing heavy initialization work exceeding timeout',
      'Network-dependent service waiting for unavailable network resource',
      'Deadlock in service startup code',
      'System overloaded during boot',
      'Service binary issue causing slow startup'
    ],
    steps: [
      'Filter System log for 7009',
      'Note the service name',
      'Check if a 7000 follows (timeout → failure) or if the service eventually started',
      'Check the Application log for service-specific error messages',
      'Check if the timeout occurs consistently or only after cold boot',
      'If network-dependent: check network availability during boot'
    ],
    symptoms: [
      'service timeout',
      'service timed out starting',
      'service took too long to start',
      'service start hung',
      'service not responding on startup'
    ],
    tags: ['service', 'timeout', 'startup', 'scm', 'performance'],
    powershell: `# Service Timeout Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7009
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [7000, 7001, 7011, 7023],
    ms_docs: null
  },

  {
    id: 7011,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Service Transaction Timeout',
    short_desc: 'A service did not respond to a control request (stop, pause, continue) within the timeout.',
    description: 'Event ID 7011 is similar to 7009 but occurs when an already-running service fails to respond to a control request — typically a stop, pause, or continue command — within the timeout period. This usually means the service is hung or deadlocked in its running state. A service that cannot be stopped normally may need to be terminated via Task Manager or by stopping the process directly.',
    why_it_happens: 'The SCM sends control codes to services via the service\'s service control handler. If the service\'s handler is blocked (thread deadlock, hung I/O, or simply not processing the control pipe), it does not acknowledge the control request, and the SCM times out.',
    what_good_looks_like: 'No 7011 events. Any 7011 indicates a service is not properly handling control signals, which is a reliability concern.',
    common_mistakes: [
      'Not finding the service\'s process ID and killing it if the service won\'t stop normally',
      'Trying to restart a hung service without ending its process first'
    ],
    causes: [
      'Service deadlocked in its running code',
      'Service I/O operation blocking the control thread',
      'Service bug in control handler',
      'High system load preventing the service thread from running'
    ],
    steps: [
      'Identify the service and find its process: Get-WmiObject Win32_Service | Where-Object Name -eq \'<name>\' | Select ProcessId',
      'Check what the process is doing: Invoke-Command -ComputerName $computer { Get-Process -Id <pid> | Select-Object * }',
      'If the service is hung: Stop-Process -Id <pid> -Force, then Start-Service <name>',
      'Review application event log for service-specific error messages',
      'If recurring: investigate the service for deadlock conditions'
    ],
    symptoms: [
      'service hung',
      'service not responding',
      'cant stop service',
      'service wont stop',
      'service transaction timeout',
      'service hung after stopping'
    ],
    tags: ['service', 'timeout', 'hung', 'scm', 'reliability'],
    powershell: `# Service Transaction Timeout Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7011
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [7000, 7009, 7023, 7031],
    ms_docs: null
  },

  {
    id: 7023,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Service Terminated with Error',
    short_desc: 'A service stopped and reported a non-zero error code.',
    description: 'Event ID 7023 is generated when a service terminates and returns a non-zero error code to the SCM. Unlike 7031 (unexpected crash), 7023 means the service exited intentionally with an error — it detected a problem and called ExitProcess with an error code. The event includes the error code, which helps diagnose the issue. This is commonly seen with services that fail due to configuration problems, missing dependencies, or license issues.',
    why_it_happens: 'A service calls ExitProcess() or returns a non-zero exit code from its service main function, signalling to the SCM that it failed. The SCM records this as 7023. The exit code is typically a Win32 error code (e.g., 5 = Access Denied, 1060 = Service not found) or an application-specific error code.',
    what_good_looks_like: 'No 7023 events. Any 7023 warrants investigation. Check the Application event log for additional context from the service itself.',
    common_mistakes: [
      'Trying to fix 7023 without also checking the Application event log — the service may log more detail about why it exited',
      'Treating 7023 the same as 7031 — 7023 is a graceful exit with error, 7031 is an unexpected crash'
    ],
    causes: [
      'Service detected missing configuration file',
      'Service could not connect to required database',
      'Service license validation failed',
      'Service detected permission problem',
      'Service explicitly exiting after detecting unrecoverable error'
    ],
    steps: [
      'Filter System log for 7023 and note service name and error code',
      'Check Application log for service-specific messages around the same time',
      'Look up the error code (Win32 error or application-specific)',
      'Check service configuration files and dependencies',
      'Restart service after fixing underlying cause: Start-Service <name>'
    ],
    symptoms: [
      'service terminated with error',
      'service exited with error code',
      'service crashed with error',
      'service stopped unexpectedly with code',
      'service failure error'
    ],
    tags: ['service', 'error', 'failure', 'scm', 'reliability'],
    powershell: `# Service Termination Error Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7023
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [7000, 7001, 7031, 7034],
    ms_docs: null
  },

  {
    id: 7031,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Service Crashed Unexpectedly',
    short_desc: 'A service terminated unexpectedly — the SCM may attempt automatic recovery actions.',
    description: 'Event ID 7031 records that a service terminated unexpectedly — meaning it did not exit gracefully and the SCM did not expect the termination. This is typically caused by the service process crashing (access violation, unhandled exception) rather than exiting cleanly. The event includes how many times the service has crashed (crash count) and what recovery action was taken. Recovery actions are configured per-service (restart, run a program, reboot) and can be viewed in the service properties.',
    why_it_happens: 'When a service process terminates without deregistering from the SCM, the SCM detects the orphaned service process and logs 7031. This happens when the service binary crashes due to an unhandled exception, memory corruption, or external process termination. The SCM then checks the configured failure actions (First/Second/Subsequent failure) and executes the appropriate recovery.',
    what_good_looks_like: 'No 7031 events. First crash: investigate. Repeated crashes: urgent — the service has a serious problem or the application has a bug. Check the Application event log for Application Error (ID 1000) events that will have the faulting module and exception code.',
    common_mistakes: [
      'Not checking Event 1000 in the Application log alongside 7031 — the application crash detail is there',
      'Enabling "restart service automatically" without finding root cause — the service will keep crashing',
      'Not checking if an update or config change preceded the first crash'
    ],
    causes: [
      'Service binary bug causing access violation',
      'Memory corruption',
      'Unhandled exception in service code',
      'Third-party DLL injected into service process crashing it',
      'Out of memory condition',
      'Antivirus terminating the service process (false positive)'
    ],
    steps: [
      'Find Event 7031 and note the service name and crash count',
      'Check Application log for Event 1000 (Application Error) matching the service around the same time',
      'Note faulting module in 1000 — is it the service\'s own DLL or a third-party one?',
      'Check if there were recent updates or configuration changes',
      'Review service recovery actions: (Get-WmiObject Win32_Service | Where Name -eq \'<name>\').FailureActions',
      'If recurring: contact software vendor or check for patches'
    ],
    symptoms: [
      'service crashed',
      'service keeps crashing',
      'service keeps stopping',
      'service restarting repeatedly',
      'service died',
      'service unexpectedly terminated',
      'service auto restarted'
    ],
    tags: ['service', 'crash', 'failure', 'scm', 'reliability', 'application-crash'],
    powershell: `# Service Crash Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

# Get service crashes
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = @(7031, 7034)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Also check Application log for crash details
Write-Host "\n--- Application Crash Events (1000) ---" -ForegroundColor Cyan
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Application'
    Id        = 1000
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Select-Object -First 5 | Format-List`,
    related_ids: [7034, 7000, 7023, 1000],
    ms_docs: null
  },

  {
    id: 7034,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Service Crashed Unexpectedly (Repeated)',
    short_desc: 'A service crashed unexpectedly — this event marks subsequent crashes after the first.',
    description: 'Event ID 7034 is very similar to 7031 but represents the second and subsequent unexpected terminations of a service. The SCM distinguishes between the first crash (7031) and repeat crashes (7034) because the recovery actions are typically different. If the configured recovery actions (restart, run program, reboot) are not resolving the crash, 7034 events indicate an ongoing problem that the automatic recovery is not fixing.',
    why_it_happens: 'Generated by the SCM each time after the first crash when a service exits unexpectedly. Unlike 7031 (which may have a "restart service" recovery action), by the third crash the configured recovery action may be "take no action" — leaving the service permanently stopped.',
    what_good_looks_like: 'No 7034 events. Any 7034 with high crash count is urgent — the service is in a crash loop.',
    common_mistakes: [
      'Treating 7034 and 7031 as identical — 7034 indicates the problem is persistent and recovery actions are not working',
      'Not counting how many times the service has crashed — the crash count indicates severity'
    ],
    causes: [
      'Same as 7031 — persistent service bug, hardware fault, or external cause',
      'Recovery action set to restart, which keeps restarting into the same crash',
      'Application configuration issue that is not fixed between restarts'
    ],
    steps: [
      'Filter System log for 7034 and count occurrences for the same service',
      'Follow 7031 investigation steps',
      'Check configured recovery actions in service properties',
      'If crash count is high: disable automatic recovery temporarily and investigate root cause',
      'Contact software vendor with crash details from Event 1000'
    ],
    symptoms: [
      'service keeps crashing over and over',
      'service crash loop',
      'service restarting every few minutes',
      'service crashing repeatedly',
      'service in crash loop'
    ],
    tags: ['service', 'crash', 'loop', 'reliability', 'scm'],
    powershell: `# Repeated Service Crash Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7034
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [7031, 7000, 7023, 1000],
    ms_docs: null
  },

  {
    id: 7036,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Service State Changed',
    short_desc: 'A service entered a running or stopped state — normal operational event.',
    description: 'Event ID 7036 records every time a service transitions to "running" or "stopped" state. It is one of the highest-volume SCM events and by itself is not suspicious — services start and stop constantly. However, 7036 becomes very useful when you want to know exactly when a specific service started or stopped, and whether a service that should always be running was temporarily stopped.',
    why_it_happens: 'The SCM logs 7036 every time a service changes to a "running" or "stopped" state. This includes boot-time service starts, user-initiated stops and starts, and stops due to crashes (where it will appear alongside 7031/7034).',
    what_good_looks_like: 'Normal: Windows Defender, Print Spooler, and other services stopping and starting as expected. Investigate: a critical service (SQL, IIS, AD) stopping without a corresponding planned action, a security service (antivirus, firewall) stopping unexpectedly, many services stopping simultaneously (suggests shutdown or crash).',
    common_mistakes: [
      'Being overwhelmed by 7036 volume — filter specifically for the service and state you care about',
      'Not using 7036 to confirm when a service was available during a troubleshooting window'
    ],
    causes: [
      'Normal service lifecycle',
      'Scheduled maintenance',
      'Service crash recovery',
      'Intentional admin action',
      'Malware stopping security services'
    ],
    steps: [
      'Filter System log for 7036 scoped to a specific service name',
      'Look for "stopped" transitions on critical or security services',
      'Correlate timestamps with 7031/7034 crash events',
      'Check if antivirus or security services stopped unexpectedly'
    ],
    symptoms: [
      'service stopped',
      'service started',
      'service state changed',
      'when did this service start',
      'when did this service stop'
    ],
    tags: ['service', 'state', 'lifecycle', 'scm', 'monitoring'],
    powershell: `# Service State Change Investigation
# Eventful

$computer     = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime    = (Get-Date).AddDays(-3)  # Adjust time range as needed
$serviceName  = 'WinDefend'   # Replace with service to track

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7036
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*$serviceName*"
} | Select-Object TimeCreated, Message | Format-Table -AutoSize`,
    related_ids: [7000, 7031, 7034, 7040],
    ms_docs: null
  },

  {
    id: 7040,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Service Start Type Changed',
    short_desc: 'A service\'s startup type was changed (e.g., Automatic to Disabled).',
    description: 'Event ID 7040 records changes to a service\'s start type — Automatic, Manual, Disabled. This is important from a security perspective because disabling a security service (antivirus, firewall, audit service) is a technique attackers use to weaken defenses before carrying out malicious activity. It also helps troubleshoot cases where a service unexpectedly stops starting on boot — someone may have changed it to Manual or Disabled.',
    why_it_happens: 'The SCM logs 7040 when the start type of a service is modified. This happens via the Services MMC snap-in, sc.exe config command, the Set-Service cmdlet, or registry modifications. Group Policy can also force start type changes, which will appear as 7040 events.',
    what_good_looks_like: 'Expected: planned changes to service start types during configuration management. Investigate: security-critical services (Windows Defender, Windows Firewall, Event Log) being changed to Disabled or Manual, changes made at unusual times, changes not reflected in change management records.',
    common_mistakes: [
      'Not alerting on changes to security services\' start type — this is a common attacker technique',
      'Changing a service to Automatic without understanding why it was Manual'
    ],
    causes: [
      'IT admin changing service configuration',
      'Software installer modifying service startup',
      'Group Policy applying service configuration',
      'Attacker disabling security services',
      'Malware modifying startup type to survive reboots or disable detection'
    ],
    steps: [
      'Filter System log for 7040',
      'Note service name and new start type',
      'If "Disabled" or "Manual" for a security service: immediate investigation',
      'Restore correct start type: Set-Service <name> -StartupType Automatic',
      'Correlate with 4688 to find what process made the change'
    ],
    symptoms: [
      'service start type changed',
      'service disabled',
      'service changed to manual',
      'antivirus service disabled',
      'windows defender disabled',
      'firewall service disabled'
    ],
    tags: ['service', 'configuration', 'security', 'defense-evasion', 'scm'],
    powershell: `# Service Start Type Change Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7040
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [7036, 7000, 7031, 4688],
    ms_docs: null
  },

  {
    id: 7045,
    source: 'Service Control Manager',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'New Service Installed',
    short_desc: 'A new service was installed and registered with the Service Control Manager.',
    description: 'Event ID 7045 records when a new service is installed on the system. Like scheduled task creation (4698), new service installation is a favourite persistence mechanism for attackers — services run under SYSTEM or service accounts, start automatically, and are often overlooked by defenders focused on user-space activity. The event includes the service name, binary path, account it runs under, and the start type. Service names that don\'t match known software should be immediately investigated.',
    why_it_happens: 'When a service is created via the SCM APIs (CreateService), the SCM logs 7045. This happens during software installation, when admin tools deploy services, and when malware installs a service for persistence or remote access. The binary path field is particularly important — malicious services often run from unusual paths (AppData, Temp, random hex-named directories).',
    what_good_looks_like: 'Expected: known software installing services during installation (SQL Server, antivirus, monitoring agents). Investigate: services installed outside of known software installation events, binary paths in AppData, Temp, or with random names, services running as LocalSystem (SYSTEM) installed by non-admin processes, service names that try to blend in with system services.',
    common_mistakes: [
      'Not having a baseline list of expected services to compare against',
      'Missing that even services installed by an admin account can be malicious if the admin account was compromised',
      'Not checking the binary path — a service that looks legitimate by name but runs from AppData is suspicious'
    ],
    causes: [
      'Software installation creating a service',
      'RMM or monitoring agent deploying a service',
      'IT admin installing a management service',
      'Malware installing a persistent service',
      'Attacker using PsExec or similar (which installs a temporary service)'
    ],
    steps: [
      'Filter System log for 7045',
      'Note service name, binary path, account, and start type',
      'Check if binary path is in a standard location (Program Files, Windows, etc.)',
      'Verify the service matches a known installation event (Event 4688, installer logs)',
      'Check the service binary hash against VirusTotal if suspicious',
      'Investigate unknown services: Get-Service <name> | Select-Object *',
      'Remove malicious services: sc.exe delete <name>'
    ],
    symptoms: [
      'new service installed',
      'unknown service appeared',
      'suspicious service',
      'new service on system',
      'service installed by malware',
      'unauthorized service'
    ],
    tags: ['service', 'persistence', 'installation', 'malware', 'scm', 'security'],
    powershell: `# New Service Installation Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7045
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        ServiceName   = ($data | Where-Object Name -eq 'ServiceName').'#text'
        BinaryPath    = ($data | Where-Object Name -eq 'ImagePath').'#text'
        AccountName   = ($data | Where-Object Name -eq 'AccountName').'#text'
        StartType     = ($data | Where-Object Name -eq 'StartType').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [7036, 7000, 4688, 4698],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697'
  },

  {
    id: 12,
    source: 'Microsoft-Windows-Kernel-General',
    channel: 'System',
    severity: 'Information',
    skill_level: 'Beginner',
    title: 'Operating System Started',
    short_desc: 'The OS initialized successfully and logged the exact start time for this boot.',
    description: 'Event ID 12 from Kernel-General is written early in every normal boot. It records the precise system time the OS kernel started running. On its own it is informational — no action needed. Its primary value in incident analysis is as a timeline anchor: you can see exactly when the machine booted, correlate it against Event 13 (shutdown) and Event 41 (unexpected reboot), and determine uptime at the time of an incident.',
    why_it_happens: 'Logged by the Windows kernel during initialization on every boot, before user-mode processes start. The timestamp comes from the hardware clock (RTC) before time sync occurs, so it may be slightly off by a few seconds from NTP-corrected time.',
    what_good_looks_like: 'One Event 12 per boot cycle. Frequent Event 12 entries without corresponding Event 13 entries before them indicates repeated unexpected reboots — correlate with Event 41.',
    causes: [
      'Normal system boot',
      'Reboot after update',
      'Reboot following a crash (Event 41)',
      'Reboot after manual shutdown'
    ],
    steps: [
      'Use Event 12 timestamps to map the full boot history of the machine',
      'Check if Event 13 appears before each Event 12 — missing Event 13 means the previous shutdown was unexpected',
      'Correlate with Event 41 to confirm crash vs. clean reboot',
      'Measure uptime between Event 12 and the incident timestamp'
    ],
    symptoms: [
      'when did the computer start',
      'boot time',
      'last reboot time',
      'system start time',
      'os startup'
    ],
    tags: ['boot', 'startup', 'kernel', 'timeline', 'uptime'],
    powershell: `# Boot History (last 30 days)
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-General'
    Id           = @(12, 13)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 12) {'STARTED'} else {'SHUTDOWN'} }} |
    Sort-Object TimeCreated | Format-Table -AutoSize`,
    related_ids: [13, 41, 6008, 6005],
    ms_docs: null
  },

  {
    id: 13,
    source: 'Microsoft-Windows-Kernel-General',
    channel: 'System',
    severity: 'Information',
    skill_level: 'Beginner',
    title: 'Operating System Shutdown',
    short_desc: 'The OS began a clean shutdown and logged the exact time.',
    description: 'Event ID 13 from Kernel-General is written at the beginning of every clean, intentional shutdown or restart. It is the counterpart to Event 12. In incident analysis its absence is the key signal — if you see Event 12 (boot) without a preceding Event 13 (clean shutdown), the previous session ended unexpectedly. That gap, combined with Event 41 or 6008, confirms a crash, power loss, or hard reset.',
    why_it_happens: 'The Windows kernel writes Event 13 during the shutdown phase after user and service shutdown has completed. It is one of the last events written before the OS halts. If the machine crashes or loses power before reaching this phase, Event 13 is never written.',
    what_good_looks_like: 'Every Event 12 (boot) should be preceded by an Event 13 (clean shutdown) from the previous boot. Exception: the very first boot after OS installation.',
    causes: [
      'Normal user-initiated shutdown or restart',
      'Shutdown via update installation',
      'Remote shutdown command',
      'System entering hibernation (S4 sleep)'
    ],
    steps: [
      'Find Event 12 entries and check for a preceding Event 13 — gap = unexpected shutdown',
      'If no Event 13 before a boot: check Event 41 (crash/power loss) or Event 6008 (unexpected shutdown)',
      'Correlate shutdown time with Event 1074 to see what initiated the shutdown',
      'Repeated missing Event 13 entries = recurring stability problem requiring investigation'
    ],
    symptoms: [
      'when did the computer shut down',
      'last shutdown time',
      'clean shutdown',
      'unexpected reboot history',
      'os shutdown time'
    ],
    tags: ['shutdown', 'kernel', 'timeline', 'uptime', 'clean-shutdown'],
    powershell: `# Shutdown and Boot History (last 30 days)
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-General'
    Id           = @(12, 13)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 12) {'STARTED'} else {'SHUTDOWN'} }} |
    Sort-Object TimeCreated | Format-Table -AutoSize`,
    related_ids: [12, 41, 1074, 6008],
    ms_docs: null
  },

  {
    id: 18,
    source: 'Microsoft-Windows-Kernel-General',
    channel: 'System',
    severity: 'Information',
    skill_level: 'Beginner',
    title: 'System Time Changed',
    short_desc: 'The system clock was adjusted — either by NTP sync, a user, or a domain time policy.',
    description: 'Event ID 18 from Kernel-General logs whenever the system clock is changed. The event records the old time, new time, and the process that made the change. In normal environments this happens regularly via W32tm (Windows Time Service) syncing to a domain controller or NTP server. It becomes significant in incident analysis if: the time change is large (hours or days), the process making the change is not W32tm or a trusted service, or it occurs immediately before suspicious activity (attackers sometimes shift clocks to corrupt log correlation).',
    why_it_happens: 'The Windows Time Service (W32tm) adjusts the clock periodically to stay in sync with its configured time source. Domain-joined machines sync to a domain controller; standalone machines use time.windows.com. Large jumps happen when the machine was offline for a long time, the CMOS battery died, or someone manually changed the time.',
    what_good_looks_like: 'Small adjustments (milliseconds to seconds) by the SYSTEM process or W32tm are normal. Investigate: large adjustments (minutes or more), adjustments by a non-system process, repeated adjustments in a short period, or time changes that correlate with other suspicious events.',
    causes: [
      'NTP or domain time sync (normal)',
      'Manual clock change by a user or admin',
      'CMOS/RTC battery failure causing clock drift',
      'VM host adjusting guest clock',
      'Time zone change',
      'System recovering from long offline period'
    ],
    steps: [
      'Check the ProcessName field — W32tm.exe or SYSTEM is expected',
      'Check the magnitude of the change — small ms adjustments are normal, large jumps are not',
      'If large jump: check CMOS battery health and NTP sync status (w32tm /query /status)',
      'If made by unexpected process: investigate that process — potential indicator of tampering',
      'Run: w32tm /query /status to check current sync health'
    ],
    symptoms: [
      'clock changed',
      'system time wrong',
      'time jumped',
      'timestamps are off',
      'ntp sync problem',
      'clock drift'
    ],
    tags: ['time', 'clock', 'ntp', 'sync', 'kernel', 'timeline'],
    powershell: `# System Time Change History
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-General'
    Id           = 18
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        OldTime     = ($data | Where-Object Name -eq 'OldTime').'#text'
        NewTime     = ($data | Where-Object Name -eq 'NewTime').'#text'
        Process     = ($data | Where-Object Name -eq 'ProcessName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [12, 13],
    ms_docs: null
  },

  {
    id: 20,
    source: 'Microsoft-Windows-WindowsUpdateClient',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Beginner',
    title: 'Windows Update Installation Failure',
    short_desc: 'A Windows Update failed to install — the update and error code are recorded.',
    description: 'Event ID 20 from WindowsUpdateClient is logged when an update download or installation fails. It records the update title, KB number, and the error code. This is the primary event for diagnosing Windows Update failures. The error code is the critical field — it maps to a specific failure reason (network, disk space, component corruption, conflicting software, etc.). Repeated failures of the same KB usually indicate an underlying system health problem rather than a transient network issue.',
    why_it_happens: 'Windows Update failures occur for many reasons: network interruption during download, insufficient disk space (Windows needs 10–20 GB free), corruption in the Windows Update component store (DISM /ScanHealth), driver conflicts, third-party security software blocking the update, or the update being genuinely incompatible with installed hardware/software.',
    what_good_looks_like: 'Occasional single failures followed by a successful install on retry are normal. Investigate: the same KB failing repeatedly across multiple attempts, multiple different KBs all failing, failures with component store corruption errors (0x800F0***), failures in the last 30 days with no successful updates.',
    common_mistakes: [
      'Not checking the error code — "update failed" tells you nothing, the hex code tells you everything',
      'Running Windows Update troubleshooter first without checking disk space (most common root cause)',
      'Not checking that Windows Update services are running (wuauserv, bits, cryptsvc, msiserver)',
      'Forgetting that some updates require a reboot before the next update can install'
    ],
    causes: [
      'Insufficient free disk space (need 10–20 GB)',
      'Windows Update component store corruption',
      'Windows Update services stopped or disabled',
      'Network connectivity issue during download',
      'Third-party security software blocking installation',
      'Conflicting software or driver',
      'Pending reboot blocking further updates'
    ],
    steps: [
      'Note the error code from Event 20 — search it with the KB number for specific guidance',
      'Check disk space: Get-PSDrive C | Select-Object Used, Free',
      'Verify Update services running: Get-Service wuauserv, bits, cryptsvc | Select-Object Name, Status',
      'Run DISM to check component health: DISM /Online /Cleanup-Image /CheckHealth',
      'If corruption found: DISM /Online /Cleanup-Image /RestoreHealth',
      'Then run: sfc /scannow',
      'Check Event 19 (successful download) — if missing, download itself is failing (network/BITS)',
      'Check free space in C:\\Windows\\SoftwareDistribution — clear with: net stop wuauserv && rd /s /q C:\\Windows\\SoftwareDistribution && net start wuauserv'
    ],
    symptoms: [
      'windows update failed',
      'update wont install',
      'update error',
      'kb failed to install',
      'windows update stuck',
      'updates keep failing',
      'cumulative update failed',
      'feature update failed'
    ],
    tags: ['windows-update', 'patch', 'installation', 'error', 'maintenance'],
    powershell: `# Windows Update Failure History
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
    Id           = @(19, 20, 21, 43)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $type = switch ($_.Id) {
        19 { 'DOWNLOAD_OK'  }
        20 { 'INSTALL_FAIL' }
        21 { 'INSTALL_FAIL' }
        43 { 'DOWNLOAD_FAIL'}
    }
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Type    = $type
        Message = $_.Message.Substring(0, [Math]::Min(120, $_.Message.Length))
    }
} | Sort-Object Time -Descending | Format-Table -AutoSize`,
    related_ids: [19, 1074],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-error-reference'
  },

  {
    id: 5,
    source: 'Microsoft-Windows-Kernel-Boot',
    channel: 'System',
    severity: 'Information',
    skill_level: 'Intermediate',
    title: 'Boot Configuration Data Loaded',
    short_desc: 'The Boot Configuration Data (BCD) store was read and applied during startup.',
    description: 'Event ID 5 from Kernel-Boot is logged during the early boot phase when Windows reads its Boot Configuration Data (BCD) store. The event records which boot entry was selected and the boot type (normal, safe mode, WinRE, etc.). It is informational in a normal boot, but useful for diagnosing repeated failures to boot into normal mode, unexpected safe mode boots, or BCD corruption. Check the BootType field: 1 = normal boot, 2 = safe mode, 3 = safe mode with networking.',
    why_it_happens: 'The Windows Boot Manager reads the BCD store on every boot to determine which OS to load and in what mode. Event 5 is written once per boot as confirmation that this step completed. If the BCD is corrupt or missing, the boot process fails before this event is written.',
    what_good_looks_like: 'BootType 1 (normal) on every boot. Investigate: repeated BootType 2/3 (safe mode) without admin action, multiple Event 5 entries for a single boot cycle (can indicate boot repair attempts), or absence of Event 5 before a successful Event 12 (rare, possible if BCD events are filtered).',
    causes: [
      'Normal system boot (BootType 1)',
      'Safe mode boot (BootType 2/3) — user or automatic recovery',
      'Windows Recovery Environment (BootType 4)',
      'Automatic Repair triggered by repeated boot failures',
      'Admin booting into diagnostic mode'
    ],
    steps: [
      'Check BootType field — normal is 1, safe mode is 2 or 3',
      'If repeated safe mode boots: check what triggered them (user, automatic repair, or policy)',
      'If BCD issues suspected: bcdedit /enum all (run as admin)',
      'To repair BCD: boot from Windows media → Repair your computer → Startup Repair',
      'Check Event 12 and 41 for correlation with unexpected boot modes'
    ],
    symptoms: [
      'booted into safe mode',
      'unexpected safe mode',
      'boot configuration',
      'bcd',
      'startup mode',
      'computer keeps booting to recovery'
    ],
    tags: ['boot', 'bcd', 'safe-mode', 'startup', 'kernel-boot'],
    powershell: `# Recent Boot Type History
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Boot'
    Id           = 5
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $type = ($data | Where-Object Name -eq 'BootType').'#text'
    $desc = switch ($type) {
        '1' { 'Normal' }
        '2' { 'Safe Mode' }
        '3' { 'Safe Mode with Networking' }
        '4' { 'WinRE / Recovery' }
        default { "Type $type" }
    }
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        BootType    = $type
        Description = $desc
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [12, 41, 6008],
    ms_docs: null
  },

  {
    id: 27,
    source: 'Microsoft-Windows-Kernel-Boot',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Boot Environment Error',
    short_desc: 'The boot environment encountered a problem setting or reading a boot configuration value.',
    description: 'Event ID 27 from Kernel-Boot is generated when the boot environment fails to properly apply a configuration value from the BCD store, or when a requested boot option cannot be set. This often appears after failed Windows Update installs, interrupted in-place upgrades, or BCD corruption. It can also appear from the disk driver context when a device was removed without a proper dismount ("surprise removal"). Check the Provider field in the raw event — Kernel-Boot indicates a boot configuration issue; the disk driver indicates a storage device removal problem.',
    why_it_happens: 'Boot configuration errors arise when the BCD store has an inconsistency, a pending boot operation could not complete (e.g., an update that required a specific boot mode failed), or the boot hardware abstraction layer encountered unexpected firmware behaviour. Disk-context Event 27 occurs when Windows detects that a device was physically removed while still mounted — common with hot-swap bays, USB drives with running I/O, or iSCSI targets that dropped.',
    what_good_looks_like: 'Absence is normal. Any occurrence warrants investigation. A single isolated Event 27 after a known upgrade attempt is low priority. Repeated occurrences or Event 27 combined with disk I/O errors (51, 129) is higher priority.',
    causes: [
      'Failed or interrupted Windows Update requiring a boot-time operation',
      'BCD store corruption or inconsistency',
      'Storage device removed without safe ejection (Kernel-Boot or disk context)',
      'Firmware/UEFI reporting an unexpected boot configuration state',
      'iSCSI or network storage target disconnect'
    ],
    steps: [
      'Check the Provider/Source field — determines if this is a boot config or disk removal issue',
      'For boot config: run bcdedit /enum all and look for inconsistencies',
      'Run startup repair if the machine had boot problems: boot from Windows media',
      'For disk removal: identify which device was removed and check Event 51 or 129 around the same time',
      'Check Windows Update history for failed installs immediately before Event 27'
    ],
    symptoms: [
      'boot error',
      'boot configuration problem',
      'drive surprise removal',
      'device disconnected unexpectedly',
      'usb drive error on removal',
      'iscsi disconnected'
    ],
    tags: ['boot', 'bcd', 'disk', 'removal', 'kernel-boot', 'storage'],
    powershell: `# Boot Environment Errors
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 27
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, ProviderName, LevelDisplayName, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [5, 12, 41, 51, 129],
    ms_docs: null
  },

  {
    id: 238,
    source: 'Microsoft-Windows-Kernel-Processor-Power',
    channel: 'System',
    severity: 'Information',
    skill_level: 'Advanced',
    title: 'Processor Power Capability Change',
    short_desc: 'A processor reported a change in its available power or performance states.',
    description: 'Event ID 238 from Kernel-Processor-Power is logged when a processor reports a change in its power management capabilities or performance state enumeration. This typically occurs during boot, after a driver update, or when firmware/UEFI adjusts CPU power policy. On its own it is informational. It becomes relevant in incident investigations involving unexpected CPU throttling, performance degradation, or thermal events — particularly when combined with Event 37 (CPU speed limited by firmware) or high-temperature readings.',
    why_it_happens: 'Modern processors expose their available performance and power states (P-states, C-states) to the OS via ACPI. When the set of available states changes — due to thermal limits, firmware intervention, driver update, or hardware capability reporting — Windows logs Event 238 to record the new state of affairs. In some cases, the CPU reports fewer performance states than expected because the firmware is limiting it due to a thermal condition.',
    what_good_looks_like: 'Appearing once at boot for each logical processor is normal. Investigate: Event 238 occurring outside of boot, in conjunction with performance complaints, or combined with thermal events and Event 37.',
    causes: [
      'Normal processor power state enumeration at boot',
      'CPU driver or firmware update changing available P-states',
      'Thermal throttling causing firmware to restrict performance states',
      'Virtualisation host changing CPU capability exposure',
      'BIOS/UEFI setting change affecting power management'
    ],
    steps: [
      'Check if Event 238 appears only at boot — if so, likely informational',
      'If mid-operation: check for thermal events and CPU temperature (Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root/wmi)',
      'Check Event 37 (Kernel-Processor-Power) for CPU speed limiting',
      'Check BIOS/UEFI for power management settings — "Performance" mode vs "Power Saver"',
      'Ensure CPU drivers and chipset drivers are current'
    ],
    symptoms: [
      'cpu throttling',
      'processor performance changed',
      'cpu running slow',
      'processor power state',
      'cpu frequency reduced'
    ],
    tags: ['cpu', 'power', 'performance', 'throttling', 'processor', 'kernel'],
    powershell: `# CPU Power Events
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
    Id           = @(37, 238, 247)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [37, 247, 41],
    ms_docs: null
  },

  {
    id: 247,
    source: 'Microsoft-Windows-Kernel-Processor-Power',
    channel: 'System',
    severity: 'Information',
    skill_level: 'Advanced',
    title: 'Processor Performance State Transition',
    short_desc: 'A processor transitioned to a different performance (P-state) level.',
    description: 'Event ID 247 from Kernel-Processor-Power records a significant processor performance state (P-state) transition — typically a switch to a lower performance tier due to power policy, thermal management, or battery/power plan constraints. Like Event 238, it is informational in isolation but important when investigating CPU performance degradation. The event records the processor index, the target performance percentage, and the reason for the transition. Repeated 247 events showing reductions to low percentages indicate sustained throttling.',
    why_it_happens: 'Windows power management continuously adjusts CPU performance states to balance power consumption against workload demand. Event 247 is written when this adjustment is significant enough to log — particularly when performance is constrained rather than just scaled up. The trigger can be a temperature threshold being reached, a power plan switch (Balanced → Power Saver), a UPS switching to battery, or firmware-level limits being applied.',
    what_good_looks_like: 'Occasional 247 entries with performance levels that return to 100% are normal under balanced power plans. Investigate: consistent 247 entries showing low performance percentages during business hours, 247 paired with thermal events, or 247 following a UPS or power supply event.',
    causes: [
      'Active power plan throttling CPU (Balanced or Power Saver mode)',
      'Thermal throttling — CPU too hot',
      'UPS switched to battery — system reducing power draw',
      'Firmware-level power limits (TDP limits)',
      'Virtualisation host restricting CPU performance'
    ],
    steps: [
      'Check the performance percentage in the event — sustained below 50% is a problem',
      'Check CPU temperatures during the throttling period',
      'Review active power plan: powercfg /getactivescheme',
      'Change to High Performance if throttling is unwanted: powercfg /setactive SCHEME_MIN',
      'Check Event 37 for firmware-level speed limits',
      'If on a laptop/UPS: check power source at time of events'
    ],
    symptoms: [
      'cpu running slow',
      'processor throttled',
      'performance degraded',
      'computer feels sluggish',
      'cpu percentage low',
      'performance state change'
    ],
    tags: ['cpu', 'power', 'throttling', 'performance', 'p-state', 'thermal'],
    powershell: `# Processor Performance State Events
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
    Id           = @(37, 238, 247)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        EventId     = $_.Id
        Processor   = ($data | Where-Object Name -eq 'ProcessorNumber').'#text'
        PerfPercent = ($data | Where-Object Name -eq 'TargetProcessorThrottle').'#text'
        Message     = $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length))
    }
} | Sort-Object Time -Descending | Format-Table -AutoSize`,
    related_ids: [238, 37, 41],
    ms_docs: null
  }
];
