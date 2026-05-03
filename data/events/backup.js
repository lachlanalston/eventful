export const backupEvents = [
  {
    id: 4,
    source: 'Microsoft-Windows-Backup',
    channel: 'Microsoft-Windows-Backup',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Windows Server Backup Started',
    short_desc: 'Windows Server Backup has started a backup job.',
    description: 'Event 4 from Microsoft-Windows-Backup is logged when Windows Server Backup starts a backup operation. This is used for auditing whether backups actually ran, and for correlating with completion (Event 14) or failure (Event 5) events to determine backup duration and outcome. Monitoring for the absence of Event 4 on expected backup days detects silent backup job failures before the absence of a backup is discovered during a recovery attempt.',
    why_it_happens: 'Logged whenever wbengine.exe (Windows Backup Engine) initiates a backup session. Triggered by scheduled backup tasks, manual "Backup now" from the GUI, or wbadmin start backup command.',
    what_good_looks_like: 'Event 4 appearing on schedule (daily, etc.) followed by Event 14 (backup completed successfully). Backup duration consistent with data volume. No gap in backup start events.',
    common_mistakes: [
      'Not monitoring for the absence of Event 4 — if the backup job itself fails to start, no events are generated',
      'Not checking the backup destination free space — backups can fail silently if the destination fills up'
    ],
    causes: [
      'Scheduled backup task running on time',
      'Manual backup initiated by administrator',
      'Automated backup script running wbadmin'
    ],
    steps: [
      'Verify backup ran: check for Event 4 today/since last expected run',
      'Check for Event 14 (completed) or Event 5 (failed) after Event 4',
      'Verify backup destination has free space: Get-PSDrive',
      'Check Windows Server Backup console for backup history'
    ],
    symptoms: [
      'backup started',
      'Windows backup running',
      'backup job began',
      'server backup initiated',
      'wbadmin backup started',
      'Windows Server Backup audit'
    ],
    tags: ['backup', 'windows-backup', 'disaster-recovery', 'wbadmin'],
    powershell: `# Windows Server Backup History
# Eventful

# Backup start, complete, and failure events
Get-WinEvent -LogName 'Microsoft-Windows-Backup' -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(4, 14, 5) -and $_.TimeCreated -gt (Get-Date).AddDays(-30) } |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ switch($_.Id){ 4{'STARTED'} 14{'COMPLETED'} 5{'FAILED'} } }},
        Message |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# Backup status via wbadmin
wbadmin get status`,
    related_ids: [14, 5, 517],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin'
  },

  {
    id: 14,
    source: 'Microsoft-Windows-Backup',
    channel: 'Microsoft-Windows-Backup',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Windows Server Backup Completed Successfully',
    short_desc: 'A backup job completed without errors — data is protected.',
    description: 'Event 14 from Microsoft-Windows-Backup confirms a successful backup completion. The event includes the backup destination, the types of data backed up (volumes, system state), and the completion time. This is the event that should appear after every backup job. The absence of Event 14 after Event 4 (backup started) means the backup failed, was interrupted, or is still running. For disaster recovery readiness, confirming regular Event 14 generation is essential.',
    why_it_happens: 'Generated when the Windows Backup engine successfully completes writing all backup data and closes the backup set on the destination.',
    what_good_looks_like: 'Event 14 after every Event 4 (backup started). Consistent time gap between 4 and 14. Backup destination shows valid backup sets.',
    common_mistakes: [
      'Not regularly testing backup restore — a backup that generates Event 14 but has corrupt data is useless',
      'Not monitoring backup duration — a backup taking 3× longer than usual may indicate destination performance issues'
    ],
    causes: [
      'Scheduled or manual backup completed without errors',
      'All selected volumes and system state backed up successfully'
    ],
    steps: [
      'Verify restore point is accessible: wbadmin get versions',
      'Periodically test a file restore: wbadmin start recovery',
      'Check backup destination free space to ensure future backups can run'
    ],
    symptoms: [
      'backup completed',
      'backup successful',
      'server backup done',
      'backup job finished',
      'Windows backup completed',
      'backup audit success'
    ],
    tags: ['backup', 'windows-backup', 'disaster-recovery', 'success'],
    powershell: `# Verify Backup Completion
# Eventful

# Recent backup completions
Get-WinEvent -LogName 'Microsoft-Windows-Backup' -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 14 -and $_.TimeCreated -gt (Get-Date).AddDays(-30) } |
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# Available recovery versions
wbadmin get versions`,
    related_ids: [4, 5, 517],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin'
  },

  {
    id: 5,
    source: 'Microsoft-Windows-Backup',
    channel: 'Microsoft-Windows-Backup',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Windows Server Backup Failed',
    short_desc: 'A backup job failed — the latest backup point may be out of date or missing.',
    description: 'Event 5 from Microsoft-Windows-Backup indicates a backup job failed. This is a critical event — if unnoticed, the last valid backup may be days, weeks, or months old when a recovery is needed. The event message includes an error code and description identifying the cause of failure. Common causes include full backup destination, VSS errors preventing snapshot creation, and destination drive offline.',
    why_it_happens: 'Backup failures occur when: the backup destination volume has insufficient free space, a VSS writer fails preventing consistent snapshot of a volume, the destination drive goes offline during backup, the service account lacks permissions on the destination, or an antivirus locks files that need to be included in the backup.',
    what_good_looks_like: 'No Event 5 events. All backup jobs produce Event 14 (success). Backup destination has at least 20% free space. VSS writers healthy.',
    common_mistakes: [
      'Not monitoring backup failures until a restore is needed',
      'Not alerting immediately on Event 5 — a missed backup needs same-day attention, not next-week attention',
      'Not checking VSS writer health which is frequently the cause of backup failures'
    ],
    causes: [
      'Backup destination volume full',
      'VSS snapshot failure — application writer not responding',
      'Backup destination drive offline or disconnected',
      'Network destination unreachable at backup time',
      'Insufficient permissions on backup destination',
      'Antivirus or open file locking preventing backup of in-use files'
    ],
    steps: [
      'Check the error code in Event 5 message',
      'Check backup destination free space: Get-PSDrive',
      'Check VSS writers: vssadmin list writers — look for State: [8] Failed',
      'Restart VSS writers if failed: restart dependent services',
      'Check backup destination connectivity: Test-Path "<backupDestination>"',
      'Run backup manually: wbadmin start backup -backupTarget:<destination> -include:<volumes> -quiet',
      'Review VSS event log: Applications and Services Logs → Microsoft → Windows → VSS'
    ],
    symptoms: [
      'backup failed',
      'server backup error',
      'Windows backup not working',
      'backup job failing',
      'no backup completed',
      'backup destination full',
      'VSS backup error',
      'backup keeps failing',
      'last backup old'
    ],
    tags: ['backup', 'windows-backup', 'failure', 'vss', 'disaster-recovery'],
    powershell: `# Backup Failure Investigation
# Eventful

# Backup failures
Get-WinEvent -LogName 'Microsoft-Windows-Backup' -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 5 -and $_.TimeCreated -gt (Get-Date).AddDays(-30) } |
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending | Format-List

# VSS writer health (common backup failure cause)
vssadmin list writers

# Check backup destination free space
Get-PSDrive | Where-Object { $_.Provider -match 'FileSystem' } |
    Select-Object Name, @{N='FreeGB'; E={[math]::Round($_.Free/1GB,1)}},
        @{N='UsedGB'; E={[math]::Round($_.Used/1GB,1)}} | Format-Table`,
    related_ids: [4, 14, 8193, 8194],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin'
  }
];
