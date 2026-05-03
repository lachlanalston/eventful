export const vssEvents = [
  {
    id: 8193,
    source: 'VSS',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'VSS: Unexpected Error (General VSS Failure)',
    short_desc: 'The Volume Shadow Copy Service encountered an unexpected error — the most common VSS error, usually blocking backups.',
    description: 'Event 8193 from the VSS source is the most frequently encountered VSS error. It indicates the Volume Shadow Copy Service hit an unexpected error during an operation — typically while a backup application (Windows Server Backup, Veeam, Backup Exec, Azure Backup, etc.) was trying to create a shadow copy. The error code (hr = 0x...) in the message identifies the specific failure. When a backup or shadow copy operation fails, this event almost always appears in the Application log. The hr = 0x80070005 code means Access Denied; 0x8004230f means the shadow copy provider is not registered.',
    why_it_happens: 'VSS acts as a coordinator between the requesting application (backup software), the VSS writers (applications like SQL, Exchange, AD that freeze their data), and the VSS provider (the component that creates the actual snapshot). Any failure in this chain produces Event 8193. Common triggers: VSS writers in a failed state, VSS provider not registered, COM+ application catalog corruption, or the background copy service having insufficient permissions.',
    what_good_looks_like: 'No Event 8193. Backups completing without errors. VSS errors are not normal and indicate something needs attention — they will cause backup failures every time until resolved.',
    common_mistakes: [
      'Restarting the VSS service without resetting failed VSS writers — the next backup will fail again',
      'Not checking the hr error code, which is the most important field in the message',
      'Ignoring VSS errors because "the backup seemed to finish" — some backups report success even with VSS errors, resulting in inconsistent restore points',
      'Not checking if VSS writers are in a failed state before and after a backup attempt'
    ],
    causes: [
      'VSS writer in a failed/error state (run vssadmin list writers to check)',
      'COM+ application catalog corrupt, preventing VSS component registration',
      'VSS provider not registered in the system (hr = 0x8004230f)',
      'Insufficient disk space on the shadow copy storage volume',
      'Access denied to VSS service account (hr = 0x80070005)',
      'Antivirus or backup agent interfering with the VSS snapshot process',
      'Pending Windows updates or a required reboot blocking VSS operations'
    ],
    steps: [
      'Run vssadmin list writers — check for writers in a Retryable Error or No Stable Data state',
      'Check the hr error code in the Event 8193 message for the specific failure reason',
      'Restart failed writers: net stop <servicename> && net start <servicename> for each failed writer service',
      'Check VSS provider: vssadmin list providers — verify Microsoft Software Shadow Copy Provider is listed',
      'Check COM+ application catalog: run services.msc → COM+ System Application → restart it',
      'Run the PowerShell snippet below to reset all common VSS-related services',
      'Check Application log for Event 8194 and 8196 immediately after 8193 — they often appear together'
    ],
    symptoms: [
      'backup failed vss error',
      'volume shadow copy error',
      'vss error',
      'shadow copy failed',
      'backup failed unexpected error',
      'vss unexpected error',
      'veeam backup vss error',
      'windows backup failed vss',
      'azure backup vss error',
      'backup exec vss failure',
      'shadow copy service error',
      'backup failing consistently',
      'vss writer error backup',
      'cannot create shadow copy'
    ],
    tags: ['vss', 'shadow-copy', 'backup', 'error', 'writers', 'application'],
    powershell: `# VSS health check and writer reset
# Eventful

# List all VSS writers and their current state
vssadmin list writers

# List VSS providers
vssadmin list providers

# Check for VSS errors in Application log — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'VSS'
    Id           = @(8193, 8194, 8196, 8224)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Reset VSS-related services (run as admin — stop first, then start)
# $vssServices = @('VSS', 'swprv', 'sdrsvc', 'vds', 'COMSysApp')
# $vssServices | ForEach-Object { net stop $_ /y }
# Start-Sleep 5
# $vssServices | ForEach-Object { net start $_ }`,
    related_ids: [8194, 8196, 8224],
    ms_docs: null
  },

  {
    id: 8194,
    source: 'VSS',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'VSS: Writer Callback Interface Error',
    short_desc: 'A VSS writer failed to respond during the snapshot process — the backup or shadow copy cannot proceed.',
    description: 'Event 8194 from VSS means the Volume Shadow Copy Service tried to query the IVssWriterCallback interface for a VSS writer and got an unexpected error. VSS writers are components in applications like SQL Server, Exchange, Active Directory, and Hyper-V that guarantee data consistency during snapshots — they "freeze" writes temporarily while the shadow copy is taken. If a writer fails during this handshake, VSS cannot safely snapshot the data and the backup fails. Event 8194 almost always appears alongside Event 8193.',
    why_it_happens: 'VSS writer communication uses COM/RPC channels. If the writer\'s host service has crashed, if RPC is blocked between components, or if the writer is in a failed state from a previous incomplete backup, the callback fails. Exchange, SQL, and AD writers are the most frequent sources of this error — they are complex writers that can enter a failed state if the host application is under stress or has recently crashed.',
    what_good_looks_like: 'No Event 8194. This error should never appear in a healthy backup environment.',
    common_mistakes: [
      'Not running vssadmin list writers to identify which writer is in a failed state',
      'Restarting VSS without restarting the writer\'s parent service — the writer state is tied to its service',
      'Not correlating Event 8194 with the backup software log — the backup tool usually names the problematic writer'
    ],
    causes: [
      'VSS writer in a failed or unstable state from a prior interrupted backup',
      'Host application service (SQL Server, Exchange, IIS, etc.) crashed or restarting',
      'RPC communication failure between VSS coordinator and writer',
      'Writer registered but its host process has exited',
      'System under heavy I/O load preventing the writer from responding in time'
    ],
    steps: [
      'Run vssadmin list writers — identify writers in "Retryable Error" or "No Stable Data" state',
      'Note the writer name — correlate with its host service (e.g. "SqlServerWriter" → SQL Server service)',
      'Restart the host service of the failed writer: Restart-Service <ServiceName>',
      'After restarting: re-run vssadmin list writers — all writers should show "Stable"',
      'Retry the backup — if 8194 recurs, check the backup software log for which writer is failing',
      'If all writers are stable and errors persist: run the VSS service reset script from the 8193 steps'
    ],
    symptoms: [
      'vss writer callback failed',
      'vss writer error',
      'backup failed writer error',
      'sql vss writer error',
      'exchange vss writer failed',
      'shadow copy writer not responding',
      'vss writer in failed state',
      'backup inconsistent vss writer',
      'vss writer callback error',
      'shadow copy failed writer'
    ],
    tags: ['vss', 'shadow-copy', 'backup', 'error', 'writers', 'sql', 'exchange'],
    powershell: `# VSS writer state check
# Eventful

# List all writers and their state
vssadmin list writers

# Get VSS errors from Application log — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'VSS'
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.LevelDisplayName -eq 'Error' } |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [8193, 8196, 8224],
    ms_docs: null
  },

  {
    id: 8196,
    source: 'VSS',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'VSS: Failed to Resolve Service Account',
    short_desc: 'VSS could not resolve an account name required to run a VSS writer — typically a permissions or service account problem.',
    description: 'Event 8196 from VSS means the Volume Shadow Copy Service failed to resolve (look up) an account name during its operation. The account named in the error message is a service account that VSS or one of its writers needs to function — typically the account under which a VSS writer service runs. This is most commonly seen after: a service account password change where the service was not updated, after a domain rename, or after migrating a server to a new domain where service account SIDs are no longer valid.',
    why_it_happens: 'VSS writers run as specific service accounts (LocalSystem, NetworkService, or a custom domain account). During VSS initialization, it attempts to look up and validate these accounts. If the account is deleted, renamed, disabled, locked out, or the domain suffix changed, the lookup fails and Event 8196 is logged.',
    what_good_looks_like: 'No Event 8196. This error is a clear indicator of a service account or permissions problem that needs direct investigation.',
    common_mistakes: [
      'Not checking whether the service account named in the event actually exists and is enabled in AD',
      'Forgetting that scheduled password changes can affect the VSS writer service if the password was changed in AD but not updated in the service properties',
      'Missing that this error often appears after a domain or server migration'
    ],
    causes: [
      'Service account for a VSS writer was deleted or disabled in Active Directory',
      'Service account password changed in AD but not updated in Services (services.msc)',
      'Service account locked out due to failed authentication attempts',
      'Server migrated to a new domain — old domain SIDs no longer valid',
      'Domain rename or restructure invalidating account references'
    ],
    steps: [
      'Note the account name in the Event 8196 message',
      'Check if the account exists and is enabled in AD: Get-ADUser <accountname> -Properties Enabled, LockedOut',
      'Check if the account is locked out: Get-ADUser <accountname> -Properties LockedOut',
      'Open services.msc → find the VSS writer service → check the "Log On As" account matches and the password is current',
      'If account was deleted: recreate it or reassign the service to run under a valid account',
      'After correcting: restart the VSS writer service and retest the backup'
    ],
    symptoms: [
      'vss account error',
      'vss service account failed',
      'vss permissions error',
      'shadow copy account resolution failed',
      'vss failed to resolve account',
      'backup vss account error',
      'vss writer account problem',
      'vss error after password change',
      'vss error after migration',
      'shadow copy permissions denied'
    ],
    tags: ['vss', 'shadow-copy', 'backup', 'error', 'account', 'permissions', 'service-account'],
    powershell: `# VSS service account and writer check
# Eventful

# List all VSS writers and their state
vssadmin list writers

# Check VSS errors related to accounts
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'VSS'
    Id           = @(8196, 8193)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-List

# List service logon accounts for VSS-related services
Get-WmiObject Win32_Service |
    Where-Object { $_.Name -in @('VSS','swprv','SQLWriter','MSExchangeIS') } |
    Select-Object Name, State, StartName`,
    related_ids: [8193, 8194, 8224],
    ms_docs: null
  },

  {
    id: 8224,
    source: 'VSS',
    channel: 'Application',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'VSS: Service Shutting Down Due to Idle Timeout',
    short_desc: 'The VSS service stopped because it has been idle — this is normal, but repeated entries around backup time indicate VSS is not staying active during a backup.',
    description: 'Event 8224 from VSS means the Volume Shadow Copy Service shut itself down due to inactivity. VSS runs on demand — it starts when a snapshot is requested and shuts down after an idle period to conserve resources. Event 8224 on its own is completely normal and requires no action. However, when this event appears during a backup window or immediately after a failed backup, it can indicate that the backup software triggered VSS, VSS started, but then the backup software failed to properly request the snapshot before the idle timeout expired — leaving a failed backup with no shadow copy created.',
    why_it_happens: 'VSS is implemented as a demand-start service. After completing its work, or when no snapshot request has been received within the idle timeout period, it shuts down cleanly and logs Event 8224.',
    what_good_looks_like: 'Event 8224 appearing at random intervals with no correlation to backup failure = normal. Event 8224 appearing immediately after a backup attempt with backup failure events = investigate the backup software\'s VSS coordination.',
    common_mistakes: [
      'Treating every Event 8224 as an error — it is informational and normal in most contexts',
      'Not correlating the timestamp with backup job times — 8224 during a backup window is the suspicious pattern'
    ],
    causes: [
      'Normal idle timeout — VSS shuts down when not in use',
      'Backup software failed to initiate a snapshot request fast enough after starting the VSS service',
      'Backup job cancelled or timed out before VSS completed the snapshot'
    ],
    steps: [
      'Check the timestamp — if it aligns with a backup window, cross-reference the backup software log',
      'If occurring during backup failures: check whether the backup software has a VSS timeout setting that needs increasing',
      'If occurring at random (no backup correlation): no action needed — this is normal VSS behavior',
      'Check backup software logs for "VSS timeout" or "failed to request snapshot" messages near the 8224 timestamp'
    ],
    symptoms: [
      'vss shutting down',
      'volume shadow copy stopped',
      'vss idle timeout',
      'vss service stopped during backup',
      'backup vss timeout',
      'shadow copy service shut down',
      'vss stopped unexpectedly during backup'
    ],
    tags: ['vss', 'shadow-copy', 'backup', 'info', 'idle', 'timeout'],
    powershell: `# VSS service state and idle events
# Eventful

# Current VSS service state
Get-Service VSS | Select-Object Name, Status, StartType

# VSS shutdown events — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'VSS'
    Id           = 8224
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [8193, 8194, 8196],
    ms_docs: null
  }
];
