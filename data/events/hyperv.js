export const hypervEvents = [
  {
    id: 18590,
    source: 'Microsoft-Windows-Hyper-V-VMMS',
    channel: 'Microsoft-Windows-Hyper-V-VMMS/Admin',
    severity: 'Critical',
    skill_level: 'Intermediate',
    title: 'Hyper-V: VM Paused Due to Storage I/O Issue',
    short_desc: 'A virtual machine was automatically paused because Hyper-V detected a storage problem — the VM is frozen until storage is restored.',
    description: 'Event 18590 means Hyper-V paused a virtual machine because it detected a critical storage I/O error on the volume hosting the VM\'s VHD/VHDX files. Hyper-V pauses the VM (rather than crashing it) to protect data integrity — a paused VM holds all its state in memory and will resume cleanly once storage is restored. Users see the VM as completely unresponsive. The root cause is almost always: the storage volume is full, the LUN is offline, the SMB share hosting the VHD is unreachable, or a storage controller fault.',
    why_it_happens: 'Hyper-V monitors every write to the VHD/VHDX files. If a write fails and cannot be completed — because the disk is full, the LUN went offline, the network path to an SMB share dropped, or a RAID/SAN array reported an error — Hyper-V pauses the VM to prevent a split-brain state where the VM thinks data was written but it was not.',
    what_good_looks_like: 'No Event 18590. VMs running continuously with no pauses. Monitor free space on VHD storage volumes and LUN/share health proactively.',
    common_mistakes: [
      'Trying to resume the VM without first fixing the storage issue — it will pause again immediately',
      'Not checking free space on the host volume hosting the VHD files',
      'Forgetting that SMB share storage (VHDs on file servers) can lose connectivity mid-operation, causing this event',
      'Not checking the Hyper-V VMMS/Admin log for the specific storage path mentioned in the event message'
    ],
    causes: [
      'Host storage volume full — VHD file cannot expand (especially dynamic VHDs)',
      'LUN or disk offline on the storage array',
      'SMB/CIFS share hosting VHD files became unreachable (network issue)',
      'Storage controller hardware failure',
      'iSCSI target disconnected',
      'CSV (Cluster Shared Volume) failure in a clustered environment'
    ],
    steps: [
      'Do NOT try to resume the VM yet — fix storage first',
      'Check free space on the host volume: Get-PSDrive | Where-Object { $_.Free -lt 5GB }',
      'Check if the storage volume or LUN is online: Get-Disk | Select-Object Number, OperationalStatus, HealthStatus',
      'Check if SMB storage paths are accessible: Test-Path \\\\<server>\\<share>',
      'Free up space or bring storage online',
      'Once storage is healthy: right-click the VM in Hyper-V Manager → Resume (or Start-VM <VMName>)',
      'Verify the VM resumes and applications inside are stable after resume'
    ],
    symptoms: [
      'hyper-v vm paused',
      'virtual machine paused',
      'vm frozen hyper-v',
      'hyper-v vm not responding',
      'vm paused storage error',
      'virtual machine automatically paused',
      'hyper-v vm went offline',
      'vm paused disk full',
      'hyper-v storage error vm',
      'virtual machine paused unexpectedly',
      'vm paused in hyper-v manager',
      'hyper-v vm critical pause'
    ],
    tags: ['hyper-v', 'vm', 'storage', 'paused', 'critical', 'vhd', 'vmms'],
    powershell: `# Hyper-V VM status and storage check
# Eventful

# List all VMs and their state
Get-VM | Select-Object Name, State, Status, Uptime

# Check host storage free space (flag volumes under 10GB free)
Get-PSDrive -PSProvider FileSystem |
    Select-Object Name, @{N='FreeGB'; E={[math]::Round($_.Free/1GB,1)}}, @{N='UsedGB'; E={[math]::Round($_.Used/1GB,1)}} |
    Where-Object { $_.FreeGB -lt 10 }

# Check VM storage file paths
Get-VM | Get-VMHardDiskDrive |
    Select-Object VMName, Path, @{N='SizeGB'; E={[math]::Round((Get-Item $_.Path -ErrorAction SilentlyContinue).Length/1GB,1)}}

# Recent Hyper-V critical events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Hyper-V-VMMS/Admin'
    StartTime = (Get-Date).AddDays(-7)
    Level     = @(1, 2)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [3040, 32022, 13003],
    ms_docs: null
  },

  {
    id: 3040,
    source: 'Microsoft-Windows-Hyper-V-VMMS',
    channel: 'Microsoft-Windows-Hyper-V-VMMS/Admin',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Hyper-V: Integration Services Outdated',
    short_desc: 'The integration services (tools) inside a guest VM are outdated — performance, backup, and time sync may be impaired.',
    description: 'Event 3040 means the Hyper-V Integration Services components inside the guest virtual machine are older than the version expected by the host. Integration Services (also called Hyper-V Guest Services) provide the communication channel between the VM and the Hyper-V host — enabling heartbeat monitoring, time synchronization, live backup (VSS), graceful shutdown, and data exchange. Outdated integration services typically means the guest OS was installed with an older Windows ISO and has not been updated, or the VM was migrated from an older host and the guest updates have not been applied.',
    why_it_happens: 'Integration Services components are built into Windows (since Windows Server 2012 / Windows 8, they are updated via Windows Update). On older guests or guests without Windows Update, the version bundled with the original OS installation remains installed while the host gets newer Hyper-V features that require a newer guest-side component.',
    what_good_looks_like: 'All running VMs showing current integration services versions. Check via Hyper-V Manager → select VM → check Integration Services version, or Get-VM | Select-Object Name, IntegrationServicesVersion.',
    common_mistakes: [
      'Not updating integration services on migrated VMs — migration does not update the guest components',
      'Trying to install integration services from the old ISO (.iso) method on modern Windows guests — Windows Update handles this automatically since Windows 8/2012',
      'Ignoring this warning and then being surprised when live backup (VSS) or heartbeat fails'
    ],
    causes: [
      'Guest OS installed from an older Windows image and not updated via Windows Update',
      'VM migrated from an older Hyper-V host version',
      'Windows Update disabled or blocked inside the guest',
      'Guest is running a Linux distribution with outdated linux-azure or hyper-v-daemons package'
    ],
    steps: [
      'On Windows guests: ensure Windows Update is running and apply all pending updates — Integration Services are delivered via Windows Update on Server 2012+ / Windows 8+',
      'On older Windows guests (2008 R2, 7): In Hyper-V Manager, right-click VM → Insert Integration Services Setup Disk, then run setup inside the VM',
      'Verify version after update: Get-VM <VMName> | Select-Object IntegrationServicesVersion',
      'For Linux guests: install or update the linux-azure or hyperv-daemons package via the distro package manager',
      'After updating: test heartbeat, graceful shutdown, and live backup (VSS) within the VM'
    ],
    symptoms: [
      'hyper-v integration services outdated',
      'vm integration components old',
      'hyper-v tools need update',
      'vm heartbeat not working',
      'hyper-v backup failing integration services',
      'vm time sync not working',
      'graceful shutdown not working vm',
      'hyper-v integration services version mismatch',
      'vm vss backup failing hyper-v',
      'hyper-v guest tools outdated'
    ],
    tags: ['hyper-v', 'vm', 'integration-services', 'warning', 'backup', 'vss', 'heartbeat'],
    powershell: `# Check integration services version across all VMs
# Eventful

Get-VM | Select-Object Name, State, IntegrationServicesVersion,
    @{N='ISState'; E={ ($_ | Get-VMIntegrationService | Where-Object Enabled | Select-Object -ExpandProperty OperationalStatus | Sort-Object -Unique) -join ',' }} |
    Format-Table -AutoSize

# Check which integration services components are enabled per VM
Get-VM | ForEach-Object {
    $vm = $_
    Get-VMIntegrationService -VM $vm | Select-Object @{N='VM';E={$vm.Name}}, Name, Enabled, OperationalStatus
} | Format-Table -AutoSize`,
    related_ids: [18590, 32022, 13003],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services'
  },

  {
    id: 13003,
    source: 'Microsoft-Windows-Hyper-V-VMMS',
    channel: 'Microsoft-Windows-Hyper-V-VMMS/Admin',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Hyper-V: Lost Communication with Virtual Machine',
    short_desc: 'Hyper-V lost the management communication channel with a running VM — heartbeat failed or worker process crashed.',
    description: 'Event 13003 means Hyper-V VMMS lost its management communication channel with a virtual machine. This is separate from the VM itself being unresponsive to users — the VM may still be running and serving users, but Hyper-V cannot manage it (heartbeat fails, graceful shutdown is unavailable, live backup via VSS is broken). The worker process (vmwp.exe) responsible for that VM may have crashed. This event often precedes a VM entering a saved state or being forced off.',
    why_it_happens: 'Each VM has a dedicated worker process (vmwp.exe). If this process crashes — due to a bug, memory corruption, or Hyper-V host memory pressure — VMMS loses its communication channel with the VM. The VM may keep running at the hardware level but cannot be managed gracefully.',
    what_good_looks_like: 'No Event 13003. Heartbeat checks for all VMs returning healthy status.',
    common_mistakes: [
      'Assuming the VM has crashed when users report it is working normally — the VM may be running fine with just the management channel broken',
      'Force-turning off the VM immediately without first trying graceful shutdown',
      'Not checking vmwp.exe process on the host to see if the worker is running'
    ],
    causes: [
      'VM worker process (vmwp.exe) crashed — check host System log',
      'Integration Services heartbeat timeout (outdated or disabled)',
      'Hyper-V host memory pressure killing worker processes',
      'Host hardware error affecting worker process execution'
    ],
    steps: [
      'Check if the VM is still serving users — ping it, test application access',
      'Check host task manager or: Get-Process vmwp | Measure-Object — count should match running VMs',
      'Try graceful shutdown first: Stop-VM <VMName> -Force -TurnOff if graceful fails',
      'Check System log on the host for vmwp.exe crash events at the same time',
      'After restart, check integration services are current (see Event 3040)',
      'Monitor for recurrence — repeated 13003 may indicate hardware instability on the host'
    ],
    symptoms: [
      'hyper-v lost communication with vm',
      'vm heartbeat failing',
      'hyper-v cannot manage vm',
      'vm worker process crashed',
      'hyper-v vm unmanageable',
      'vm heartbeat timeout hyper-v',
      'hyper-v vmms communication error',
      'vm graceful shutdown not working',
      'hyper-v management channel lost'
    ],
    tags: ['hyper-v', 'vm', 'heartbeat', 'error', 'worker-process', 'vmms'],
    powershell: `# VM heartbeat and worker process health
# Eventful

# Check VM heartbeat status
Get-VM | ForEach-Object {
    $hb = Get-VMIntegrationService -VM $_ -Name 'Heartbeat'
    [PSCustomObject]@{
        VMName    = $_.Name
        State     = $_.State
        Heartbeat = $hb.PrimaryOperationalStatus
        LastContact = $hb.LastCommunicationTimestamp
    }
} | Format-Table -AutoSize

# Check worker process count vs running VMs
$runningVMs = (Get-VM | Where-Object State -eq 'Running').Count
$workers    = (Get-Process vmwp -ErrorAction SilentlyContinue).Count
Write-Host "Running VMs: $runningVMs  |  Worker processes: $workers"`,
    related_ids: [18590, 3040, 32022],
    ms_docs: null
  },

  {
    id: 32022,
    source: 'Microsoft-Windows-Hyper-V-VMMS',
    channel: 'Microsoft-Windows-Hyper-V-VMMS/Admin',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Hyper-V: VM Configuration File Not Found or Inaccessible',
    short_desc: 'The VM configuration file (.vmcx or .xml) is missing or cannot be opened — the VM cannot start.',
    description: 'Event 32022 means Hyper-V cannot find or open the configuration file for a virtual machine. In modern Hyper-V (Server 2016+), this is the .vmcx binary file. In older versions it is an XML file. Without the configuration file, the VM cannot start — Hyper-V does not know what hardware the VM has, where its VHD files are, or how much memory it has. This typically happens after storage migration without moving the config, accidental deletion, or corruption of the VM config file.',
    why_it_happens: 'VM configuration files are stored in the VM\'s configuration store path (default: C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\). If the storage path was changed, if the VM was moved and the config was not moved with it, or if the file was deleted, Event 32022 fires.',
    what_good_looks_like: 'All VMs starting without 32022. No orphaned VM entries in Hyper-V Manager.',
    common_mistakes: [
      'Moving VHD files without moving the configuration file — the VM config is stored separately from the VHD',
      'Trying to start the VM before locating and restoring the config file',
      'Not using Export VM when moving VMs between hosts — Export packages config and VHD together'
    ],
    causes: [
      'VM files manually moved or copied without using Hyper-V export',
      'VM configuration file accidentally deleted',
      'Storage path changed and config files not relocated',
      'Incomplete VM import — config file not created',
      'Ransomware or accidental deletion of VM files'
    ],
    steps: [
      'Locate the VM\'s storage path: Get-VM <VMName> | Select-Object ConfigurationLocation',
      'Check if the .vmcx or .xml file exists at that path',
      'If the file is missing: check backups, previous snapshot locations, or other storage paths',
      'If you have the VHD but not the config: use New-VM to create a new VM and attach the existing VHD',
      'For future moves: always use Export-VM / Import-VM to keep config and VHD together'
    ],
    symptoms: [
      'hyper-v vm configuration not found',
      'vm config file missing',
      'virtual machine cannot start config error',
      'hyper-v vm file not found',
      'vm disappeared after moving files',
      'hyper-v vm import failed config',
      'vmcx file missing',
      'vm configuration inaccessible',
      'hyper-v vm not starting after move'
    ],
    tags: ['hyper-v', 'vm', 'configuration', 'error', 'vmcx', 'storage', 'import'],
    powershell: `# VM configuration paths and file existence check
# Eventful

Get-VM | ForEach-Object {
    $configPath = $_.ConfigurationLocation
    $configFile = Get-ChildItem -Path $configPath -Filter '*.vmcx' -ErrorAction SilentlyContinue |
                  Select-Object -First 1
    [PSCustomObject]@{
        VMName        = $_.Name
        State         = $_.State
        ConfigPath    = $configPath
        ConfigExists  = if ($configFile) { 'YES' } else { 'MISSING' }
    }
} | Format-Table -AutoSize`,
    related_ids: [18590, 3040, 13003],
    ms_docs: null
  },

  {
    id: 20415,
    source: 'Microsoft-Windows-Hyper-V-VMMS',
    channel: 'Microsoft-Windows-Hyper-V-VMMS/Admin',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Hyper-V: Saved State Could Not Be Restored',
    short_desc: 'A VM\'s saved state file could not be opened or is corrupt — the VM must be started fresh, losing the previous state.',
    description: 'Event 20415 means Hyper-V could not restore a virtual machine from its saved state file. Saved state is similar to hibernate — the VM\'s entire memory is written to disk so it can be resumed later. If the saved state file (.vsv) is missing, corrupt, or on unavailable storage, the VM cannot resume from where it left off. The VM must either be started fresh (losing any in-flight work) or the saved state must be deleted. This commonly occurs after: host storage issues during a save operation, host failure during a save, or migration without transferring the saved state file.',
    why_it_happens: 'Saved state files are written during: a live save operation, a VM pause, or a Hyper-V host shutdown with default action set to save. If the host crashes or loses storage during the save, the file may be incomplete. If the VM is migrated without the saved state file, or if the file is on storage that is no longer available, restoration fails.',
    what_good_looks_like: 'VMs resuming cleanly from saved state with no 20415 events.',
    common_mistakes: [
      'Not understanding that deleting the saved state and starting fresh means any unsaved application work is lost',
      'Not backing up saved state files before attempting recovery operations',
      'Migrating a VM while it is in saved state without transferring the .vsv file'
    ],
    causes: [
      'Host crashed or lost power while writing the saved state file (incomplete file)',
      'Saved state file stored on storage that is now offline or removed',
      'VM migrated to a new host without transferring the .vsv saved state file',
      'Saved state file accidentally deleted',
      'File system corruption affecting the saved state file'
    ],
    steps: [
      'In Hyper-V Manager: right-click the VM → Delete Saved State — this discards the state and allows a fresh start',
      'Or via PowerShell: Remove-VMSavedState <VMName>',
      'Start the VM fresh: Start-VM <VMName>',
      'Notify users that any in-progress work from the last session is lost',
      'Investigate why the save failed — check storage and host health at the time of failure'
    ],
    symptoms: [
      'hyper-v vm saved state error',
      'vm cannot resume from saved state',
      'hyper-v saved state corrupt',
      'virtual machine saved state failed',
      'vm stuck in saved state',
      'hyper-v vm will not resume',
      'delete saved state hyper-v',
      'vm saved state file missing',
      'hyper-v resume failed'
    ],
    tags: ['hyper-v', 'vm', 'saved-state', 'warning', 'resume', 'storage'],
    powershell: `# Check for VMs in saved state
# Eventful

# List VMs in saved state
Get-VM | Where-Object State -eq 'Saved' |
    Select-Object Name, State, ConfigurationLocation, Path

# Remove saved state and start fresh (only if confirmed OK to lose state)
# Remove-VMSavedState <VMName>
# Start-VM <VMName>`,
    related_ids: [18590, 32022, 3040],
    ms_docs: null
  },

  {
    id: 14024,
    source: 'Microsoft-Windows-Hyper-V-VMMS',
    channel: 'Microsoft-Windows-Hyper-V-VMMS/Admin',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Hyper-V: Failed to Start Virtual Machine',
    short_desc: 'Hyper-V could not start a virtual machine — the specific reason is in the event message.',
    description: 'Event 14024 from Hyper-V VMMS means a virtual machine failed to start or transition state. The error message contains the specific reason: could be insufficient host memory, missing VHD file, configuration error, authorization failure, or a Hyper-V component error. This is the primary event to investigate when a VM shows as "Off" but will not start, or when a start attempt fails immediately. The hex error code in the message maps to a specific failure category.',
    why_it_happens: 'VM start failures occur when: the host lacks sufficient free memory to allocate to the VM, the VHD/VHDX files are missing or corrupt, the VM\'s virtual switch no longer exists on the host, the VM config is corrupt, or the user account doesn\'t have permission to start VMs.',
    what_good_looks_like: 'VMs starting cleanly with no Event 14024. Pre-flight checks (memory, storage, networking) completed before starting.',
    common_mistakes: [
      'Not reading the error message text carefully — the specific reason is always stated',
      'Not checking host free memory before starting large VMs',
      'Not verifying the virtual switch the VM is attached to still exists (common after host config changes)'
    ],
    causes: [
      'Insufficient host RAM — the VM\'s startup RAM exceeds available free memory',
      'VHD/VHDX file missing, locked, or on offline storage',
      'Virtual switch the VM is connected to was deleted or renamed',
      'VM configuration is corrupt',
      'Hyper-V authorization failure — account lacks permissions',
      'Required Hyper-V components not running on the host'
    ],
    steps: [
      'Read the error message in Event 14024 — note the specific reason',
      'Check host free memory: Get-VMMemory <VMName> | Select-Object Startup — compare to: (Get-Counter "\\Memory\\Available MBytes").CounterSamples.CookedValue',
      'Verify VHD files exist: Get-VM <VMName> | Get-VMHardDiskDrive | Select-Object Path',
      'Check virtual switch: Get-VMNetworkAdapter <VMName> | Select-Object SwitchName — then Get-VMSwitch',
      'If memory is the issue: shut down other VMs or increase host RAM',
      'If switch is missing: create a new switch or disconnect the adapter before starting'
    ],
    symptoms: [
      'hyper-v vm failed to start',
      'virtual machine wont turn on',
      'vm start failed hyper-v',
      'hyper-v cannot start vm',
      'virtual machine failed to power on',
      'vm start error',
      'hyper-v vm not starting',
      'failed to start virtual machine error',
      'hyper-v insufficient memory vm',
      'vm switch not found hyper-v'
    ],
    tags: ['hyper-v', 'vm', 'start', 'error', 'memory', 'vmms', 'configuration'],
    powershell: `# Hyper-V VM start failure diagnostics
# Eventful

# VM states
Get-VM | Select-Object Name, State, Status, DynamicMemoryEnabled,
    @{N='MemoryStartupGB'; E={[math]::Round($_.MemoryStartup/1GB,1)}} | Format-Table -AutoSize

# Host available memory
$hostMem = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1)
Write-Host "Host free RAM: $hostMem GB"

# Virtual switches
Get-VMSwitch | Select-Object Name, SwitchType, NetAdapterInterfaceDescription

# Recent Hyper-V errors
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Hyper-V-VMMS/Admin'
    Id        = 14024
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List`,
    related_ids: [18590, 3040, 32022, 13003],
    ms_docs: null
  }
];
