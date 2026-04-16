export const bundles = [
  {
    id: 'slow-machine',
    title: 'Computer Running Slowly',
    icon: '🐌',
    description: 'Systematic investigation of a slow or sluggish Windows endpoint.',
    brief: 'A slow machine complaint can stem from a huge range of causes: resource contention (CPU, RAM, disk), failing hardware (a disk in the early stages of failure is often slow before it dies), background processes consuming resources, malware, or a Windows update still installing. This bundle helps you gather the events that identify the actual cause rather than guessing.',
    start_here: 'Start by checking Event 41 and 1001 in the System log to rule out recent crashes or unexpected reboots that may have corrupted data or triggered chkdsk on next boot. Then look at Application log Event 1000 and 1002 for crashing or hanging applications consuming resources. Check Service events (7031, 7034) for services in crash loops. Finally, correlate with the timeline — did the slowness start after a specific event (Windows Update, new software, hardware change)?',
    escalate_if: [
      'Event 41 with BugcheckCode 0x00000124 (WHEA_UNCORRECTABLE_ERROR) — hardware fault requiring immediate attention',
      'NTFS Event 55 — disk corruption suggesting imminent drive failure',
      'Multiple Event 7031/7034 crash loops for critical services — may need OS rebuild',
      'Disk I/O queue length consistently above 2 — storage bottleneck requiring hardware change',
      'Available physical memory consistently below 200MB — RAM upgrade or memory leak investigation needed'
    ],
    event_ids: [41, 55, 1001, 1000, 1002, 7031, 7034, 7000, 6008],
    composite_powershell: `# Slow Machine Investigation Bundle
# Eventful
# Queries System and Application logs for events indicating resource/reliability issues

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-3)   # 3 days — capture recent changes

Write-Host "=== SLOW MACHINE INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer | Window: $startTime to now\`n"

# 1. Unexpected reboots and kernel crashes
Write-Host "--- [1] Unexpected Reboots & Crashes ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id           = 41
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $bc  = ($xml.Event.EventData.Data | Where-Object Name -eq 'BugcheckCode').'#text'
    "$(($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')) | Kernel Power 41 | BugcheckCode: $bc"
} | Select-Object -First 10

# 2. BSOD records
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
    Id           = 1001
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Select-Object -First 5 |
    ForEach-Object { "$(($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')) | BSOD (1001)" }

# 3. NTFS corruption
Write-Host "\`n--- [2] Disk / Filesystem Issues ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Ntfs'
    Id           = 55
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Select-Object -First 5 |
    ForEach-Object { "$(($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')) | NTFS Corruption (55)" }

# 4. Application crashes
Write-Host "\`n--- [3] Application Crashes & Hangs ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Application'
    Id        = @(1000, 1002)
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $type = if ($_.Id -eq 1000) { 'Crash' } else { 'Hang' }
    "$(($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')) | App $type | $($data[0].'#text')"
} | Select-Object -First 10

# 5. Service crashes
Write-Host "\`n--- [4] Service Failures ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = @(7000, 7031, 7034)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ForEach-Object { "$(($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')) | SCM $($_.Id) | $($_.Message.Split(\"\`n\")[0])" } |
    Select-Object -First 10

# 6. Current system resources
Write-Host "\`n--- [5] Current Resource Usage ---" -ForegroundColor Yellow
$os  = Get-CimInstance -ComputerName $computer Win32_OperatingSystem
$cpu = Get-CimInstance -ComputerName $computer Win32_Processor | Measure-Object LoadPercentage -Average
"RAM Free: $([math]::Round($os.FreePhysicalMemory/1MB,1)) GB / Total: $([math]::Round($os.TotalVisibleMemorySize/1MB,1)) GB"
"CPU Load: $($cpu.Average)%"
"Uptime: $((Get-Date) - $os.LastBootUpTime)"`
  },

  {
    id: 'bsod',
    title: 'Blue Screen / Kernel Crash',
    icon: '💥',
    description: 'Full investigation of a BSOD — from crash code to responsible driver.',
    brief: 'A Blue Screen of Death (BSOD) means the Windows kernel encountered an unrecoverable error and halted execution to prevent data corruption. The stop code tells you the error type; the minidump tells you which driver or component caused it. Do not guess — always analyse the dump. Most BSODs on modern hardware are caused by faulty drivers, bad RAM, or hardware faults, in that order of likelihood.',
    start_here: 'First, check Event 41 (Kernel Power) and Event 1001 (WER BugCheck) in the System log on the next boot after the crash. The BugcheckCode tells you the stop code. Then open C:\\Windows\\Minidump\\ and open the most recent .dmp file in WinDbg or the free WhoCrashed tool. The !analyze -v command in WinDbg will identify the responsible driver. Check for pattern: same code every time = specific hardware fault; varying codes = RAM.',
    escalate_if: [
      'BugcheckCode 0x00000124 (WHEA_UNCORRECTABLE_ERROR) — hardware fault, often CPU or memory controller, may need hardware replacement',
      'BugcheckCode 0x0000007A (KERNEL_DATA_INPAGE_ERROR) — disk I/O error, possible drive failure',
      'More than 3 BSODs in a week — machine unstable, may need rebuild or hardware replacement',
      'BSODs occurring during specific hardware operations (heavy GPU load, USB device insertion) — specific hardware fault',
      'memtest86 showing errors — replace RAM immediately'
    ],
    event_ids: [41, 1001, 6008, 55],
    composite_powershell: `# BSOD Investigation Bundle
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Look back further for crash patterns

Write-Host "=== BSOD / KERNEL CRASH INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer\`n"

# 1. Kernel Power unexpected reboots
Write-Host "--- [1] Kernel Power Events (41) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id           = 41
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $bc  = ($xml.Event.EventData.Data | Where-Object Name -eq 'BugcheckCode').'#text'
    [PSCustomObject]@{
        Time          = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')
        BugcheckCode  = "0x$([Convert]::ToString([int]$bc, 16).ToUpper().PadLeft(8,'0'))"
        Interpretation = if ([int]$bc -eq 0) { 'No crash (power event)' } else { 'Kernel crash occurred' }
    }
} | Format-Table -AutoSize

# 2. WER BugCheck records
Write-Host "--- [2] WER BugCheck Records (1001) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
    Id           = 1001
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# 3. Unexpected shutdowns
Write-Host "--- [3] Unexpected Shutdown Records (6008) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'EventLog'
    Id           = 6008
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-Table -AutoSize

# 4. List minidump files
Write-Host "--- [4] Minidump Files ---" -ForegroundColor Yellow
Get-ChildItem "\\\\$computer\\c$\\Windows\\Minidump\\" -Filter "*.dmp" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, LastWriteTime, @{N='SizeMB'; E={[math]::Round($_.Length/1MB,1)}} |
    Format-Table -AutoSize`
  },

  {
    id: 'rdp-disconnecting',
    title: 'RDP Keeps Dropping',
    icon: '📵',
    description: 'Investigate intermittent or repeated RDP/Remote Desktop disconnections.',
    brief: 'RDP disconnections can be caused by network instability, session policy timeouts, server resource exhaustion, protocol errors, or authentication issues. The key is to use the RDS Event IDs (especially Event 40 with its reason code) to distinguish between user-initiated disconnects, timeouts, and unexpected drops. Network-layer issues show up as protocol error reason codes; policy issues show up as timeout reason codes.',
    start_here: 'Start with Event 40 in the TerminalServices-LocalSessionManager/Operational log — the reason code tells you why the session disconnected. Reason code 5 = user closed window (not a problem), reason code 12 = session timeout (check GPO timeout settings), reason code 9 = protocol error (network issue). Then look at Security Events 4778/4779 for the broader session timeline. Check network quality on both the server and client side.',
    escalate_if: [
      'Reason code 2 (server out of memory) on RDS server — memory pressure, may need RAM upgrade or session limits',
      'All users dropping simultaneously — server crash, network switch issue, or ISP problem',
      'Reason code 263 (licensing error) — RDS CAL licensing problem requiring license server investigation',
      'Repeated drops for one user only from one location — client-side NIC, driver, or network issue',
      'Event 4625 or 4771 failures accompanying disconnects — possible authentication infrastructure issue'
    ],
    event_ids: [21, 22, 23, 24, 25, 40, 41, 1149, 4778, 4779, 4624],
    composite_powershell: `# RDP Disconnection Investigation Bundle
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS/RDP server hostname
$startTime = (Get-Date).AddHours(-24)

Write-Host "=== RDP DISCONNECTION INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer\`n"

$reasonMap = @{
    0='No info'; 1='Server terminated'; 2='Out of memory'; 5='Client disconnect';
    6='Client logoff'; 9='RDP protocol/network error'; 11='Admin disconnect';
    12='Session timeout'; 263='Licensing error'
}

# 1. Session lifecycle events with reason codes
Write-Host "--- [1] Session Lifecycle (Events 21, 24, 25, 40) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id        = @(21, 24, 25, 40)
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $ud  = $xml.Event.UserData.EventXML
    $rc  = if ($_.Id -eq 40) { [int]$ud.Reason } else { $null }
    [PSCustomObject]@{
        Time      = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')
        EventID   = $_.Id
        Type      = @{21='Logon'; 24='Disconnect'; 25='Reconnect'; 40='Disconnect+Reason'}[$_.Id]
        User      = $ud.User
        Session   = $ud.SessionID
        SourceIP  = $ud.Address
        Reason    = if ($rc -ne $null) { "$rc - $($reasonMap[$rc] ?? 'Unknown')" } else { '' }
    }
} | Sort-Object Time | Format-Table -AutoSize

# 2. Security log RDP events
Write-Host "\`n--- [2] Security Log RDP Events (4778, 4779) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4778, 4779)
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-Table -AutoSize

# 3. Current sessions
Write-Host "\`n--- [3] Current Sessions ---" -ForegroundColor Yellow
qwinsta /server:$computer 2>$null`
  },

  {
    id: 'app-crashing',
    title: 'Application Keeps Crashing',
    icon: '🔄',
    description: 'Diagnose repeated application crashes using WER and runtime events.',
    brief: 'Application crashes are logged in the Application event log. The combination of Event 1000 (crash), 1001 (WER bucket), and 1026 (.NET exceptions) gives you the full picture. The key fields are the faulting module name and exception code. A faulting module that is the application itself points to a bug in the application. A faulting module that is a third-party DLL (AV, shell extension) or system DLL suggests an incompatibility or injection issue.',
    start_here: 'Filter Application log for Event 1000 and note the "Faulting Module Name" — this is more important than the application name. If the exception code is 0xe0434352, look for Event 1026 (.NET Runtime) for more detail. Check for updates for both the application and Windows. If the faulting module is a system DLL, check for pending Windows updates. If it\'s an AV DLL, try temporarily disabling AV scan of the application\'s directory for testing.',
    escalate_if: [
      'Faulting module ntdll.dll with code 0xC0000005 — often indicates corrupt Windows files, run sfc /scannow',
      'Application crashes on multiple machines simultaneously after an update — roll back the update',
      'Any exception code 0xC0000409 (STACK_BUFFER_OVERRUN) — potential security vulnerability in the application',
      'Crash rate increasing over time — possible memory leak causing eventual corruption',
      'Crashes starting after a specific Windows Update — report to vendor and test with update uninstalled'
    ],
    event_ids: [1000, 1001, 1002, 1026],
    composite_powershell: `# Application Crash Investigation Bundle
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)
$appFilter = ''   # Optional: filter by app name e.g. 'outlook.exe'

Write-Host "=== APPLICATION CRASH INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer\`n"

# 1. Application crashes
Write-Host "--- [1] Application Crashes (1000) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Application'
    Id        = 1000
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time           = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')
        Application    = $data[0].'#text'
        FaultingModule = $data[3].'#text'
        ExceptionCode  = $data[6].'#text'
    }
} | Where-Object { -not $appFilter -or $_.Application -like "*$appFilter*" } |
    Sort-Object Time -Descending | Select-Object -First 20 | Format-Table -AutoSize

# 2. Application hangs
Write-Host "\`n--- [2] Application Hangs (1002) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Application Hang'
    Id           = 1002
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Select-Object -First 10 | Format-Table -AutoSize

# 3. .NET errors
Write-Host "\`n--- [3] .NET Runtime Errors (1026) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = '.NET Runtime'
    Id           = 1026
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Select-Object -First 5 | Format-List`
  },

  {
    id: 'network-drops',
    title: 'Network Keeps Disconnecting',
    icon: '🌐',
    description: 'Diagnose intermittent network drops — DNS, DHCP, WiFi, and TCP events.',
    brief: 'Network drops manifest as DNS timeouts, DHCP failures, WiFi disconnections, or TCP connectivity loss. The root cause can be physical (cable, NIC, AP), protocol-level (DHCP scope exhausted, DNS misconfigured), or driver-related. Start with WiFi if wireless, otherwise look at DHCP lease events and DNS resolution failures. Intermittent connectivity is often power management putting the NIC to sleep.',
    start_here: 'If WiFi: check Event 10317 (disconnection reason code) and 10400 (association failure). If wired: check DHCP events (1030, 1048). For all types, check 1014 (DNS timeout) — slow DNS causes connectivity symptoms even when the network is physically connected. Check NIC power management (Allow computer to turn off this device to save power) which is enabled by default and causes frequent brief drops.',
    escalate_if: [
      'DHCP Event 1020 (IP conflict) — another device has the same IP, causing network interruption',
      'DNS Event 1014 occurring constantly — DNS server unreachable, affecting all hostname resolution',
      'WiFi reason code 9 on many users simultaneously — AP or switch infrastructure issue',
      'DHCP Event 1030 (cannot get IP) — DHCP server issue or scope exhaustion',
      'Physical layer issues (NIC errors, cable problems) visible in device manager or network adapter statistics'
    ],
    event_ids: [10317, 10400, 1014, 1032, 1020, 1030, 1048, 1063, 4226],
    composite_powershell: `# Network Drops Investigation Bundle
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)

Write-Host "=== NETWORK DISCONNECTION INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer\`n"

# 1. WiFi disconnections
Write-Host "--- [1] WiFi Events (10317, 10400) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WLAN-AutoConfig'
    Id           = @(10317, 10400)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Select-Object -First 10 | Format-Table -AutoSize

# 2. DHCP events
Write-Host "\`n--- [2] DHCP Events (1020, 1030, 1048) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Dhcp-Client'
    Id           = @(1020, 1030, 1048, 1063)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize

# 3. DNS failures
Write-Host "\`n--- [3] DNS Timeouts (1014) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DNS-Client'
    Id           = @(1014, 1032)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Select-Object -First 10 | Format-Table -AutoSize

# 4. Current network state
Write-Host "\`n--- [4] Current Network State ---" -ForegroundColor Yellow
Get-NetIPConfiguration -ComputerName $computer -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer | Format-Table -AutoSize

# 5. NIC power management
Write-Host "\`n--- [5] NIC Power Management (check for auto-sleep) ---" -ForegroundColor Yellow
Get-NetAdapter -CimSession $computer -ErrorAction SilentlyContinue | ForEach-Object {
    Get-NetAdapterPowerManagement -Name $_.Name -CimSession $computer -ErrorAction SilentlyContinue
} | Select-Object Name, AllowComputerToTurnOffDevice | Format-Table -AutoSize`
  },

  {
    id: 'unexpected-reboot',
    title: 'Computer Randomly Reboots',
    icon: '⚡',
    description: 'Identify the cause of random or unexplained system reboots.',
    brief: 'A system that reboots without warning is either crashing (BSOD), losing power (PSU or UPS failure), or being restarted by a process or policy. The first step is always to determine whether the reboot was clean (Event 1074 + 6006) or unexpected (Event 6008 + 41). If unexpected and BugcheckCode is 0, no crash occurred — look at hardware power issues. If BugcheckCode is non-zero, analyse the minidump for the responsible driver.',
    start_here: 'Find Event 6008 (unexpected shutdown) in the System log on the affected boot. If present, look for Event 41 (Kernel Power) — check BugcheckCode. If BugcheckCode is 0: no BSOD, look at power/hardware. If non-zero: BSOD occurred, analyse minidump in C:\\Windows\\Minidump. Also check Event 1074 to see if any process triggered the reboot intentionally.',
    escalate_if: [
      'Repeated reboots with BugcheckCode 0 (no crash) — power delivery problem, PSU or UPS failure, check hardware',
      'BugcheckCode 0x00000124 — hardware fault (CPU, MCE), may need motherboard or CPU replacement',
      'Reboots correlating with high CPU or GPU load — thermal shutdown, clean/replace heatsink, check fans',
      'Multiple machines in the same rack rebooting — power infrastructure issue, escalate to facilities',
      'Event 1074 showing a non-standard process initiating the reboot — investigate that process'
    ],
    event_ids: [41, 1001, 6008, 6005, 6006, 1074, 1076],
    composite_powershell: `# Unexpected Reboot Investigation Bundle
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)

Write-Host "=== UNEXPECTED REBOOT INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer\`n"

# 1. Full boot/shutdown timeline
Write-Host "--- [1] Boot/Shutdown Timeline ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'EventLog'
    Id           = @(6005, 6006, 6008)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Time  = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')
        ID    = $_.Id
        Type  = @{ 6005 = 'BOOT'; 6006 = 'CLEAN SHUTDOWN'; 6008 = '*** UNEXPECTED SHUTDOWN ***' }[$_.Id]
    }
} | Sort-Object Time | Format-Table -AutoSize

# 2. Kernel power events
Write-Host "\`n--- [2] Kernel Power Events (41) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id           = 41
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $bc  = [int]($xml.Event.EventData.Data | Where-Object Name -eq 'BugcheckCode').'#text'
    [PSCustomObject]@{
        Time           = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')
        BugcheckCode   = "0x$([Convert]::ToString($bc, 16).ToUpper().PadLeft(8,'0'))"
        Crashed        = if ($bc -eq 0) { 'No (power event)' } else { 'Yes (BSOD)' }
    }
} | Format-Table -AutoSize

# 3. Intentional reboots
Write-Host "\`n--- [3] Planned Reboots (1074) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'USER32'
    Id           = 1074
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-Table -AutoSize

# 4. Minidumps
Write-Host "\`n--- [4] Minidump Files ---" -ForegroundColor Yellow
Get-ChildItem "\\\\$computer\\c$\\Windows\\Minidump\\" -Filter "*.dmp" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
    Select-Object Name, LastWriteTime | Format-Table -AutoSize`
  },

  {
    id: 'slow-rds',
    title: 'RDS/Terminal Server Session Slow',
    icon: '🖥️',
    description: 'Diagnose slow logon, slow session, or high resource usage on an RDS server.',
    brief: 'RDS session slowness typically manifests as slow logon (Events 21 to 22 gap), high CPU or memory on the server (many users sharing resources), or slow in-session performance (display, application response). Use Event 21/22 timing to identify logon bottlenecks (GPO, profile, logon scripts). Check Event 7031/7034 for services crashing and consuming resources during recovery. Identify the top CPU and memory consumers on the RDS server.',
    start_here: 'First measure how slow: is it slow to log on, or slow once logged on? If slow to log on, measure the gap between Event 21 (session created) and Event 22 (shell started). A gap over 30 seconds points to GPO processing, profile loading, or logon scripts. If slow once logged on: check CPU and RAM utilisation on the server. Identify per-process resource usage. Check if a service is in a crash loop (7031/7034) consuming restart overhead.',
    escalate_if: [
      'Available server RAM below 500MB — users will experience extreme slowness, add sessions to other servers or add RAM',
      'CPU sustained above 90% — user-causing or runaway process, identify and terminate',
      'Logon gap between Event 21 and 22 exceeding 3 minutes — GPO or profile issue requiring infrastructure investigation',
      'Event 7031 crash loop for a service consuming CPU on recovery — fix the crashing service first',
      'Many Event 40 (disconnect) with reason code 2 (out of memory) — server is OOM, emergency capacity action needed'
    ],
    event_ids: [21, 22, 23, 24, 25, 40, 41, 7031, 7034, 7036],
    composite_powershell: `# Slow RDS Session Investigation Bundle
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-8)

Write-Host "=== SLOW RDS INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer\`n"

# 1. Session logon timing (21 to 22 gap)
Write-Host "--- [1] Session Logon Timing (Events 21 & 22) ---" -ForegroundColor Yellow
$sessionEvents = Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id        = @(21, 22)
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $ud  = $xml.Event.UserData.EventXML
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        EventID   = $_.Id
        User      = $ud.User
        SessionID = $ud.SessionID
    }
}
$logons = $sessionEvents | Where-Object EventID -eq 21
$shells  = $sessionEvents | Where-Object EventID -eq 22
foreach ($logon in $logons) {
    $shell = $shells | Where-Object SessionID -eq $logon.SessionID | Sort-Object Time | Select-Object -First 1
    $gap   = if ($shell) { ($shell.Time - $logon.Time).TotalSeconds } else { 'No shell event' }
    "$($logon.Time.ToString('HH:mm:ss')) | User: $($logon.User) | Session: $($logon.SessionID) | Logon-to-Shell gap: $gap sec"
}

# 2. Service crashes
Write-Host "\`n--- [2] Service Crashes (7031, 7034) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = @(7031, 7034)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Select-Object -First 10 | Format-Table -AutoSize

# 3. Current server resource usage
Write-Host "\`n--- [3] Server Resources ---" -ForegroundColor Yellow
$os  = Get-CimInstance -ComputerName $computer Win32_OperatingSystem
$cpu = (Get-CimInstance -ComputerName $computer Win32_Processor | Measure-Object LoadPercentage -Average).Average
"Sessions: $(((qwinsta /server:$computer 2>$null) | Where-Object { $_ -match 'Active' }).Count) active"
"CPU: $cpu%"
"RAM Free: $([math]::Round($os.FreePhysicalMemory/1MB,1)) GB / $([math]::Round($os.TotalVisibleMemorySize/1MB,1)) GB"

# 4. Top processes by CPU
Write-Host "\`n--- [4] Top CPU Processes ---" -ForegroundColor Yellow
Get-Process -ComputerName $computer -ErrorAction SilentlyContinue |
    Sort-Object CPU -Descending | Select-Object -First 10 |
    Select-Object Name, Id, CPU, WorkingSet | Format-Table -AutoSize`
  },

  {
    id: 'account-lockout',
    title: 'User Account Keeps Locking Out',
    icon: '🔒',
    description: 'Trace recurring account lockouts to the source device and process.',
    brief: 'Account lockouts are caused by repeated bad password attempts. The lockout event (4740) is logged on the PDC Emulator domain controller and critically contains the "Caller Computer Name" — the machine sending the bad passwords. Go to that machine and look at Event 4625 for the specific process sending bad credentials. Common culprits: stale Outlook profile, remembered credentials in Credential Manager, a mobile device with the old password, or a service configured with old credentials.',
    start_here: 'Find Event 4740 on the PDC Emulator. Note the Caller Computer Name field. That is the machine to investigate next. On the Caller Computer, look at Event 4625 (failed logons) for the affected account. The "Caller Process Name" in 4625 reveals the application sending bad passwords. Check Credential Manager, Outlook profiles, mapped drives, scheduled tasks, and any services running under the user\'s account.',
    escalate_if: [
      'Lockouts coming from many different machines simultaneously — possible password spray attack, escalate to security incident',
      'Caller Computer Name is blank or the lockout is from an unexpected IP — possible external brute-force',
      'No Caller Computer Name available and the lockout is on the DC itself — NTLM authentication attempt from unknown source',
      'Lockouts happening outside business hours — investigate the source machine for unauthorised access or malware',
      'Multiple accounts locking out at the same time — strong indicator of credential spraying attack'
    ],
    event_ids: [4740, 4625, 4767, 4771, 4776, 4624],
    composite_powershell: `# Account Lockout Investigation Bundle
# Eventful
# Step 1: Run this on the PDC Emulator domain controller

$computer   = (Get-ADDomain).PDCEmulator    # PDC Emulator DC
$startTime  = (Get-Date).AddHours(-24)
$lockedUser = 'USERNAME'                     # Replace with the locked-out username

Write-Host "=== ACCOUNT LOCKOUT INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "PDC: $computer | User: $lockedUser\`n"

# 1. Find lockout events and source machine
Write-Host "--- [1] Lockout Events (4740) on PDC ---" -ForegroundColor Yellow
$lockouts = Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4740
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time          = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss')
        LockedAccount = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        CallerMachine = ($data | Where-Object Name -eq 'CallerComputerName').'#text'
    }
} | Where-Object LockedAccount -eq $lockedUser
$lockouts | Format-Table -AutoSize

$callerMachine = ($lockouts | Select-Object -First 1).CallerMachine
if ($callerMachine) {
    Write-Host "Lockout source machine: $callerMachine" -ForegroundColor Magenta
    Write-Host "--- [2] Failed Logons on Source Machine (4625) ---" -ForegroundColor Yellow
    # Run on the caller machine to find the specific process
    Get-WinEvent -ComputerName $callerMachine -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time        = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss')
            Account     = ($data | Where-Object Name -eq 'TargetUserName').'#text'
            Process     = ($data | Where-Object Name -eq 'ProcessName').'#text'
            FailureCode = ($data | Where-Object Name -eq 'SubStatus').'#text'
        }
    } | Where-Object Account -eq $lockedUser | Select-Object -First 20 | Format-Table -AutoSize
}

# 3. Unlock events (to measure frequency)
Write-Host "\`n--- [3] Unlock Events (4767) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4767
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time          = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss')
        TargetAccount = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        UnlockedBy    = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Where-Object TargetAccount -eq $lockedUser | Format-Table -AutoSize`
  },

  {
    id: 'service-failure',
    title: 'Service Won\'t Start or Keeps Crashing',
    icon: '⚙️',
    description: 'Diagnose Windows service startup failures and crash loops using SCM events.',
    brief: 'Service failures fall into two categories: won\'t start (7000, 7001, 7009) and keeps crashing (7031, 7034). For startup failures, the error code tells you why: file not found (2), access denied (5), timeout (1053). For crashes, check the Application log for Event 1000 alongside 7031 — the faulting module in 1000 identifies the responsible code. Always check dependencies (7001) before diagnosing the primary service.',
    start_here: 'First filter System log for all SCM events (7000, 7001, 7009, 7023, 7031, 7034) in the relevant time window. Identify whether it\'s a startup failure or a crash. For startup failures, check the error code and dependency chain. For crashes, find Event 1000 in Application log at the same time — it contains the faulting module. Check the Application event log for any service-specific messages immediately before the crash.',
    escalate_if: [
      'Critical service (Print Spooler, DNS, DHCP, AD DS, SQL Server) failing — immediate business impact, escalate now',
      'Service crash loop (7034 appearing every few minutes) — service consuming restart overhead, causing system instability',
      'Service failure after a Windows Update — possible compatibility issue, consider rolling back the update',
      'Service running as a domain account with the error code 5 (access denied) — domain account may be locked or disabled',
      'Multiple services failing in sequence — possible cascading dependency failure, find the root service'
    ],
    event_ids: [7000, 7001, 7009, 7011, 7023, 7031, 7034, 7036, 7040, 7045],
    composite_powershell: `# Service Failure Investigation Bundle
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-3)
$svcName   = ''   # Optional: filter by service name

Write-Host "=== SERVICE FAILURE INVESTIGATION ===" -ForegroundColor Cyan
Write-Host "Target: $computer\`n"

# 1. All service failure events
Write-Host "--- [1] Service Control Manager Events ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = @(7000, 7001, 7009, 7011, 7023, 7031, 7034)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Time    = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss')
        EventID = $_.Id
        Level   = $_.LevelDisplayName
        Message = $_.Message.Split([char]10)[0].Trim()
    }
} | Where-Object { -not $svcName -or $_.Message -like "*$svcName*" } |
    Sort-Object Time -Descending | Select-Object -First 20 | Format-Table -AutoSize

# 2. New services (persistence check)
Write-Host "\`n--- [2] New Services Installed (7045) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7045
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')
        ServiceName = ($data | Where-Object Name -eq 'ServiceName').'#text'
        BinaryPath  = ($data | Where-Object Name -eq 'ImagePath').'#text'
        Account     = ($data | Where-Object Name -eq 'AccountName').'#text'
    }
} | Format-Table -AutoSize

# 3. Application crash events (often correlate with service crashes)
Write-Host "\`n--- [3] Correlated Application Crashes (1000) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Application'
    Id        = 1000
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time           = ($_.TimeCreated).ToString('yyyy-MM-dd HH:mm')
        Application    = $data[0].'#text'
        FaultingModule = $data[3].'#text'
        ExceptionCode  = $data[6].'#text'
    }
} | Sort-Object Time -Descending | Select-Object -First 10 | Format-Table -AutoSize

# 4. Currently stopped services that should be running
Write-Host "\`n--- [4] Services in Unexpected Stopped State ---" -ForegroundColor Yellow
Get-Service -ComputerName $computer -ErrorAction SilentlyContinue |
    Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped' } |
    Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize`
  },

  {
    id: 'suspicious-activity',
    title: 'Possible Compromise or Suspicious Behaviour',
    icon: '🦠',
    description: 'Security incident triage — authentication anomalies, persistence, and lateral movement.',
    brief: 'Investigating possible compromise requires looking for anomalies across authentication (4624, 4625, 4648), persistence (4698, 7045, 4720, 4732), lateral movement (4648, 4688), defence evasion (4719, 7040), and privilege escalation (4672, 4728). No single event confirms compromise — you are looking for a pattern of unusual activity. Start by establishing a timeline of suspicious authentication events, then pivot to process creation and scheduled tasks.',
    start_here: 'Start with 4625 (failed logons) for any unusual volume or source IPs. Then check 4624 for logons with unusual logon types (Type 3 from unexpected IPs, Type 10 RDP from unexpected sources). Check 4688 for processes run from AppData, Temp, or with encoded PowerShell. Check 4698 for new scheduled tasks and 7045 for new services. Check 4720 and 4732 for new accounts or local admin group changes. Check 4719 for audit policy changes (attackers often disable logging).',
    escalate_if: [
      'Audit policy (4719) was changed to disable categories — attacker may have blinded the log before acting',
      'New account created (4720) and immediately added to Administrators or Domain Admins (4728/4732) — clear compromise indicator',
      'Scheduled task or service installed with binary in AppData, Temp, or with encoded command line',
      'Logons from unexpected geographic IPs or outside business hours for sensitive accounts',
      'Multiple accounts failing simultaneously from one source IP — password spray in progress, isolate immediately',
      'Process creation (4688) showing Office apps spawning cmd.exe or powershell.exe — possible document-based exploit'
    ],
    event_ids: [4624, 4625, 4648, 4672, 4688, 4698, 4700, 4702, 4719, 4720, 4728, 4732, 4740, 7040, 7045],
    composite_powershell: `# Suspicious Activity Investigation Bundle
# Eventful
# Run on the suspect machine AND the domain controller

$computer  = $env:COMPUTERNAME  # Replace with suspect machine hostname
$startTime = (Get-Date).AddHours(-48)   # Look back 48 hours

Write-Host "=== SUSPICIOUS ACTIVITY INVESTIGATION ===" -ForegroundColor Red
Write-Host "Target: $computer | Window: $startTime to now\`n"

# 1. Audit policy changes
Write-Host "--- [1] CRITICAL: Audit Policy Changes (4719) ---" -ForegroundColor Red
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4719
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# 2. Failed logons (brute-force / spray indicators)
Write-Host "--- [2] Failed Logons (4625) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time     = ($_.TimeCreated).ToString('HH:mm:ss')
        Account  = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        SourceIP = ($data | Where-Object Name -eq 'IpAddress').'#text'
        SubStatus= ($data | Where-Object Name -eq 'SubStatus').'#text'
    }
} | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize

# 3. Explicit credential use (lateral movement)
Write-Host "\`n--- [3] Explicit Credential Use (4648) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4648
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time         = ($_.TimeCreated).ToString('HH:mm:ss')
        From         = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        CredentialAs = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        Target       = ($data | Where-Object Name -eq 'TargetServerName').'#text'
        Process      = ($data | Where-Object Name -eq 'ProcessName').'#text'
    }
} | Select-Object -First 20 | Format-Table -AutoSize

# 4. Process creation (suspicious paths)
Write-Host "\`n--- [4] Suspicious Process Creation (4688) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time    = ($_.TimeCreated).ToString('HH:mm:ss')
        Account = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        Process = ($data | Where-Object Name -eq 'NewProcessName').'#text'
        CmdLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
        Parent  = ($data | Where-Object Name -eq 'ParentProcessName').'#text'
    }
} | Where-Object {
    $_.Process -match 'AppData|Temp|Users\\\\Public|Recycle' -or
    $_.CmdLine -match '-enc|-EncodedCommand|IEX|Invoke-Expression|DownloadString' -or
    ($_.Parent -match 'winword|excel|outlook|powerpnt' -and $_.Process -match 'cmd|powershell|wscript|cscript')
} | Select-Object -First 20 | Format-Table -AutoSize

# 5. New scheduled tasks and services
Write-Host "\`n--- [5] New Persistence (4698, 7045) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4698
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Select-Object -First 5 | Format-List

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7045
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    "$( ($_.TimeCreated).ToString('HH:mm') ) | New Service: $(($data | Where-Object Name -eq 'ServiceName').'#text') | Path: $(($data | Where-Object Name -eq 'ImagePath').'#text')"
} | Select-Object -First 5

# 6. Account and group changes
Write-Host "\`n--- [6] Account / Group Changes (4720, 4732) ---" -ForegroundColor Yellow
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4720, 4722, 4728, 4732)
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-Table -AutoSize`
  }
];
