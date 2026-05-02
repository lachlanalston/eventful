export const applicationEvents = [
  {
    id: 1000,
    source: 'Application Error',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Application Crash (Faulting Application)',
    short_desc: 'An application crashed — records the faulting process, module, and exception code.',
    description: 'Event ID 1000 from "Application Error" is the primary event for application crashes. It records the name and version of the crashing application, the specific DLL or module that faulted, the exception code (e.g., 0xc0000005 = access violation, 0xe0434352 = .NET exception), and the offset within the module where the fault occurred. This event is generated for any crash in user-mode that Windows Error Reporting (WER) captures — not kernel crashes (those are Event 41/1001 in System log). It is your starting point for any "application keeps crashing" investigation.',
    why_it_happens: 'When an application throws an unhandled exception — typically an access violation (reading/writing invalid memory), a null pointer dereference, a stack overflow, or an uncaught software exception — Windows Error Reporting intercepts the crash, creates a minidump, and logs Event 1000. The faulting module identifies which specific library caused the crash, which is often more useful than the application name since third-party DLLs frequently cause crashes in the host process.',
    what_good_looks_like: 'Occasional crashes during extreme edge cases are normal for complex applications. Investigate: repeated crashes at the same offset in the same module (reliable reproduction means there is a deterministic bug), crashes beginning after an update (regression), crashes of critical business applications affecting productivity, crashes caused by known-malicious modules.',
    common_mistakes: [
      'Only looking at the application name and ignoring the faulting module — the faulting module is usually the actual culprit',
      'Not correlating with 1001 (WER bucket) or 1002 (hang) for related events',
      'Trying to fix the application without checking for updates first — many crashes are fixed by vendor patches',
      'Not checking if antivirus is injecting into the process (shell extensions and AV DLLs frequently cause crashes in other apps)',
      'Ignoring that 0xe0434352 means a .NET exception — look for Event 1026 for more detail'
    ],
    causes: [
      'Bug in application code causing access violation or unhandled exception',
      'Incompatible third-party DLL injected into process (shell extensions, AV)',
      'Corrupt application installation',
      'Missing or incompatible dependency (DLL, .NET runtime version)',
      'Hardware memory fault causing random corruption',
      'Application updated and introduced a regression',
      'Incompatible Windows update affecting application APIs'
    ],
    steps: [
      'Filter Application log for Event 1000',
      'Note the "Faulting Application Name" and "Faulting Module Name"',
      'Note the "Exception Code": 0xc0000005 = access violation, 0xe0434352 = .NET unhandled',
      'If faulting module is the app itself: check vendor for updates or known issues',
      'If faulting module is a third-party DLL: investigate if it is an AV, shell extension, or inject',
      'Check for pending Windows Update that may include a fix',
      'If .NET exception (0xe0434352): check Event 1026 for more detail',
      'Reproduce the crash and capture a full dump with ProcDump: procdump -e 1 <pid> C:\\crashes\\'
    ],
    symptoms: [
      'application crashed',
      'program keeps crashing',
      'app crashes',
      'application keeps closing',
      'program stopped working',
      'this application has stopped working',
      'application error popup',
      'program crashes randomly',
      'app closes itself',
      'software keeps crashing'
    ],
    tags: ['crash', 'application', 'exception', 'faulting-module', 'wer', 'reliability'],
    powershell: `# Application Crash Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed
$appName   = ''  # Optional: filter by app name, e.g. 'outlook.exe'

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Application'
    Id        = 1000
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated      = $_.TimeCreated
        FaultingApp      = $data[0].'#text'
        AppVersion       = $data[1].'#text'
        FaultingModule   = $data[3].'#text'
        ModuleVersion    = $data[4].'#text'
        ExceptionCode    = $data[6].'#text'
        FaultOffset      = $data[7].'#text'
    }
} | Where-Object { -not $appName -or $_.FaultingApp -like "*$appName*" } |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [1001, 1002, 1026, 7031],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/win32/wer/about-wer'
  },

  {
    id: 1001,
    source: 'Windows Error Reporting',
    channel: 'Application',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Windows Error Reporting: Fault Bucket',
    short_desc: 'WER grouped a crash into a fault bucket for reporting — may include Watson report details.',
    description: 'Event ID 1001 from Windows Error Reporting (note: this is Application log, different from the System log 1001 which is BugCheck) records a fault bucket assignment for a crash. WER groups similar crashes by fault signature (Bucket ID) so that crash patterns can be identified. The Bucket ID can be used to look up known issues in Microsoft\'s crash database. This event may appear alongside 1000 (crash) and provides additional context including whether a crash report was sent to Microsoft and whether a solution exists.',
    why_it_happens: 'After WER captures a crash (triggering Event 1000), it analyses the crash data and assigns it to a fault bucket based on the crash signature. If crash reporting is enabled, WER may send the crash to Microsoft\'s crash analysis service. Event 1001 records this bucket assignment and any solutions found.',
    what_good_looks_like: 'Look for the Bucket ID when searching Microsoft knowledge base or support forums — the ID can help find relevant patches or workarounds. If a solution is available, WER may display it in Action Center.',
    common_mistakes: [
      'Ignoring this event because it looks informational — the Bucket ID is useful for research',
      'Not checking Windows Action Center for WER-recommended solutions'
    ],
    causes: [
      'Generated automatically by WER alongside any crash event',
      'Triggered for both application crashes and non-fatal faults'
    ],
    steps: [
      'Find Event 1001 that corresponds to a known crash (same time as 1000)',
      'Note the Bucket ID',
      'Search Microsoft support and knowledge base with the Bucket ID',
      'Check Windows Action Center for any recommended solutions'
    ],
    symptoms: [
      'windows error reporting',
      'fault bucket',
      'crash report',
      'wer report',
      'watson report',
      'error reporting crash'
    ],
    tags: ['wer', 'crash', 'fault-bucket', 'reporting', 'watson'],
    powershell: `# Windows Error Reporting Fault Bucket Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Windows Error Reporting'
    Id           = 1001
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [1000, 1002, 1026],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/win32/wer/about-wer'
  },

  {
    id: 1002,
    source: 'Application Hang',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Application Hang',
    short_desc: 'An application stopped responding and Windows terminated it or it was killed by the user.',
    description: 'Event ID 1002 from "Application Hang" is generated when a GUI application stops processing messages on its main thread for more than 5 seconds, causing the "(Not Responding)" state. Unlike 1000 (crash), the application has not crashed — it is alive but stuck. Windows may generate this event when the user clicks "Close" on a hung window and confirms termination, or after an extended period of unresponsiveness. The event records the application name, version, and the time it stopped responding.',
    why_it_happens: 'Windows applications use a message loop on the main thread to handle user input and window updates. If the main thread is blocked — waiting on a slow file I/O, a network call, a database query, a mutex, or an infinite loop — it cannot process messages, and the window goes (Not Responding). Windows detects this by sending a WM_NULL message and waiting for a response. If no response comes within 5 seconds, the application is considered hung.',
    what_good_looks_like: 'Occasional hangs during heavy operations are tolerable. Investigate: repeated hangs of the same application at the same operation, hangs affecting many users simultaneously, hangs that began after an update or configuration change, hangs during operations that involve file servers or databases (may indicate network/storage latency).',
    common_mistakes: [
      'Treating hangs and crashes identically — hung processes often have different root causes (I/O blocking, deadlock) vs crashes (memory corruption)',
      'Not checking if the hang correlates with disk or network latency events',
      'Not capturing a dump of the hung process to see which thread is blocked and what it\'s waiting for',
      'Ignoring that Outlook hangs often correlate with Exchange or network issues, not Outlook bugs'
    ],
    causes: [
      'Main thread blocked on slow I/O (disk, network, database)',
      'Deadlock between two threads',
      'Infinite loop in application code',
      'Waiting on a COM object or shell extension that is hung',
      'Slow antivirus scanning during file access',
      'Memory pressure causing heavy paging',
      'Remote file share latency causing synchronous operations to block'
    ],
    steps: [
      'Filter Application log for Event 1002',
      'Note application name and time of hang',
      'Check if hangs correlate with disk, network, or database events in System log',
      'Check resource usage at time of hang: CPU, RAM, disk queue length',
      'If recurring: capture hung process dump with Task Manager (Create dump file)',
      'Analyse dump with WinDbg: !analyze -v, ~* k (all thread stacks)',
      'Check if antivirus is scanning the directories the app accesses',
      'Test network path latency if the app accesses file shares'
    ],
    symptoms: [
      'application not responding',
      'app hangs',
      'program freezes',
      'not responding',
      'application froze',
      'outlook hangs',
      'program stuck',
      'app freezes',
      'application becomes unresponsive',
      'software stops responding'
    ],
    tags: ['hang', 'application', 'frozen', 'not-responding', 'reliability', 'performance'],
    powershell: `# Application Hang Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed
$appName   = ''  # Optional: filter by app name, e.g. 'outlook.exe'

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Application Hang'
    Id           = 1002
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        Application  = $data[0].'#text'
        AppVersion   = $data[1].'#text'
        HangType     = $data[4].'#text'
    }
} | Where-Object { -not $appName -or $_.Application -like "*$appName*" } |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [1000, 1001, 1026],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/win32/wer/about-wer'
  },

  {
    id: 1026,
    source: '.NET Runtime',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: '.NET Runtime Error',
    short_desc: 'A .NET application threw an unhandled exception — includes full exception type and stack trace.',
    description: 'Event ID 1026 from the ".NET Runtime" source is logged when a .NET application encounters an unhandled exception and crashes. Unlike Event 1000 (which gives low-level Windows crash data), Event 1026 provides the full .NET exception type (e.g., System.NullReferenceException, System.OutOfMemoryException), the full stack trace in managed code, and the thread that threw the exception. This is extremely valuable for .NET developers and MSPs dealing with business application crashes.',
    why_it_happens: 'When a .NET application throws an exception that is not caught anywhere in the call stack, the CLR (Common Language Runtime) invokes the unhandled exception handler. If no application-level handler is registered, the CLR logs Event 1026 with the full exception information and then terminates the process. This also generates a companion Event 1000 (Application Error) with exception code 0xe0434352.',
    what_good_looks_like: 'No Event 1026 events for production applications. In development or test environments, they are acceptable during debugging. For MSP-managed clients: 1026 for a business application (ERP, accounting, line-of-business) is a vendor support escalation item.',
    common_mistakes: [
      'Looking only at Event 1000 for .NET crashes — 1000 gives exception code 0xe0434352 (useless) but 1026 gives the real exception type and stack',
      'Not providing the stack trace to the software vendor — they need 1026 detail to diagnose the issue',
      'Missing that "System.OutOfMemoryException" needs memory investigation, not application reinstall'
    ],
    causes: [
      '.NET application bug — null reference, argument out of range, etc.',
      'Out of memory (System.OutOfMemoryException)',
      'Corrupt application installation or missing assembly',
      'Incompatible .NET runtime version',
      'Database connection failure causing exception in data access layer',
      'File system permission error throwing UnauthorizedAccessException'
    ],
    steps: [
      'Filter Application log for Event 1026',
      'Read the full event message — it contains the exception type and stack trace',
      'Note the exception type: NullReferenceException, OutOfMemoryException, etc.',
      'Note the innermost exception and the stack frame it occurred in',
      'If OutOfMemoryException: investigate available memory and application memory usage',
      'Provide the full exception and stack trace to the software vendor',
      'Check for application updates that may have fixed the bug',
      'Correlate with .NET version: [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription'
    ],
    symptoms: [
      '.net error',
      'dotnet crash',
      '.net application crashed',
      '.net runtime error',
      'net framework error',
      'application error 1026',
      'managed code crash',
      'c# application crash',
      'asp.net error',
      '.net exception'
    ],
    tags: ['dotnet', 'runtime', 'exception', 'application-crash', 'managed-code'],
    powershell: `# .NET Runtime Error Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = '.NET Runtime'
    Id           = 1026
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Sort-Object TimeCreated -Descending |
    Format-List`,
    related_ids: [1000, 1001, 1002],
    ms_docs: 'https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run'
  },

  {
    id: 1530,
    source: 'Microsoft-Windows-User Profiles Service',
    channel: 'Application',
    severity: 'Warning',
    skill_level: 'Beginner',
    title: 'User Profile Registry Still In Use at Logoff',
    short_desc: 'Windows could not cleanly unload a user\'s registry hive at logoff — can cause slow logins, profile corruption, and temporary profiles.',
    description: 'Event ID 1530 from the User Profiles Service is generated when a user logs off but Windows cannot fully unload their registry hive (NTUSER.DAT) because one or more processes still have it open. Windows logs the offending processes in the event details. The immediate consequence is that the profile is not cleanly saved — on the next login, Windows may load a temporary profile instead of the user\'s real profile, causing the user to lose desktop settings, saved passwords, and application preferences. This event is responsible for the common support complaint: "all my settings are gone and my desktop is blank." Recurring Event 1530 means the offending process should be identified and addressed.',
    why_it_happens: 'When a user logs off, Windows attempts to unload the user registry hive. If any process (antivirus, backup agent, indexing service, or a misbehaving application) still has a handle to any key in HKEY_CURRENT_USER, the unload fails. Windows proceeds with logoff but cannot flush the hive cleanly. Subsequent logins may find the hive locked and load a fresh temporary profile instead. Common offenders: antivirus real-time scanning, Outlook holding its profile key, Windows Search indexing, and background sync agents.',
    what_good_looks_like: 'Occasional single occurrences (e.g., during a forced logoff) are low priority. Investigate: recurring Event 1530 for the same user, users reporting blank desktops or missing settings after login, or Event 1530 immediately before a user reports a "temporary profile" login.',
    common_mistakes: [
      'Rebuilding the user profile without first finding and fixing the root cause — Event 1530 will keep occurring',
      'Not reading the event details — the offending process is listed in the event, which tells you exactly what to fix',
      'Not restarting the offending service before attempting profile repair'
    ],
    causes: [
      'Antivirus scanning NTUSER.DAT at logoff',
      'Outlook or Office holding profile registry keys open',
      'Windows Search (SearchIndexer) indexing the profile',
      'Backup agent with handles to user registry',
      'Application crashed and left handles open',
      'Remote desktop session not cleanly terminated'
    ],
    steps: [
      'Read the event details — it lists the process(es) holding the registry hive open',
      'If it is antivirus: add NTUSER.DAT to the AV exclusion list, or configure the AV to release handles at logoff',
      'If it is SearchIndexer: restart the Windows Search service or rebuild the index',
      'If the user is already getting temporary profiles: copy their real profile data from C:\\Users\\<username>.bak',
      'To force a clean profile copy: log in as admin, copy settings from the old profile to the new one',
      'For recurring issue: use Process Monitor (Sysinternals) filtered to NTUSER.DAT to catch the offending process in real time'
    ],
    symptoms: [
      'blank desktop after login',
      'all settings gone',
      'temporary profile',
      'desktop is empty',
      'profile not loading',
      'settings reset after reboot',
      'user profile error',
      'slow login',
      'my documents missing',
      'preferences lost'
    ],
    tags: ['profile', 'registry', 'logoff', 'login', 'settings', 'temporary-profile', 'corruption'],
    powershell: `# User Profile Registry Issue Investigation
# Eventful

# Recent profile unload failures
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Microsoft-Windows-User Profiles Service'
    Id           = 1530
    StartTime    = (Get-Date).AddDays(-14)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Check for temporary profiles loaded currently
Get-WmiObject Win32_UserProfile |
    Where-Object { $_.Special -eq $false } |
    Select-Object LocalPath, Loaded, LastUseTime, Status |
    Format-Table -AutoSize`,
    related_ids: [1000],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/fix-user-profile-corrupted'
  },

  {
    id: 1008,
    source: 'Microsoft-Windows-Perflib',
    channel: 'Application',
    severity: 'Warning',
    skill_level: 'Beginner',
    title: 'Performance Counter Provider Error (Usually Harmless)',
    short_desc: 'A performance counter provider returned an error. Appears constantly in most Application logs — almost always harmless noise.',
    description: 'Event ID 1008 from Perflib (Performance Library) is generated when a performance counter provider — a component that feeds data to Performance Monitor, Task Manager, or third-party monitoring tools — returns an error or fails to respond. Like Event 10016 (DCOM), this event appears in nearly every Windows Application log and is almost never the cause of user-reported problems. Windows has many built-in performance counter providers; some are buggy or register but provide no data, generating 1008 continuously. The event names the provider that failed. In the vast majority of IT support cases, 1008 is background noise. It only warrants investigation if a monitoring tool or application that specifically uses performance counters is broken.',
    why_it_happens: 'Third-party software installs performance counter providers during installation and sometimes fails to cleanly remove them on uninstall, leaving broken registrations. Windows built-in providers can also fail if the underlying service they monitor is not running. The Perflib subsystem logs 1008 whenever it calls a provider and gets back an unexpected error or timeout.',
    what_good_looks_like: 'Present in virtually every Windows Application log — this is normal. Only investigate 1008 if: Performance Monitor or a monitoring application that uses perf counters is broken, or the named provider matches a recently uninstalled application.',
    common_mistakes: [
      'Assuming Event 1008 is causing the reported problem — it almost never is',
      'Spending time rebuilding performance counters when the user\'s complaint is unrelated'
    ],
    causes: [
      'Broken performance counter registration left by uninstalled software (expected after uninstalls)',
      'Built-in provider for a service that is stopped or disabled',
      'Corrupted performance counter database'
    ],
    steps: [
      'Check if Event 1008 matches a recently uninstalled application — if so, ignore it',
      'If Performance Monitor or monitoring tools are actually broken: rebuild perf counters',
      'Rebuild performance counters: lodctr /r (run as admin from elevated command prompt)',
      'If specific provider named: check if the associated service/application is installed and running',
      'Otherwise: look elsewhere for the actual cause of the user\'s complaint'
    ],
    symptoms: [
      'performance counter error',
      'perflib error',
      'lots of warnings in application log',
      'event log warnings',
      'performance monitor not working',
      'task manager shows 0'
    ],
    tags: ['performance', 'perflib', 'noise', 'harmless', 'counter', 'warning', 'common'],
    powershell: `# Performance Counter Error Summary
# Eventful — Usually harmless. Check which provider is named.

Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Microsoft-Windows-Perflib'
    Id           = 1008
    StartTime    = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Group-Object { ($_ | Select-Object -ExpandProperty Message).Substring(0, 80) } |
    Select-Object Count, Name |
    Sort-Object Count -Descending | Format-Table -AutoSize

# Rebuild performance counters if actually needed
# Run as admin: lodctr /r`,
    related_ids: [1000],
    ms_docs: null
  },

  {
    id: 1033,
    source: 'MsiInstaller',
    channel: 'Application',
    severity: 'Information',
    skill_level: 'Beginner',
    title: 'Software Installed or Removed',
    short_desc: 'Windows Installer recorded a software installation, removal, or update — useful for correlating "started after installing X" complaints.',
    description: 'Event ID 1033 (and related 1034, 11707) from MsiInstaller is written whenever a Windows Installer (MSI) package is installed, updated, or removed. It records the product name, version, manufacturer, and whether the operation succeeded. This event is invaluable for the common support scenario: a user says "my computer started crashing / running slowly / application stopped working — nothing changed" — checking MsiInstaller events often reveals a software install or update that happened just before the problems began. Related event 1034 covers uninstallation, and 11707/11708 cover installation success/failure in older MSI formats.',
    why_it_happens: 'Written by the Windows Installer service (msiexec.exe) on completion of any MSI-based install or remove operation. Not all software uses MSI — modern installers (MSIX, Squirrel, Inno Setup, NSIS) may not produce this event — but most enterprise and traditional desktop software does.',
    what_good_looks_like: 'Correlate timestamps with reported problem onset. Expected installs (Windows Update components, known software rollouts) are normal. Investigate: installs that coincide exactly with when a user says problems started, software installed outside business hours, unrecognised software, or multiple rapid installs from the same manufacturer.',
    causes: [
      'User or admin installing software',
      'Windows Update installing components via MSI',
      'Software auto-updater running in background',
      'IT management tool pushing a deployment',
      'Malware installer (if software name is unrecognised)'
    ],
    steps: [
      'Filter Application log for Event 1033 and 1034 around the time problems started',
      'Note the product name, version, and manufacturer',
      'If a suspicious install coincides with problem onset: uninstall it and test',
      'Cross-reference with Event 1000 (app crashes) timestamps — did crashes start after the install?',
      'For Windows Update MSI components: check Windows Update history in Settings for the same timeframe',
      'To see all recently installed software: Get-WmiObject Win32_Product | Sort-Object InstallDate -Descending'
    ],
    symptoms: [
      'started after installing something',
      'problem after update',
      'new software causing issues',
      'software install timeline',
      'what was installed recently',
      'crashes after software update',
      'application conflict'
    ],
    tags: ['installer', 'msi', 'software', 'installation', 'timeline', 'change-tracking'],
    powershell: `# Software Installation History
# Eventful

# MSI install/remove events (last 30 days)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'MsiInstaller'
    Id           = @(1033, 1034, 11707, 11708)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $type = switch ($_.Id) {
        1033  { 'INSTALLED'   }
        1034  { 'REMOVED'     }
        11707 { 'SUCCESS'     }
        11708 { 'FAILED'      }
    }
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Type    = $type
        Message = $_.Message.Substring(0, [Math]::Min(120, $_.Message.Length))
    }
} | Sort-Object Time -Descending | Format-Table -AutoSize`,
    related_ids: [1000, 1002, 11708],
    ms_docs: null
  },

  {
    id: 11708,
    source: 'MsiInstaller',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Beginner',
    title: 'Software Installation Failed',
    short_desc: 'A Windows Installer package failed to install — records the product name and error code.',
    description: 'Event ID 11708 from MsiInstaller is written when an MSI installation fails. It records the product name and the error code. This pairs with Event 1033 (which records successful installs) to give a complete picture of software change activity. Installation failures are relevant in IT support when: a user cannot install required software, a Windows Update component fails to install via MSI, or a deployment tool reports installation failure. The error code in the event maps to a specific failure reason. Common codes: 1603 = fatal error during installation (permissions, disk space, conflicting process), 1618 = another installation already in progress, 1619 = package file not found.',
    why_it_happens: 'MSI installations fail for several reasons: insufficient permissions (the installer needs admin rights), the package requires a reboot from a previous install before it can proceed, disk space is insufficient, the package is corrupt, a prerequisite is missing, or antivirus is blocking the installer from writing files.',
    what_good_looks_like: 'Absence is ideal. Occasional 11708 for background auto-updaters that retry successfully is low priority. Investigate: 11708 for software a user is actively trying to install, repeated 11708 for the same product (blocked by a persistent condition), or 11708 for a Windows component that is required for system functionality.',
    causes: [
      'Installation run without administrator rights',
      'Pending reboot blocking installation (error 1618)',
      'Insufficient disk space on C:',
      'Antivirus blocking installer file operations',
      'Corrupt MSI package',
      'Missing prerequisite (e.g., required .NET version not installed)',
      'Conflicting software already installed'
    ],
    steps: [
      'Note the error code from the event',
      '1603: Run installer as admin, check disk space, check AV exclusions, check for pending reboot',
      '1618: Another installer is running — wait and retry, or reboot first',
      '1619: Package file path is missing or inaccessible',
      'Enable verbose MSI logging: msiexec /i package.msi /l*v install.log',
      'Check the verbose log for the exact line that failed',
      'Check free disk space: Get-PSDrive C | Select-Object Used, Free'
    ],
    symptoms: [
      'installation failed',
      'software wont install',
      'msi error',
      'setup failed',
      'install error 1603',
      'cannot install application',
      'deployment failed'
    ],
    tags: ['installer', 'msi', 'installation', 'failure', 'error', 'software'],
    powershell: `# Installation Failure Details
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'MsiInstaller'
    Id           = @(11708, 1033, 1034)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Enable verbose MSI logging for next install attempt:
# msiexec /i "C:\path\to\package.msi" /l*v "C:\install-log.txt"`,
    related_ids: [1033, 1000],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-error-messages'
  }
];
