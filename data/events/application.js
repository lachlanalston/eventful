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
  }
];
