export const iisEvents = [
  {
    id: 5002,
    source: 'Microsoft-Windows-WAS',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'IIS Application Pool Stopped — Worker Process Failure',
    short_desc: 'Windows Process Activation Service (WAS) stopped an app pool after repeated worker process failures.',
    description: 'Event 5002 from Microsoft-Windows-WAS (Windows Activation Service) is logged when an IIS application pool is taken offline after a series of rapid worker process (w3wp.exe) crashes or failures to start. IIS has a rapid fail protection threshold (default: 5 failures in 5 minutes) and will disable the pool automatically to prevent system instability. All sites in that app pool begin returning 503 Service Unavailable.',
    why_it_happens: 'App pools enter rapid-fail protection when the worker process crashes repeatedly without recovering. Common causes include unhandled .NET exceptions on startup, missing DLLs or dependencies, incorrect service account credentials, or a misconfigured web.config. WAS disables the pool to prevent a crash loop from consuming all server resources.',
    what_good_looks_like: 'App pool in "Started" state. No 5002/5011 events in System log. Worker process w3wp.exe running stably without restarts. Application Event log has no related 1000/1026 crash events.',
    common_mistakes: [
      'Restarting the app pool without investigating why it crashed — it will crash again',
      'Not correlating with Application log Event 1000 (crash) or 1026 (.NET exception) which will explain the actual failure',
      'Forgetting that the app pool identity (service account) credentials may have expired or been changed',
      'Not checking the IIS Worker Process Identity — it needs access to the application folder and its dependencies'
    ],
    causes: [
      'Worker process crashing due to unhandled .NET or native exception',
      'App pool identity account password expired or changed',
      'Missing or inaccessible application dependencies on startup',
      'web.config syntax error or misconfiguration',
      'Rapid memory pressure causing repeated worker process recycling',
      'Corrupt IIS application or module failing to load'
    ],
    steps: [
      'Open IIS Manager → Application Pools — note which pool is stopped',
      'Check System log for Event 5002 and note the app pool name',
      'Check Application log for Event 1000 (crash) or 1026 (.NET) around the same time',
      'Review IIS log files in C:\\inetpub\\logs\\LogFiles for 503 or startup error details',
      'Verify the app pool identity account and password: IIS Manager → Application Pools → Advanced Settings → Identity',
      'Check folder permissions for the web application root — pool identity needs Read (and Modify if writes needed)',
      'Temporarily enable Failed Request Tracing in IIS for detailed error capture'
    ],
    symptoms: [
      'IIS website returning 503',
      'IIS app pool stopped',
      'website not working 503 error',
      'IIS application pool crashed',
      'web app not responding',
      'IIS worker process crashed',
      'app pool disabled by rapid fail',
      'website down IIS error',
      'w3wp.exe crash',
      'application pool keeps stopping'
    ],
    tags: ['iis', 'app-pool', 'was', '503', 'w3wp', 'web-server'],
    powershell: `# IIS App Pool Status and Crash Investigation
# Eventful

# List all app pools and their current state
Import-Module WebAdministration -ErrorAction SilentlyContinue
Get-WebConfiguration system.applicationHost/applicationPools/add |
    Select-Object name, state, autoStart, @{N='Identity'; E={$_.processModel.userName}} |
    Format-Table -AutoSize

# Recent WAS events (5002, 5011, 5059 = stop/failure events)
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WAS'
    Id           = @(5002, 5011, 5059)
    StartTime    = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Co-occurring app crashes
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Application Error'
    Id           = 1000
    StartTime    = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending |
    Select-Object -First 5 | Format-List`,
    related_ids: [5011, 5059, 1000, 1026],
    ms_docs: 'https://learn.microsoft.com/en-us/iis/manage/managing-your-configuration-settings/an-overview-of-feature-delegation-in-iis'
  },

  {
    id: 5011,
    source: 'Microsoft-Windows-WAS',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'IIS Application Pool Identity Could Not Log On',
    short_desc: 'IIS app pool failed to start because its identity account could not authenticate.',
    description: 'Event 5011 from WAS indicates the application pool failed to start because the configured identity account could not be authenticated. The app pool will not start, and all sites assigned to it will return 503. This is a credential or account problem — most commonly an expired password, a locked account, or a mistyped username.',
    why_it_happens: 'When IIS starts an app pool, WAS uses the configured identity to create the worker process token. If the password is wrong, the account is disabled, or the account no longer has the "Log On As a Service" or "Log On As a Batch Job" right, WAS cannot create the process and logs Event 5011.',
    what_good_looks_like: 'App pool starts cleanly with Event 5019 (worker process started successfully). No 5011 errors. Service account password managed by GMSA (group managed service account) to eliminate password rotation issues.',
    common_mistakes: [
      'Rotating a service account password without updating it in IIS app pool settings',
      'Using a regular user account instead of a managed service account (gMSA) for app pools',
      'Locking the service account through too many failed logon attempts (which may be the old password still configured in IIS)'
    ],
    causes: [
      'App pool identity account password has expired or been changed',
      'Account disabled in Active Directory',
      'Account locked due to repeated authentication failures',
      '"Log On As a Service" right removed from the account',
      'Typo in account name or domain in IIS app pool identity settings'
    ],
    steps: [
      'Open IIS Manager → Application Pools → select the failing pool → Advanced Settings → Process Model → Identity',
      'Verify the account name and password are correct',
      'Check the account status in AD: Get-ADUser <username> | Select Enabled, LockedOut, PasswordExpired',
      'If using a service account, reset the password and update it in IIS',
      'Consider migrating to ApplicationPoolIdentity (built-in virtual account) or a gMSA',
      'After fixing credentials, restart the app pool: Restart-WebAppPool -Name "<poolname>"',
      'Check Event 4625 in Security log for the logon failure details'
    ],
    symptoms: [
      'IIS app pool cannot start',
      'app pool identity logon failed',
      'IIS service account wrong password',
      'website 503 after password change',
      'IIS app pool account locked',
      'application pool identity error',
      'IIS not starting account problem'
    ],
    tags: ['iis', 'app-pool', 'was', 'service-account', '503', 'credentials'],
    powershell: `# Check IIS App Pool Identity Account Status
# Eventful

Import-Module WebAdministration -ErrorAction SilentlyContinue

# Get all app pools and their identities
Get-WebConfiguration system.applicationHost/applicationPools/add |
    Select-Object name, @{N='IdentityType'; E={$_.processModel.identityType}},
        @{N='UserName'; E={$_.processModel.userName}} |
    Format-Table -AutoSize

# Check if a specific service account is locked or expired
# $user = Get-ADUser "svc-iispool" -Properties LockedOut, Enabled, PasswordExpired
# $user | Select-Object Name, Enabled, LockedOut, PasswordExpired | Format-List

# Restart a specific app pool
# Restart-WebAppPool -Name "DefaultAppPool"`,
    related_ids: [5002, 5059, 4625],
    ms_docs: 'https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities'
  },

  {
    id: 5059,
    source: 'Microsoft-Windows-WAS',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'IIS — Worker Process Startup Failed',
    short_desc: 'WAS could not start a worker process for an application pool.',
    description: 'Event 5059 is logged by WAS when it attempts to start a worker process (w3wp.exe) for an application pool and the process fails to start, start within the timeout, or register with WAS. This is a broader failure than 5011 (which is specifically a credentials issue) and can indicate missing executables, permissions errors, or a broken IIS installation.',
    why_it_happens: 'Worker process startup can fail for many reasons: the w3wp.exe executable is missing or corrupt, IIS ISAPI filters are broken, .NET Framework installation is corrupt, or the system is under extreme resource pressure. WAS logs 5059 and eventually 5002 (pool disabled) if startup consistently fails.',
    what_good_looks_like: 'App pools start cleanly. System log shows 5019 (worker started) not 5059. IIS site responds within startup timeout.',
    common_mistakes: [
      'Not running "iisreset" and checking if IIS itself starts cleanly after a failed reboot',
      'Forgetting to repair .NET Framework after a failed update or upgrade',
      'Not checking if disk space is available for IIS logs and temp files'
    ],
    causes: [
      'w3wp.exe or required IIS binaries missing or corrupt',
      '.NET Framework registration with IIS broken',
      'Insufficient disk space for IIS temporary files',
      'IIS module configuration error preventing startup',
      'System resource exhaustion (out of memory, handles)'
    ],
    steps: [
      'Run: iisreset /noforce — if IIS does not start, investigate further',
      'Check IIS installation integrity: dism /online /enable-feature /featurename:IIS-WebServer',
      'Re-register .NET with IIS: %windir%\\Microsoft.NET\\Framework64\\<version>\\aspnet_regiis.exe -i',
      'Check disk space on the system drive and IIS log drive',
      'Review IIS Setup log: C:\\Windows\\System32\\inetsrv\\setupapi.log',
      'Try restarting WAS service: Restart-Service WAS'
    ],
    symptoms: [
      'IIS worker process failed to start',
      'IIS not starting after reboot',
      'all IIS websites down',
      'w3wp failed to launch',
      'IIS 503 all sites',
      'WAS service error IIS'
    ],
    tags: ['iis', 'was', 'w3wp', 'app-pool', 'startup', 'web-server'],
    powershell: `# IIS Service and Worker Process Status
# Eventful

# IIS service status
Get-Service W3SVC, WAS, WMSVC -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize

# Running w3wp processes
Get-Process w3wp -ErrorAction SilentlyContinue |
    Select-Object Id, WorkingSet, CPU, StartTime | Format-Table -AutoSize

# WAS errors
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WAS'
    Level        = @(1, 2, 3)
    StartTime    = (Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [5002, 5011, 1000],
    ms_docs: 'https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-8/iis-80-using-aspnet-35-and-aspnet-45'
  },

  {
    id: 1309,
    source: 'ASP.NET 4.0.30319.0',
    channel: 'Application',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'ASP.NET Unhandled Exception in Request',
    short_desc: 'An ASP.NET web application threw an unhandled exception while processing a request.',
    description: 'Event 1309 from ASP.NET is logged to the Application event log when an unhandled exception occurs during web request processing. The event includes the exception type, message, and a partial stack trace. While the application typically returns a 500 error to the browser, the root cause details are in this event. Frequent 1309 events indicate an application code bug, a missing dependency, or a misconfiguration.',
    why_it_happens: 'ASP.NET logs this event when an exception propagates up to the HttpApplication level without being caught by application code. Common causes: database connection failures, missing configuration keys in web.config, null reference exceptions in request handlers, and file/resource access errors.',
    what_good_looks_like: 'No 1309 events. Application returns 200 responses. If occasional 1309 events are expected (user errors), they should not include system-level exceptions like SqlException or FileNotFoundException.',
    common_mistakes: [
      'Not looking at the stack trace in the event — it usually points directly to the failing method',
      'Fixing the symptom (500 error page) instead of the root cause in the application',
      'Not enabling detailed errors or custom error logging in the application to capture full stack traces'
    ],
    causes: [
      'Database connection failure (wrong connection string, DB offline)',
      'Missing required key in web.config or appSettings',
      'Null reference exception in application code',
      'File or resource the application depends on is missing',
      'Unhandled exception in async code path',
      'Third-party library throwing unexpected exception'
    ],
    steps: [
      'Open Application log, filter for source "ASP.NET*" and Event 1309',
      'Read the exception type and message — SqlException = database issue, FileNotFoundException = missing file',
      'Read the stack trace to identify the failing method and line number',
      'Enable detailed error logging in web.config: <customErrors mode="Off"/> temporarily',
      'Check web application logs if the app has its own logging (e.g., NLog, Serilog)',
      'Test the failing operation manually if reproducible',
      'Check the application\'s database connection string and database availability'
    ],
    symptoms: [
      'website returning 500 error',
      'ASP.NET error 500',
      'web application throwing exceptions',
      'website internal server error',
      'ASP.NET application crash',
      'web app error after update',
      'IIS 500 internal error',
      'ASP.NET unhandled exception'
    ],
    tags: ['iis', 'asp.net', 'web-application', '500', 'exception', 'request'],
    powershell: `# ASP.NET Application Errors
# Eventful

# Recent ASP.NET exceptions (1309 = unhandled, 1310 = error handled)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'ASP.NET 4.0.30319.0'
    Id           = @(1309, 1310)
    StartTime    = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Select-Object -First 10 | Format-List

# Also check for .NET CLR exceptions (Event 1026)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = '.NET Runtime'
    Id           = 1026
    StartTime    = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending |
    Select-Object -First 5 | Format-List`,
    related_ids: [5002, 1000, 1026],
    ms_docs: 'https://learn.microsoft.com/en-us/aspnet/web-forms/overview/getting-started/'
  },

  {
    id: 1026,
    source: '.NET Runtime',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: '.NET Runtime — Unhandled Exception (Application Crash)',
    short_desc: 'A .NET application crashed due to an unhandled exception — full exception and stack trace logged.',
    description: 'Event 1026 from ".NET Runtime" is logged when a .NET application crashes due to an unhandled exception that terminates the process. Unlike Event 1000 (which only gives module info), Event 1026 contains the full exception type, message, and stack trace. This is the most useful event for diagnosing .NET application crashes and should always be checked alongside Event 1000.',
    why_it_happens: 'When a .NET application throws an exception that is not caught anywhere in the call stack, the .NET runtime terminates the process and logs the full exception details to the Application event log. This applies to WinForms, WPF, console apps, Windows services, and IIS-hosted apps (which also generate Event 1309).',
    what_good_looks_like: 'No 1026 events. Applications handle expected exceptions and log them internally. Only truly unexpected conditions cause process termination.',
    common_mistakes: [
      'Reading only Event 1000 and missing the detailed stack trace in Event 1026',
      'Not searching for the exception type in the vendor\'s known issues database',
      'Not checking if a newer version of the application or .NET runtime fixes the issue',
      'Ignoring OutOfMemoryException — this is not just a code bug, it may indicate a memory leak or undersized server'
    ],
    causes: [
      'Unhandled exception in application code (null reference, argument, index out of range)',
      'Unhandled exception in async Task that was not awaited',
      'OutOfMemoryException due to memory leak or insufficient RAM',
      'StackOverflowException from infinite recursion',
      'Application crashed on startup due to missing .NET dependency'
    ],
    steps: [
      'Open Application log, filter for source ".NET Runtime" and Event 1026',
      'Read the exception type: NullReferenceException, OutOfMemoryException, etc.',
      'Read the stack trace to identify the exact method and line number that threw',
      'Check if vendor has released a fix for this exception type in recent updates',
      'If OutOfMemoryException: check memory usage with Task Manager or Process Monitor',
      'Enable .NET crash dump collection: procdump -e 1 -p <pid> C:\\dumps\\ for next occurrence',
      'Cross-reference with Event 1000 for the faulting module information'
    ],
    symptoms: [
      '.NET application crash',
      'application crashed with exception',
      'unhandled exception dotnet',
      '.net runtime error',
      'application stopped working dotnet',
      'null reference exception crash',
      'dotnet app crash log',
      'managed application crash',
      'c# application crash event log'
    ],
    tags: ['dotnet', 'application', 'crash', 'exception', 'runtime', 'managed-code'],
    powershell: `# .NET Application Crash Investigation
# Eventful

$startTime = (Get-Date).AddDays(-7)

# Full .NET crash details (1026)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = '.NET Runtime'
    Id           = 1026
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Select-Object -First 5 | Format-List

# Corresponding WER crash record (1000)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Application Error'
    Id           = 1000
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Select-Object -First 5 | Format-List`,
    related_ids: [1000, 1002, 1309, 5002],
    ms_docs: 'https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions'
  }
];
