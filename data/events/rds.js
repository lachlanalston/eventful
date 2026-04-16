export const rdsEvents = [
  {
    id: 21,
    source: 'Microsoft-Windows-TerminalServices-LocalSessionManager',
    channel: 'RDS',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'RDS: Session Logon Successful',
    short_desc: 'A user successfully logged on to a Remote Desktop Services session.',
    description: 'Event ID 21 from the TerminalServices-LocalSessionManager is generated on the RDS host when a user successfully establishes and logs on to a Remote Desktop session. It records the username, domain, session ID, and the source network address of the connecting client. This is the RDS-specific equivalent of Security Event 4624 Type 10, and provides more RDS-specific context. It is the primary event to check when verifying who has connected to an RDS server.',
    why_it_happens: 'The Local Session Manager (LSM) on the RDS host manages all session lifecycle events. When a user completes authentication (handled by 1149 and Security events) and their session is created and initialized, the LSM logs Event 21 to record the successful logon. The session ID in this event can be used to correlate with other RDS events (22, 23, 24, 25, 40) for the full session lifecycle.',
    what_good_looks_like: 'Expected: known users connecting during business hours from known IP ranges. Investigate: logons outside business hours for non-on-call staff, logons from unexpected IP addresses (not corporate VPN or known client locations), a user logging on to many sessions simultaneously, admin accounts logging on via RDS to servers they don\'t normally manage.',
    common_mistakes: [
      'Only checking Security Event 4624 and missing the RDS-specific session detail in Event 21',
      'Not using the Session ID to correlate the full session timeline (21 → 22 → 24/25/40 → 23)',
      'Ignoring the Source Network Address field which tells you where the connection came from'
    ],
    causes: [
      'Authorised user connecting for work',
      'Admin connecting for management',
      'Automated process using RDP',
      'Attacker using compromised credentials to connect',
      'Session reconnection (look for Event 25 instead)'
    ],
    steps: [
      'Filter Microsoft-Windows-TerminalServices-LocalSessionManager log for Event 21',
      'Note "User", "Session ID", and "Source Network Address"',
      'Verify user is authorised and the source IP is expected',
      'Track the session lifecycle using Session ID with Events 22, 24, 25, 40, 23',
      'Correlate Source Network Address with your asset/user inventory',
      'If suspicious: check concurrent sessions from same account or IP'
    ],
    symptoms: [
      'rdp login',
      'remote desktop logon',
      'rds session started',
      'who connected via rdp',
      'terminal services logon',
      'remote desktop session started',
      'rds user connected'
    ],
    tags: ['rdp', 'rds', 'remote-desktop', 'logon', 'terminal-services', 'session'],
    powershell: `# RDS Session Logon Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id           = 21
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $ud   = $xml.Event.UserData.EventXML
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        User           = $ud.User
        SessionID      = $ud.SessionID
        SourceIP       = $ud.Address
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [22, 23, 24, 25, 40, 1149, 4624],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-outside-access'
  },

  {
    id: 22,
    source: 'Microsoft-Windows-TerminalServices-LocalSessionManager',
    channel: 'RDS',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'RDS: Shell Start Notification',
    short_desc: 'The user\'s shell (Explorer or application) started in their RDS session.',
    description: 'Event ID 22 is generated when the user\'s shell or initial application starts within their Remote Desktop session. It typically follows Event 21 (logon) immediately and indicates the session is fully established and the user has access to their desktop environment. This event is useful for measuring session start time (time between Event 21 and 22 indicates logon processing duration) and for confirming the session progressed past simple authentication to full desktop access.',
    why_it_happens: 'After the session is created and logon succeeds (Event 21), the Session Manager starts the user\'s shell process — typically explorer.exe or, in RemoteApp mode, the published application. Event 22 is logged when this process successfully initialises. A significant gap between 21 and 22 indicates slow logon processing (profile loading, Group Policy, logon scripts).',
    what_good_looks_like: 'Normal: Event 22 appears within a few seconds of Event 21. Investigate: sessions where 22 never appears after 21 (session may be stuck in logon), large time gaps between 21 and 22 (slow logon — investigate GPO, profile, or slow profile path).',
    common_mistakes: [
      'Not measuring the gap between Events 21 and 22 to diagnose slow logon times',
      'Confusing slow shell start with slow authentication — if 21 is quick but 22 is delayed, the authentication is fine but logon is slow'
    ],
    causes: [
      'Normal session establishment following successful authentication',
      'Slow logon scripts or Group Policy (causes delay between 21 and 22)',
      'Large roaming profile loading slowly',
      'Antivirus scanning profile on first load'
    ],
    steps: [
      'Filter TerminalServices-LocalSessionManager log for Event 22',
      'Correlate with Event 21 using Session ID',
      'Calculate time delta between 21 and 22 — more than 30 seconds warrants investigation',
      'If slow: check GPO processing (Event 4001 in System log), profile size, and logon scripts',
      'Use UE-V or FSLogix profiling if large profiles are causing delays'
    ],
    symptoms: [
      'rdp logon slow',
      'remote desktop slow to load',
      'rds desktop slow to appear',
      'remote desktop login takes forever',
      'terminal services slow logon',
      'rdp session slow to start'
    ],
    tags: ['rdp', 'rds', 'shell', 'logon', 'performance', 'session'],
    powershell: `# RDS Shell Start Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id           = @(21, 22)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $ud  = $xml.Event.UserData.EventXML
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID     = $_.Id
        EventType   = if ($_.Id -eq 21) { 'Session Logon' } else { 'Shell Started' }
        User        = $ud.User
        SessionID   = $ud.SessionID
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [21, 23, 24, 25, 40],
    ms_docs: null
  },

  {
    id: 23,
    source: 'Microsoft-Windows-TerminalServices-LocalSessionManager',
    channel: 'RDS',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'RDS: Session Logoff',
    short_desc: 'A user fully logged off from an RDS session — session resources released.',
    description: 'Event ID 23 records a complete logoff from an RDS session — the user has signed out, all their session processes have terminated, and the session has been destroyed. This is distinct from a disconnect (Event 24) — a disconnect leaves the session alive. Event 23 is the definitive "session ended" event. Use it to calculate session duration (time between Event 21 and Event 23) and to confirm users are logging off rather than disconnecting (disconnected sessions consume memory on the RDS host).',
    why_it_happens: 'When a user logs off via Start → Sign Out, closes all RemoteApp windows, or is logged off by a session policy, the LSM terminates all session processes, cleans up the session, and logs Event 23. Sessions can also be forcibly logged off by an administrator.',
    what_good_looks_like: 'Expected: Event 23 should follow every Event 21 eventually. Users should log off, not just disconnect. Investigate: sessions with no Event 23 after disconnect (accumulating disconnected sessions), very short sessions (may indicate authentication or configuration problems), admin logging off other users\' sessions.',
    common_mistakes: [
      'Not distinguishing between logoff (23) and disconnect (24) — disconnected sessions linger and consume RAM',
      'Not having session timeout policies to force logoff of long-disconnected sessions'
    ],
    causes: [
      'User manually logging off',
      'Admin forcibly logging off a session',
      'Session idle timeout policy logging off disconnected session',
      'RemoteApp session closed when last published app closed'
    ],
    steps: [
      'Filter TerminalServices-LocalSessionManager log for Event 23',
      'Correlate with Event 21 using Session ID to calculate session duration',
      'Count Event 24 (disconnects) vs Event 23 (logoffs) — high disconnect ratio means users aren\'t logging off',
      'Check session timeout policy: Get-RDSessionCollectionConfiguration -CollectionName <name>',
      'Query active/disconnected sessions: qwinsta /server:<server>'
    ],
    symptoms: [
      'user logged off rdp',
      'rdp session ended',
      'remote desktop session closed',
      'rds logoff',
      'terminal session ended',
      'rdp disconnected and logged off'
    ],
    tags: ['rdp', 'rds', 'logoff', 'session', 'lifecycle'],
    powershell: `# RDS Session Logoff Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id           = @(21, 23)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $ud  = $xml.Event.UserData.EventXML
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID     = $_.Id
        EventType   = if ($_.Id -eq 21) { 'Logon' } else { 'Logoff' }
        User        = $ud.User
        SessionID   = $ud.SessionID
    }
} | Sort-Object SessionID, TimeCreated | Format-Table -AutoSize`,
    related_ids: [21, 22, 24, 25, 40],
    ms_docs: null
  },

  {
    id: 24,
    source: 'Microsoft-Windows-TerminalServices-LocalSessionManager',
    channel: 'RDS',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'RDS: Session Disconnected',
    short_desc: 'A user disconnected from their RDS session without logging off — session remains in memory.',
    description: 'Event ID 24 records when a user disconnects from an RDS session without logging off. The session remains alive on the server — all their applications continue running, all their documents remain open. The user can reconnect later and pick up where they left off (Event 25). While convenient for users, accumulated disconnected sessions consume significant RAM on RDS servers. Event 24 should be monitored to detect users who are not logging off as required by policy.',
    why_it_happens: 'A disconnect occurs when the RDP client closes without sending a logoff (closing the RDP window with the X button, network interruption, or locking the client machine). The RDS host detects the loss of the RDP channel and transitions the session to "Disconnected" state while keeping all session processes running. The Session ID is preserved for potential reconnection.',
    what_good_looks_like: 'Some disconnects are normal (network blips, laptop lid close). Investigate: sessions that have been disconnected for days without reconnecting (likely abandoned), a pattern of users disconnecting but never logging off (consuming unnecessary resources), disconnects at unusual times that may indicate network issues.',
    common_mistakes: [
      'Treating disconnect (24) as the same as logoff (23) — disconnected sessions keep running and consuming memory',
      'Not having session timeout policies that log off long-disconnected sessions',
      'Not querying qwinsta to find the current state of sessions on the RDS server'
    ],
    causes: [
      'User closed RDP window without logging off',
      'Network interruption breaking the RDP connection',
      'Client machine locked or suspended',
      'RDP client crashed',
      'Admin-initiated disconnect'
    ],
    steps: [
      'Filter TerminalServices-LocalSessionManager log for Event 24',
      'Check if Event 25 (reconnect) follows — if not, the session is still disconnected',
      'Query current session state: qwinsta /server:<server>',
      'If sessions are accumulating as Disconnected: enforce logoff policy via GPO',
      'Forcibly log off stale sessions: logoff <sessionid> /server:<server>',
      'Set session policies: Computer Configuration → Policies → Admin Templates → Windows Components → Remote Desktop Services'
    ],
    symptoms: [
      'rdp disconnected',
      'remote desktop session disconnected',
      'rds session dropped',
      'rdp keeps disconnecting',
      'remote desktop connection dropped',
      'rdp session disconnected unexpectedly',
      'rds session drops randomly'
    ],
    tags: ['rdp', 'rds', 'disconnect', 'session', 'memory', 'lifecycle'],
    powershell: `# RDS Session Disconnect Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id           = 24
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $ud  = $xml.Event.UserData.EventXML
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        User        = $ud.User
        SessionID   = $ud.SessionID
        SourceIP    = $ud.Address
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# Show currently disconnected sessions
Write-Host "\`n--- Currently Disconnected Sessions ---" -ForegroundColor Cyan
qwinsta /server:$computer 2>$null | Where-Object { $_ -match 'Disc' }`,
    related_ids: [21, 23, 25, 40, 4779],
    ms_docs: null
  },

  {
    id: 25,
    source: 'Microsoft-Windows-TerminalServices-LocalSessionManager',
    channel: 'RDS',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'RDS: Session Reconnected',
    short_desc: 'A user reconnected to a previously disconnected RDS session.',
    description: 'Event ID 25 records when a user successfully reconnects to a previously disconnected RDS session. The existing session (with all its running applications) is resumed from the disconnected state. This is the expected follow-up to Event 24 (disconnect). The session ID remains the same as the original session. Event 25 is important for security because it can reveal when an attacker or other user reconnects to an existing session — especially if the connecting IP differs from the original session.',
    why_it_happens: 'When an RDP client connects to an RDS server and the server finds an existing disconnected session for that user, it reconnects the client to the existing session rather than creating a new one. The LSM logs Event 25 and the session state changes from Disconnected back to Active.',
    what_good_looks_like: 'Normal: Event 25 from the same IP as the original Event 21/24 logon. Investigate: Event 25 where the reconnecting IP differs from the original connection IP (possible session takeover), reconnections to sessions that were disconnected for an extended period, reconnections at unusual hours.',
    common_mistakes: [
      'Not comparing the source IP in Event 25 with the source IP in the original Event 21 — a change may indicate session hijacking',
      'Not correlating Event 25 with Security Event 4778 (both record RDP session reconnection)'
    ],
    causes: [
      'User reconnecting after network interruption',
      'User reconnecting after laptop lid open',
      'Admin reconnecting to their own disconnected session',
      'Another user reconnecting to an abandoned session (if policies allow)'
    ],
    steps: [
      'Filter TerminalServices-LocalSessionManager log for Event 25',
      'Match with preceding Event 24 using Session ID',
      'Compare Source Network Address in Event 25 vs original Event 21',
      'If IPs differ: investigate potential session hijacking',
      'Calculate how long the session was disconnected before reconnection'
    ],
    symptoms: [
      'rdp reconnected',
      'remote desktop reconnected',
      'rds session resumed',
      'reconnected to rdp',
      'remote session came back',
      'rdp reconnection'
    ],
    tags: ['rdp', 'rds', 'reconnect', 'session', 'lifecycle'],
    powershell: `# RDS Session Reconnect Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id           = 25
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $ud  = $xml.Event.UserData.EventXML
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        User        = $ud.User
        SessionID   = $ud.SessionID
        SourceIP    = $ud.Address
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [21, 23, 24, 40, 4778],
    ms_docs: null
  },

  {
    id: 40,
    source: 'Microsoft-Windows-TerminalServices-LocalSessionManager',
    channel: 'RDS',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'RDS: Session Disconnected with Reason Code',
    short_desc: 'An RDS session was disconnected — includes a reason code explaining why.',
    description: 'Event ID 40 records an RDS session disconnection with a specific reason code that explains the cause. The reason code is the most valuable part — it distinguishes between user-initiated disconnects, network failures, timeout-based disconnects, and protocol errors. This event appears in the TerminalServices-LocalSessionManager log and the RemoteConnectionManager log. Key reason codes: 0 = no information, 5 = client disconnect (user closed window), 11 = client disconnected with admin disconnected, 12 = session timeout, 5 = RPC error, 9 = RDP protocol error.',
    why_it_happens: 'When an RDS session disconnects, the terminal services stack determines why and records a reason code. This mechanism exists specifically to help administrators distinguish between expected disconnects (user closed window, timeout) and unexpected ones (network failure, protocol error, server resource issue).',
    what_good_looks_like: 'Reason code 5 (client disconnect) is entirely normal — user closed window. Investigate: reason code 9 (RDP protocol error — possible network issue), reason code 2 (server out of resources — RAM or session limit), reason codes in the 256+ range (application-specific or custom RDP infrastructure codes), any reason code that repeats for many users simultaneously.',
    common_mistakes: [
      'Treating all Event 40s as problems — reason code 5 (normal user disconnect) is not a problem',
      'Not looking up the reason code — each code has a specific meaning that guides the investigation',
      'Ignoring the user and session fields that identify which session disconnected'
    ],
    causes: [
      'User closed RDP window (reason 5)',
      'Session idle timeout reached (reason 12)',
      'Network interruption (reason 9 or protocol errors)',
      'Server out of resources (reason 2)',
      'Admin disconnected the session',
      'RDP protocol negotiation failure'
    ],
    steps: [
      'Filter TerminalServices-LocalSessionManager log for Event 40',
      'Note the Reason Code and look it up (common: 5=normal, 9=protocol error, 12=timeout)',
      'If reason 9 or other error codes: check network connectivity and RDP port availability',
      'If reason 2: check server RAM and session license count',
      'Correlate with Event 24 for the same session to see the full disconnect record'
    ],
    symptoms: [
      'rdp disconnecting with reason',
      'remote desktop dropped with error',
      'rdp session ended reason code',
      'why did rdp disconnect',
      'rdp connection dropped reason',
      'rds session disconnected with code'
    ],
    tags: ['rdp', 'rds', 'disconnect', 'reason-code', 'troubleshooting', 'session'],
    powershell: `# RDS Session Disconnect with Reason Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Reason code lookup
$reasonMap = @{
    0  = 'No information'
    1  = 'Server terminated'
    2  = 'Server out of memory'
    3  = 'Server out of memory 2'
    4  = 'Server idle'
    5  = 'Client disconnect (user closed window)'
    6  = 'Client logoff'
    7  = 'RDP log off'
    9  = 'Server RPC error / network issue'
    11 = 'Server admin disconnect'
    12 = 'Session timeout'
    263= 'Licensing error'
}

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id           = 40
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml    = [xml]$_.ToXml()
    $ud     = $xml.Event.UserData.EventXML
    $code   = [int]$ud.Reason
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        User         = $ud.User
        SessionID    = $ud.SessionID
        ReasonCode   = $code
        ReasonDesc   = $reasonMap[$code] ?? "Unknown ($code)"
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [21, 23, 24, 25, 41],
    ms_docs: null
  },

  {
    id: 41,
    source: 'Microsoft-Windows-TerminalServices-LocalSessionManager',
    channel: 'RDS',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'RDS: Session Connection Failed',
    short_desc: 'A Remote Desktop session connection attempt failed before a session was created.',
    description: 'Event ID 41 from TerminalServices-LocalSessionManager records a connection failure before a session was established. Note this is distinct from Event 41 in the System log (Kernel Power) — same ID, different source. In the RDS context, this event indicates a pre-session failure: the connection was refused or failed before the user was authenticated or a session was created. This can indicate authentication failures, licensing issues, or server resource problems.',
    why_it_happens: 'The RDS connection broker or local session manager refuses or fails the connection attempt before creating a session. Common causes include NLA (Network Level Authentication) pre-authentication failures, the RDS server being at its session limit, the user not having Remote Desktop access rights, or a server-side issue.',
    what_good_looks_like: 'Occasional failures are expected (wrong password, user not in RD Users group). Investigate: many failures from one IP (brute-force scan), failures for accounts that should have access (misconfiguration), failures after a change to RDS configuration.',
    common_mistakes: [
      'Confusing this Event 41 (RDS connection failed) with System Event 41 (Kernel Power unexpected reboot)',
      'Not checking if the user is a member of Remote Desktop Users group',
      'Missing that NLA pre-auth failures here won\'t have a corresponding 4625 in Security log if NLA was fully rejected'
    ],
    causes: [
      'Authentication failure (NLA pre-auth)',
      'User not in Remote Desktop Users group',
      'RDS server at session or license limit',
      'Firewall blocking RDP port 3389',
      'Server resource exhaustion',
      'RDP Restricted Admin mode misconfiguration'
    ],
    steps: [
      'Filter TerminalServices-LocalSessionManager log for Event 41',
      'Note the error code and username (if available)',
      'Check if user is in Remote Desktop Users or Administrators group',
      'Check session limit: qwinsta /server:<server> (count sessions)',
      'Check RDP firewall rules: Get-NetFirewallRule -Name "RemoteDesktop*"',
      'Check RDS Licensing if in an RDS farm environment'
    ],
    symptoms: [
      'rdp connection refused',
      'cannot connect rdp',
      'remote desktop connection failed',
      'rdp not accepting connections',
      'remote desktop access denied',
      'rds connection error',
      'cant connect via remote desktop'
    ],
    tags: ['rdp', 'rds', 'connection-failed', 'authentication', 'access-denied', 'troubleshooting'],
    powershell: `# RDS Connection Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id           = 41
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Also check RemoteConnectionManager for more detail
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Warning' } |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Select-Object -First 10 | Format-List`,
    related_ids: [21, 1149, 4625, 4771],
    ms_docs: null
  },

  {
    id: 1149,
    source: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager',
    channel: 'RDS',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'RDS: User Authentication Succeeded',
    short_desc: 'Network Level Authentication (NLA) pre-authentication succeeded for an RDP connection.',
    description: 'Event ID 1149 from the TerminalServices-RemoteConnectionManager records that a user successfully passed Network Level Authentication (NLA) before their RDS session was created. NLA is the pre-authentication step that occurs before the full RDS session is established — it validates credentials at the network level to prevent unauthenticated users from reaching the login screen. Event 1149 means NLA passed; it does not guarantee a session was created (Event 21 confirms the session).',
    why_it_happens: 'When an RDP client connects with NLA enabled (the default for modern Windows), it authenticates at the protocol level using CredSSP before the RDS session stack is initialized. The RemoteConnectionManager logs 1149 when NLA validation succeeds. This event appears even if the subsequent session creation fails for other reasons (license limit, session policy).',
    what_good_looks_like: 'Expected: 1149 events from known users and IPs during business hours. Event 1149 without a corresponding Event 21 may indicate a session creation failure after successful NLA. Investigate: 1149 events from unexpected IP ranges, 1149 for accounts that should not have RDP access, 1149 at unusual hours for non-on-call accounts.',
    common_mistakes: [
      'Confusing 1149 (NLA passed) with Event 21 (session created) — both should appear for a successful connection',
      'Not checking the client IP in 1149 — this is where the connection physically came from before any load balancer or broker',
      'Not having NLA enabled on RDS servers — without NLA, unauthenticated users reach the login screen and can exploit pre-auth vulnerabilities'
    ],
    causes: [
      'Legitimate user successfully pre-authenticated via NLA',
      'Admin connecting to manage the server',
      'Automated process with valid credentials connecting via RDP'
    ],
    steps: [
      'Filter Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational for Event 1149',
      'Note the username and source IP',
      'Correlate with Event 21 to confirm a session was created',
      'If 1149 exists but no Event 21: session creation failed — investigate license or policy',
      'If the source IP is unexpected: investigate who has those credentials'
    ],
    symptoms: [
      'rdp authentication succeeded',
      'nla authentication',
      'network level authentication passed',
      'rdp pre auth succeeded',
      'rds nla success'
    ],
    tags: ['rdp', 'rds', 'nla', 'authentication', 'network-level-authentication', 'security'],
    powershell: `# RDS NLA Authentication Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with RDS server hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    Id           = 1149
    StartTime    = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $ud   = $xml.Event.UserData.EventXML
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        UserName    = $ud.Param1
        Domain      = $ud.Param2
        SourceIP    = $ud.Param3
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [21, 41, 4624, 4625],
    ms_docs: null
  }
];
