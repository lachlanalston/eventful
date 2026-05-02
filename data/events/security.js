export const securityEvents = [
  {
    id: 4624,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Successful Logon',
    short_desc: 'A user or process successfully authenticated and was granted access.',
    description: 'Event 4624 is generated every time an account successfully logs on to the computer. The event captures who logged on, how they logged on (logon type), from where, and under what process. It is one of the highest-volume events in the Security log and forms the backbone of authentication auditing. Logon Type is the most important field — Type 2 is interactive (keyboard at the machine), Type 3 is network (file share, mapped drive), Type 7 is unlock, Type 10 is Remote Interactive (RDP), and Type 11 is cached credentials.',
    why_it_happens: 'Windows generates this event as part of Logon/Logoff auditing whenever the Security Account Manager (SAM) or Kerberos authentication packages validate credentials successfully. Every resource access — opening a file share, unlocking a workstation, an RDP session — produces a logon event. Services also generate Type 5 (service logon) events on startup. The volume makes this event noisy on domain controllers, which see every network logon from every machine authenticating to AD.',
    what_good_looks_like: 'Expected: Type 3 logons from your file server to member computers during business hours, Type 2 logons from known user accounts, Type 5 logons from known service accounts. Investigate: logons outside business hours for sensitive accounts, Type 10 (RDP) logons from unexpected source IPs, logons from accounts that should not be accessing a particular machine, Type 9 (NewCredentials/RunAs) logons.',
    common_mistakes: [
      'Treating all 4624 events as significant — on a domain controller you will see thousands per hour; filter by logon type first',
      'Forgetting that Type 3 logons are normal for every mapped drive, printer access, or file share access',
      'Overlooking the "Account for which logon was performed" vs the "Subject" field — the Subject is often SYSTEM, the target account is the important one',
      'Not checking the Workstation Name and Source IP fields to see where the logon originated',
      'Assuming a logon means a human sat at the keyboard — services, scheduled tasks, and scripts all generate logon events'
    ],
    causes: [
      'User interactively logging in at the console (Type 2)',
      'User accessing a network share or mapped drive (Type 3)',
      'A service starting under a service account (Type 5)',
      'A user unlocking their workstation (Type 7)',
      'An RDP session being established (Type 10)',
      'Credentials being cached used offline (Type 11)',
      'A process using RunAs or alternate credentials (Type 9)'
    ],
    steps: [
      'Open Event Viewer → Windows Logs → Security, filter for Event ID 4624',
      'Identify the "Logon Type" field — this tells you how the logon occurred',
      'Check "Account Name" under "New Logon" — this is who logged on',
      'Check "Workstation Name" and "Source Network Address" for remote logons',
      'For Type 10 logons, cross-reference with RDS events 21, 25, 4778',
      'If investigating suspicious activity, export and pivot on Account Name and Source IP',
      'Use PowerShell snippet below to filter by logon type or account name'
    ],
    symptoms: [
      'user logged in',
      'who logged into this computer',
      'when did someone log on',
      'check login history',
      'see who accessed this pc',
      'authentication successful',
      'rdp login',
      'remote login',
      'account logged on'
    ],
    tags: ['authentication', 'logon', 'audit', 'rdp', 'kerberos', 'ntlm', 'security', 'baseline'],
    powershell: `# Successful Logon Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Get all successful logons and decode logon type
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated      = $_.TimeCreated
        TargetAccount    = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        LogonType        = ($data | Where-Object Name -eq 'LogonType').'#text'
        SourceIP         = ($data | Where-Object Name -eq 'IpAddress').'#text'
        WorkstationName  = ($data | Where-Object Name -eq 'WorkstationName').'#text'
        AuthPackage      = ($data | Where-Object Name -eq 'AuthenticationPackageName').'#text'
    }
} | Where-Object { $_.TargetAccount -notlike '*$' } |
    Sort-Object TimeCreated -Descending |
    Format-Table -AutoSize`,
    related_ids: [4625, 4634, 4647, 4648, 4672, 4771, 4776, 4778],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624'
  },

  {
    id: 4625,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Failed Logon',
    short_desc: 'An account failed to log on — wrong password, bad account, or locked out.',
    description: 'Event 4625 is generated whenever a logon attempt fails. It is the primary event for investigating account lockouts, brute-force attacks, and misconfigured service accounts. The most critical field is "Failure Reason" / "Sub Status" code — 0xC000006A means wrong password, 0xC0000234 means account already locked, 0xC000006D means bad username, 0xC000006F means logon outside permitted hours. A burst of these events from a single source IP strongly suggests a brute-force or password spray attack.',
    why_it_happens: 'Windows logs failed logons as part of Logon/Logoff auditing. Failures happen for many reasons: typos, cached credentials after a password change, stale service account credentials, or deliberate attack. The Sub Status code is generated by the authentication package (Kerberos or NTLM) and distinguishes between "wrong password" and "account doesn\'t exist", which is important — attackers enumerating accounts generate mostly 0xC000006D errors.',
    what_good_looks_like: 'One or two failed logons followed by a successful 4624 is normal (typo, then correct password). Investigate: repeated failures for the same account from multiple sources (password spray), repeated failures for many accounts from one source (credential stuffing), failures for accounts that shouldn\'t exist (deleted user still configured in a service), failures outside business hours for interactive accounts.',
    common_mistakes: [
      'Looking at 4625 without also looking at 4740 — the lockout event tells you which computer triggered it',
      'Ignoring the Sub Status code — it distinguishes wrong password from bad account, which matters for attack detection',
      'Only looking at the DC — failed logons also appear on the member computer where the attempt occurred',
      'Not checking the Caller Computer Name or Source Network Address when investigating remote failures',
      'Assuming every failed logon is an attack — users mistype passwords constantly'
    ],
    causes: [
      'User typed wrong password',
      'Cached credentials not updated after password change',
      'Service account configured with old password',
      'Account locked out from previous failures',
      'Account disabled or deleted',
      'Logon attempt outside permitted hours or from non-allowed workstation',
      'Brute-force or password spray attack',
      'VPN or remote access client using stale credentials'
    ],
    steps: [
      'Filter Security log for 4625 on the target machine or DC',
      'Note the "Account Name" — is this a known user, service account, or unknown name?',
      'Check Sub Status code: 0xC000006A = wrong password, 0xC0000234 = locked, 0xC000006D = bad username',
      'If Sub Status 0xC000006A: find what device is sending the bad password (Workstation Name / Source IP)',
      'If Sub Status 0xC0000234: find 4740 lockout event to see triggering computer',
      'Correlate Source IP with your asset inventory — is it a known machine?',
      'If many accounts failed from one IP, escalate — likely spray attack',
      'Check for corresponding 4740 to confirm lockout occurred'
    ],
    symptoms: [
      'user cant log in',
      'account locked out',
      'wrong password',
      'login failed',
      'authentication failed',
      'bad password',
      'user keeps getting locked out',
      'account lockout investigation',
      'brute force',
      'failed authentication'
    ],
    tags: ['authentication', 'lockout', 'failed-logon', 'brute-force', 'password', 'security', 'audit'],
    powershell: `# Failed Logon Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Decode Sub Status codes for failure reason
$subStatusMap = @{
    '0xC000006A' = 'Wrong password'
    '0xC0000234' = 'Account locked out'
    '0xC000006D' = 'Bad username or authentication failure'
    '0xC000006F' = 'Logon outside permitted hours'
    '0xC0000070' = 'Logon from unauthorised workstation'
    '0xC000015B' = 'Logon type not granted'
    '0xC0000064' = 'Account does not exist'
    '0xC0000072' = 'Account disabled'
    '0xC000006E' = 'Account restriction'
}

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $sub  = ($data | Where-Object Name -eq 'SubStatus').'#text'
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        TargetAccount  = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        FailureReason  = $subStatusMap[$sub] ?? $sub
        SourceIP       = ($data | Where-Object Name -eq 'IpAddress').'#text'
        LogonType      = ($data | Where-Object Name -eq 'LogonType').'#text'
        Workstation    = ($data | Where-Object Name -eq 'WorkstationName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4624, 4740, 4767, 4771, 4776],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625'
  },

  {
    id: 4627,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Group Membership Enumeration During Logon',
    short_desc: 'Windows enumerated group memberships for an account at logon time.',
    description: 'Event 4627 records the full list of security groups a user is a member of at the time of logon. It is generated alongside 4624 when group membership auditing is enabled. The event includes every group SID — domain groups, local groups, special identities (Everyone, Authenticated Users), and privilege groups (Administrators, Domain Admins). It is primarily useful for confirming what access a user had at a specific point in time, which is valuable in insider threat investigations and compliance audits.',
    why_it_happens: 'When a user logs on, the Local Security Authority (LSA) builds an access token containing all the user\'s group memberships and privileges. Event 4627 is the audit record of this token-building process. It captures the group state at logon time, not the current state — if group membership changes after logon, the existing session\'s token is not updated until the user logs off and back on.',
    what_good_looks_like: 'Normal: user is a member of expected groups (Domain Users, department groups, maybe a few resource groups). Investigate: a standard user appearing in Domain Admins, Schema Admins, or Backup Operators; group memberships that change between logon events for the same user; a service account with unexpectedly broad group membership.',
    common_mistakes: [
      'Confusing this event with group membership change events (4728, 4732) — 4627 shows membership at logon, not changes',
      'Not realising the token is built at logon — a group change won\'t show up until next logon',
      'Ignoring the special identity SIDs (S-1-1-0 Everyone, S-1-5-11 Authenticated Users) in the membership list — these are normal',
      'This event can be very large — some users have 50+ group memberships and the XML is lengthy'
    ],
    causes: [
      'Any successful interactive or network logon with group membership auditing enabled',
      'Elevated privilege use via RunAs generating a separate logon token',
      'Service account logon building its access token'
    ],
    steps: [
      'Filter Security log for 4627 alongside a specific 4624 using the LogonID correlation field',
      'Look at the "Group Membership" field for any unexpected privileged groups',
      'Cross-reference with HR records if investigating insider threat or access review',
      'Compare group memberships across multiple logon events for the same user to spot changes',
      'Use the LogonID from 4624 to find the corresponding 4627 for the same session'
    ],
    symptoms: [
      'what groups is this user in',
      'check user group membership',
      'audit user access',
      'privileged group membership',
      'when did user get admin rights'
    ],
    tags: ['group-membership', 'access-token', 'privileged-access', 'audit', 'compliance'],
    powershell: `# Group Membership Enumeration Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4627
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4624, 4728, 4732, 4756, 4672],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4627'
  },

  {
    id: 4648,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Logon with Explicit Credentials (RunAs)',
    short_desc: 'A process used different credentials than the logged-on user to access a resource.',
    description: 'Event 4648 is generated when a process uses alternate credentials — via RunAs, a "net use" command with credentials, or a script that embeds credentials. It records both the account that initiated the logon (the "Subject") and the account whose credentials were used (the "Account Whose Credentials Were Used"). This event is important because it can reveal credential exposure: if an attacker has compromised a machine, they may use 4648 to pivot using harvested credentials. It also appears during legitimate admin activities.',
    why_it_happens: 'Windows generates 4648 when the LogonUser() API is called with the LOGON32_LOGON_NEW_CREDENTIALS flag, or when CreateProcessWithLogonW is used. These APIs are called by RunAs, scheduled tasks using alternate accounts, scripts with embedded credentials, and tools like PsExec. The event is generated on the machine where the credential use originates, not on the target machine.',
    what_good_looks_like: 'Expected: an IT admin using RunAs to launch a management console with admin credentials, a script explicitly connecting to a remote resource. Investigate: a standard user account generating 4648 events (they shouldn\'t be using alternate credentials), the "Target Server" being a sensitive system, 4648 events at unusual times, credentials for accounts that shouldn\'t be used interactively.',
    common_mistakes: [
      'Confusing 4648 with 4624 Type 9 (NewCredentials logon) — they are related but 4648 is on the source machine, 4624 Type 9 on the target',
      'Not noticing this event because it is often buried in high-volume logs — set an alert for 4648 from standard user accounts',
      'Ignoring scheduled tasks — they generate 4648 on every run if configured with alternate credentials',
      'Missing that "mapped drives" configured with credentials generate 4648 repeatedly'
    ],
    causes: [
      'Admin using RunAs to elevate',
      'Script or batch file embedding credentials',
      'Scheduled task configured with alternate account credentials',
      'net use command with explicit credentials',
      'PsExec or similar tools using alternate credentials',
      'Malware using harvested credentials to pivot laterally'
    ],
    steps: [
      'Filter Security log for 4648 on the suspect machine',
      'Identify "Account Whose Credentials Were Used" — is this a privileged account?',
      'Check "Target Server Name" — what resource was being accessed?',
      'Check the initiating process name — is it cmd.exe, powershell.exe, or an unknown executable?',
      'Correlate with 4624 Type 9 on the target machine to confirm the credential use succeeded',
      'If the initiating process is unexpected, investigate the process tree',
      'Check if the Subject account should normally be using alternate credentials at all'
    ],
    symptoms: [
      'runas command',
      'explicit credentials',
      'alternate credentials',
      'user running as admin',
      'credentials used by different account',
      'pass the hash',
      'lateral movement',
      'privilege escalation'
    ],
    tags: ['runas', 'credentials', 'lateral-movement', 'privilege-escalation', 'security', 'audit'],
    powershell: `# Explicit Credential Use (RunAs) Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4648
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated      = $_.TimeCreated
        SubjectAccount   = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        CredentialUsed   = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        TargetServer     = ($data | Where-Object Name -eq 'TargetServerName').'#text'
        ProcessName      = ($data | Where-Object Name -eq 'ProcessName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4624, 4672, 4688],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648'
  },

  {
    id: 4663,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Advanced',
    title: 'File or Object Access Attempt',
    short_desc: 'An account attempted to access a file, registry key, or Active Directory object.',
    description: 'Event 4663 records every access attempt to an audited object — a file, folder, registry key, or Active Directory object. It is generated only when object access auditing is enabled AND the specific object has a System Access Control List (SACL) configured to audit that type of access. The event records who accessed the object, what type of access was requested (Read, Write, Delete, etc.), and whether it succeeded. This event is extremely noisy without careful SACL scoping and should only be enabled on sensitive objects.',
    why_it_happens: 'Windows generates 4663 as part of Object Access auditing. The audit policy must be enabled (either File System or Registry subcategory), and the specific object must have a SACL that defines which users and access types to audit. Without a SACL, no events are generated regardless of audit policy. SACLs are configured in the Security tab → Advanced → Auditing of a file or folder. Group Policy can deploy SACLs at scale.',
    what_good_looks_like: 'Normal: known users accessing expected files during business hours. Investigate: access to files outside normal working hours, DELETE or WRITE access to sensitive files like scripts or configs, access from unexpected accounts (e.g., service accounts accessing user documents), a burst of access events suggesting bulk file enumeration or exfiltration.',
    common_mistakes: [
      'Enabling Object Access auditing globally without configuring SACLs — this generates zero events (policy without SACLs = nothing)',
      'Enabling SACLs on high-volume locations like C:\\ — the event volume will overwhelm the security log instantly',
      'Not filtering for the "Accesses" field — Read Data, Write Data, Delete are very different risk levels',
      'Confusing 4663 (access attempt) with 4656 (handle request) — 4663 means the access actually happened',
      'Not setting the security log size large enough to retain 4663 events before they are overwritten'
    ],
    causes: [
      'Normal file access by authorised users',
      'Application accessing files it needs to function',
      'Backup agent reading files',
      'Malware reading, writing, or deleting sensitive files',
      'Insider threat accessing data they should not',
      'Ransomware encrypting files (massive burst of write events)'
    ],
    steps: [
      'Confirm Object Access auditing is enabled via auditpol /get /subcategory:"File System"',
      'Confirm the target file/folder has a SACL configured (Security → Advanced → Auditing)',
      'Filter Security log for 4663, scoped to the object name in question',
      'Check "Accesses" field — is it Read, Write, Delete, or others?',
      'Check "Account Name" — is the accessing account expected to touch this file?',
      'For ransomware investigation, look for a burst of Write events across many files from one process',
      'Correlate with 4688 to find the process that made the access'
    ],
    symptoms: [
      'who accessed this file',
      'file was deleted',
      'file was modified',
      'ransomware file access',
      'audit file access',
      'sensitive file accessed',
      'who read this document',
      'data exfiltration investigation'
    ],
    tags: ['file-access', 'object-access', 'sacl', 'audit', 'ransomware', 'data-exfiltration', 'dlp'],
    powershell: `# File/Object Access Investigation
# Eventful

$computer   = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime  = (Get-Date).AddHours(-24)  # Adjust time range as needed
$objectName = 'C:\\Sensitive\\folder'   # Replace with target path

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4663
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        Account      = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        ObjectName   = ($data | Where-Object Name -eq 'ObjectName').'#text'
        Accesses     = ($data | Where-Object Name -eq 'Accesses').'#text'
        ProcessName  = ($data | Where-Object Name -eq 'ProcessName').'#text'
    }
} | Where-Object { $_.ObjectName -like "*$objectName*" } |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4656, 4670, 4688, 4624],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663'
  },

  {
    id: 4670,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Advanced',
    title: 'Permissions on Object Changed',
    short_desc: 'The access control list (ACL) on a file, registry key, or AD object was modified.',
    description: 'Event 4670 is generated when the permissions (DACL) on a file, folder, registry key, or Active Directory object are changed. It records the original permissions and the new permissions in SDDL format, along with who made the change and what process performed it. This event requires Object Access auditing and an appropriate SACL on the object. ACL changes on sensitive resources — like adding "Everyone Full Control" to a sensitive folder — are a strong indicator of privilege escalation or lateral movement.',
    why_it_happens: 'When an application or user calls SetSecurityInfo() or SetNamedSecurityInfo() to modify an object\'s DACL, Windows logs 4670. This happens during legitimate admin tasks (granting a user access to a folder), but also during attacks where adversaries try to weaken permissions on sensitive files or registry keys to gain persistent access.',
    what_good_looks_like: 'Expected: IT admin changing folder permissions through a documented change process. Investigate: permissions changed outside of change windows, a non-admin account changing permissions, permissions changed on system binaries or registry run keys, ACL changes that add broad access (Everyone, Authenticated Users) to sensitive paths.',
    common_mistakes: [
      'Not having SACL audit entries on sensitive paths — 4670 will not fire without both audit policy and SACL',
      'Ignoring the SDDL strings because they look complex — focus on the "New SD" field, specifically any A;;FA;;;WD (Full Access for Everyone) or similar broad grants',
      'Not correlating with 4688 to find the process that made the change'
    ],
    causes: [
      'IT admin explicitly modifying folder permissions',
      'Software installer setting permissions on program files',
      'Malware weakening permissions on files for persistence',
      'Ransomware modifying ACLs to ensure write access before encryption',
      'GPO applying new file system permissions'
    ],
    steps: [
      'Filter Security log for 4670',
      'Check "Object Name" — what file/folder was changed?',
      'Decode the "New SD" SDDL string — look for WD (World/Everyone) with FA (Full Access)',
      'Check "Subject Account Name" — was this a known admin doing authorized work?',
      'Check "Process Name" — was it Explorer.exe (manual), or something unexpected?',
      'Review change management records to see if this was planned',
      'If unauthorized, restore original permissions from backup and investigate further'
    ],
    symptoms: [
      'permissions changed on file',
      'acl modified',
      'access control changed',
      'who changed permissions',
      'folder permissions modified',
      'security descriptor changed'
    ],
    tags: ['permissions', 'acl', 'dacl', 'sacl', 'file-system', 'privilege-escalation', 'audit'],
    powershell: `# Permissions Change Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4670
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4663, 4688, 4698],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670'
  },

  {
    id: 4672,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Special Privileges Assigned to New Logon',
    short_desc: 'A user logged on with administrative or sensitive privileges in their access token.',
    description: 'Event 4672 is generated immediately after 4624 whenever the account that logged on holds one or more sensitive privileges. These include SeDebugPrivilege (debug any process), SeBackupPrivilege (read any file for backup), SeImpersonatePrivilege (impersonate any user), SeTakeOwnershipPrivilege, and others that grant powerful OS capabilities. This event effectively marks every admin logon. It appears extremely frequently for SYSTEM and built-in admin accounts — the key is filtering for unexpected accounts or unexpected machines.',
    why_it_happens: 'When the LSA builds an access token for a logon, it checks whether any of the user\'s group memberships or direct assignments include sensitive privileges. If they do, 4672 is generated. Local Administrators always hold many of these privileges. Domain Admins inherit them. The event fires even if the account never actually uses those privileges — it is based on token construction, not privilege use.',
    what_good_looks_like: 'Expected: Domain Admin accounts generating 4672 on DCs and servers they manage, local admin accounts generating it on workstations. Investigate: 4672 for standard user accounts (they should not hold sensitive privileges), 4672 on machines the admin account shouldn\'t access, an account gaining SeDebugPrivilege that wasn\'t previously an admin.',
    common_mistakes: [
      'Alerting on every 4672 — SYSTEM generates one on every boot, and every admin logon generates one',
      'Not filtering for the specific privileges in the event — SeDebugPrivilege and SeTcbPrivilege are more dangerous than SeChangeNotifyPrivilege',
      'Ignoring 4672 on domain controllers — these are critical machines and unexpected admin logons matter more there',
      'Not correlating with 4624 using the LogonID — they should always appear together'
    ],
    causes: [
      'Admin user logging on interactively or via RDP',
      'Service running under a privileged service account starting',
      'Scheduled task running under admin credentials',
      'Malware that has elevated to SYSTEM or admin generating logon events'
    ],
    steps: [
      'Filter Security log for 4672',
      'Check "Account Name" — is this account expected to be an admin?',
      'Check "Privileges" — focus on SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege',
      'Correlate with 4624 using the LogonID to see where the logon came from',
      'On DCs, any unexpected 4672 should be immediately investigated',
      'Cross-reference with AD group membership to see if the privilege assignment is expected'
    ],
    symptoms: [
      'admin logged on',
      'privileged logon',
      'who has admin access',
      'administrative logon',
      'sensitive privileges',
      'debug privilege',
      'domain admin logon'
    ],
    tags: ['privileges', 'admin', 'access-token', 'audit', 'security-baseline'],
    powershell: `# Special Privileges Assigned Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4672
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        AccountName  = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        Domain       = ($data | Where-Object Name -eq 'SubjectDomainName').'#text'
        Privileges   = ($data | Where-Object Name -eq 'PrivilegeList').'#text'
    }
} | Where-Object { $_.AccountName -notlike '*$' -and $_.AccountName -ne 'SYSTEM' -and $_.AccountName -ne 'LOCAL SERVICE' -and $_.AccountName -ne 'NETWORK SERVICE' } |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4624, 4627, 4648],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672'
  },

  {
    id: 4688,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Advanced',
    title: 'New Process Created',
    short_desc: 'A new process was created — records executable path, parent process, and user context.',
    description: 'Event 4688 records every new process creation when Process Creation auditing is enabled. It captures the full executable path, the account running it, the parent process, and — when command line auditing is also enabled — the exact command line arguments. This is one of the most valuable events for threat hunting and incident response. It shows exactly what programs were run, by whom, and under what process lineage. Attackers frequently try to live off the land using built-in tools (cmd.exe, powershell.exe, wmic.exe, certutil.exe) — 4688 reveals this.',
    why_it_happens: 'Windows generates 4688 through the Process Tracking audit subcategory. It fires every time CreateProcess() is called and a new process kernel object is instantiated. On a busy workstation this can be hundreds per hour. The command line is only included if "Include command line in process creation events" is enabled in Group Policy (Computer Configuration → Admin Templates → System → Audit Process Creation). This setting is off by default.',
    what_good_looks_like: 'Normal: known applications launching from standard paths (C:\\Program Files\\, C:\\Windows\\System32\\), with expected parent processes (explorer.exe for user-launched apps, services.exe for services). Investigate: executables running from unusual paths (temp folders, AppData, recycle bin), PowerShell encoded commands, processes launched by unusual parents (Word spawning cmd.exe), known LOLBins (certutil, mshta, regsvr32) used unexpectedly.',
    common_mistakes: [
      'Not enabling command line auditing — the executable path alone is much less useful than the full command line',
      'Not enabling this audit policy at all — it is off by default and must be explicitly enabled',
      'Being overwhelmed by volume and not using specific parent process or path filters to narrow down',
      'Missing that Windows Defender and AV engines create many processes when scanning — these are expected noise'
    ],
    causes: [
      'User launching an application',
      'A service or scheduled task spawning a child process',
      'Script interpreter (cmd.exe, powershell.exe, wscript.exe) executing code',
      'An exploit using a trusted application to run attacker-controlled code',
      'Malware executing a payload',
      'Lateral movement tools like PsExec creating remote processes'
    ],
    steps: [
      'Confirm audit policy: auditpol /get /subcategory:"Process Creation"',
      'Confirm command line logging is enabled via GPO or local security policy',
      'Filter 4688 for a specific user, time window, or parent process',
      'Look for processes running from non-standard paths (AppData, Temp, Recycle Bin)',
      'Look for cmd.exe or powershell.exe spawned by Office applications (Word, Excel)',
      'Check for encoded PowerShell commands (-enc or -EncodedCommand)',
      'Build a process tree using ParentProcessId and ProcessId fields',
      'Cross-reference unusual processes with VirusTotal by hash if available'
    ],
    symptoms: [
      'what programs were run',
      'process executed',
      'command was run',
      'malware running process',
      'suspicious executable',
      'powershell command ran',
      'process tracking',
      'who ran this program',
      'application launched'
    ],
    tags: ['process-creation', 'threat-hunting', 'lolbins', 'powershell', 'malware', 'incident-response', 'audit'],
    powershell: `# Process Creation Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Note: Command line captured only if "Include command line in process creation events" GPO is enabled
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        Account        = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        NewProcess     = ($data | Where-Object Name -eq 'NewProcessName').'#text'
        CommandLine    = ($data | Where-Object Name -eq 'CommandLine').'#text'
        ParentProcess  = ($data | Where-Object Name -eq 'ParentProcessName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4624, 4648, 4698, 4663],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688'
  },

  {
    id: 4698,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Scheduled Task Created',
    short_desc: 'A new scheduled task was registered on the system.',
    description: 'Event 4698 is generated when a new scheduled task is created through Task Scheduler. It records the task name, the account that created it, and the full task XML including triggers, actions, and the account it runs under. Scheduled tasks are a favourite persistence mechanism for attackers — they survive reboots, run silently, and blend in with legitimate administrative tasks. Every new task creation should be reviewed, especially outside of known change windows.',
    why_it_happens: 'Windows records task creation through the Object Access auditing subsystem. The Task Scheduler service calls the security audit API when a task is registered via the COM interface, the schtasks command, or PowerShell. The task XML embedded in the event contains everything about the task — when it runs, what it runs, and under what credentials.',
    what_good_looks_like: 'Expected: software installers creating update tasks (Google, Adobe, Microsoft), IT management tools (RMM agents, monitoring), GPO-deployed tasks. Investigate: tasks created outside business hours, tasks running from AppData or Temp directories, tasks using encoded commands, tasks running under SYSTEM that weren\'t there before, task names mimicking system tasks but in slightly wrong locations.',
    common_mistakes: [
      'Assuming tasks in unusual folders like C:\\Windows\\System32\\Tasks\\ are legitimate just because of the path',
      'Not reading the full task XML in the event — the Action element reveals the actual command being run',
      'Overlooking tasks that use "schtasks /create" from command line — they also generate 4698',
      'Not setting a baseline of legitimate scheduled tasks to compare against'
    ],
    causes: [
      'Software installation creating an update or maintenance task',
      'IT admin scheduling a maintenance script',
      'RMM or monitoring agent deploying a task',
      'Malware creating a persistence mechanism',
      'Attacker using schtasks for lateral execution or persistence'
    ],
    steps: [
      'Filter Security log for 4698',
      'Read the "Task Name" — does it match a known application?',
      'Read the "Task Content" XML — examine the Action element for the command being executed',
      'Check the "Subject Account Name" — was this created by a known admin or SYSTEM?',
      'Verify the task exists and matches what the event recorded: Get-ScheduledTask | Where-Object TaskName -eq \'<name>\'',
      'Check the trigger — when does it run? At logon? Every minute?',
      'If suspicious, delete with Remove-ScheduledTask and investigate further'
    ],
    symptoms: [
      'scheduled task created',
      'new task in task scheduler',
      'malware persistence',
      'task created overnight',
      'suspicious scheduled task',
      'who created this task',
      'task running as system'
    ],
    tags: ['scheduled-task', 'persistence', 'malware', 'audit', 'security'],
    powershell: `# Scheduled Task Creation Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4698
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        CreatedBy     = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        TaskName      = ($data | Where-Object Name -eq 'TaskName').'#text'
        TaskContent   = ($data | Where-Object Name -eq 'TaskContent').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [4700, 4702, 4688, 4624],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698'
  },

  {
    id: 4700,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Scheduled Task Enabled',
    short_desc: 'A previously disabled scheduled task was enabled.',
    description: 'Event 4700 records when a scheduled task transitions from disabled to enabled. Attackers sometimes create tasks in a disabled state to avoid immediate execution, then enable them later when they are ready to use them. It is also generated when an admin re-enables a task they previously disabled. The event includes the task name, the account that enabled it, and a timestamp.',
    why_it_happens: 'Task Scheduler generates a security audit event when a task\'s enabled status is changed. This happens when a task is enabled via the Task Scheduler GUI, the schtasks /change /enable command, or the PowerShell Enable-ScheduledTask cmdlet. The event is logged on the machine where the task lives.',
    what_good_looks_like: 'Expected: an IT admin enabling a task during a maintenance window, software update enabling its own task. Investigate: a disabled task being re-enabled at an unusual time, a task being enabled immediately after being created (suggesting automated persistence setup), tasks being enabled that you don\'t recognise.',
    common_mistakes: [
      'Treating this event in isolation — always check 4698 to find the original task creation',
      'Not realising a task can be created disabled (to avoid detection), then enabled later'
    ],
    causes: [
      'IT admin enabling a maintenance task',
      'Software enabling its own update task',
      'Malware enabling a previously created persistence task',
      'GPO enabling a centrally managed task'
    ],
    steps: [
      'Filter Security log for 4700',
      'Note the Task Name and cross-reference with 4698 to see when it was created',
      'Check who enabled it and whether they should have access to that task',
      'Verify the task still exists and inspect it with Get-ScheduledTask',
      'If suspicious, disable and investigate: Disable-ScheduledTask -TaskName \'<name>\''
    ],
    symptoms: [
      'scheduled task enabled',
      'task enabled',
      'task turned on',
      'task was activated'
    ],
    tags: ['scheduled-task', 'persistence', 'audit', 'security'],
    powershell: `# Scheduled Task Enabled Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4700
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4698, 4702, 4688],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4700'
  },

  {
    id: 4702,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Scheduled Task Updated',
    short_desc: 'An existing scheduled task\'s configuration was modified.',
    description: 'Event 4702 records modifications to existing scheduled tasks — changes to the action (what it runs), triggers (when it runs), or run-as account. Like task creation (4698), this event includes the full task XML after the change, making it possible to see exactly what was modified. Attackers who have established a foothold may modify existing legitimate tasks to add malicious actions, making this event critical for detecting that type of persistence modification.',
    why_it_happens: 'Task Scheduler generates 4702 when an existing task\'s properties are changed through any interface — the GUI, schtasks /change, or Set-ScheduledTask in PowerShell. The full updated task XML is embedded in the event.',
    what_good_looks_like: 'Expected: software updates changing their own task schedules, IT admins modifying maintenance tasks. Investigate: changes to tasks you did not initiate, actions being added or changed to run from suspicious paths, trigger intervals being shortened (an attacker making a task run more frequently), run-as account being changed to a more privileged account.',
    common_mistakes: [
      'Only looking at task creation (4698) for persistence — attackers often modify existing tasks to avoid creating obvious new ones',
      'Not comparing the new XML against the previous known-good task definition'
    ],
    causes: [
      'Software update modifying its own task',
      'IT admin changing task schedule or action',
      'Malware modifying a legitimate task to add malicious commands',
      'Attacker changing the run-as account of a task to escalate privileges'
    ],
    steps: [
      'Filter Security log for 4702',
      'Read the full task XML to see what changed',
      'Cross-reference with 4698 to see the original task definition',
      'Check who made the change and when',
      'If the action changed, examine the new command being run',
      'Compare with current task definition: (Get-ScheduledTask -TaskName \'<name>\').Actions'
    ],
    symptoms: [
      'scheduled task changed',
      'task modified',
      'task action changed',
      'task schedule changed',
      'who modified this task'
    ],
    tags: ['scheduled-task', 'persistence', 'audit', 'security'],
    powershell: `# Scheduled Task Update Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4702
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4698, 4700, 4688],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4702'
  },

  {
    id: 4719,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Critical',
    skill_level: 'Advanced',
    title: 'System Audit Policy Changed',
    short_desc: 'The local audit policy was modified — someone changed what security events are logged.',
    description: 'Event 4719 is one of the most significant security events — it records that the audit policy itself was changed. This matters enormously because an attacker who changes the audit policy can blind the security log before carrying out subsequent malicious activity. The event shows which audit subcategory was changed, who changed it, and what it was changed to. "No Auditing" on any category should immediately raise concern.',
    why_it_happens: 'Windows generates 4719 whenever auditpol.exe modifies a local audit policy, Group Policy applies an audit configuration, or an application calls the audit policy APIs. Importantly, this event is generated even when the change is to disable auditing of something — the event itself is always logged because "Audit Policy Change" auditing cannot be disabled.',
    what_good_looks_like: 'Expected: GPO enforcing audit policy and generating 4719 on policy refresh, planned changes during a security hardening exercise. Investigate: audit subcategories being set to "No Auditing" (especially Logon, Process Creation, Account Management), changes made outside of GPO refresh times, changes by accounts other than SYSTEM or known admin accounts.',
    common_mistakes: [
      'Not alerting on 4719 at all — this is one of the most important events to have high-priority alerts for',
      'Assuming SYSTEM making this change is always GPO — check if GPO is actually the source or if something else changed it',
      'Not knowing what your baseline audit policy is, making it impossible to notice changes'
    ],
    causes: [
      'Group Policy applying or refreshing audit settings',
      'IT admin using auditpol.exe to change settings',
      'Security tool modifying audit configuration',
      'Attacker disabling auditing before malicious activity',
      'Malware evading detection by disabling process tracking or logon auditing'
    ],
    steps: [
      'Filter Security log for 4719 — any hit should be investigated',
      'Check "Account Name" — was this SYSTEM (likely GPO) or a human account?',
      'Check the subcategory and what it was changed to (Enabled/Disabled/No Auditing)',
      'Run auditpol /get /category:* to see current policy',
      'If unauthorized change: restore policy via GPO or auditpol /set',
      'If policy was set to "No Auditing" on critical categories, check what else happened while auditing was disabled',
      'Alert SOC and escalate if this was not a planned change'
    ],
    symptoms: [
      'audit policy changed',
      'logging disabled',
      'audit disabled',
      'who changed audit policy',
      'event logging turned off',
      'audit policy modified',
      'someone turned off logging'
    ],
    tags: ['audit-policy', 'evasion', 'critical', 'security', 'compliance'],
    powershell: `# Audit Policy Change Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4719
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List

# Also check current audit policy state
Write-Host "\n--- Current Audit Policy ---" -ForegroundColor Cyan
auditpol /get /category:*`,
    related_ids: [4688, 4624, 4698],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719'
  },

  {
    id: 4720,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'User Account Created',
    short_desc: 'A new user account was created.',
    description: 'Event 4720 records the creation of a new local or domain user account. It includes the name of the new account, the account that created it, and attributes like the account\'s full name and description. Unauthorized account creation is a major red flag — attackers create accounts for persistence, and insiders may create shadow accounts. In MSP environments, alert on any account creation that was not preceded by a service desk ticket or change request.',
    why_it_happens: 'Windows generates 4720 through Account Management auditing whenever Net User, the local Users and Groups MMC snap-in, or Active Directory Users and Computers creates an account. The event is generated on the machine where the account was created — for domain accounts, this is the domain controller that processed the request.',
    what_good_looks_like: 'Expected: IT admin creating accounts during onboarding following a documented process. Investigate: accounts created outside business hours, accounts created by non-admin users, accounts with names that mimic system accounts (svc_backup2, administrator1), accounts created on endpoints rather than the domain controller.',
    common_mistakes: [
      'Not having an alert for 4720 — any account creation should be a low-friction alert',
      'Forgetting that local account creation (on a workstation) also generates 4720 — and local admin accounts are often more dangerous than domain ones',
      'Not correlating with HR onboarding records to verify the account was expected'
    ],
    causes: [
      'IT admin onboarding a new employee',
      'Software installing a service account',
      'RMM or automation tool creating an account',
      'Attacker creating a backdoor account for persistence',
      'Insider threat creating a secondary account'
    ],
    steps: [
      'Filter Security log for 4720',
      'Note "New Account Name" and "Account Domain"',
      'Check "Subject Account Name" — who created this account?',
      'Verify the creation aligns with an onboarding ticket or change request',
      'If domain account: check the DC event log for the original creation event',
      'Check if the account was immediately added to privileged groups (look for 4728, 4732 nearby)',
      'If unauthorized: disable immediately with Disable-ADAccount, then investigate'
    ],
    symptoms: [
      'new account created',
      'new user was created',
      'account creation',
      'unknown user account appeared',
      'backdoor account',
      'who created this account',
      'new local account'
    ],
    tags: ['account-management', 'user-creation', 'persistence', 'audit', 'security'],
    powershell: `# User Account Creation Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4720
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        NewAccount     = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        CreatedBy      = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        Domain         = ($data | Where-Object Name -eq 'TargetDomainName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4722, 4728, 4732, 4726],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720'
  },

  {
    id: 4722,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'User Account Enabled',
    short_desc: 'A user account was enabled after being disabled.',
    description: 'Event 4722 records that a previously disabled user account was re-enabled. This is important because it can indicate that a dormant account (perhaps a former employee\'s account that was disabled but not deleted) has been reactivated. Dormant accounts are attractive targets for attackers because they may still have valid group memberships, permissions, and access, but are less monitored than active accounts.',
    why_it_happens: 'Windows generates 4722 as part of Account Management auditing when an account\'s "Account is disabled" flag is cleared. This happens via Active Directory Users and Computers, Net User, or PowerShell Enable-ADAccount. The event is generated on the machine (or DC) where the change was made.',
    what_good_looks_like: 'Expected: IT admin re-enabling a user account after a period of leave, following a documented process. Investigate: former employee accounts being re-enabled, accounts that should remain permanently disabled (terminated contractors), accounts re-enabled outside business hours.',
    common_mistakes: [
      'Not correlating with 4625 — if a disabled account is generating failed logon attempts, someone may be trying to use it',
      'Not checking when the account was last active before being disabled'
    ],
    causes: [
      'HR process for returning employee',
      'IT admin re-enabling an account following a support ticket',
      'Attacker re-enabling a dormant account for lateral access',
      'Automated process incorrectly re-enabling accounts'
    ],
    steps: [
      'Filter Security log for 4722',
      'Note the account being enabled and who enabled it',
      'Check when the account was last active before being disabled',
      'Verify this matches an HR or helpdesk ticket',
      'Check for subsequent logon events (4624) for the re-enabled account',
      'If unauthorized: re-disable immediately and investigate'
    ],
    symptoms: [
      'account enabled',
      'account reactivated',
      'disabled account turned on',
      'old account re-enabled',
      'user account unlocked by admin'
    ],
    tags: ['account-management', 'dormant-accounts', 'audit', 'security'],
    powershell: `# User Account Enabled Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4722
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4720, 4725, 4624],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4722'
  },

  {
    id: 4723,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Password Change Attempt',
    short_desc: 'A user attempted to change their own password.',
    description: 'Event 4723 records when a user attempts to change their own password (as opposed to 4724, which is an admin resetting someone else\'s password). The event records whether the attempt succeeded or failed. Failed attempts may indicate the user forgot their current password (they must know it to change it), or that a password complexity policy blocked the new password. This event is primarily used to track voluntary password changes for compliance auditing.',
    why_it_happens: 'Windows generates 4723 as part of Account Management auditing. A user changing their own password calls a different API than an admin reset — the user must provide their current password for verification. Failures generate a 4723 event with a failure reason, while successes generate 4723 followed by audit trail entries.',
    what_good_looks_like: 'Expected: users changing passwords after expiry reminders or when prompted by policy. Investigate: repeated failures (user can\'t remember current password — may need admin reset), password changes for service accounts (these should be managed, not user-initiated), password changes outside business hours.',
    common_mistakes: [
      'Confusing 4723 (self-service change) with 4724 (admin reset) — different privileges and workflows',
      'Ignoring failures — a user who failed to change their own password may then call the helpdesk for a reset'
    ],
    causes: [
      'User changing password proactively',
      'Password expiry prompt accepted',
      'User response to security training recommendation',
      'Suspected compromise prompting password change',
      'Compliance policy requiring periodic change'
    ],
    steps: [
      'Filter Security log for 4723',
      'Note success or failure',
      'If failure: check failure reason — may need to assist user with a 4724 admin reset',
      'Correlate with any recent 4625 events for the same account',
      'For service accounts: if a user is changing a service account password, escalate immediately'
    ],
    symptoms: [
      'user changed password',
      'password change attempt',
      'user updating their password',
      'password expired',
      'password change failed'
    ],
    tags: ['password', 'account-management', 'audit', 'compliance'],
    powershell: `# Password Change Attempt Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4723
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4724, 4625, 4740],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4723'
  },

  {
    id: 4724,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Password Reset Attempt',
    short_desc: 'An administrator attempted to reset another account\'s password.',
    description: 'Event 4724 records when a privileged account attempts to reset another user\'s password — without needing to know the current password. This requires Reset Password rights in Active Directory or local administrator privileges for local accounts. It is a critical event for account security auditing. If an attacker has compromised an admin account, resetting a target user\'s password is an early step in account takeover.',
    why_it_happens: 'Windows generates 4724 as part of Account Management auditing when a user with sufficient privilege calls the password reset API. Unlike 4723 (self-service change), 4724 does not require the current password. The event is generated on the DC that processed the request for domain accounts.',
    what_good_looks_like: 'Expected: helpdesk staff resetting passwords via a documented ticket. Investigate: password resets by non-helpdesk accounts, resets for accounts not in a current ticket, a compromised admin account resetting passwords (especially for other admin accounts), password resets for service accounts.',
    common_mistakes: [
      'Not correlating with a helpdesk ticket system — every 4724 should have a corresponding ticket',
      'Missing that this event is generated on the DC, not the helpdesk workstation',
      'Not alerting when admin accounts reset other admin account passwords — this is very sensitive'
    ],
    causes: [
      'Helpdesk agent following a verified password reset request',
      'Admin resetting their own account through an admin tool',
      'Automated password management system rotating credentials',
      'Attacker using a compromised admin account for account takeover',
      'Insider threat resetting a target account\'s password'
    ],
    steps: [
      'Filter Security log for 4724 on DC or target machine',
      'Note the "Target Account Name" and "Subject Account Name" (who reset whom)',
      'Verify against helpdesk ticket records',
      'If no ticket: contact the admin who made the change to verify',
      'If unauthorized: immediately re-rotate the affected account\'s password and investigate the admin account',
      'Check for 4624 logons using the affected account after the reset'
    ],
    symptoms: [
      'password reset',
      'admin reset password',
      'who reset this users password',
      'password was changed by helpdesk',
      'account password changed',
      'forced password reset'
    ],
    tags: ['password', 'account-management', 'helpdesk', 'audit', 'security'],
    powershell: `# Password Reset Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4724
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        ResetBy        = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        TargetAccount  = ($data | Where-Object Name -eq 'TargetUserName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4723, 4720, 4625],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724'
  },

  {
    id: 4725,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'User Account Disabled',
    short_desc: 'A user account was disabled.',
    description: 'Event 4725 records the disabling of a user account. This should correspond to offboarding processes, security responses, or account lifecycle management. Unexpected account disabling — especially for admin accounts or shared service accounts — can indicate sabotage or an attacker trying to lock out defenders during an incident. Equally, if you see an account disabled followed by being re-enabled (4722), investigate who did both.',
    why_it_happens: 'Windows generates 4725 as part of Account Management auditing when an account\'s "Account is disabled" flag is set. This happens through AD Users and Computers, Net User, or Disable-ADAccount in PowerShell.',
    what_good_looks_like: 'Expected: IT admin disabling accounts as part of offboarding (aligned with HR termination list). Investigate: accounts disabled outside of standard offboarding process, admin accounts being disabled unexpectedly, service accounts being disabled causing service outages.',
    common_mistakes: [
      'Not linking account disable events to an HR or ITSM ticket for the offboarding',
      'Not checking for service dependencies before disabling service accounts',
      'Ignoring who performed the disable — was it the expected admin or an unexpected account?'
    ],
    causes: [
      'Employee offboarding',
      'Security incident response (compromised account)',
      'Account lockout mitigation (disabling before investigation)',
      'Policy enforcement',
      'Accidental disable',
      'Insider sabotage'
    ],
    steps: [
      'Filter Security log for 4725',
      'Identify "Target Account" and "Subject Account" (who disabled whom)',
      'Verify against offboarding records or incident tickets',
      'If a service account: check for 7000/7023 service failure events',
      'If unauthorized: re-enable the account and investigate immediately',
      'If part of a security response: confirm the account is appropriately contained'
    ],
    symptoms: [
      'account disabled',
      'user account disabled',
      'who disabled this account',
      'account turned off',
      'user locked out by admin'
    ],
    tags: ['account-management', 'offboarding', 'audit', 'security'],
    powershell: `# User Account Disabled Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4725
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4722, 4720, 4726],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4725'
  },

  {
    id: 4726,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'User Account Deleted',
    short_desc: 'A user account was permanently deleted.',
    description: 'Event 4726 records the deletion of a user account. This is more severe than disabling (4725) because the action is harder to reverse — especially for local accounts on a workstation where no AD recycle bin exists. Unauthorised account deletion can be a sign of sabotage or an attacker covering their tracks by removing the account they used. The event includes who deleted the account and which account was deleted.',
    why_it_happens: 'Windows generates 4726 as part of Account Management auditing when a user account is deleted via Active Directory Users and Computers, Net User /delete, or Remove-ADUser. For AD accounts with the Recycle Bin feature enabled, the account can be restored. For local accounts, deletion is permanent.',
    what_good_looks_like: 'Expected: IT admin deleting accounts following the retention period after offboarding (accounts usually disabled first, then deleted 30-90 days later). Investigate: accounts deleted immediately after disabling (skipping the retention period), deletion of admin or service accounts, accounts deleted outside of a change window.',
    common_mistakes: [
      'Not having AD Recycle Bin enabled — makes recovery much harder',
      'Deleting accounts without first auditing what resources they own (files, mailboxes, groups)',
      'Not keeping records — once deleted without recycle bin, the SID is gone'
    ],
    causes: [
      'End of account retention period after offboarding',
      'Cleanup of test or temporary accounts',
      'Admin error',
      'Attacker covering tracks by deleting accounts they created (4720)',
      'Insider sabotage targeting specific accounts'
    ],
    steps: [
      'Filter Security log for 4726',
      'Note "Target Account" (deleted) and "Subject Account" (who deleted)',
      'Check if there was a preceding 4725 (disable before delete) — expected for offboarding',
      'If no prior 4725: account was deleted directly, which is unusual',
      'For AD accounts: attempt restore from Recycle Bin if available',
      'For local accounts: deletion is permanent — document the incident'
    ],
    symptoms: [
      'account deleted',
      'user account removed',
      'who deleted this account',
      'account missing from AD',
      'user account gone'
    ],
    tags: ['account-management', 'offboarding', 'audit', 'security'],
    powershell: `# User Account Deletion Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4726
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4725, 4720, 4722],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4726'
  },

  {
    id: 4728,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Member Added to Global Security Group',
    short_desc: 'A user or computer was added to an Active Directory global security group.',
    description: 'Event 4728 records membership additions to global security groups in Active Directory. Global groups apply domain-wide and are typically used to assign permissions to users of the same domain. Additions to high-privilege groups — Domain Admins, Enterprise Admins, Schema Admins — should immediately generate an alert. Even additions to lower-privilege groups can matter if the group controls access to sensitive resources.',
    why_it_happens: 'Windows generates 4728 as part of Account Management auditing on domain controllers when a member is added to a global group. Global groups have domain-wide scope and are replicated across all DCs. The event captures who was added (Target Account) and who made the change (Subject).',
    what_good_looks_like: 'Expected: IT admin adding a new employee to department groups during onboarding, following a ticket. Investigate: anyone added to Domain Admins, Schema Admins, or Group Policy Creator Owners, additions made outside business hours, additions not linked to a ticket, a standard user account being used to make group changes.',
    common_mistakes: [
      'Not having real-time alerts for additions to Domain Admins — this should page someone immediately',
      'Only monitoring Domain Admins and missing other dangerous groups like Backup Operators or Account Operators',
      'Not tracking what groups service accounts are members of'
    ],
    causes: [
      'IT admin following onboarding process',
      'Permissions change for a project or role',
      'Attacker adding compromised account to privileged group',
      'Software deployment requiring group membership',
      'GPO-managed group membership update'
    ],
    steps: [
      'Filter Security log for 4728 on a DC',
      'Note the "Member Account Name" (who was added) and "Group Name"',
      'Check "Subject Account Name" — who made the change?',
      'Verify against a helpdesk ticket or change request',
      'If the group is privileged (Domain Admins, Backup Operators): immediately escalate',
      'If unauthorized: remove the account from the group immediately',
      'Check for subsequent 4624 logon events from the newly added account'
    ],
    symptoms: [
      'user added to group',
      'member added to domain admins',
      'privilege escalation group',
      'who added this user to the group',
      'group membership change',
      'unexpected admin group member'
    ],
    tags: ['group-membership', 'account-management', 'privilege-escalation', 'audit', 'security'],
    powershell: `# Global Group Member Added Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4728
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        MemberAdded   = ($data | Where-Object Name -eq 'MemberName').'#text'
        GroupName     = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        ChangedBy     = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4732, 4756, 4720, 4672],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728'
  },

  {
    id: 4732,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Member Added to Local Security Group',
    short_desc: 'A user or computer was added to a local security group (e.g., local Administrators).',
    description: 'Event 4732 records membership additions to local security groups — most importantly the local Administrators group. Unlike domain groups (4728, 4756), local groups apply only to the specific machine. Adding an account to the local Administrators group gives that account full control over the machine, including the ability to read all files, install software, and bypass many security controls. This is a very high-value alert for endpoint security.',
    why_it_happens: 'Windows generates 4732 on the local machine as part of Account Management auditing when a user is added to a local group via Computer Management, Net Localgroup, or Add-LocalGroupMember. On domain-joined machines, this may also be triggered by GPO Restricted Groups or Local Users and Groups preferences.',
    what_good_looks_like: 'Expected: IT policy intentionally adding specific accounts to local Admins (e.g., helpdesk group added via GPO). Investigate: standard user accounts being added to local Admins manually, domain users being added to local Admins on machines they shouldn\'t administer, additions made by unexpected accounts or at unexpected times.',
    common_mistakes: [
      'Not monitoring local group changes on endpoints — most SIEM configurations only monitor DCs',
      'Not realising that local admin rights on a workstation can be used to dump credentials with tools like Mimikatz',
      'Assuming the change was made by GPO just because the machine is domain-joined'
    ],
    causes: [
      'IT admin adding a user to local admins for a specific task',
      'GPO Restricted Groups policy applying',
      'Software installer adding its service account to local admins',
      'Attacker adding a compromised account to local admins for persistence',
      'User escalating their own privileges after an exploit'
    ],
    steps: [
      'Filter Security log for 4732 on the specific machine',
      'Check "Group Name" — is it Administrators or another sensitive group?',
      'Check "Member Account Name" — who was added?',
      'Check "Subject Account Name" — who made the change?',
      'Verify this was an authorized change (ticket, GPO)',
      'If unauthorized: remove immediately with Remove-LocalGroupMember',
      'Investigate how the person making the change had rights to do so'
    ],
    symptoms: [
      'added to local admins',
      'user became local administrator',
      'local admin group changed',
      'who added this user to administrators',
      'unexpected local admin',
      'user got local admin rights'
    ],
    tags: ['group-membership', 'local-admin', 'privilege-escalation', 'endpoint', 'audit', 'security'],
    powershell: `# Local Group Member Added Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4732
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        MemberAdded  = ($data | Where-Object Name -eq 'MemberName').'#text'
        GroupName    = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        ChangedBy    = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4728, 4756, 4720, 4672],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732'
  },

  {
    id: 4740,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'User Account Locked Out',
    short_desc: 'An account reached the failed logon threshold and was locked out.',
    description: 'Event 4740 is generated on the domain controller (or local machine for local accounts) when an account is locked out due to too many failed password attempts. Critically, this event identifies the "Caller Computer Name" — the machine that sent the bad passwords. This is the starting point for every account lockout investigation. Note that 4740 is generated on the DC that processed the lockout, not on the machine the bad password came from.',
    why_it_happens: 'Windows locks accounts when the failed logon count reaches the configured bad password threshold (typically 5-10 attempts). The lockout counter is maintained by the DC holding the PDC Emulator role. When the threshold is crossed, the PDC Emulator logs 4740 and the account is marked as locked. The "Caller Computer Name" field reveals which machine sent the authentication attempts that caused the lockout.',
    what_good_looks_like: 'Expected: occasional lockouts from users mistyping passwords, quickly resolved. Investigate: repeated lockouts for the same account throughout the day (stale credentials on a device), lockouts coming from unexpected machines (a server, not a workstation), lockouts at 3am, multiple accounts locking out simultaneously (password spray attack).',
    common_mistakes: [
      'Looking for 4740 on the workstation rather than the domain controller — it\'s on the DC',
      'Looking at the wrong DC — check the PDC Emulator specifically for 4740 events, as lockouts are processed there',
      'Stopping after finding the Caller Computer Name without investigating what application on that machine is sending bad passwords',
      'Not looking at 4625 events on the Caller Computer to find the specific process sending bad credentials',
      'Resetting the password without finding the source — the lockout will just happen again immediately'
    ],
    causes: [
      'User locked out after forgetting new password',
      'Stale credentials cached on a mobile device after password change',
      'Service configured with old password still attempting authentication',
      'Mapped drive or Outlook profile with old credentials',
      'Brute-force attack from an external source',
      'VPN client using expired cached credentials'
    ],
    steps: [
      'Find 4740 on the PDC Emulator: Get-ADDomain | Select-Object PDCEmulator',
      'Note the "Caller Computer Name" from the event — go to that machine next',
      'On the Caller Computer, look for 4625 events matching the locked account',
      'Identify the "Caller Process Name" in 4625 — this reveals what application is sending bad passwords',
      'Common sources: Outlook (stale profile), mapped drives, scheduled tasks, mobile email apps, Chrome/Firefox saved passwords',
      'Fix the credential source (update password in the application), then unlock the account with 4767',
      'If no obvious source: check for RunAS, PST files, old VPN configs'
    ],
    symptoms: [
      'account locked out',
      'user cant log in account locked',
      'account keeps locking',
      'lockout keeps happening',
      'why does this account keep locking out',
      'AD account locked',
      'user account locked all the time',
      'lockout every morning'
    ],
    tags: ['lockout', 'authentication', 'password', 'security', 'helpdesk', 'fundamental'],
    powershell: `# Account Lockout Investigation
# Eventful
# Run this on the PDC Emulator DC

$computer  = (Get-ADDomain).PDCEmulator   # Targets the PDC Emulator
$startTime = (Get-Date).AddHours(-24)
$lockedUser = 'username'                   # Replace with the locked-out username

# Find lockout events and the triggering machine
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4740
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        LockedAccount = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        CallerMachine = ($data | Where-Object Name -eq 'CallerComputerName').'#text'
    }
} | Where-Object { $_.LockedAccount -eq $lockedUser -or $lockedUser -eq 'username' } |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4625, 4767, 4771, 4776],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740'
  },

  {
    id: 4756,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Member Added to Universal Security Group',
    short_desc: 'A user or computer was added to a universal security group in Active Directory.',
    description: 'Event 4756 records membership additions to universal security groups. Universal groups have forest-wide scope and can contain members from any domain in the forest. They are often used for enterprise-wide access control and appear in the Global Catalog. Like 4728 (global group changes), additions to privileged universal groups should be immediately alerted on.',
    why_it_happens: 'Windows generates 4756 as part of Account Management auditing on DCs when a member is added to a universal group. Universal groups are replicated to the Global Catalog, meaning they are visible across the entire forest. Changes to these groups affect forest-wide access control.',
    what_good_looks_like: 'Expected: IT admin updating enterprise access groups as part of onboarding. Investigate: additions to groups with forest-wide administrative rights, changes made by non-admin accounts, changes outside business hours.',
    common_mistakes: [
      'Treating universal groups as less important than global groups — high-privilege universal groups can have forest-wide impact',
      'Not monitoring the Global Catalog for group changes if the forest spans multiple domains'
    ],
    causes: [
      'IT admin updating enterprise access control groups',
      'New user requiring forest-wide resource access',
      'Software deployment using universal groups for licensing',
      'Attacker adding accounts to forest-wide privileged groups'
    ],
    steps: [
      'Filter Security log for 4756 on a DC',
      'Note "Member Account Name" and "Group Name"',
      'Check "Subject Account Name" — who made the change?',
      'Verify against ticket/change record',
      'If the group is privileged, escalate immediately and remove if unauthorized'
    ],
    symptoms: [
      'universal group membership changed',
      'user added to enterprise group',
      'forest wide group change',
      'universal security group member added'
    ],
    tags: ['group-membership', 'universal-group', 'active-directory', 'audit', 'security'],
    powershell: `# Universal Group Member Added Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with DC hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4756
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
    related_ids: [4728, 4732, 4720, 4672],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4756'
  },

  {
    id: 4767,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'User Account Unlocked',
    short_desc: 'A locked user account was unlocked by an administrator.',
    description: 'Event 4767 records when a locked-out account is manually unlocked by an admin. It includes who unlocked the account and which account was unlocked. On its own this is routine, but when combined with 4740 (lockout) data, it lets you see the full lockout/unlock cycle and measure how long users are locked out. If an account is being unlocked repeatedly, it means the root cause of the lockout was not fixed — the account will lock again.',
    why_it_happens: 'Windows generates 4767 when an admin clears the "Account is locked out" flag via AD Users and Computers, Unlock-ADAccount, or Net User /active:yes. The event is generated on the DC that processes the unlock.',
    what_good_looks_like: 'Expected: helpdesk unlocking accounts as part of a verified support call. Investigate: the same account being unlocked multiple times in a day (lockout root cause not fixed), unlocks happening at 3am (automated, or unauthorized), accounts being unlocked without a corresponding helpdesk ticket.',
    common_mistakes: [
      'Unlocking the account without finding and fixing the source of bad credentials — it will lock again',
      'Not verifying user identity before unlocking — social engineering can trick helpdesk into unlocking attacker-controlled accounts'
    ],
    causes: [
      'Helpdesk response to user support request',
      'Automated unlock script',
      'Admin directly managing account lifecycle',
      'Scheduled task running unlock process'
    ],
    steps: [
      'Filter Security log for 4767',
      'Match with preceding 4740 events for the same account',
      'If the account locks out again after unlock: the root cause was not fixed',
      'Investigate the Caller Computer Name from 4740 and fix the credential source',
      'Track unlock frequency — repeated unlocks signal an unresolved problem'
    ],
    symptoms: [
      'account unlocked',
      'account unlock',
      'helpdesk unlocked account',
      'who unlocked this account',
      'account was unlocked'
    ],
    tags: ['lockout', 'account-management', 'helpdesk', 'audit'],
    powershell: `# Account Unlock Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with PDC Emulator DC hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4767
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        UnlockedBy     = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        TargetAccount  = ($data | Where-Object Name -eq 'TargetUserName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4740, 4625, 4624],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4767'
  },

  {
    id: 4771,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Kerberos Pre-Authentication Failed',
    short_desc: 'A Kerberos authentication attempt failed at the pre-authentication stage.',
    description: 'Event 4771 is generated on domain controllers when a Kerberos pre-authentication request fails. The failure code indicates the reason: 0x12 means account disabled, 0x18 means wrong password (pre-auth failed), 0x17 means password expired, 0x25 means the client clock is out of sync. This event is the Kerberos equivalent of 4625 for NTLM — it appears on the DC, not the workstation. A burst of 0x18 codes from many accounts is a strong indicator of a Kerberos password spray.',
    why_it_happens: 'Kerberos pre-authentication is a security feature where the client must prove it knows the user\'s password before the KDC issues a Ticket Granting Ticket (TGT). The client encrypts a timestamp with the user\'s password hash. If the decryption fails (wrong password), 4771 is logged on the DC. If an account does not require pre-authentication (a security misconfiguration), AS-REP Roasting attacks become possible.',
    what_good_looks_like: 'Expected: occasional 4771 events with 0x18 code from users mistyping passwords. Investigate: many 0x18 events for many accounts from one source IP (password spray), accounts without pre-authentication required (AS-REP Roast target), clock skew errors (0x25) that may indicate a time manipulation attack, failures for service accounts.',
    common_mistakes: [
      'Not monitoring the DC for 4771 — junior admins only look at the workstation and miss Kerberos failures',
      'Not knowing which accounts have pre-auth disabled — run: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}',
      'Confusing 4771 with 4768 (Kerberos TGT request) — 4771 is specifically a failure'
    ],
    causes: [
      'User typed wrong password',
      'Account locked out or disabled',
      'Password expired',
      'Client clock out of sync with DC (>5 minute skew)',
      'Kerberos password spray attack',
      'Service account credentials not updated after password change'
    ],
    steps: [
      'Filter Security log for 4771 on the domain controller',
      'Check failure code: 0x18 = wrong password, 0x12 = disabled, 0x17 = expired, 0x25 = clock skew',
      'If 0x25: check time synchronization on the client machine',
      'If many 0x18 for many accounts from one IP: password spray in progress — block the source',
      'If 0x12 or account not found: correlate with 4740 to find lockout cause',
      'Check if the affected account has pre-auth disabled: Get-ADUser <name> -Properties DoesNotRequirePreAuth'
    ],
    symptoms: [
      'kerberos authentication failed',
      'kerberos error',
      'kdc error',
      'cannot authenticate to domain',
      'domain login failure',
      'kerberos pre auth failed',
      'time skew kerberos',
      'krb5 error'
    ],
    tags: ['kerberos', 'authentication', 'domain-controller', 'password-spray', 'audit', 'security'],
    powershell: `# Kerberos Pre-Auth Failure Investigation
# Eventful
# Run on Domain Controller

$computer  = $env:COMPUTERNAME  # Run on a DC
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

$failureCodeMap = @{
    '0x6'  = 'Client not found in Kerberos database'
    '0x12' = 'Account disabled, expired, or locked'
    '0x17' = 'Password has expired'
    '0x18' = 'Wrong password (pre-auth failed)'
    '0x19' = 'Pre-authentication required'
    '0x25' = 'Clock skew too large (>5 min)'
    '0x32' = 'Service not available'
}

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4771
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $code = ($data | Where-Object Name -eq 'Status').'#text'
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        AccountName   = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        FailureReason = $failureCodeMap[$code] ?? $code
        ClientAddress = ($data | Where-Object Name -eq 'IpAddress').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4625, 4740, 4776, 4624],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771'
  },

  {
    id: 4776,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'NTLM Authentication Attempt',
    short_desc: 'The domain controller attempted to validate NTLM credentials.',
    description: 'Event 4776 is generated on the domain controller that processed an NTLM authentication request. It records the account name, the workstation, and whether authentication succeeded or failed. NTLM is the legacy authentication protocol — modern environments should primarily use Kerberos. High volumes of 4776 events may indicate NTLM relay attacks, pass-the-hash attempts, or clients that cannot reach a DC for Kerberos. Failed 4776 events with error code 0xC000006A indicate wrong credentials.',
    why_it_happens: 'NTLM authentication occurs when Kerberos is unavailable or not supported — accessing resources by IP address instead of hostname, accessing resources in non-domain environments, older clients and servers. The DC validates the NTLM challenge/response by re-computing the expected response using the stored credential hash. If it matches, authentication succeeds.',
    what_good_looks_like: 'Expected: some NTLM authentication for legacy applications, connecting to resources by IP. Investigate: large volumes of failed 4776 for one account (brute-force or pass-the-hash), NTLM from unexpected sources, NTLM where Kerberos should be working, errors indicating pass-the-hash tools were used (error code 0xC000006D with blank workstation name).',
    common_mistakes: [
      'Treating all NTLM as malicious — it is still common in many environments and not all of it is suspicious',
      'Not knowing what "NTLM relay attack" means — an attacker intercepts NTLM challenges and relays them to authenticate elsewhere',
      'Not checking if NTLM is being used for internal authentications that should be Kerberos (accessing shares by IP instead of name)'
    ],
    causes: [
      'Client accessing resource by IP instead of DNS name (forces NTLM)',
      'Legacy application not supporting Kerberos',
      'Domain trust using NTLM',
      'NTLM relay attack in progress',
      'Pass-the-hash attack using captured NTLM hash',
      'Service account cached credentials using NTLM'
    ],
    steps: [
      'Filter Security log for 4776 on the DC',
      'Check Error Code: 0xC0000064 = bad username, 0xC000006A = wrong password, 0x0 = success',
      'Check Workstation Name — is it a known machine?',
      'High volume from one machine with failures = possible pass-the-hash or brute-force',
      'Blank Workstation Name = possible network-level attack',
      'If investigating NTLM relay: look for successful 4776 where the source is not the real client'
    ],
    symptoms: [
      'ntlm authentication',
      'ntlm failed',
      'pass the hash',
      'ntlm relay',
      'legacy authentication',
      'ntlm error',
      'authentication ntlm'
    ],
    tags: ['ntlm', 'authentication', 'pass-the-hash', 'relay', 'domain-controller', 'audit', 'security'],
    powershell: `# NTLM Authentication Investigation
# Eventful
# Run on Domain Controller

$computer  = $env:COMPUTERNAME  # Run on a DC
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4776
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $err  = ($data | Where-Object Name -eq 'Status').'#text'
    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        AccountName  = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        Workstation  = ($data | Where-Object Name -eq 'Workstation').'#text'
        ErrorCode    = $err
        Outcome      = if ($err -eq '0x0') { 'Success' } else { 'Failure' }
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4625, 4740, 4771, 4624],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776'
  },

  {
    id: 4778,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'RDP Session Reconnected',
    short_desc: 'A previously disconnected Remote Desktop session was reconnected.',
    description: 'Event 4778 is generated when a Remote Desktop or Remote Assistance session is reconnected after being in a disconnected state. Unlike 4624 (which is logged when a new session starts), 4778 specifically indicates a reconnection to an existing disconnected session. It includes the account name, the client machine name, and the client address. Paired with 4779 (disconnection), it gives a complete picture of RDP session lifecycle.',
    why_it_happens: 'When an RDP session is disconnected (rather than logged off), the session remains alive on the server in a suspended state. When the user — or any user with appropriate credentials — reconnects, Windows logs 4778 with the "Logon Type 10" designation. A new session logs 4624 Type 10; a reconnection to existing disconnected session logs 4778.',
    what_good_looks_like: 'Expected: a user reconnecting to their own session after a network drop or laptop close/open. Investigate: reconnections from different IP addresses than the original session (session hijacking risk), reconnections to sessions owned by other users, reconnections at unusual times to sessions that have been disconnected for extended periods.',
    common_mistakes: [
      'Treating 4778 identically to 4624 — reconnections are a distinct event type with different security implications',
      'Not noticing when a user reconnects to another user\'s session (on RDS servers, this is possible for admins)',
      'Not correlating Client Address in 4778 vs 4779 to detect session hijacking'
    ],
    causes: [
      'User reconnecting after network interruption',
      'User reconnecting after closing laptop lid',
      'Admin reconnecting to manage a disconnected session',
      'Automated reconnection by RDP client',
      'Session hijacking (admin connecting to another user\'s session)'
    ],
    steps: [
      'Filter Security log for 4778',
      'Note "Account Name" and "Client Address"',
      'Compare Client Address with the previous 4779 (disconnect) for the same session',
      'If Client Address changed: possible session handoff or compromise — investigate',
      'On RDS servers: check for admins reconnecting to other users\' sessions',
      'Correlate with RDS events 25 (session reconnected) in the TerminalServices-LocalSessionManager log'
    ],
    symptoms: [
      'rdp reconnected',
      'remote desktop reconnect',
      'session reconnected',
      'rdp session resumed',
      'remote session resumed'
    ],
    tags: ['rdp', 'session-reconnect', 'remote-desktop', 'audit', 'security'],
    powershell: `# RDP Session Reconnect Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4778
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        AccountName    = ($data | Where-Object Name -eq 'AccountName').'#text'
        ClientName     = ($data | Where-Object Name -eq 'ClientName').'#text'
        ClientAddress  = ($data | Where-Object Name -eq 'ClientAddress').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4779, 4624, 4634, 21, 25],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778'
  },

  {
    id: 4779,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'RDP Session Disconnected',
    short_desc: 'A Remote Desktop session was disconnected (not logged off — session stays alive).',
    description: 'Event 4779 records when an RDP or Remote Assistance session transitions to disconnected state — meaning the user closed the RDP window or lost connectivity, but did not formally log off. The session remains alive on the server and can be reconnected (4778). This event includes the account, client machine, and client address. Understanding the difference between a disconnect (4779) and a logoff (4634) is fundamental to RDP session management.',
    why_it_happens: 'When the RDP client window is closed without logging off, or when a network interruption occurs, the RDP session state transitions from active to disconnected. Windows keeps the session alive for the configured session idle/disconnect timeout period. If the session times out without reconnection, it is logged off. 4779 is the audit record of the disconnect transition.',
    what_good_looks_like: 'Expected: users disconnecting and reconnecting throughout the day, especially on RDS servers where multiple users work. Investigate: sessions that stay disconnected for very long periods (potential abandoned sessions with data exposed), many sessions disconnecting simultaneously (network event), disconnect followed by reconnection from a different IP.',
    common_mistakes: [
      'Assuming a 4779 means the user logged off — they did not, the session is still alive',
      'Not checking for idle disconnected sessions on RDS servers — these waste resources and are a security risk'
    ],
    causes: [
      'User closed RDP window without logging off',
      'Network interruption broke the connection',
      'RDP client timeout',
      'Admin forced disconnect of a session',
      'Session policy disconnected idle session'
    ],
    steps: [
      'Filter Security log for 4779',
      'Note the "Client Address" — where was the session connecting from?',
      'Check if the session was reconnected (4778) after disconnect',
      'If no 4778 follows: session is still disconnected — check if it should be terminated',
      'On RDS: enumerate disconnected sessions with: qwinsta /server:<server>',
      'Terminate stale sessions with: logoff <sessionid> /server:<server>'
    ],
    symptoms: [
      'rdp disconnected',
      'remote desktop disconnected',
      'session disconnected',
      'rdp session ended',
      'user disconnected from rdp'
    ],
    tags: ['rdp', 'session-disconnect', 'remote-desktop', 'audit'],
    powershell: `# RDP Session Disconnect Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4779
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        AccountName   = ($data | Where-Object Name -eq 'AccountName').'#text'
        ClientName    = ($data | Where-Object Name -eq 'ClientName').'#text'
        ClientAddress = ($data | Where-Object Name -eq 'ClientAddress').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4778, 4624, 4634, 24, 40],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4779'
  },

  {
    id: 4798,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Advanced',
    title: "User's Local Group Membership Enumerated",
    short_desc: 'A process queried the local group membership of a specific user account.',
    description: 'Event 4798 is generated when a process enumerates the local group memberships of a user account. This is frequently triggered by Windows components during logon as part of building the access token, but it can also be triggered by reconnaissance scripts enumerating which local groups a user belongs to. When generated by unexpected processes (not winlogon.exe, lsass.exe, or explorer.exe) at scale, it may indicate an attacker performing internal reconnaissance.',
    why_it_happens: 'Applications and Windows components enumerate group membership using the NetUserGetLocalGroups() API or its equivalent. During normal logon, lsass.exe calls this to build the access token. Security assessment tools, and unfortunately attackers, call the same APIs to understand what access a user or set of users has across local machines.',
    what_good_looks_like: 'Expected: winlogon.exe, lsass.exe, and explorer.exe generating these events during logon. Investigate: enumeration by unexpected processes, high-volume enumeration of many accounts in a short time from one process (automated reconnaissance), enumeration of admin accounts specifically.',
    common_mistakes: [
      'Alerting on every 4798 — most are legitimate logon infrastructure',
      'Not filtering by Process Name — the process doing the enumeration is the critical field'
    ],
    causes: [
      'Normal Windows logon process building access token',
      'Security compliance tools performing audits',
      'Attacker tool enumerating accounts for privilege escalation targeting',
      'IT management scripts checking group membership'
    ],
    steps: [
      'Filter Security log for 4798',
      'Check "CallerProcessName" — is it a known Windows process or something unexpected?',
      'If unexpected process: investigate with 4688 to find where that process came from',
      'Check if multiple accounts were enumerated in quick succession from the same process'
    ],
    symptoms: [
      'local group enumeration',
      'who is in local admins',
      'group membership query',
      'account reconnaissance',
      'listing local group members'
    ],
    tags: ['reconnaissance', 'group-membership', 'enumeration', 'audit', 'security'],
    powershell: `# Local Group Membership Enumeration Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4798
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        TargetAccount = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        CallerProcess = ($data | Where-Object Name -eq 'CallerProcessName').'#text'
        SubjectUser   = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Where-Object { $_.CallerProcess -notlike '*winlogon*' -and $_.CallerProcess -notlike '*lsass*' } |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4799, 4627, 4688],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798'
  },

  {
    id: 4799,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Advanced',
    title: 'Local Group Membership Enumerated',
    short_desc: 'A process queried the membership of a local security group.',
    description: 'Event 4799 is generated when a process enumerates the members of a local security group (as opposed to 4798, which enumerates the groups a user belongs to). This event is particularly interesting when the target group is Administrators — it reveals what processes are checking who has local admin rights on the machine. Malware and attacker tools frequently query local Administrators group membership to understand the privilege landscape before escalating.',
    why_it_happens: 'Enumeration via the NetLocalGroupGetMembers() API generates 4799. This is called by many legitimate tools (LAPS, Windows Admin Center, compliance tools), but also by attacker tools during post-exploitation reconnaissance.',
    what_good_looks_like: 'Expected: management tools and Windows components enumerating Administrators membership. Investigate: unknown processes enumerating Administrators specifically, batch enumeration of many groups in a short period, enumeration from processes launched by unusual parents.',
    common_mistakes: [
      'Not filtering by the Target Group Name — enumeration of Administrators is much more interesting than Other groups',
      'Treating every 4799 as suspicious when most are legitimate management tool activity'
    ],
    causes: [
      'Windows management tools checking group membership',
      'LAPS (Local Administrator Password Solution) checking admin accounts',
      'Attacker tool enumerating local admin members for targeting',
      'Compliance scanning tools'
    ],
    steps: [
      'Filter Security log for 4799',
      'Check "Target Group Name" — is it Administrators?',
      'Check "Calling Process Name" — is it a known tool or unexpected?',
      'Correlate with 4688 if the calling process is unusual',
      'High frequency from one process: possible automated reconnaissance'
    ],
    symptoms: [
      'local admins enumerated',
      'who is in administrators group',
      'listing administrator group members',
      'local group query',
      'local group enumeration'
    ],
    tags: ['reconnaissance', 'group-membership', 'enumeration', 'local-admin', 'audit', 'security'],
    powershell: `# Local Group Enumeration Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4799
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated   = $_.TimeCreated
        TargetGroup   = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        CallerProcess = ($data | Where-Object Name -eq 'CallerProcessName').'#text'
        SubjectUser   = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4798, 4627, 4688, 4732],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4799'
  },

  {
    id: 1102,
    source: 'Microsoft-Windows-Eventlog',
    channel: 'Security',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Security Audit Log Cleared',
    short_desc: 'The Security event log was cleared — records who cleared it and when.',
    description: 'Event ID 1102 from Microsoft-Windows-Eventlog is written to the Security log immediately before it is cleared. It records the account that performed the clear. For IT support, this event explains why a Security log starts from a recent date with no earlier history — someone cleared it. In an IT support context this is usually an admin clearing logs to free space or a management script. The key is identifying who cleared it and whether that was expected. All evidence from before the clear is permanently gone.',
    why_it_happens: 'Written by the Windows event logging service immediately before the Security log is wiped. Clearing the Security log requires SeSecurityPrivilege — only administrators hold this right. Event 1102 is always the last event before the gap in the log.',
    what_good_looks_like: 'Absent in most IT support logs. When present: check the SubjectUserName field — was this a known admin at an expected time? If yes, low priority. Unknown account or unexpected timing warrants follow-up.',
    causes: [
      'Admin clearing the log manually to free disk space',
      'Log management or SIEM tool rotating the log',
      'Diagnostic or setup script clearing logs',
      'Automated policy clearing logs on schedule'
    ],
    steps: [
      'Check SubjectUserName — who cleared the log',
      'Confirm with that user or their manager whether the action was intentional',
      'Check Event 104 in System log — if System log was also cleared at the same time, investigate further',
      'Note: all log data before the clear is permanently gone'
    ],
    symptoms: [
      'security log empty',
      'no security events before a date',
      'security log was cleared',
      'event log history missing',
      'logs start from today'
    ],
    tags: ['log-clear', 'security', 'audit', 'admin'],
    powershell: `# Security Log Clear History
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 1102
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [104, 4624, 4672],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102'
  }
];
