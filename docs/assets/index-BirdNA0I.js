const e=[{id:4624,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Fundamental",title:"Successful Logon",short_desc:"A user or process successfully authenticated and was granted access.",description:"Event 4624 is generated every time an account successfully logs on to the computer. The event captures who logged on, how they logged on (logon type), from where, and under what process. It is one of the highest-volume events in the Security log and forms the backbone of authentication auditing. Logon Type is the most important field — Type 2 is interactive (keyboard at the machine), Type 3 is network (file share, mapped drive), Type 7 is unlock, Type 10 is Remote Interactive (RDP), and Type 11 is cached credentials.",why_it_happens:"Windows generates this event as part of Logon/Logoff auditing whenever the Security Account Manager (SAM) or Kerberos authentication packages validate credentials successfully. Every resource access — opening a file share, unlocking a workstation, an RDP session — produces a logon event. Services also generate Type 5 (service logon) events on startup. The volume makes this event noisy on domain controllers, which see every network logon from every machine authenticating to AD.",what_good_looks_like:"Expected: Type 3 logons from your file server to member computers during business hours, Type 2 logons from known user accounts, Type 5 logons from known service accounts. Investigate: logons outside business hours for sensitive accounts, Type 10 (RDP) logons from unexpected source IPs, logons from accounts that should not be accessing a particular machine, Type 9 (NewCredentials/RunAs) logons.",common_mistakes:["Treating all 4624 events as significant — on a domain controller you will see thousands per hour; filter by logon type first","Forgetting that Type 3 logons are normal for every mapped drive, printer access, or file share access",'Overlooking the "Account for which logon was performed" vs the "Subject" field — the Subject is often SYSTEM, the target account is the important one',"Not checking the Workstation Name and Source IP fields to see where the logon originated","Assuming a logon means a human sat at the keyboard — services, scheduled tasks, and scripts all generate logon events"],causes:["User interactively logging in at the console (Type 2)","User accessing a network share or mapped drive (Type 3)","A service starting under a service account (Type 5)","A user unlocking their workstation (Type 7)","An RDP session being established (Type 10)","Credentials being cached used offline (Type 11)","A process using RunAs or alternate credentials (Type 9)"],steps:["Open Event Viewer → Windows Logs → Security, filter for Event ID 4624",'Identify the "Logon Type" field — this tells you how the logon occurred','Check "Account Name" under "New Logon" — this is who logged on','Check "Workstation Name" and "Source Network Address" for remote logons',"For Type 10 logons, cross-reference with RDS events 21, 25, 4778","If investigating suspicious activity, export and pivot on Account Name and Source IP","Use PowerShell snippet below to filter by logon type or account name"],symptoms:["user logged in","who logged into this computer","when did someone log on","check login history","see who accessed this pc","authentication successful","rdp login","remote login","account logged on"],tags:["authentication","logon","audit","rdp","kerberos","ntlm","security","baseline"],powershell:`# Successful Logon Investigation
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
    Format-Table -AutoSize`,related_ids:[4625,4634,4647,4648,4672,4771,4776,4778],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624"},{id:4625,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"Failed Logon",short_desc:"An account failed to log on — wrong password, bad account, or locked out.",description:'Event 4625 is generated whenever a logon attempt fails. It is the primary event for investigating account lockouts, brute-force attacks, and misconfigured service accounts. The most critical field is "Failure Reason" / "Sub Status" code — 0xC000006A means wrong password, 0xC0000234 means account already locked, 0xC000006D means bad username, 0xC000006F means logon outside permitted hours. A burst of these events from a single source IP strongly suggests a brute-force or password spray attack.',why_it_happens:`Windows logs failed logons as part of Logon/Logoff auditing. Failures happen for many reasons: typos, cached credentials after a password change, stale service account credentials, or deliberate attack. The Sub Status code is generated by the authentication package (Kerberos or NTLM) and distinguishes between "wrong password" and "account doesn't exist", which is important — attackers enumerating accounts generate mostly 0xC000006D errors.`,what_good_looks_like:"One or two failed logons followed by a successful 4624 is normal (typo, then correct password). Investigate: repeated failures for the same account from multiple sources (password spray), repeated failures for many accounts from one source (credential stuffing), failures for accounts that shouldn't exist (deleted user still configured in a service), failures outside business hours for interactive accounts.",common_mistakes:["Looking at 4625 without also looking at 4740 — the lockout event tells you which computer triggered it","Ignoring the Sub Status code — it distinguishes wrong password from bad account, which matters for attack detection","Only looking at the DC — failed logons also appear on the member computer where the attempt occurred","Not checking the Caller Computer Name or Source Network Address when investigating remote failures","Assuming every failed logon is an attack — users mistype passwords constantly"],causes:["User typed wrong password","Cached credentials not updated after password change","Service account configured with old password","Account locked out from previous failures","Account disabled or deleted","Logon attempt outside permitted hours or from non-allowed workstation","Brute-force or password spray attack","VPN or remote access client using stale credentials"],steps:["Filter Security log for 4625 on the target machine or DC",'Note the "Account Name" — is this a known user, service account, or unknown name?',"Check Sub Status code: 0xC000006A = wrong password, 0xC0000234 = locked, 0xC000006D = bad username","If Sub Status 0xC000006A: find what device is sending the bad password (Workstation Name / Source IP)","If Sub Status 0xC0000234: find 4740 lockout event to see triggering computer","Correlate Source IP with your asset inventory — is it a known machine?","If many accounts failed from one IP, escalate — likely spray attack","Check for corresponding 4740 to confirm lockout occurred"],symptoms:["user cant log in","account locked out","wrong password","login failed","authentication failed","bad password","user keeps getting locked out","account lockout investigation","brute force","failed authentication"],tags:["authentication","lockout","failed-logon","brute-force","password","security","audit"],powershell:`# Failed Logon Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4624,4740,4767,4771,4776],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625"},{id:4627,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Intermediate",title:"Group Membership Enumeration During Logon",short_desc:"Windows enumerated group memberships for an account at logon time.",description:"Event 4627 records the full list of security groups a user is a member of at the time of logon. It is generated alongside 4624 when group membership auditing is enabled. The event includes every group SID — domain groups, local groups, special identities (Everyone, Authenticated Users), and privilege groups (Administrators, Domain Admins). It is primarily useful for confirming what access a user had at a specific point in time, which is valuable in insider threat investigations and compliance audits.",why_it_happens:"When a user logs on, the Local Security Authority (LSA) builds an access token containing all the user's group memberships and privileges. Event 4627 is the audit record of this token-building process. It captures the group state at logon time, not the current state — if group membership changes after logon, the existing session's token is not updated until the user logs off and back on.",what_good_looks_like:"Normal: user is a member of expected groups (Domain Users, department groups, maybe a few resource groups). Investigate: a standard user appearing in Domain Admins, Schema Admins, or Backup Operators; group memberships that change between logon events for the same user; a service account with unexpectedly broad group membership.",common_mistakes:["Confusing this event with group membership change events (4728, 4732) — 4627 shows membership at logon, not changes","Not realising the token is built at logon — a group change won't show up until next logon","Ignoring the special identity SIDs (S-1-1-0 Everyone, S-1-5-11 Authenticated Users) in the membership list — these are normal","This event can be very large — some users have 50+ group memberships and the XML is lengthy"],causes:["Any successful interactive or network logon with group membership auditing enabled","Elevated privilege use via RunAs generating a separate logon token","Service account logon building its access token"],steps:["Filter Security log for 4627 alongside a specific 4624 using the LogonID correlation field",'Look at the "Group Membership" field for any unexpected privileged groups',"Cross-reference with HR records if investigating insider threat or access review","Compare group memberships across multiple logon events for the same user to spot changes","Use the LogonID from 4624 to find the corresponding 4627 for the same session"],symptoms:["what groups is this user in","check user group membership","audit user access","privileged group membership","when did user get admin rights"],tags:["group-membership","access-token","privileged-access","audit","compliance"],powershell:`# Group Membership Enumeration Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4627
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4624,4728,4732,4756,4672],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4627"},{id:4648,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Intermediate",title:"Logon with Explicit Credentials (RunAs)",short_desc:"A process used different credentials than the logged-on user to access a resource.",description:'Event 4648 is generated when a process uses alternate credentials — via RunAs, a "net use" command with credentials, or a script that embeds credentials. It records both the account that initiated the logon (the "Subject") and the account whose credentials were used (the "Account Whose Credentials Were Used"). This event is important because it can reveal credential exposure: if an attacker has compromised a machine, they may use 4648 to pivot using harvested credentials. It also appears during legitimate admin activities.',why_it_happens:"Windows generates 4648 when the LogonUser() API is called with the LOGON32_LOGON_NEW_CREDENTIALS flag, or when CreateProcessWithLogonW is used. These APIs are called by RunAs, scheduled tasks using alternate accounts, scripts with embedded credentials, and tools like PsExec. The event is generated on the machine where the credential use originates, not on the target machine.",what_good_looks_like:`Expected: an IT admin using RunAs to launch a management console with admin credentials, a script explicitly connecting to a remote resource. Investigate: a standard user account generating 4648 events (they shouldn't be using alternate credentials), the "Target Server" being a sensitive system, 4648 events at unusual times, credentials for accounts that shouldn't be used interactively.`,common_mistakes:["Confusing 4648 with 4624 Type 9 (NewCredentials logon) — they are related but 4648 is on the source machine, 4624 Type 9 on the target","Not noticing this event because it is often buried in high-volume logs — set an alert for 4648 from standard user accounts","Ignoring scheduled tasks — they generate 4648 on every run if configured with alternate credentials",'Missing that "mapped drives" configured with credentials generate 4648 repeatedly'],causes:["Admin using RunAs to elevate","Script or batch file embedding credentials","Scheduled task configured with alternate account credentials","net use command with explicit credentials","PsExec or similar tools using alternate credentials","Malware using harvested credentials to pivot laterally"],steps:["Filter Security log for 4648 on the suspect machine",'Identify "Account Whose Credentials Were Used" — is this a privileged account?','Check "Target Server Name" — what resource was being accessed?',"Check the initiating process name — is it cmd.exe, powershell.exe, or an unknown executable?","Correlate with 4624 Type 9 on the target machine to confirm the credential use succeeded","If the initiating process is unexpected, investigate the process tree","Check if the Subject account should normally be using alternate credentials at all"],symptoms:["runas command","explicit credentials","alternate credentials","user running as admin","credentials used by different account","pass the hash","lateral movement","privilege escalation"],tags:["runas","credentials","lateral-movement","privilege-escalation","security","audit"],powershell:`# Explicit Credential Use (RunAs) Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4624,4672,4688],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648"},{id:4663,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Advanced",title:"File or Object Access Attempt",short_desc:"An account attempted to access a file, registry key, or Active Directory object.",description:"Event 4663 records every access attempt to an audited object — a file, folder, registry key, or Active Directory object. It is generated only when object access auditing is enabled AND the specific object has a System Access Control List (SACL) configured to audit that type of access. The event records who accessed the object, what type of access was requested (Read, Write, Delete, etc.), and whether it succeeded. This event is extremely noisy without careful SACL scoping and should only be enabled on sensitive objects.",why_it_happens:"Windows generates 4663 as part of Object Access auditing. The audit policy must be enabled (either File System or Registry subcategory), and the specific object must have a SACL that defines which users and access types to audit. Without a SACL, no events are generated regardless of audit policy. SACLs are configured in the Security tab → Advanced → Auditing of a file or folder. Group Policy can deploy SACLs at scale.",what_good_looks_like:"Normal: known users accessing expected files during business hours. Investigate: access to files outside normal working hours, DELETE or WRITE access to sensitive files like scripts or configs, access from unexpected accounts (e.g., service accounts accessing user documents), a burst of access events suggesting bulk file enumeration or exfiltration.",common_mistakes:["Enabling Object Access auditing globally without configuring SACLs — this generates zero events (policy without SACLs = nothing)","Enabling SACLs on high-volume locations like C:\\ — the event volume will overwhelm the security log instantly",'Not filtering for the "Accesses" field — Read Data, Write Data, Delete are very different risk levels',"Confusing 4663 (access attempt) with 4656 (handle request) — 4663 means the access actually happened","Not setting the security log size large enough to retain 4663 events before they are overwritten"],causes:["Normal file access by authorised users","Application accessing files it needs to function","Backup agent reading files","Malware reading, writing, or deleting sensitive files","Insider threat accessing data they should not","Ransomware encrypting files (massive burst of write events)"],steps:['Confirm Object Access auditing is enabled via auditpol /get /subcategory:"File System"',"Confirm the target file/folder has a SACL configured (Security → Advanced → Auditing)","Filter Security log for 4663, scoped to the object name in question",'Check "Accesses" field — is it Read, Write, Delete, or others?','Check "Account Name" — is the accessing account expected to touch this file?',"For ransomware investigation, look for a burst of Write events across many files from one process","Correlate with 4688 to find the process that made the access"],symptoms:["who accessed this file","file was deleted","file was modified","ransomware file access","audit file access","sensitive file accessed","who read this document","data exfiltration investigation"],tags:["file-access","object-access","sacl","audit","ransomware","data-exfiltration","dlp"],powershell:`# File/Object Access Investigation
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
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4656,4670,4688,4624],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663"},{id:4670,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Advanced",title:"Permissions on Object Changed",short_desc:"The access control list (ACL) on a file, registry key, or AD object was modified.",description:'Event 4670 is generated when the permissions (DACL) on a file, folder, registry key, or Active Directory object are changed. It records the original permissions and the new permissions in SDDL format, along with who made the change and what process performed it. This event requires Object Access auditing and an appropriate SACL on the object. ACL changes on sensitive resources — like adding "Everyone Full Control" to a sensitive folder — are a strong indicator of privilege escalation or lateral movement.',why_it_happens:"When an application or user calls SetSecurityInfo() or SetNamedSecurityInfo() to modify an object's DACL, Windows logs 4670. This happens during legitimate admin tasks (granting a user access to a folder), but also during attacks where adversaries try to weaken permissions on sensitive files or registry keys to gain persistent access.",what_good_looks_like:"Expected: IT admin changing folder permissions through a documented change process. Investigate: permissions changed outside of change windows, a non-admin account changing permissions, permissions changed on system binaries or registry run keys, ACL changes that add broad access (Everyone, Authenticated Users) to sensitive paths.",common_mistakes:["Not having SACL audit entries on sensitive paths — 4670 will not fire without both audit policy and SACL",'Ignoring the SDDL strings because they look complex — focus on the "New SD" field, specifically any A;;FA;;;WD (Full Access for Everyone) or similar broad grants',"Not correlating with 4688 to find the process that made the change"],causes:["IT admin explicitly modifying folder permissions","Software installer setting permissions on program files","Malware weakening permissions on files for persistence","Ransomware modifying ACLs to ensure write access before encryption","GPO applying new file system permissions"],steps:["Filter Security log for 4670",'Check "Object Name" — what file/folder was changed?','Decode the "New SD" SDDL string — look for WD (World/Everyone) with FA (Full Access)','Check "Subject Account Name" — was this a known admin doing authorized work?','Check "Process Name" — was it Explorer.exe (manual), or something unexpected?',"Review change management records to see if this was planned","If unauthorized, restore original permissions from backup and investigate further"],symptoms:["permissions changed on file","acl modified","access control changed","who changed permissions","folder permissions modified","security descriptor changed"],tags:["permissions","acl","dacl","sacl","file-system","privilege-escalation","audit"],powershell:`# Permissions Change Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4670
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4663,4688,4698],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670"},{id:4672,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Intermediate",title:"Special Privileges Assigned to New Logon",short_desc:"A user logged on with administrative or sensitive privileges in their access token.",description:"Event 4672 is generated immediately after 4624 whenever the account that logged on holds one or more sensitive privileges. These include SeDebugPrivilege (debug any process), SeBackupPrivilege (read any file for backup), SeImpersonatePrivilege (impersonate any user), SeTakeOwnershipPrivilege, and others that grant powerful OS capabilities. This event effectively marks every admin logon. It appears extremely frequently for SYSTEM and built-in admin accounts — the key is filtering for unexpected accounts or unexpected machines.",why_it_happens:"When the LSA builds an access token for a logon, it checks whether any of the user's group memberships or direct assignments include sensitive privileges. If they do, 4672 is generated. Local Administrators always hold many of these privileges. Domain Admins inherit them. The event fires even if the account never actually uses those privileges — it is based on token construction, not privilege use.",what_good_looks_like:"Expected: Domain Admin accounts generating 4672 on DCs and servers they manage, local admin accounts generating it on workstations. Investigate: 4672 for standard user accounts (they should not hold sensitive privileges), 4672 on machines the admin account shouldn't access, an account gaining SeDebugPrivilege that wasn't previously an admin.",common_mistakes:["Alerting on every 4672 — SYSTEM generates one on every boot, and every admin logon generates one","Not filtering for the specific privileges in the event — SeDebugPrivilege and SeTcbPrivilege are more dangerous than SeChangeNotifyPrivilege","Ignoring 4672 on domain controllers — these are critical machines and unexpected admin logons matter more there","Not correlating with 4624 using the LogonID — they should always appear together"],causes:["Admin user logging on interactively or via RDP","Service running under a privileged service account starting","Scheduled task running under admin credentials","Malware that has elevated to SYSTEM or admin generating logon events"],steps:["Filter Security log for 4672",'Check "Account Name" — is this account expected to be an admin?','Check "Privileges" — focus on SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege',"Correlate with 4624 using the LogonID to see where the logon came from","On DCs, any unexpected 4672 should be immediately investigated","Cross-reference with AD group membership to see if the privilege assignment is expected"],symptoms:["admin logged on","privileged logon","who has admin access","administrative logon","sensitive privileges","debug privilege","domain admin logon"],tags:["privileges","admin","access-token","audit","security-baseline"],powershell:`# Special Privileges Assigned Investigation
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
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4624,4627,4648],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672"},{id:4688,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Advanced",title:"New Process Created",short_desc:"A new process was created — records executable path, parent process, and user context.",description:"Event 4688 records every new process creation when Process Creation auditing is enabled. It captures the full executable path, the account running it, the parent process, and — when command line auditing is also enabled — the exact command line arguments. This is one of the most valuable events for threat hunting and incident response. It shows exactly what programs were run, by whom, and under what process lineage. Attackers frequently try to live off the land using built-in tools (cmd.exe, powershell.exe, wmic.exe, certutil.exe) — 4688 reveals this.",why_it_happens:'Windows generates 4688 through the Process Tracking audit subcategory. It fires every time CreateProcess() is called and a new process kernel object is instantiated. On a busy workstation this can be hundreds per hour. The command line is only included if "Include command line in process creation events" is enabled in Group Policy (Computer Configuration → Admin Templates → System → Audit Process Creation). This setting is off by default.',what_good_looks_like:"Normal: known applications launching from standard paths (C:\\Program Files\\, C:\\Windows\\System32\\), with expected parent processes (explorer.exe for user-launched apps, services.exe for services). Investigate: executables running from unusual paths (temp folders, AppData, recycle bin), PowerShell encoded commands, processes launched by unusual parents (Word spawning cmd.exe), known LOLBins (certutil, mshta, regsvr32) used unexpectedly.",common_mistakes:["Not enabling command line auditing — the executable path alone is much less useful than the full command line","Not enabling this audit policy at all — it is off by default and must be explicitly enabled","Being overwhelmed by volume and not using specific parent process or path filters to narrow down","Missing that Windows Defender and AV engines create many processes when scanning — these are expected noise"],causes:["User launching an application","A service or scheduled task spawning a child process","Script interpreter (cmd.exe, powershell.exe, wscript.exe) executing code","An exploit using a trusted application to run attacker-controlled code","Malware executing a payload","Lateral movement tools like PsExec creating remote processes"],steps:['Confirm audit policy: auditpol /get /subcategory:"Process Creation"',"Confirm command line logging is enabled via GPO or local security policy","Filter 4688 for a specific user, time window, or parent process","Look for processes running from non-standard paths (AppData, Temp, Recycle Bin)","Look for cmd.exe or powershell.exe spawned by Office applications (Word, Excel)","Check for encoded PowerShell commands (-enc or -EncodedCommand)","Build a process tree using ParentProcessId and ProcessId fields","Cross-reference unusual processes with VirusTotal by hash if available"],symptoms:["what programs were run","process executed","command was run","malware running process","suspicious executable","powershell command ran","process tracking","who ran this program","application launched"],tags:["process-creation","threat-hunting","lolbins","powershell","malware","incident-response","audit"],powershell:`# Process Creation Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4624,4648,4698,4663],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688"},{id:4698,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Intermediate",title:"Scheduled Task Created",short_desc:"A new scheduled task was registered on the system.",description:"Event 4698 is generated when a new scheduled task is created through Task Scheduler. It records the task name, the account that created it, and the full task XML including triggers, actions, and the account it runs under. Scheduled tasks are a favourite persistence mechanism for attackers — they survive reboots, run silently, and blend in with legitimate administrative tasks. Every new task creation should be reviewed, especially outside of known change windows.",why_it_happens:"Windows records task creation through the Object Access auditing subsystem. The Task Scheduler service calls the security audit API when a task is registered via the COM interface, the schtasks command, or PowerShell. The task XML embedded in the event contains everything about the task — when it runs, what it runs, and under what credentials.",what_good_looks_like:"Expected: software installers creating update tasks (Google, Adobe, Microsoft), IT management tools (RMM agents, monitoring), GPO-deployed tasks. Investigate: tasks created outside business hours, tasks running from AppData or Temp directories, tasks using encoded commands, tasks running under SYSTEM that weren't there before, task names mimicking system tasks but in slightly wrong locations.",common_mistakes:["Assuming tasks in unusual folders like C:\\Windows\\System32\\Tasks\\ are legitimate just because of the path","Not reading the full task XML in the event — the Action element reveals the actual command being run",'Overlooking tasks that use "schtasks /create" from command line — they also generate 4698',"Not setting a baseline of legitimate scheduled tasks to compare against"],causes:["Software installation creating an update or maintenance task","IT admin scheduling a maintenance script","RMM or monitoring agent deploying a task","Malware creating a persistence mechanism","Attacker using schtasks for lateral execution or persistence"],steps:["Filter Security log for 4698",'Read the "Task Name" — does it match a known application?','Read the "Task Content" XML — examine the Action element for the command being executed','Check the "Subject Account Name" — was this created by a known admin or SYSTEM?',"Verify the task exists and matches what the event recorded: Get-ScheduledTask | Where-Object TaskName -eq '<name>'","Check the trigger — when does it run? At logon? Every minute?","If suspicious, delete with Remove-ScheduledTask and investigate further"],symptoms:["scheduled task created","new task in task scheduler","malware persistence","task created overnight","suspicious scheduled task","who created this task","task running as system"],tags:["scheduled-task","persistence","malware","audit","security"],powershell:`# Scheduled Task Creation Investigation
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
} | Sort-Object TimeCreated -Descending | Format-List`,related_ids:[4700,4702,4688,4624],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698"},{id:4700,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Intermediate",title:"Scheduled Task Enabled",short_desc:"A previously disabled scheduled task was enabled.",description:"Event 4700 records when a scheduled task transitions from disabled to enabled. Attackers sometimes create tasks in a disabled state to avoid immediate execution, then enable them later when they are ready to use them. It is also generated when an admin re-enables a task they previously disabled. The event includes the task name, the account that enabled it, and a timestamp.",why_it_happens:"Task Scheduler generates a security audit event when a task's enabled status is changed. This happens when a task is enabled via the Task Scheduler GUI, the schtasks /change /enable command, or the PowerShell Enable-ScheduledTask cmdlet. The event is logged on the machine where the task lives.",what_good_looks_like:"Expected: an IT admin enabling a task during a maintenance window, software update enabling its own task. Investigate: a disabled task being re-enabled at an unusual time, a task being enabled immediately after being created (suggesting automated persistence setup), tasks being enabled that you don't recognise.",common_mistakes:["Treating this event in isolation — always check 4698 to find the original task creation","Not realising a task can be created disabled (to avoid detection), then enabled later"],causes:["IT admin enabling a maintenance task","Software enabling its own update task","Malware enabling a previously created persistence task","GPO enabling a centrally managed task"],steps:["Filter Security log for 4700","Note the Task Name and cross-reference with 4698 to see when it was created","Check who enabled it and whether they should have access to that task","Verify the task still exists and inspect it with Get-ScheduledTask","If suspicious, disable and investigate: Disable-ScheduledTask -TaskName '<name>'"],symptoms:["scheduled task enabled","task enabled","task turned on","task was activated"],tags:["scheduled-task","persistence","audit","security"],powershell:`# Scheduled Task Enabled Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4700
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4698,4702,4688],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4700"},{id:4702,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Intermediate",title:"Scheduled Task Updated",short_desc:"An existing scheduled task's configuration was modified.",description:"Event 4702 records modifications to existing scheduled tasks — changes to the action (what it runs), triggers (when it runs), or run-as account. Like task creation (4698), this event includes the full task XML after the change, making it possible to see exactly what was modified. Attackers who have established a foothold may modify existing legitimate tasks to add malicious actions, making this event critical for detecting that type of persistence modification.",why_it_happens:"Task Scheduler generates 4702 when an existing task's properties are changed through any interface — the GUI, schtasks /change, or Set-ScheduledTask in PowerShell. The full updated task XML is embedded in the event.",what_good_looks_like:"Expected: software updates changing their own task schedules, IT admins modifying maintenance tasks. Investigate: changes to tasks you did not initiate, actions being added or changed to run from suspicious paths, trigger intervals being shortened (an attacker making a task run more frequently), run-as account being changed to a more privileged account.",common_mistakes:["Only looking at task creation (4698) for persistence — attackers often modify existing tasks to avoid creating obvious new ones","Not comparing the new XML against the previous known-good task definition"],causes:["Software update modifying its own task","IT admin changing task schedule or action","Malware modifying a legitimate task to add malicious commands","Attacker changing the run-as account of a task to escalate privileges"],steps:["Filter Security log for 4702","Read the full task XML to see what changed","Cross-reference with 4698 to see the original task definition","Check who made the change and when","If the action changed, examine the new command being run","Compare with current task definition: (Get-ScheduledTask -TaskName '<name>').Actions"],symptoms:["scheduled task changed","task modified","task action changed","task schedule changed","who modified this task"],tags:["scheduled-task","persistence","audit","security"],powershell:`# Scheduled Task Update Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4702
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4698,4700,4688],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4702"},{id:4719,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Critical",skill_level:"Advanced",title:"System Audit Policy Changed",short_desc:"The local audit policy was modified — someone changed what security events are logged.",description:'Event 4719 is one of the most significant security events — it records that the audit policy itself was changed. This matters enormously because an attacker who changes the audit policy can blind the security log before carrying out subsequent malicious activity. The event shows which audit subcategory was changed, who changed it, and what it was changed to. "No Auditing" on any category should immediately raise concern.',why_it_happens:'Windows generates 4719 whenever auditpol.exe modifies a local audit policy, Group Policy applies an audit configuration, or an application calls the audit policy APIs. Importantly, this event is generated even when the change is to disable auditing of something — the event itself is always logged because "Audit Policy Change" auditing cannot be disabled.',what_good_looks_like:'Expected: GPO enforcing audit policy and generating 4719 on policy refresh, planned changes during a security hardening exercise. Investigate: audit subcategories being set to "No Auditing" (especially Logon, Process Creation, Account Management), changes made outside of GPO refresh times, changes by accounts other than SYSTEM or known admin accounts.',common_mistakes:["Not alerting on 4719 at all — this is one of the most important events to have high-priority alerts for","Assuming SYSTEM making this change is always GPO — check if GPO is actually the source or if something else changed it","Not knowing what your baseline audit policy is, making it impossible to notice changes"],causes:["Group Policy applying or refreshing audit settings","IT admin using auditpol.exe to change settings","Security tool modifying audit configuration","Attacker disabling auditing before malicious activity","Malware evading detection by disabling process tracking or logon auditing"],steps:["Filter Security log for 4719 — any hit should be investigated",'Check "Account Name" — was this SYSTEM (likely GPO) or a human account?',"Check the subcategory and what it was changed to (Enabled/Disabled/No Auditing)","Run auditpol /get /category:* to see current policy","If unauthorized change: restore policy via GPO or auditpol /set",'If policy was set to "No Auditing" on critical categories, check what else happened while auditing was disabled',"Alert SOC and escalate if this was not a planned change"],symptoms:["audit policy changed","logging disabled","audit disabled","who changed audit policy","event logging turned off","audit policy modified","someone turned off logging"],tags:["audit-policy","evasion","critical","security","compliance"],powershell:`# Audit Policy Change Investigation
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
Write-Host "
--- Current Audit Policy ---" -ForegroundColor Cyan
auditpol /get /category:*`,related_ids:[4688,4624,4698],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719"},{id:4720,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"User Account Created",short_desc:"A new user account was created.",description:"Event 4720 records the creation of a new local or domain user account. It includes the name of the new account, the account that created it, and attributes like the account's full name and description. Unauthorized account creation is a major red flag — attackers create accounts for persistence, and insiders may create shadow accounts. In MSP environments, alert on any account creation that was not preceded by a service desk ticket or change request.",why_it_happens:"Windows generates 4720 through Account Management auditing whenever Net User, the local Users and Groups MMC snap-in, or Active Directory Users and Computers creates an account. The event is generated on the machine where the account was created — for domain accounts, this is the domain controller that processed the request.",what_good_looks_like:"Expected: IT admin creating accounts during onboarding following a documented process. Investigate: accounts created outside business hours, accounts created by non-admin users, accounts with names that mimic system accounts (svc_backup2, administrator1), accounts created on endpoints rather than the domain controller.",common_mistakes:["Not having an alert for 4720 — any account creation should be a low-friction alert","Forgetting that local account creation (on a workstation) also generates 4720 — and local admin accounts are often more dangerous than domain ones","Not correlating with HR onboarding records to verify the account was expected"],causes:["IT admin onboarding a new employee","Software installing a service account","RMM or automation tool creating an account","Attacker creating a backdoor account for persistence","Insider threat creating a secondary account"],steps:["Filter Security log for 4720",'Note "New Account Name" and "Account Domain"','Check "Subject Account Name" — who created this account?',"Verify the creation aligns with an onboarding ticket or change request","If domain account: check the DC event log for the original creation event","Check if the account was immediately added to privileged groups (look for 4728, 4732 nearby)","If unauthorized: disable immediately with Disable-ADAccount, then investigate"],symptoms:["new account created","new user was created","account creation","unknown user account appeared","backdoor account","who created this account","new local account"],tags:["account-management","user-creation","persistence","audit","security"],powershell:`# User Account Creation Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4722,4728,4732,4726],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720"},{id:4722,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"User Account Enabled",short_desc:"A user account was enabled after being disabled.",description:"Event 4722 records that a previously disabled user account was re-enabled. This is important because it can indicate that a dormant account (perhaps a former employee's account that was disabled but not deleted) has been reactivated. Dormant accounts are attractive targets for attackers because they may still have valid group memberships, permissions, and access, but are less monitored than active accounts.",why_it_happens:`Windows generates 4722 as part of Account Management auditing when an account's "Account is disabled" flag is cleared. This happens via Active Directory Users and Computers, Net User, or PowerShell Enable-ADAccount. The event is generated on the machine (or DC) where the change was made.`,what_good_looks_like:"Expected: IT admin re-enabling a user account after a period of leave, following a documented process. Investigate: former employee accounts being re-enabled, accounts that should remain permanently disabled (terminated contractors), accounts re-enabled outside business hours.",common_mistakes:["Not correlating with 4625 — if a disabled account is generating failed logon attempts, someone may be trying to use it","Not checking when the account was last active before being disabled"],causes:["HR process for returning employee","IT admin re-enabling an account following a support ticket","Attacker re-enabling a dormant account for lateral access","Automated process incorrectly re-enabling accounts"],steps:["Filter Security log for 4722","Note the account being enabled and who enabled it","Check when the account was last active before being disabled","Verify this matches an HR or helpdesk ticket","Check for subsequent logon events (4624) for the re-enabled account","If unauthorized: re-disable immediately and investigate"],symptoms:["account enabled","account reactivated","disabled account turned on","old account re-enabled","user account unlocked by admin"],tags:["account-management","dormant-accounts","audit","security"],powershell:`# User Account Enabled Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4722
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4720,4725,4624],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4722"},{id:4723,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Fundamental",title:"Password Change Attempt",short_desc:"A user attempted to change their own password.",description:"Event 4723 records when a user attempts to change their own password (as opposed to 4724, which is an admin resetting someone else's password). The event records whether the attempt succeeded or failed. Failed attempts may indicate the user forgot their current password (they must know it to change it), or that a password complexity policy blocked the new password. This event is primarily used to track voluntary password changes for compliance auditing.",why_it_happens:"Windows generates 4723 as part of Account Management auditing. A user changing their own password calls a different API than an admin reset — the user must provide their current password for verification. Failures generate a 4723 event with a failure reason, while successes generate 4723 followed by audit trail entries.",what_good_looks_like:"Expected: users changing passwords after expiry reminders or when prompted by policy. Investigate: repeated failures (user can't remember current password — may need admin reset), password changes for service accounts (these should be managed, not user-initiated), password changes outside business hours.",common_mistakes:["Confusing 4723 (self-service change) with 4724 (admin reset) — different privileges and workflows","Ignoring failures — a user who failed to change their own password may then call the helpdesk for a reset"],causes:["User changing password proactively","Password expiry prompt accepted","User response to security training recommendation","Suspected compromise prompting password change","Compliance policy requiring periodic change"],steps:["Filter Security log for 4723","Note success or failure","If failure: check failure reason — may need to assist user with a 4724 admin reset","Correlate with any recent 4625 events for the same account","For service accounts: if a user is changing a service account password, escalate immediately"],symptoms:["user changed password","password change attempt","user updating their password","password expired","password change failed"],tags:["password","account-management","audit","compliance"],powershell:`# Password Change Attempt Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4723
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4724,4625,4740],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4723"},{id:4724,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"Password Reset Attempt",short_desc:"An administrator attempted to reset another account's password.",description:"Event 4724 records when a privileged account attempts to reset another user's password — without needing to know the current password. This requires Reset Password rights in Active Directory or local administrator privileges for local accounts. It is a critical event for account security auditing. If an attacker has compromised an admin account, resetting a target user's password is an early step in account takeover.",why_it_happens:"Windows generates 4724 as part of Account Management auditing when a user with sufficient privilege calls the password reset API. Unlike 4723 (self-service change), 4724 does not require the current password. The event is generated on the DC that processed the request for domain accounts.",what_good_looks_like:"Expected: helpdesk staff resetting passwords via a documented ticket. Investigate: password resets by non-helpdesk accounts, resets for accounts not in a current ticket, a compromised admin account resetting passwords (especially for other admin accounts), password resets for service accounts.",common_mistakes:["Not correlating with a helpdesk ticket system — every 4724 should have a corresponding ticket","Missing that this event is generated on the DC, not the helpdesk workstation","Not alerting when admin accounts reset other admin account passwords — this is very sensitive"],causes:["Helpdesk agent following a verified password reset request","Admin resetting their own account through an admin tool","Automated password management system rotating credentials","Attacker using a compromised admin account for account takeover","Insider threat resetting a target account's password"],steps:["Filter Security log for 4724 on DC or target machine",'Note the "Target Account Name" and "Subject Account Name" (who reset whom)',"Verify against helpdesk ticket records","If no ticket: contact the admin who made the change to verify","If unauthorized: immediately re-rotate the affected account's password and investigate the admin account","Check for 4624 logons using the affected account after the reset"],symptoms:["password reset","admin reset password","who reset this users password","password was changed by helpdesk","account password changed","forced password reset"],tags:["password","account-management","helpdesk","audit","security"],powershell:`# Password Reset Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4723,4720,4625],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724"},{id:4725,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"User Account Disabled",short_desc:"A user account was disabled.",description:"Event 4725 records the disabling of a user account. This should correspond to offboarding processes, security responses, or account lifecycle management. Unexpected account disabling — especially for admin accounts or shared service accounts — can indicate sabotage or an attacker trying to lock out defenders during an incident. Equally, if you see an account disabled followed by being re-enabled (4722), investigate who did both.",why_it_happens:`Windows generates 4725 as part of Account Management auditing when an account's "Account is disabled" flag is set. This happens through AD Users and Computers, Net User, or Disable-ADAccount in PowerShell.`,what_good_looks_like:"Expected: IT admin disabling accounts as part of offboarding (aligned with HR termination list). Investigate: accounts disabled outside of standard offboarding process, admin accounts being disabled unexpectedly, service accounts being disabled causing service outages.",common_mistakes:["Not linking account disable events to an HR or ITSM ticket for the offboarding","Not checking for service dependencies before disabling service accounts","Ignoring who performed the disable — was it the expected admin or an unexpected account?"],causes:["Employee offboarding","Security incident response (compromised account)","Account lockout mitigation (disabling before investigation)","Policy enforcement","Accidental disable","Insider sabotage"],steps:["Filter Security log for 4725",'Identify "Target Account" and "Subject Account" (who disabled whom)',"Verify against offboarding records or incident tickets","If a service account: check for 7000/7023 service failure events","If unauthorized: re-enable the account and investigate immediately","If part of a security response: confirm the account is appropriately contained"],symptoms:["account disabled","user account disabled","who disabled this account","account turned off","user locked out by admin"],tags:["account-management","offboarding","audit","security"],powershell:`# User Account Disabled Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4725
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4722,4720,4726],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4725"},{id:4726,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"User Account Deleted",short_desc:"A user account was permanently deleted.",description:"Event 4726 records the deletion of a user account. This is more severe than disabling (4725) because the action is harder to reverse — especially for local accounts on a workstation where no AD recycle bin exists. Unauthorised account deletion can be a sign of sabotage or an attacker covering their tracks by removing the account they used. The event includes who deleted the account and which account was deleted.",why_it_happens:"Windows generates 4726 as part of Account Management auditing when a user account is deleted via Active Directory Users and Computers, Net User /delete, or Remove-ADUser. For AD accounts with the Recycle Bin feature enabled, the account can be restored. For local accounts, deletion is permanent.",what_good_looks_like:"Expected: IT admin deleting accounts following the retention period after offboarding (accounts usually disabled first, then deleted 30-90 days later). Investigate: accounts deleted immediately after disabling (skipping the retention period), deletion of admin or service accounts, accounts deleted outside of a change window.",common_mistakes:["Not having AD Recycle Bin enabled — makes recovery much harder","Deleting accounts without first auditing what resources they own (files, mailboxes, groups)","Not keeping records — once deleted without recycle bin, the SID is gone"],causes:["End of account retention period after offboarding","Cleanup of test or temporary accounts","Admin error","Attacker covering tracks by deleting accounts they created (4720)","Insider sabotage targeting specific accounts"],steps:["Filter Security log for 4726",'Note "Target Account" (deleted) and "Subject Account" (who deleted)',"Check if there was a preceding 4725 (disable before delete) — expected for offboarding","If no prior 4725: account was deleted directly, which is unusual","For AD accounts: attempt restore from Recycle Bin if available","For local accounts: deletion is permanent — document the incident"],symptoms:["account deleted","user account removed","who deleted this account","account missing from AD","user account gone"],tags:["account-management","offboarding","audit","security"],powershell:`# User Account Deletion Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4726
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4725,4720,4722],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4726"},{id:4728,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"Member Added to Global Security Group",short_desc:"A user or computer was added to an Active Directory global security group.",description:"Event 4728 records membership additions to global security groups in Active Directory. Global groups apply domain-wide and are typically used to assign permissions to users of the same domain. Additions to high-privilege groups — Domain Admins, Enterprise Admins, Schema Admins — should immediately generate an alert. Even additions to lower-privilege groups can matter if the group controls access to sensitive resources.",why_it_happens:"Windows generates 4728 as part of Account Management auditing on domain controllers when a member is added to a global group. Global groups have domain-wide scope and are replicated across all DCs. The event captures who was added (Target Account) and who made the change (Subject).",what_good_looks_like:"Expected: IT admin adding a new employee to department groups during onboarding, following a ticket. Investigate: anyone added to Domain Admins, Schema Admins, or Group Policy Creator Owners, additions made outside business hours, additions not linked to a ticket, a standard user account being used to make group changes.",common_mistakes:["Not having real-time alerts for additions to Domain Admins — this should page someone immediately","Only monitoring Domain Admins and missing other dangerous groups like Backup Operators or Account Operators","Not tracking what groups service accounts are members of"],causes:["IT admin following onboarding process","Permissions change for a project or role","Attacker adding compromised account to privileged group","Software deployment requiring group membership","GPO-managed group membership update"],steps:["Filter Security log for 4728 on a DC",'Note the "Member Account Name" (who was added) and "Group Name"','Check "Subject Account Name" — who made the change?',"Verify against a helpdesk ticket or change request","If the group is privileged (Domain Admins, Backup Operators): immediately escalate","If unauthorized: remove the account from the group immediately","Check for subsequent 4624 logon events from the newly added account"],symptoms:["user added to group","member added to domain admins","privilege escalation group","who added this user to the group","group membership change","unexpected admin group member"],tags:["group-membership","account-management","privilege-escalation","audit","security"],powershell:`# Global Group Member Added Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4732,4756,4720,4672],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728"},{id:4732,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"Member Added to Local Security Group",short_desc:"A user or computer was added to a local security group (e.g., local Administrators).",description:"Event 4732 records membership additions to local security groups — most importantly the local Administrators group. Unlike domain groups (4728, 4756), local groups apply only to the specific machine. Adding an account to the local Administrators group gives that account full control over the machine, including the ability to read all files, install software, and bypass many security controls. This is a very high-value alert for endpoint security.",why_it_happens:"Windows generates 4732 on the local machine as part of Account Management auditing when a user is added to a local group via Computer Management, Net Localgroup, or Add-LocalGroupMember. On domain-joined machines, this may also be triggered by GPO Restricted Groups or Local Users and Groups preferences.",what_good_looks_like:"Expected: IT policy intentionally adding specific accounts to local Admins (e.g., helpdesk group added via GPO). Investigate: standard user accounts being added to local Admins manually, domain users being added to local Admins on machines they shouldn't administer, additions made by unexpected accounts or at unexpected times.",common_mistakes:["Not monitoring local group changes on endpoints — most SIEM configurations only monitor DCs","Not realising that local admin rights on a workstation can be used to dump credentials with tools like Mimikatz","Assuming the change was made by GPO just because the machine is domain-joined"],causes:["IT admin adding a user to local admins for a specific task","GPO Restricted Groups policy applying","Software installer adding its service account to local admins","Attacker adding a compromised account to local admins for persistence","User escalating their own privileges after an exploit"],steps:["Filter Security log for 4732 on the specific machine",'Check "Group Name" — is it Administrators or another sensitive group?','Check "Member Account Name" — who was added?','Check "Subject Account Name" — who made the change?',"Verify this was an authorized change (ticket, GPO)","If unauthorized: remove immediately with Remove-LocalGroupMember","Investigate how the person making the change had rights to do so"],symptoms:["added to local admins","user became local administrator","local admin group changed","who added this user to administrators","unexpected local admin","user got local admin rights"],tags:["group-membership","local-admin","privilege-escalation","endpoint","audit","security"],powershell:`# Local Group Member Added Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4728,4756,4720,4672],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732"},{id:4740,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"User Account Locked Out",short_desc:"An account reached the failed logon threshold and was locked out.",description:'Event 4740 is generated on the domain controller (or local machine for local accounts) when an account is locked out due to too many failed password attempts. Critically, this event identifies the "Caller Computer Name" — the machine that sent the bad passwords. This is the starting point for every account lockout investigation. Note that 4740 is generated on the DC that processed the lockout, not on the machine the bad password came from.',why_it_happens:'Windows locks accounts when the failed logon count reaches the configured bad password threshold (typically 5-10 attempts). The lockout counter is maintained by the DC holding the PDC Emulator role. When the threshold is crossed, the PDC Emulator logs 4740 and the account is marked as locked. The "Caller Computer Name" field reveals which machine sent the authentication attempts that caused the lockout.',what_good_looks_like:"Expected: occasional lockouts from users mistyping passwords, quickly resolved. Investigate: repeated lockouts for the same account throughout the day (stale credentials on a device), lockouts coming from unexpected machines (a server, not a workstation), lockouts at 3am, multiple accounts locking out simultaneously (password spray attack).",common_mistakes:["Looking for 4740 on the workstation rather than the domain controller — it's on the DC","Looking at the wrong DC — check the PDC Emulator specifically for 4740 events, as lockouts are processed there","Stopping after finding the Caller Computer Name without investigating what application on that machine is sending bad passwords","Not looking at 4625 events on the Caller Computer to find the specific process sending bad credentials","Resetting the password without finding the source — the lockout will just happen again immediately"],causes:["User locked out after forgetting new password","Stale credentials cached on a mobile device after password change","Service configured with old password still attempting authentication","Mapped drive or Outlook profile with old credentials","Brute-force attack from an external source","VPN client using expired cached credentials"],steps:["Find 4740 on the PDC Emulator: Get-ADDomain | Select-Object PDCEmulator",'Note the "Caller Computer Name" from the event — go to that machine next',"On the Caller Computer, look for 4625 events matching the locked account",'Identify the "Caller Process Name" in 4625 — this reveals what application is sending bad passwords',"Common sources: Outlook (stale profile), mapped drives, scheduled tasks, mobile email apps, Chrome/Firefox saved passwords","Fix the credential source (update password in the application), then unlock the account with 4767","If no obvious source: check for RunAS, PST files, old VPN configs"],symptoms:["account locked out","user cant log in account locked","account keeps locking","lockout keeps happening","why does this account keep locking out","AD account locked","user account locked all the time","lockout every morning"],tags:["lockout","authentication","password","security","helpdesk","fundamental"],powershell:`# Account Lockout Investigation
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
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4625,4767,4771,4776],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740"},{id:4756,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Fundamental",title:"Member Added to Universal Security Group",short_desc:"A user or computer was added to a universal security group in Active Directory.",description:"Event 4756 records membership additions to universal security groups. Universal groups have forest-wide scope and can contain members from any domain in the forest. They are often used for enterprise-wide access control and appear in the Global Catalog. Like 4728 (global group changes), additions to privileged universal groups should be immediately alerted on.",why_it_happens:"Windows generates 4756 as part of Account Management auditing on DCs when a member is added to a universal group. Universal groups are replicated to the Global Catalog, meaning they are visible across the entire forest. Changes to these groups affect forest-wide access control.",what_good_looks_like:"Expected: IT admin updating enterprise access groups as part of onboarding. Investigate: additions to groups with forest-wide administrative rights, changes made by non-admin accounts, changes outside business hours.",common_mistakes:["Treating universal groups as less important than global groups — high-privilege universal groups can have forest-wide impact","Not monitoring the Global Catalog for group changes if the forest spans multiple domains"],causes:["IT admin updating enterprise access control groups","New user requiring forest-wide resource access","Software deployment using universal groups for licensing","Attacker adding accounts to forest-wide privileged groups"],steps:["Filter Security log for 4756 on a DC",'Note "Member Account Name" and "Group Name"','Check "Subject Account Name" — who made the change?',"Verify against ticket/change record","If the group is privileged, escalate immediately and remove if unauthorized"],symptoms:["universal group membership changed","user added to enterprise group","forest wide group change","universal security group member added"],tags:["group-membership","universal-group","active-directory","audit","security"],powershell:`# Universal Group Member Added Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with DC hostname
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4756
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,related_ids:[4728,4732,4720,4672],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4756"},{id:4767,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Fundamental",title:"User Account Unlocked",short_desc:"A locked user account was unlocked by an administrator.",description:"Event 4767 records when a locked-out account is manually unlocked by an admin. It includes who unlocked the account and which account was unlocked. On its own this is routine, but when combined with 4740 (lockout) data, it lets you see the full lockout/unlock cycle and measure how long users are locked out. If an account is being unlocked repeatedly, it means the root cause of the lockout was not fixed — the account will lock again.",why_it_happens:'Windows generates 4767 when an admin clears the "Account is locked out" flag via AD Users and Computers, Unlock-ADAccount, or Net User /active:yes. The event is generated on the DC that processes the unlock.',what_good_looks_like:"Expected: helpdesk unlocking accounts as part of a verified support call. Investigate: the same account being unlocked multiple times in a day (lockout root cause not fixed), unlocks happening at 3am (automated, or unauthorized), accounts being unlocked without a corresponding helpdesk ticket.",common_mistakes:["Unlocking the account without finding and fixing the source of bad credentials — it will lock again","Not verifying user identity before unlocking — social engineering can trick helpdesk into unlocking attacker-controlled accounts"],causes:["Helpdesk response to user support request","Automated unlock script","Admin directly managing account lifecycle","Scheduled task running unlock process"],steps:["Filter Security log for 4767","Match with preceding 4740 events for the same account","If the account locks out again after unlock: the root cause was not fixed","Investigate the Caller Computer Name from 4740 and fix the credential source","Track unlock frequency — repeated unlocks signal an unresolved problem"],symptoms:["account unlocked","account unlock","helpdesk unlocked account","who unlocked this account","account was unlocked"],tags:["lockout","account-management","helpdesk","audit"],powershell:`# Account Unlock Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4740,4625,4624],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4767"},{id:4771,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Intermediate",title:"Kerberos Pre-Authentication Failed",short_desc:"A Kerberos authentication attempt failed at the pre-authentication stage.",description:"Event 4771 is generated on domain controllers when a Kerberos pre-authentication request fails. The failure code indicates the reason: 0x12 means account disabled, 0x18 means wrong password (pre-auth failed), 0x17 means password expired, 0x25 means the client clock is out of sync. This event is the Kerberos equivalent of 4625 for NTLM — it appears on the DC, not the workstation. A burst of 0x18 codes from many accounts is a strong indicator of a Kerberos password spray.",why_it_happens:"Kerberos pre-authentication is a security feature where the client must prove it knows the user's password before the KDC issues a Ticket Granting Ticket (TGT). The client encrypts a timestamp with the user's password hash. If the decryption fails (wrong password), 4771 is logged on the DC. If an account does not require pre-authentication (a security misconfiguration), AS-REP Roasting attacks become possible.",what_good_looks_like:"Expected: occasional 4771 events with 0x18 code from users mistyping passwords. Investigate: many 0x18 events for many accounts from one source IP (password spray), accounts without pre-authentication required (AS-REP Roast target), clock skew errors (0x25) that may indicate a time manipulation attack, failures for service accounts.",common_mistakes:["Not monitoring the DC for 4771 — junior admins only look at the workstation and miss Kerberos failures","Not knowing which accounts have pre-auth disabled — run: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}","Confusing 4771 with 4768 (Kerberos TGT request) — 4771 is specifically a failure"],causes:["User typed wrong password","Account locked out or disabled","Password expired","Client clock out of sync with DC (>5 minute skew)","Kerberos password spray attack","Service account credentials not updated after password change"],steps:["Filter Security log for 4771 on the domain controller","Check failure code: 0x18 = wrong password, 0x12 = disabled, 0x17 = expired, 0x25 = clock skew","If 0x25: check time synchronization on the client machine","If many 0x18 for many accounts from one IP: password spray in progress — block the source","If 0x12 or account not found: correlate with 4740 to find lockout cause","Check if the affected account has pre-auth disabled: Get-ADUser <name> -Properties DoesNotRequirePreAuth"],symptoms:["kerberos authentication failed","kerberos error","kdc error","cannot authenticate to domain","domain login failure","kerberos pre auth failed","time skew kerberos","krb5 error"],tags:["kerberos","authentication","domain-controller","password-spray","audit","security"],powershell:`# Kerberos Pre-Auth Failure Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4625,4740,4776,4624],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771"},{id:4776,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Warning",skill_level:"Intermediate",title:"NTLM Authentication Attempt",short_desc:"The domain controller attempted to validate NTLM credentials.",description:"Event 4776 is generated on the domain controller that processed an NTLM authentication request. It records the account name, the workstation, and whether authentication succeeded or failed. NTLM is the legacy authentication protocol — modern environments should primarily use Kerberos. High volumes of 4776 events may indicate NTLM relay attacks, pass-the-hash attempts, or clients that cannot reach a DC for Kerberos. Failed 4776 events with error code 0xC000006A indicate wrong credentials.",why_it_happens:"NTLM authentication occurs when Kerberos is unavailable or not supported — accessing resources by IP address instead of hostname, accessing resources in non-domain environments, older clients and servers. The DC validates the NTLM challenge/response by re-computing the expected response using the stored credential hash. If it matches, authentication succeeds.",what_good_looks_like:"Expected: some NTLM authentication for legacy applications, connecting to resources by IP. Investigate: large volumes of failed 4776 for one account (brute-force or pass-the-hash), NTLM from unexpected sources, NTLM where Kerberos should be working, errors indicating pass-the-hash tools were used (error code 0xC000006D with blank workstation name).",common_mistakes:["Treating all NTLM as malicious — it is still common in many environments and not all of it is suspicious",'Not knowing what "NTLM relay attack" means — an attacker intercepts NTLM challenges and relays them to authenticate elsewhere',"Not checking if NTLM is being used for internal authentications that should be Kerberos (accessing shares by IP instead of name)"],causes:["Client accessing resource by IP instead of DNS name (forces NTLM)","Legacy application not supporting Kerberos","Domain trust using NTLM","NTLM relay attack in progress","Pass-the-hash attack using captured NTLM hash","Service account cached credentials using NTLM"],steps:["Filter Security log for 4776 on the DC","Check Error Code: 0xC0000064 = bad username, 0xC000006A = wrong password, 0x0 = success","Check Workstation Name — is it a known machine?","High volume from one machine with failures = possible pass-the-hash or brute-force","Blank Workstation Name = possible network-level attack","If investigating NTLM relay: look for successful 4776 where the source is not the real client"],symptoms:["ntlm authentication","ntlm failed","pass the hash","ntlm relay","legacy authentication","ntlm error","authentication ntlm"],tags:["ntlm","authentication","pass-the-hash","relay","domain-controller","audit","security"],powershell:`# NTLM Authentication Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4625,4740,4771,4624],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776"},{id:4778,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Intermediate",title:"RDP Session Reconnected",short_desc:"A previously disconnected Remote Desktop session was reconnected.",description:"Event 4778 is generated when a Remote Desktop or Remote Assistance session is reconnected after being in a disconnected state. Unlike 4624 (which is logged when a new session starts), 4778 specifically indicates a reconnection to an existing disconnected session. It includes the account name, the client machine name, and the client address. Paired with 4779 (disconnection), it gives a complete picture of RDP session lifecycle.",why_it_happens:'When an RDP session is disconnected (rather than logged off), the session remains alive on the server in a suspended state. When the user — or any user with appropriate credentials — reconnects, Windows logs 4778 with the "Logon Type 10" designation. A new session logs 4624 Type 10; a reconnection to existing disconnected session logs 4778.',what_good_looks_like:"Expected: a user reconnecting to their own session after a network drop or laptop close/open. Investigate: reconnections from different IP addresses than the original session (session hijacking risk), reconnections to sessions owned by other users, reconnections at unusual times to sessions that have been disconnected for extended periods.",common_mistakes:["Treating 4778 identically to 4624 — reconnections are a distinct event type with different security implications","Not noticing when a user reconnects to another user's session (on RDS servers, this is possible for admins)","Not correlating Client Address in 4778 vs 4779 to detect session hijacking"],causes:["User reconnecting after network interruption","User reconnecting after closing laptop lid","Admin reconnecting to manage a disconnected session","Automated reconnection by RDP client","Session hijacking (admin connecting to another user's session)"],steps:["Filter Security log for 4778",'Note "Account Name" and "Client Address"',"Compare Client Address with the previous 4779 (disconnect) for the same session","If Client Address changed: possible session handoff or compromise — investigate","On RDS servers: check for admins reconnecting to other users' sessions","Correlate with RDS events 25 (session reconnected) in the TerminalServices-LocalSessionManager log"],symptoms:["rdp reconnected","remote desktop reconnect","session reconnected","rdp session resumed","remote session resumed"],tags:["rdp","session-reconnect","remote-desktop","audit","security"],powershell:`# RDP Session Reconnect Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4779,4624,4634,21,25],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778"},{id:4779,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Intermediate",title:"RDP Session Disconnected",short_desc:"A Remote Desktop session was disconnected (not logged off — session stays alive).",description:"Event 4779 records when an RDP or Remote Assistance session transitions to disconnected state — meaning the user closed the RDP window or lost connectivity, but did not formally log off. The session remains alive on the server and can be reconnected (4778). This event includes the account, client machine, and client address. Understanding the difference between a disconnect (4779) and a logoff (4634) is fundamental to RDP session management.",why_it_happens:"When the RDP client window is closed without logging off, or when a network interruption occurs, the RDP session state transitions from active to disconnected. Windows keeps the session alive for the configured session idle/disconnect timeout period. If the session times out without reconnection, it is logged off. 4779 is the audit record of the disconnect transition.",what_good_looks_like:"Expected: users disconnecting and reconnecting throughout the day, especially on RDS servers where multiple users work. Investigate: sessions that stay disconnected for very long periods (potential abandoned sessions with data exposed), many sessions disconnecting simultaneously (network event), disconnect followed by reconnection from a different IP.",common_mistakes:["Assuming a 4779 means the user logged off — they did not, the session is still alive","Not checking for idle disconnected sessions on RDS servers — these waste resources and are a security risk"],causes:["User closed RDP window without logging off","Network interruption broke the connection","RDP client timeout","Admin forced disconnect of a session","Session policy disconnected idle session"],steps:["Filter Security log for 4779",'Note the "Client Address" — where was the session connecting from?',"Check if the session was reconnected (4778) after disconnect","If no 4778 follows: session is still disconnected — check if it should be terminated","On RDS: enumerate disconnected sessions with: qwinsta /server:<server>","Terminate stale sessions with: logoff <sessionid> /server:<server>"],symptoms:["rdp disconnected","remote desktop disconnected","session disconnected","rdp session ended","user disconnected from rdp"],tags:["rdp","session-disconnect","remote-desktop","audit"],powershell:`# RDP Session Disconnect Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4778,4624,4634,24,40],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4779"},{id:4798,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Advanced",title:"User's Local Group Membership Enumerated",short_desc:"A process queried the local group membership of a specific user account.",description:"Event 4798 is generated when a process enumerates the local group memberships of a user account. This is frequently triggered by Windows components during logon as part of building the access token, but it can also be triggered by reconnaissance scripts enumerating which local groups a user belongs to. When generated by unexpected processes (not winlogon.exe, lsass.exe, or explorer.exe) at scale, it may indicate an attacker performing internal reconnaissance.",why_it_happens:"Applications and Windows components enumerate group membership using the NetUserGetLocalGroups() API or its equivalent. During normal logon, lsass.exe calls this to build the access token. Security assessment tools, and unfortunately attackers, call the same APIs to understand what access a user or set of users has across local machines.",what_good_looks_like:"Expected: winlogon.exe, lsass.exe, and explorer.exe generating these events during logon. Investigate: enumeration by unexpected processes, high-volume enumeration of many accounts in a short time from one process (automated reconnaissance), enumeration of admin accounts specifically.",common_mistakes:["Alerting on every 4798 — most are legitimate logon infrastructure","Not filtering by Process Name — the process doing the enumeration is the critical field"],causes:["Normal Windows logon process building access token","Security compliance tools performing audits","Attacker tool enumerating accounts for privilege escalation targeting","IT management scripts checking group membership"],steps:["Filter Security log for 4798",'Check "CallerProcessName" — is it a known Windows process or something unexpected?',"If unexpected process: investigate with 4688 to find where that process came from","Check if multiple accounts were enumerated in quick succession from the same process"],symptoms:["local group enumeration","who is in local admins","group membership query","account reconnaissance","listing local group members"],tags:["reconnaissance","group-membership","enumeration","audit","security"],powershell:`# Local Group Membership Enumeration Investigation
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
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4799,4627,4688],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798"},{id:4799,source:"Microsoft-Windows-Security-Auditing",channel:"Security",severity:"Info",skill_level:"Advanced",title:"Local Group Membership Enumerated",short_desc:"A process queried the membership of a local security group.",description:"Event 4799 is generated when a process enumerates the members of a local security group (as opposed to 4798, which enumerates the groups a user belongs to). This event is particularly interesting when the target group is Administrators — it reveals what processes are checking who has local admin rights on the machine. Malware and attacker tools frequently query local Administrators group membership to understand the privilege landscape before escalating.",why_it_happens:"Enumeration via the NetLocalGroupGetMembers() API generates 4799. This is called by many legitimate tools (LAPS, Windows Admin Center, compliance tools), but also by attacker tools during post-exploitation reconnaissance.",what_good_looks_like:"Expected: management tools and Windows components enumerating Administrators membership. Investigate: unknown processes enumerating Administrators specifically, batch enumeration of many groups in a short period, enumeration from processes launched by unusual parents.",common_mistakes:["Not filtering by the Target Group Name — enumeration of Administrators is much more interesting than Other groups","Treating every 4799 as suspicious when most are legitimate management tool activity"],causes:["Windows management tools checking group membership","LAPS (Local Administrator Password Solution) checking admin accounts","Attacker tool enumerating local admin members for targeting","Compliance scanning tools"],steps:["Filter Security log for 4799",'Check "Target Group Name" — is it Administrators?','Check "Calling Process Name" — is it a known tool or unexpected?',"Correlate with 4688 if the calling process is unusual","High frequency from one process: possible automated reconnaissance"],symptoms:["local admins enumerated","who is in administrators group","listing administrator group members","local group query","local group enumeration"],tags:["reconnaissance","group-membership","enumeration","local-admin","audit","security"],powershell:`# Local Group Enumeration Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[4798,4627,4688,4732],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4799"}],t=[{id:41,source:"Microsoft-Windows-Kernel-Power",channel:"System",severity:"Critical",skill_level:"Intermediate",title:"Kernel Power: Unexpected Reboot",short_desc:"The system rebooted without a clean shutdown — power loss, crash, or hard reset.",description:"Event ID 41 from the Kernel-Power source is generated on the NEXT boot after an unexpected shutdown. It indicates the system did not go through a normal shutdown sequence — the most likely causes are a power cut, someone hitting the power button, a kernel panic (BSOD), or overheating causing emergency shutdown. The BugcheckCode field is critical: if it's 0, there was no BSOD (power loss or hard reset). A non-zero BugcheckCode means there was a crash — look at 1001 for the full minidump analysis.",why_it_happens:'Windows maintains a "clean shutdown flag" in the registry (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PagingFiles and the boot-status driver). If the system loses power, crashes, or is hard-reset before the OS can clear this flag during a normal shutdown, the next boot detects the unexpected condition and logs Event 41. BugcheckCode 0 = no crash occurred (hardware power event). Non-zero = the kernel itself crashed.',what_good_looks_like:"Occasional Event 41 after a power outage is normal. Investigate: repeated Event 41 without an obvious power explanation, BugcheckCode that keeps repeating (same hardware fault), Event 41 with a non-zero BugcheckCode (actual kernel crash), clusters of Event 41 at similar times of day (thermal throttling at peak CPU load).",common_mistakes:["Ignoring the BugcheckCode field — 0 means no crash, non-zero means BSOD and you need minidump analysis","Not checking Event 6008 in the same log — it provides the timestamp of the unexpected shutdown","Not checking the system for hardware issues: check SMART on disk, RAM with memtest86, PSU voltage, temperatures","Assuming the OS caused the crash without ruling out hardware first — Event 41 with code 0 is almost always hardware or power"],causes:["Power outage or UPS failure","Manual hard reset (power button hold)","Kernel panic (BSOD) — check BugcheckCode","Overheating causing emergency shutdown","Faulty RAM causing memory corruption","Failing power supply delivering inconsistent voltage","Hardware driver crash"],steps:["Find Event 41 and note BugcheckCode — if 0, no BSOD occurred","Check Event 6008 nearby to confirm unexpected shutdown timestamp","If BugcheckCode non-zero: check Event 1001 for full minidump details","Check Windows Reliability Monitor for pattern over time (search: perfmon /rel)","Check system temperatures: Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root/wmi","Run hardware diagnostics: memory test, disk SMART, PSU check","If BugcheckCode 0x9F: driver power state failure — check device manager for driver issues","If recurring: consider UPS installation or hardware replacement"],symptoms:["computer randomly reboots","pc turns off by itself","unexpected reboot","computer keeps restarting","blue screen then restart","machine shut off randomly","server restarted overnight","sudden shutdown"],tags:["reboot","crash","kernel-power","bsod","hardware","uptime","critical"],powershell:`# Unexpected Reboot Investigation (Kernel Power 41)
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[1001,6008,1074,6006],ms_docs:"https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/windows-kernel-event-id-41-error"},{id:55,source:"Ntfs",channel:"System",severity:"Error",skill_level:"Intermediate",title:"NTFS File System Corruption",short_desc:"The NTFS driver detected corruption on a volume — could lead to data loss.",description:"Event ID 55 from the Ntfs source indicates that the NTFS file system driver detected on-disk corruption. This can be a corrupt Master File Table (MFT), invalid file records, damaged metadata structures, or bad sectors affecting file system data. This event is serious — it can lead to data loss, application failures, and in severe cases an unbootable system. Corruption can appear without obvious symptoms until a file is accessed.",why_it_happens:"NTFS corruption occurs when writes are interrupted mid-operation (power loss during write), when the storage medium has bad sectors, when the disk controller reports errors that corrupt in-flight data, when storage drivers have bugs, or when RAM errors cause corrupt data to be written to disk. NTFS is transactional and has a journal ($LogFile), but this only protects against metadata corruption from clean failures — bad sectors and RAM corruption can still cause Event 55.",what_good_looks_like:"No Event 55 at all is ideal. Any Event 55 should be investigated. Repeated Event 55 on the same volume is urgent — the drive may be failing. Correlate with disk errors in the Disk event log (Event 7, 11, 15, 51) to see if bad sectors are triggering the corruption.",common_mistakes:["Running chkdsk on a running system rather than scheduling it for next boot — chkdsk /f cannot fully repair a mounted volume","Only running chkdsk and not investigating the underlying cause (failing disk, PSU issues, RAM)",'Ignoring Event 55 because the user "seems fine" — corruption can be silently expanding',"Not checking the disk SMART data alongside Event 55"],causes:["Power loss during a write operation","Failing hard disk with bad sectors","Faulty storage controller or cable","RAM errors causing corrupt data to be written","USB drive safely removed while mounted with pending writes","Virtual machine storage issues (snapshot corruption, thin provisioning exhaustion)","RAID array degradation affecting write integrity"],steps:["Note which volume is affected from the event message","Schedule chkdsk: chkdsk C: /f /r /b (requires reboot for system volume)","Check disk SMART health: Get-Disk | Get-StorageReliabilityCounter | Select-Object *","Check for disk errors: Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk'} | Select -First 20","Check Event 7, 11, 51 in System log for I/O errors on the same disk","If a VM: check datastore health, free space, snapshot state","If recurring: consider disk replacement and restore from backup","Verify backup is working before running chkdsk /r"],symptoms:["file system corruption","ntfs corruption","disk corruption","chkdsk finding errors","files corrupted","cant open files","disk errors","file system errors"],tags:["ntfs","corruption","disk","filesystem","data-integrity","chkdsk"],powershell:`# NTFS Corruption Investigation
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
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Select-Object -First 10 | Format-List`,related_ids:[41,1001,7023],ms_docs:"https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/troubleshoot-nfs-file-server"},{id:1001,source:"Microsoft-Windows-WER-SystemErrorReporting",channel:"System",severity:"Critical",skill_level:"Intermediate",title:"Windows Error Reporting: BugCheck (BSOD)",short_desc:"A kernel-mode crash (Blue Screen of Death) was recorded with stop code and parameters.",description:"Event ID 1001 from WER-SystemErrorReporting records the details of a kernel crash — the stop code (BugcheckCode), parameters, and a reference to the minidump file. This event is generated on the next boot after a BSOD. The BugcheckCode is the most important field: common codes include 0x0000007E (driver error), 0x00000050 (PAGE_FAULT_IN_NONPAGED_AREA, often bad RAM or driver), 0x0000009F (DRIVER_POWER_STATE_FAILURE), 0x00000124 (WHEA_UNCORRECTABLE_ERROR, hardware fault).",why_it_happens:"When the Windows kernel encounters an unrecoverable error — typically a driver accessing invalid memory, a hardware fault, or kernel data structure corruption — it halts execution and writes a memory dump. The dump file (usually C:\\Windows\\Minidump\\*.dmp) contains the full call stack at the time of the crash. Event 1001 is the event log representation of this crash, generated after the system reboots.",what_good_looks_like:"A system that never BSODs. If it does crash once, investigate the BugcheckCode. Repeated BSODs with the same code strongly suggest a specific hardware fault or driver bug. Multiple different codes on the same machine suggest bad RAM (random memory corruption causes many different stop codes).",common_mistakes:["Reading the bugcheck code without looking up what it means — each code has specific causes","Not analysing the minidump file — the code alone isn't enough; you need WinDbg or WhoCrashed to identify the responsible driver","Blaming Windows when the driver shown in WinDbg analysis is a third-party driver (AV, NIC, storage)","Running driver verifier without understanding it can cause additional crashes (use in isolated test environment)","Not checking RAM with memtest86 for at least 8 passes when stop code varies"],causes:["Faulty or incompatible device driver (most common)","RAM hardware fault","CPU overheating or overclocking instability","Power supply delivering inconsistent voltage","Failing or corrupt SSD/HDD","Kernel-mode malware or rootkit","Windows system file corruption","Hardware fault (GPU, NIC, storage controller)"],steps:["Find BugcheckCode in Event 1001 and look it up: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2","Open minidump: C:\\Windows\\Minidump\\ — open with WinDbg or use WhoCrashed (free tool)","WinDbg: !analyze -v will identify the crashing driver","Update or roll back the identified driver first","If code 0x124 (WHEA): run hardware diagnostics — this is a hardware fault","If variable codes: run memtest86 overnight — likely bad RAM","Check system temperatures and clean dust from fans/heatsinks","If driver-related: check Windows Update and vendor site for driver updates"],symptoms:["blue screen","bsod","blue screen of death","stop error","computer crashes with blue screen","windows crash","pc restarts with blue screen","kernel crash","stop code","memory dump"],tags:["bsod","crash","kernel","minidump","driver","hardware","critical"],powershell:`# BSOD / BugCheck Investigation
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
Write-Host "
--- Minidump Files ---" -ForegroundColor Cyan
Get-ChildItem -Path "\\\\$computer\\c$\\Windows\\Minidump\\" -Filter "*.dmp" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize`,related_ids:[41,6008,1074],ms_docs:"https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2"},{id:1074,source:"USER32",channel:"System",severity:"Info",skill_level:"Fundamental",title:"System Shutdown or Restart Initiated by Process",short_desc:"A process or user initiated a shutdown or restart, with reason and initiating process recorded.",description:"Event ID 1074 records when a shutdown or restart is initiated programmatically or via the Windows shutdown dialog. It captures who initiated the shutdown, what process called it, the reason code, and whether it was a shutdown or restart. This is the primary event for determining why a machine was shut down or restarted intentionally. It contrasts with Event 6008 (unexpected shutdown) — if you see 6008 without a preceding 1074, the shutdown was unplanned.",why_it_happens:'Windows generates 1074 whenever ExitWindowsEx() or InitiateSystemShutdown() is called with the shutdown or restart flag. This happens when a user clicks "Restart" or "Shut down", when Windows Update installs patches and requires a reboot, when an administrator runs "shutdown /r", or when management software (RMM, SCCM) triggers a reboot. The Reason Code provides structured information about why the restart occurred (e.g., 0x0 = other, 0x80020003 = OS/reconfiguration/planned).',what_good_looks_like:"Expected: 1074 events from Windows Update (reason code OS: Planned), from users shutting down at end of day, from RMM tools patching. Investigate: 1074 events at unexpected times, restarts initiated by unfamiliar processes, restarts on servers without a corresponding change ticket.",common_mistakes:["Not checking 1074 before concluding a reboot was unexpected — always look for 1074 first",'Ignoring the "Process" field — knowing whether it was shutdown.exe, wusa.exe, or an unknown binary matters',"Not checking for 1074 on servers when investigating unplanned downtime"],causes:["User-initiated shutdown or restart","Windows Update requiring reboot after patch installation","RMM tool triggering a managed reboot","Administrator running shutdown command","Application requesting system restart (installer)","Group Policy forcing restart after changes"],steps:["Filter System log for Event 1074",'Check "Process Name" — was it Windows Update, shutdown.exe, or an RMM tool?','Check "Reason" — does it match expected maintenance?','Check "User" — who was logged on when the restart was triggered?',"If on a server: correlate with change records","If Process Name is unexpected: investigate with Event 4688 to trace the process"],symptoms:["computer was restarted","who restarted this machine","server rebooted","why did it restart","shutdown reason","machine shut down","reboot reason","windows update reboot"],tags:["shutdown","restart","reboot","maintenance","audit","uptime"],powershell:`# Shutdown/Restart Reason Investigation
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
    Format-List`,related_ids:[41,6006,6008,1076],ms_docs:"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc940437(v=ws.10)"},{id:1076,source:"USER32",channel:"System",severity:"Info",skill_level:"Intermediate",title:"Unexpected Shutdown Reason Recorded",short_desc:"After an unexpected shutdown (6008), a user provided the reason via the shutdown tracker.",description:"Event ID 1076 is generated when the Windows Shutdown Event Tracker is enabled and a user provides a reason for the previous unexpected shutdown. This event appears after a 6008 (unexpected shutdown was detected) and a user logs in and fills in the reason dialog. Common in server environments where administrators are required to document the cause of unexpected outages. The event captures the user who provided the reason and the reason text they entered.",why_it_happens:"Windows Server has the Shutdown Event Tracker enabled by default. When the system detects that the previous shutdown was unexpected (via 6008), it prompts the next user to log in to provide a reason. This is a governance control to ensure unexpected downtime is documented. The feature can be configured via Group Policy.",what_good_looks_like:"Expected: admins documenting reasons for unexpected server reboots. Investigate: the reason entered does not match known events, the same admin keeps logging reasons suggesting systematic unplanned outages, reasons indicating hardware problems that should be addressed.",common_mistakes:["Relying on 1076 alone for root cause — the reason entered is user-supplied and may be generic or incorrect","Not having the Shutdown Event Tracker enabled on servers — it helps with accountability"],causes:["Administrator documenting the previous unexpected shutdown","Automatic population by management software","Policy requiring documentation of server downtime"],steps:["Correlate 1076 with the preceding 6008 event","Read the reason text — does it provide useful diagnosis information?","Cross-reference with Event 41 or 1001 to find technical root cause","If a pattern of unexpected shutdowns: escalate to hardware investigation"],symptoms:["unexpected shutdown explanation","shutdown reason recorded","shutdown tracker","documented reboot reason","server restart explanation"],tags:["shutdown","restart","accountability","audit","server"],powershell:`# Unexpected Shutdown Reason Investigation
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
    Format-List`,related_ids:[6008,41,1074,6006],ms_docs:null},{id:6005,source:"EventLog",channel:"System",severity:"Info",skill_level:"Fundamental",title:"Event Log Service Started (System Boot)",short_desc:"The Windows Event Log service started — marks the beginning of a new boot.",description:"Event ID 6005 is generated by the Event Log service itself when it starts during system boot. It reliably marks the beginning of a new Windows session in the event log. When combined with 6006 (event log stopped, clean shutdown) and 6008 (unexpected shutdown), you can build a complete timeline of system uptime and shutdown history. It is one of the simplest but most useful events for determining when a machine was last booted.",why_it_happens:"The Event Log service is one of the earliest services to start during Windows boot. When it initialises and opens the event log files, it writes Event 6005 to record its own startup. This event has been present since Windows NT.",what_good_looks_like:"Every 6005 should be paired with either a preceding 6006 (clean shutdown) or a preceding 6008 (unexpected shutdown). Missing 6006 before a 6005 means the previous session ended unexpectedly — this is your signal to look for 41, 1001, or other crash indicators.",common_mistakes:["Not checking what precedes 6005 — without a 6006, the previous boot ended badly","Confusing 6005 with 6006 — 6005 = start (boot), 6006 = stop (shutdown)"],causes:["Normal system boot after clean shutdown","System boot after power restoration","System boot after BSOD or hard reset"],steps:["Look for 6005 events to find all boot times","Check what precedes each 6005 — is there a 6006 (clean shutdown) or 6008 (unexpected)?","If no 6006 before 6005: previous session ended unexpectedly, look for 41 and 1001","Calculate uptime between 6005 pairs for availability reporting"],symptoms:["when did this computer last start","boot time","system started","when was it turned on","last reboot time","computer started up"],tags:["boot","startup","uptime","availability","fundamental"],powershell:`# System Boot History Investigation
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

$boots | Format-Table -AutoSize`,related_ids:[6006,6008,41,1074],ms_docs:null},{id:6006,source:"EventLog",channel:"System",severity:"Info",skill_level:"Fundamental",title:"Event Log Service Stopped (Clean Shutdown)",short_desc:"The Event Log service stopped — marks the end of a clean shutdown sequence.",description:"Event ID 6006 is generated when the Windows Event Log service stops as part of a clean shutdown. It is the last event written before the system shuts down. If you are investigating why a machine rebooted and you see a 6006 followed by a 6005 (next boot), the shutdown was intentional and clean. If 6005 appears without a preceding 6006, the previous session ended unexpectedly.",why_it_happens:"During a clean shutdown, the Event Log service is one of the last services to stop. Before stopping, it writes 6006 to record its own clean termination. This provides a reliable audit trail of clean shutdowns.",what_good_looks_like:"Every 6006 should be followed by a 6005. If you are investigating an unexpected reboot or crash, look for the absence of 6006 before a 6005.",common_mistakes:["Confusing 6006 with 6005 — 6006 = clean stop, 6005 = start","Not checking for 6006 when investigating whether a shutdown was clean or unexpected"],causes:["User-initiated shutdown","Windows Update restart","Administrator shutdown","RMM-triggered reboot"],steps:["Look for 6006 events to confirm clean shutdowns","If missing 6006 before a 6005: unexpected shutdown — investigate Event 41, 6008","Pair with 1074 to find who initiated the clean shutdown"],symptoms:["clean shutdown","planned shutdown","machine was shut down cleanly","system shutdown normally"],tags:["shutdown","clean-shutdown","uptime","audit"],powershell:`# Clean Shutdown Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-30)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'EventLog'
    Id           = 6006
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[6005,6008,1074,41],ms_docs:null},{id:6008,source:"EventLog",channel:"System",severity:"Error",skill_level:"Fundamental",title:"Unexpected Shutdown Recorded",short_desc:"The previous system shutdown was unexpected — generated on the next boot.",description:"Event ID 6008 is generated at boot time when Windows detects that the previous shutdown was not clean. The event message includes the date and time the unexpected shutdown occurred (the time the system last had a clean record). This event is your first indicator of an unplanned outage — the starting point for investigating BSODs, power losses, and hard resets. It does not tell you why the shutdown happened — for that, look at Event 41 and Event 1001.",why_it_happens:"Windows maintains a boot-status file that is updated throughout normal operation and properly closed during a clean shutdown. If the system loses power, crashes, or is hard-reset, this file is not properly closed. On the next boot, Windows checks the file, detects the improper closure, and logs Event 6008 to record the unexpected termination.",what_good_looks_like:"No 6008 events on a healthy, stable machine. A 6008 followed by investigation and resolution is acceptable. Repeated 6008 events — especially on servers — indicate an ongoing problem that must be resolved.",common_mistakes:["Reading 6008 and not following up with Event 41 and Event 1001","Assuming 6008 always means BSOD — it also occurs for power loss and hard reset","Not correlating 6008 timestamp with UPS or power monitoring logs"],causes:["Power failure (no UPS)","Hard reset (power button)","Kernel crash (BSOD)","Hypervisor force-shutdown of VM","Hardware failure causing abrupt halt"],steps:["Find Event 6008 and note the timestamp of the unexpected shutdown","Look for Event 41 (Kernel Power) near the same time","Look for Event 1001 (BugCheck) — if present, a BSOD occurred","If no 41 or 1001: likely hardware power event (check UPS logs)","Check Reliability Monitor for a visual timeline: perfmon /rel"],symptoms:["unexpected shutdown","computer shut off unexpectedly","unclean shutdown","power outage reboot","machine crashed","previous session ended unexpectedly","system did not shut down properly"],tags:["shutdown","unexpected","crash","power","uptime","fundamental"],powershell:`# Unexpected Shutdown Investigation
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
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[41,1001,6005,6006,1074],ms_docs:null},{id:6013,source:"EventLog",channel:"System",severity:"Info",skill_level:"Fundamental",title:"System Uptime",short_desc:"Daily event recording total system uptime in seconds — useful for availability reporting.",description:"Event ID 6013 is generated once per day (usually around midnight or on event log startup) and records the current system uptime in seconds. While simple, it provides a built-in uptime audit trail. If you want to know how long a machine has been up without running a command, you can look for the most recent 6013 event and calculate from its timestamp. It is also useful for confirming SLAs — a server with 6013 showing many days of uptime has been stable.",why_it_happens:"The Event Log service generates 6013 once every 24 hours as a housekeeping record. The uptime value in seconds comes from the system kernel's KeQueryTimeIncrement counter, which starts at boot.",what_good_looks_like:"Any 6013 is normal. Use the uptime value to calculate last boot time: (Get-Date).AddSeconds(-[int]$uptimeSeconds). Uptime longer than your patching cycle means the machine has not been rebooted for updates.",common_mistakes:["Not realising 6013 fires at log startup too, not just midnight — so a reboot generates a 6013 with low uptime","Using 6013 instead of checking LastBootUpTime directly — Get-CimInstance Win32_OperatingSystem is more reliable"],causes:["Automatic daily system heartbeat from Event Log service"],steps:["Find the most recent 6013 event","Note the uptime in seconds from the message","Calculate last boot: (Get-Date).AddSeconds(-<uptime_seconds>)","For real-time uptime: (Get-CimInstance Win32_OperatingSystem).LastBootUpTime"],symptoms:["check system uptime","how long has this been on","when was last reboot","system runtime","availability check"],tags:["uptime","availability","sla","baseline","monitoring"],powershell:`# System Uptime Investigation
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
    Select-Object TimeCreated, Message | Format-List`,related_ids:[6005,6006,6008],ms_docs:null},{id:7e3,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Fundamental",title:"Service Failed to Start",short_desc:"The Service Control Manager could not start a service at boot or on demand.",description:'Event ID 7000 is generated by the Service Control Manager (SCM) when a service fails to start. The event includes the service name and an error code that identifies why it failed. This is the primary event for service startup failures. Common error codes: 2 = "The system cannot find the file" (service binary missing), 5 = "Access is denied" (service account lacks permissions), 1053 = "The service did not respond to the start or control request" (service timeout).',why_it_happens:"The SCM attempts to start services during boot or when a dependent service requires them. Startup failures can occur because the service binary was deleted or moved, the service account credentials are wrong, a required dependency service failed first (see 7001), the service binary threw an exception immediately on start, or the service account was locked out or disabled.",what_good_looks_like:"No 7000 events on a healthy system. Any 7000 should be investigated — even for non-critical services, failed services can indicate a broken application. On a server, a failed critical service may mean the server is partially or fully non-functional.",common_mistakes:["Trying to start the service without reading the error code — the code tells you exactly what went wrong","Not checking Event 7001 for dependency failures — if a dependency failed, fix that first","Resetting the service account password without also updating it in the service configuration","Not checking that the service binary executable actually exists at the path configured"],causes:["Service binary file missing or corrupt","Service account credentials invalid or account locked/disabled","Dependency service not running","Insufficient permissions for service account","Service crashed immediately on start","Antivirus blocking service binary","Registry configuration corrupt for the service"],steps:["Filter System log for Event 7000","Note the service name and error code","Error 2 (file not found): check if binary exists at configured path","Error 5 (access denied): check service account permissions","Error 1053 (timeout): check Event 7009 and investigate why service is not responding","Check Event 7001 for dependency failures first","Check service configuration: Get-Service <name> | Select-Object *","Check service account status in AD if it uses a domain account"],symptoms:["service wont start","service failed to start","service not starting","service startup failure","service is stopped","application service failed","windows service error","service does not start on boot"],tags:["service","startup","scm","fundamental","reliability"],powershell:`# Service Startup Failure Investigation
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
    Format-List`,related_ids:[7001,7009,7023,7031,7045],ms_docs:"https://learn.microsoft.com/en-us/windows/client-management/troubleshoot-service-startup-errors"},{id:7001,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Fundamental",title:"Service Dependency Failed",short_desc:"A service could not start because a service it depends on failed or did not start.",description:"Event ID 7001 records that a service failed to start because one of its dependencies failed. Windows services can declare dependencies on other services — the SCM tries to start dependencies first. If a dependency fails (7000), all dependent services will also fail with 7001. This creates a cascade: one failed core service can trigger dozens of 7001 events. Always trace back to find the root cause failure (the 7000 event) rather than trying to fix each 7001 individually.",why_it_happens:"Service dependencies are configured in the service registry key under DependOnService or DependOnGroup. When the SCM starts the system, it topologically sorts services by dependency and starts them in order. A failure in a low-level service propagates to all services above it in the dependency tree.",what_good_looks_like:"A 7001 that follows a 7000 for the dependency is expected cascade behavior. Find and fix the 7000 first. If you see 7001 without a corresponding 7000 for the dependency service, the dependency may have started but then crashed (check 7031).",common_mistakes:["Fixing each 7001 service individually without finding the root 7000 cause","Not understanding that a single dependency failure can cascade to many 7001 events","Not checking the dependency chain: Get-Service -ComputerName <host> <servicename> -RequiredServices"],causes:["Root dependency service failed to start (Event 7000)","Root dependency service crashed after starting (Event 7031)","Dependency service disabled","Circular dependency (unusual)"],steps:["Find Event 7001 and note which dependency failed","Find the 7000 event for the failing dependency service","Fix the root cause dependency first","Once dependency is fixed, restart dependent services: Start-Service <name>","Check dependency chain: (Get-Service <name>).RequiredServices"],symptoms:["service dependency failed","dependent service failed","service cant start because of dependency","multiple services not starting","service dependency error"],tags:["service","dependency","startup","scm","reliability"],powershell:`# Service Dependency Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-3)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7001
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[7e3,7009,7023,7031],ms_docs:null},{id:7009,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Intermediate",title:"Service Start Timeout",short_desc:"A service did not respond to a start request within the timeout period (typically 30s).",description:'Event ID 7009 records that a service was started but failed to report "running" status within the SCM timeout period (default 30 seconds, configurable via HKLM\\SYSTEM\\CurrentControlSet\\Control\\ServicesPipeTimeout). This typically means the service binary is hung during initialization — perhaps waiting for a network resource, deadlocked in its startup code, or taking longer than expected to load. The service may eventually start or may time out and fail with a 7000.',why_it_happens:'The SCM sends a "start" control code to the service and waits for the service to call SetServiceStatus() with SERVICE_RUNNING within the timeout window. If the service is doing heavy initialization work (database connections, loading large files, network calls) it may exceed the timeout. Timeout errors during boot are common after power failure when disks or networks are slow.',what_good_looks_like:"No 7009 events. If 7009 appears: check if the service eventually started, investigate what is blocking it during initialization.",common_mistakes:["Increasing ServicesPipeTimeout as the fix without investigating why the service is slow to start","Not checking whether the service is doing network calls during startup that may be failing","Treating 7009 and 7000 as the same — 7009 is timeout specifically, 7000 is general failure"],causes:["Service doing heavy initialization work exceeding timeout","Network-dependent service waiting for unavailable network resource","Deadlock in service startup code","System overloaded during boot","Service binary issue causing slow startup"],steps:["Filter System log for 7009","Note the service name","Check if a 7000 follows (timeout → failure) or if the service eventually started","Check the Application log for service-specific error messages","Check if the timeout occurs consistently or only after cold boot","If network-dependent: check network availability during boot"],symptoms:["service timeout","service timed out starting","service took too long to start","service start hung","service not responding on startup"],tags:["service","timeout","startup","scm","performance"],powershell:`# Service Timeout Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7009
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[7e3,7001,7011,7023],ms_docs:null},{id:7011,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Intermediate",title:"Service Transaction Timeout",short_desc:"A service did not respond to a control request (stop, pause, continue) within the timeout.",description:"Event ID 7011 is similar to 7009 but occurs when an already-running service fails to respond to a control request — typically a stop, pause, or continue command — within the timeout period. This usually means the service is hung or deadlocked in its running state. A service that cannot be stopped normally may need to be terminated via Task Manager or by stopping the process directly.",why_it_happens:"The SCM sends control codes to services via the service's service control handler. If the service's handler is blocked (thread deadlock, hung I/O, or simply not processing the control pipe), it does not acknowledge the control request, and the SCM times out.",what_good_looks_like:"No 7011 events. Any 7011 indicates a service is not properly handling control signals, which is a reliability concern.",common_mistakes:["Not finding the service's process ID and killing it if the service won't stop normally","Trying to restart a hung service without ending its process first"],causes:["Service deadlocked in its running code","Service I/O operation blocking the control thread","Service bug in control handler","High system load preventing the service thread from running"],steps:["Identify the service and find its process: Get-WmiObject Win32_Service | Where-Object Name -eq '<name>' | Select ProcessId","Check what the process is doing: Invoke-Command -ComputerName $computer { Get-Process -Id <pid> | Select-Object * }","If the service is hung: Stop-Process -Id <pid> -Force, then Start-Service <name>","Review application event log for service-specific error messages","If recurring: investigate the service for deadlock conditions"],symptoms:["service hung","service not responding","cant stop service","service wont stop","service transaction timeout","service hung after stopping"],tags:["service","timeout","hung","scm","reliability"],powershell:`# Service Transaction Timeout Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7011
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[7e3,7009,7023,7031],ms_docs:null},{id:7023,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Fundamental",title:"Service Terminated with Error",short_desc:"A service stopped and reported a non-zero error code.",description:"Event ID 7023 is generated when a service terminates and returns a non-zero error code to the SCM. Unlike 7031 (unexpected crash), 7023 means the service exited intentionally with an error — it detected a problem and called ExitProcess with an error code. The event includes the error code, which helps diagnose the issue. This is commonly seen with services that fail due to configuration problems, missing dependencies, or license issues.",why_it_happens:"A service calls ExitProcess() or returns a non-zero exit code from its service main function, signalling to the SCM that it failed. The SCM records this as 7023. The exit code is typically a Win32 error code (e.g., 5 = Access Denied, 1060 = Service not found) or an application-specific error code.",what_good_looks_like:"No 7023 events. Any 7023 warrants investigation. Check the Application event log for additional context from the service itself.",common_mistakes:["Trying to fix 7023 without also checking the Application event log — the service may log more detail about why it exited","Treating 7023 the same as 7031 — 7023 is a graceful exit with error, 7031 is an unexpected crash"],causes:["Service detected missing configuration file","Service could not connect to required database","Service license validation failed","Service detected permission problem","Service explicitly exiting after detecting unrecoverable error"],steps:["Filter System log for 7023 and note service name and error code","Check Application log for service-specific messages around the same time","Look up the error code (Win32 error or application-specific)","Check service configuration files and dependencies","Restart service after fixing underlying cause: Start-Service <name>"],symptoms:["service terminated with error","service exited with error code","service crashed with error","service stopped unexpectedly with code","service failure error"],tags:["service","error","failure","scm","reliability"],powershell:`# Service Termination Error Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7023
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[7e3,7001,7031,7034],ms_docs:null},{id:7031,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Intermediate",title:"Service Crashed Unexpectedly",short_desc:"A service terminated unexpectedly — the SCM may attempt automatic recovery actions.",description:"Event ID 7031 records that a service terminated unexpectedly — meaning it did not exit gracefully and the SCM did not expect the termination. This is typically caused by the service process crashing (access violation, unhandled exception) rather than exiting cleanly. The event includes how many times the service has crashed (crash count) and what recovery action was taken. Recovery actions are configured per-service (restart, run a program, reboot) and can be viewed in the service properties.",why_it_happens:"When a service process terminates without deregistering from the SCM, the SCM detects the orphaned service process and logs 7031. This happens when the service binary crashes due to an unhandled exception, memory corruption, or external process termination. The SCM then checks the configured failure actions (First/Second/Subsequent failure) and executes the appropriate recovery.",what_good_looks_like:"No 7031 events. First crash: investigate. Repeated crashes: urgent — the service has a serious problem or the application has a bug. Check the Application event log for Application Error (ID 1000) events that will have the faulting module and exception code.",common_mistakes:["Not checking Event 1000 in the Application log alongside 7031 — the application crash detail is there",'Enabling "restart service automatically" without finding root cause — the service will keep crashing',"Not checking if an update or config change preceded the first crash"],causes:["Service binary bug causing access violation","Memory corruption","Unhandled exception in service code","Third-party DLL injected into service process crashing it","Out of memory condition","Antivirus terminating the service process (false positive)"],steps:["Find Event 7031 and note the service name and crash count","Check Application log for Event 1000 (Application Error) matching the service around the same time","Note faulting module in 1000 — is it the service's own DLL or a third-party one?","Check if there were recent updates or configuration changes","Review service recovery actions: (Get-WmiObject Win32_Service | Where Name -eq '<name>').FailureActions","If recurring: contact software vendor or check for patches"],symptoms:["service crashed","service keeps crashing","service keeps stopping","service restarting repeatedly","service died","service unexpectedly terminated","service auto restarted"],tags:["service","crash","failure","scm","reliability","application-crash"],powershell:`# Service Crash Investigation
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
Write-Host "
--- Application Crash Events (1000) ---" -ForegroundColor Cyan
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Application'
    Id        = 1000
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Select-Object -First 5 | Format-List`,related_ids:[7034,7e3,7023,1e3],ms_docs:null},{id:7034,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Intermediate",title:"Service Crashed Unexpectedly (Repeated)",short_desc:"A service crashed unexpectedly — this event marks subsequent crashes after the first.",description:"Event ID 7034 is very similar to 7031 but represents the second and subsequent unexpected terminations of a service. The SCM distinguishes between the first crash (7031) and repeat crashes (7034) because the recovery actions are typically different. If the configured recovery actions (restart, run program, reboot) are not resolving the crash, 7034 events indicate an ongoing problem that the automatic recovery is not fixing.",why_it_happens:'Generated by the SCM each time after the first crash when a service exits unexpectedly. Unlike 7031 (which may have a "restart service" recovery action), by the third crash the configured recovery action may be "take no action" — leaving the service permanently stopped.',what_good_looks_like:"No 7034 events. Any 7034 with high crash count is urgent — the service is in a crash loop.",common_mistakes:["Treating 7034 and 7031 as identical — 7034 indicates the problem is persistent and recovery actions are not working","Not counting how many times the service has crashed — the crash count indicates severity"],causes:["Same as 7031 — persistent service bug, hardware fault, or external cause","Recovery action set to restart, which keeps restarting into the same crash","Application configuration issue that is not fixed between restarts"],steps:["Filter System log for 7034 and count occurrences for the same service","Follow 7031 investigation steps","Check configured recovery actions in service properties","If crash count is high: disable automatic recovery temporarily and investigate root cause","Contact software vendor with crash details from Event 1000"],symptoms:["service keeps crashing over and over","service crash loop","service restarting every few minutes","service crashing repeatedly","service in crash loop"],tags:["service","crash","loop","reliability","scm"],powershell:`# Repeated Service Crash Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7034
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[7031,7e3,7023,1e3],ms_docs:null},{id:7036,source:"Service Control Manager",channel:"System",severity:"Info",skill_level:"Fundamental",title:"Service State Changed",short_desc:"A service entered a running or stopped state — normal operational event.",description:'Event ID 7036 records every time a service transitions to "running" or "stopped" state. It is one of the highest-volume SCM events and by itself is not suspicious — services start and stop constantly. However, 7036 becomes very useful when you want to know exactly when a specific service started or stopped, and whether a service that should always be running was temporarily stopped.',why_it_happens:'The SCM logs 7036 every time a service changes to a "running" or "stopped" state. This includes boot-time service starts, user-initiated stops and starts, and stops due to crashes (where it will appear alongside 7031/7034).',what_good_looks_like:"Normal: Windows Defender, Print Spooler, and other services stopping and starting as expected. Investigate: a critical service (SQL, IIS, AD) stopping without a corresponding planned action, a security service (antivirus, firewall) stopping unexpectedly, many services stopping simultaneously (suggests shutdown or crash).",common_mistakes:["Being overwhelmed by 7036 volume — filter specifically for the service and state you care about","Not using 7036 to confirm when a service was available during a troubleshooting window"],causes:["Normal service lifecycle","Scheduled maintenance","Service crash recovery","Intentional admin action","Malware stopping security services"],steps:["Filter System log for 7036 scoped to a specific service name",'Look for "stopped" transitions on critical or security services',"Correlate timestamps with 7031/7034 crash events","Check if antivirus or security services stopped unexpectedly"],symptoms:["service stopped","service started","service state changed","when did this service start","when did this service stop"],tags:["service","state","lifecycle","scm","monitoring"],powershell:`# Service State Change Investigation
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
} | Select-Object TimeCreated, Message | Format-Table -AutoSize`,related_ids:[7e3,7031,7034,7040],ms_docs:null},{id:7040,source:"Service Control Manager",channel:"System",severity:"Info",skill_level:"Intermediate",title:"Service Start Type Changed",short_desc:"A service's startup type was changed (e.g., Automatic to Disabled).",description:"Event ID 7040 records changes to a service's start type — Automatic, Manual, Disabled. This is important from a security perspective because disabling a security service (antivirus, firewall, audit service) is a technique attackers use to weaken defenses before carrying out malicious activity. It also helps troubleshoot cases where a service unexpectedly stops starting on boot — someone may have changed it to Manual or Disabled.",why_it_happens:"The SCM logs 7040 when the start type of a service is modified. This happens via the Services MMC snap-in, sc.exe config command, the Set-Service cmdlet, or registry modifications. Group Policy can also force start type changes, which will appear as 7040 events.",what_good_looks_like:"Expected: planned changes to service start types during configuration management. Investigate: security-critical services (Windows Defender, Windows Firewall, Event Log) being changed to Disabled or Manual, changes made at unusual times, changes not reflected in change management records.",common_mistakes:["Not alerting on changes to security services' start type — this is a common attacker technique","Changing a service to Automatic without understanding why it was Manual"],causes:["IT admin changing service configuration","Software installer modifying service startup","Group Policy applying service configuration","Attacker disabling security services","Malware modifying startup type to survive reboots or disable detection"],steps:["Filter System log for 7040","Note service name and new start type",'If "Disabled" or "Manual" for a security service: immediate investigation',"Restore correct start type: Set-Service <name> -StartupType Automatic","Correlate with 4688 to find what process made the change"],symptoms:["service start type changed","service disabled","service changed to manual","antivirus service disabled","windows defender disabled","firewall service disabled"],tags:["service","configuration","security","defense-evasion","scm"],powershell:`# Service Start Type Change Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7040
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[7036,7e3,7031,4688],ms_docs:null},{id:7045,source:"Service Control Manager",channel:"System",severity:"Warning",skill_level:"Intermediate",title:"New Service Installed",short_desc:"A new service was installed and registered with the Service Control Manager.",description:"Event ID 7045 records when a new service is installed on the system. Like scheduled task creation (4698), new service installation is a favourite persistence mechanism for attackers — services run under SYSTEM or service accounts, start automatically, and are often overlooked by defenders focused on user-space activity. The event includes the service name, binary path, account it runs under, and the start type. Service names that don't match known software should be immediately investigated.",why_it_happens:"When a service is created via the SCM APIs (CreateService), the SCM logs 7045. This happens during software installation, when admin tools deploy services, and when malware installs a service for persistence or remote access. The binary path field is particularly important — malicious services often run from unusual paths (AppData, Temp, random hex-named directories).",what_good_looks_like:"Expected: known software installing services during installation (SQL Server, antivirus, monitoring agents). Investigate: services installed outside of known software installation events, binary paths in AppData, Temp, or with random names, services running as LocalSystem (SYSTEM) installed by non-admin processes, service names that try to blend in with system services.",common_mistakes:["Not having a baseline list of expected services to compare against","Missing that even services installed by an admin account can be malicious if the admin account was compromised","Not checking the binary path — a service that looks legitimate by name but runs from AppData is suspicious"],causes:["Software installation creating a service","RMM or monitoring agent deploying a service","IT admin installing a management service","Malware installing a persistent service","Attacker using PsExec or similar (which installs a temporary service)"],steps:["Filter System log for 7045","Note service name, binary path, account, and start type","Check if binary path is in a standard location (Program Files, Windows, etc.)","Verify the service matches a known installation event (Event 4688, installer logs)","Check the service binary hash against VirusTotal if suspicious","Investigate unknown services: Get-Service <name> | Select-Object *","Remove malicious services: sc.exe delete <name>"],symptoms:["new service installed","unknown service appeared","suspicious service","new service on system","service installed by malware","unauthorized service"],tags:["service","persistence","installation","malware","scm","security"],powershell:`# New Service Installation Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[7036,7e3,4688,4698],ms_docs:"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697"},{id:12,source:"Microsoft-Windows-Kernel-General",channel:"System",severity:"Information",skill_level:"Beginner",title:"Operating System Started",short_desc:"The OS initialized successfully and logged the exact start time for this boot.",description:"Event ID 12 from Kernel-General is written early in every normal boot. It records the precise system time the OS kernel started running. On its own it is informational — no action needed. Its primary value in incident analysis is as a timeline anchor: you can see exactly when the machine booted, correlate it against Event 13 (shutdown) and Event 41 (unexpected reboot), and determine uptime at the time of an incident.",why_it_happens:"Logged by the Windows kernel during initialization on every boot, before user-mode processes start. The timestamp comes from the hardware clock (RTC) before time sync occurs, so it may be slightly off by a few seconds from NTP-corrected time.",what_good_looks_like:"One Event 12 per boot cycle. Frequent Event 12 entries without corresponding Event 13 entries before them indicates repeated unexpected reboots — correlate with Event 41.",causes:["Normal system boot","Reboot after update","Reboot following a crash (Event 41)","Reboot after manual shutdown"],steps:["Use Event 12 timestamps to map the full boot history of the machine","Check if Event 13 appears before each Event 12 — missing Event 13 means the previous shutdown was unexpected","Correlate with Event 41 to confirm crash vs. clean reboot","Measure uptime between Event 12 and the incident timestamp"],symptoms:["when did the computer start","boot time","last reboot time","system start time","os startup"],tags:["boot","startup","kernel","timeline","uptime"],powershell:`# Boot History (last 30 days)
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-General'
    Id           = @(12, 13)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 12) {'STARTED'} else {'SHUTDOWN'} }} |
    Sort-Object TimeCreated | Format-Table -AutoSize`,related_ids:[13,41,6008,6005],ms_docs:null},{id:13,source:"Microsoft-Windows-Kernel-General",channel:"System",severity:"Information",skill_level:"Beginner",title:"Operating System Shutdown",short_desc:"The OS began a clean shutdown and logged the exact time.",description:"Event ID 13 from Kernel-General is written at the beginning of every clean, intentional shutdown or restart. It is the counterpart to Event 12. In incident analysis its absence is the key signal — if you see Event 12 (boot) without a preceding Event 13 (clean shutdown), the previous session ended unexpectedly. That gap, combined with Event 41 or 6008, confirms a crash, power loss, or hard reset.",why_it_happens:"The Windows kernel writes Event 13 during the shutdown phase after user and service shutdown has completed. It is one of the last events written before the OS halts. If the machine crashes or loses power before reaching this phase, Event 13 is never written.",what_good_looks_like:"Every Event 12 (boot) should be preceded by an Event 13 (clean shutdown) from the previous boot. Exception: the very first boot after OS installation.",causes:["Normal user-initiated shutdown or restart","Shutdown via update installation","Remote shutdown command","System entering hibernation (S4 sleep)"],steps:["Find Event 12 entries and check for a preceding Event 13 — gap = unexpected shutdown","If no Event 13 before a boot: check Event 41 (crash/power loss) or Event 6008 (unexpected shutdown)","Correlate shutdown time with Event 1074 to see what initiated the shutdown","Repeated missing Event 13 entries = recurring stability problem requiring investigation"],symptoms:["when did the computer shut down","last shutdown time","clean shutdown","unexpected reboot history","os shutdown time"],tags:["shutdown","kernel","timeline","uptime","clean-shutdown"],powershell:`# Shutdown and Boot History (last 30 days)
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-General'
    Id           = @(12, 13)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 12) {'STARTED'} else {'SHUTDOWN'} }} |
    Sort-Object TimeCreated | Format-Table -AutoSize`,related_ids:[12,41,1074,6008],ms_docs:null},{id:18,source:"Microsoft-Windows-Kernel-General",channel:"System",severity:"Information",skill_level:"Beginner",title:"System Time Changed",short_desc:"The system clock was adjusted — either by NTP sync, a user, or a domain time policy.",description:"Event ID 18 from Kernel-General logs whenever the system clock is changed. The event records the old time, new time, and the process that made the change. In normal environments this happens regularly via W32tm (Windows Time Service) syncing to a domain controller or NTP server. It becomes significant in incident analysis if: the time change is large (hours or days), the process making the change is not W32tm or a trusted service, or it occurs immediately before suspicious activity (attackers sometimes shift clocks to corrupt log correlation).",why_it_happens:"The Windows Time Service (W32tm) adjusts the clock periodically to stay in sync with its configured time source. Domain-joined machines sync to a domain controller; standalone machines use time.windows.com. Large jumps happen when the machine was offline for a long time, the CMOS battery died, or someone manually changed the time.",what_good_looks_like:"Small adjustments (milliseconds to seconds) by the SYSTEM process or W32tm are normal. Investigate: large adjustments (minutes or more), adjustments by a non-system process, repeated adjustments in a short period, or time changes that correlate with other suspicious events.",causes:["NTP or domain time sync (normal)","Manual clock change by a user or admin","CMOS/RTC battery failure causing clock drift","VM host adjusting guest clock","Time zone change","System recovering from long offline period"],steps:["Check the ProcessName field — W32tm.exe or SYSTEM is expected","Check the magnitude of the change — small ms adjustments are normal, large jumps are not","If large jump: check CMOS battery health and NTP sync status (w32tm /query /status)","If made by unexpected process: investigate that process — potential indicator of tampering","Run: w32tm /query /status to check current sync health"],symptoms:["clock changed","system time wrong","time jumped","timestamps are off","ntp sync problem","clock drift"],tags:["time","clock","ntp","sync","kernel","timeline"],powershell:`# System Time Change History
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[12,13],ms_docs:null},{id:20,source:"Microsoft-Windows-WindowsUpdateClient",channel:"System",severity:"Error",skill_level:"Beginner",title:"Windows Update Installation Failure",short_desc:"A Windows Update failed to install — the update and error code are recorded.",description:"Event ID 20 from WindowsUpdateClient is logged when an update download or installation fails. It records the update title, KB number, and the error code. This is the primary event for diagnosing Windows Update failures. The error code is the critical field — it maps to a specific failure reason (network, disk space, component corruption, conflicting software, etc.). Repeated failures of the same KB usually indicate an underlying system health problem rather than a transient network issue.",why_it_happens:"Windows Update failures occur for many reasons: network interruption during download, insufficient disk space (Windows needs 10–20 GB free), corruption in the Windows Update component store (DISM /ScanHealth), driver conflicts, third-party security software blocking the update, or the update being genuinely incompatible with installed hardware/software.",what_good_looks_like:"Occasional single failures followed by a successful install on retry are normal. Investigate: the same KB failing repeatedly across multiple attempts, multiple different KBs all failing, failures with component store corruption errors (0x800F0***), failures in the last 30 days with no successful updates.",common_mistakes:['Not checking the error code — "update failed" tells you nothing, the hex code tells you everything',"Running Windows Update troubleshooter first without checking disk space (most common root cause)","Not checking that Windows Update services are running (wuauserv, bits, cryptsvc, msiserver)","Forgetting that some updates require a reboot before the next update can install"],causes:["Insufficient free disk space (need 10–20 GB)","Windows Update component store corruption","Windows Update services stopped or disabled","Network connectivity issue during download","Third-party security software blocking installation","Conflicting software or driver","Pending reboot blocking further updates"],steps:["Note the error code from Event 20 — search it with the KB number for specific guidance","Check disk space: Get-PSDrive C | Select-Object Used, Free","Verify Update services running: Get-Service wuauserv, bits, cryptsvc | Select-Object Name, Status","Run DISM to check component health: DISM /Online /Cleanup-Image /CheckHealth","If corruption found: DISM /Online /Cleanup-Image /RestoreHealth","Then run: sfc /scannow","Check Event 19 (successful download) — if missing, download itself is failing (network/BITS)","Check free space in C:\\Windows\\SoftwareDistribution — clear with: net stop wuauserv && rd /s /q C:\\Windows\\SoftwareDistribution && net start wuauserv"],symptoms:["windows update failed","update wont install","update error","kb failed to install","windows update stuck","updates keep failing","cumulative update failed","feature update failed"],tags:["windows-update","patch","installation","error","maintenance"],powershell:`# Windows Update Failure History
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
} | Sort-Object Time -Descending | Format-Table -AutoSize`,related_ids:[19,1074],ms_docs:"https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-error-reference"},{id:5,source:"Microsoft-Windows-Kernel-Boot",channel:"System",severity:"Information",skill_level:"Intermediate",title:"Boot Configuration Data Loaded",short_desc:"The Boot Configuration Data (BCD) store was read and applied during startup.",description:"Event ID 5 from Kernel-Boot is logged during the early boot phase when Windows reads its Boot Configuration Data (BCD) store. The event records which boot entry was selected and the boot type (normal, safe mode, WinRE, etc.). It is informational in a normal boot, but useful for diagnosing repeated failures to boot into normal mode, unexpected safe mode boots, or BCD corruption. Check the BootType field: 1 = normal boot, 2 = safe mode, 3 = safe mode with networking.",why_it_happens:"The Windows Boot Manager reads the BCD store on every boot to determine which OS to load and in what mode. Event 5 is written once per boot as confirmation that this step completed. If the BCD is corrupt or missing, the boot process fails before this event is written.",what_good_looks_like:"BootType 1 (normal) on every boot. Investigate: repeated BootType 2/3 (safe mode) without admin action, multiple Event 5 entries for a single boot cycle (can indicate boot repair attempts), or absence of Event 5 before a successful Event 12 (rare, possible if BCD events are filtered).",causes:["Normal system boot (BootType 1)","Safe mode boot (BootType 2/3) — user or automatic recovery","Windows Recovery Environment (BootType 4)","Automatic Repair triggered by repeated boot failures","Admin booting into diagnostic mode"],steps:["Check BootType field — normal is 1, safe mode is 2 or 3","If repeated safe mode boots: check what triggered them (user, automatic repair, or policy)","If BCD issues suspected: bcdedit /enum all (run as admin)","To repair BCD: boot from Windows media → Repair your computer → Startup Repair","Check Event 12 and 41 for correlation with unexpected boot modes"],symptoms:["booted into safe mode","unexpected safe mode","boot configuration","bcd","startup mode","computer keeps booting to recovery"],tags:["boot","bcd","safe-mode","startup","kernel-boot"],powershell:`# Recent Boot Type History
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[12,41,6008],ms_docs:null},{id:27,source:"Microsoft-Windows-Kernel-Boot",channel:"System",severity:"Warning",skill_level:"Intermediate",title:"Boot Environment Error",short_desc:"The boot environment encountered a problem setting or reading a boot configuration value.",description:'Event ID 27 from Kernel-Boot is generated when the boot environment fails to properly apply a configuration value from the BCD store, or when a requested boot option cannot be set. This often appears after failed Windows Update installs, interrupted in-place upgrades, or BCD corruption. It can also appear from the disk driver context when a device was removed without a proper dismount ("surprise removal"). Check the Provider field in the raw event — Kernel-Boot indicates a boot configuration issue; the disk driver indicates a storage device removal problem.',why_it_happens:"Boot configuration errors arise when the BCD store has an inconsistency, a pending boot operation could not complete (e.g., an update that required a specific boot mode failed), or the boot hardware abstraction layer encountered unexpected firmware behaviour. Disk-context Event 27 occurs when Windows detects that a device was physically removed while still mounted — common with hot-swap bays, USB drives with running I/O, or iSCSI targets that dropped.",what_good_looks_like:"Absence is normal. Any occurrence warrants investigation. A single isolated Event 27 after a known upgrade attempt is low priority. Repeated occurrences or Event 27 combined with disk I/O errors (51, 129) is higher priority.",causes:["Failed or interrupted Windows Update requiring a boot-time operation","BCD store corruption or inconsistency","Storage device removed without safe ejection (Kernel-Boot or disk context)","Firmware/UEFI reporting an unexpected boot configuration state","iSCSI or network storage target disconnect"],steps:["Check the Provider/Source field — determines if this is a boot config or disk removal issue","For boot config: run bcdedit /enum all and look for inconsistencies","Run startup repair if the machine had boot problems: boot from Windows media","For disk removal: identify which device was removed and check Event 51 or 129 around the same time","Check Windows Update history for failed installs immediately before Event 27"],symptoms:["boot error","boot configuration problem","drive surprise removal","device disconnected unexpectedly","usb drive error on removal","iscsi disconnected"],tags:["boot","bcd","disk","removal","kernel-boot","storage"],powershell:`# Boot Environment Errors
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 27
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, ProviderName, LevelDisplayName, Message |
    Sort-Object TimeCreated -Descending | Format-List`,related_ids:[5,12,41,51,129],ms_docs:null},{id:238,source:"Microsoft-Windows-Kernel-Processor-Power",channel:"System",severity:"Information",skill_level:"Advanced",title:"Processor Power Capability Change",short_desc:"A processor reported a change in its available power or performance states.",description:"Event ID 238 from Kernel-Processor-Power is logged when a processor reports a change in its power management capabilities or performance state enumeration. This typically occurs during boot, after a driver update, or when firmware/UEFI adjusts CPU power policy. On its own it is informational. It becomes relevant in incident investigations involving unexpected CPU throttling, performance degradation, or thermal events — particularly when combined with Event 37 (CPU speed limited by firmware) or high-temperature readings.",why_it_happens:"Modern processors expose their available performance and power states (P-states, C-states) to the OS via ACPI. When the set of available states changes — due to thermal limits, firmware intervention, driver update, or hardware capability reporting — Windows logs Event 238 to record the new state of affairs. In some cases, the CPU reports fewer performance states than expected because the firmware is limiting it due to a thermal condition.",what_good_looks_like:"Appearing once at boot for each logical processor is normal. Investigate: Event 238 occurring outside of boot, in conjunction with performance complaints, or combined with thermal events and Event 37.",causes:["Normal processor power state enumeration at boot","CPU driver or firmware update changing available P-states","Thermal throttling causing firmware to restrict performance states","Virtualisation host changing CPU capability exposure","BIOS/UEFI setting change affecting power management"],steps:["Check if Event 238 appears only at boot — if so, likely informational","If mid-operation: check for thermal events and CPU temperature (Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root/wmi)","Check Event 37 (Kernel-Processor-Power) for CPU speed limiting",'Check BIOS/UEFI for power management settings — "Performance" mode vs "Power Saver"',"Ensure CPU drivers and chipset drivers are current"],symptoms:["cpu throttling","processor performance changed","cpu running slow","processor power state","cpu frequency reduced"],tags:["cpu","power","performance","throttling","processor","kernel"],powershell:`# CPU Power Events
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
    Id           = @(37, 238, 247)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Sort-Object TimeCreated -Descending | Format-List`,related_ids:[37,247,41],ms_docs:null},{id:247,source:"Microsoft-Windows-Kernel-Processor-Power",channel:"System",severity:"Information",skill_level:"Advanced",title:"Processor Performance State Transition",short_desc:"A processor transitioned to a different performance (P-state) level.",description:"Event ID 247 from Kernel-Processor-Power records a significant processor performance state (P-state) transition — typically a switch to a lower performance tier due to power policy, thermal management, or battery/power plan constraints. Like Event 238, it is informational in isolation but important when investigating CPU performance degradation. The event records the processor index, the target performance percentage, and the reason for the transition. Repeated 247 events showing reductions to low percentages indicate sustained throttling.",why_it_happens:"Windows power management continuously adjusts CPU performance states to balance power consumption against workload demand. Event 247 is written when this adjustment is significant enough to log — particularly when performance is constrained rather than just scaled up. The trigger can be a temperature threshold being reached, a power plan switch (Balanced → Power Saver), a UPS switching to battery, or firmware-level limits being applied.",what_good_looks_like:"Occasional 247 entries with performance levels that return to 100% are normal under balanced power plans. Investigate: consistent 247 entries showing low performance percentages during business hours, 247 paired with thermal events, or 247 following a UPS or power supply event.",causes:["Active power plan throttling CPU (Balanced or Power Saver mode)","Thermal throttling — CPU too hot","UPS switched to battery — system reducing power draw","Firmware-level power limits (TDP limits)","Virtualisation host restricting CPU performance"],steps:["Check the performance percentage in the event — sustained below 50% is a problem","Check CPU temperatures during the throttling period","Review active power plan: powercfg /getactivescheme","Change to High Performance if throttling is unwanted: powercfg /setactive SCHEME_MIN","Check Event 37 for firmware-level speed limits","If on a laptop/UPS: check power source at time of events"],symptoms:["cpu running slow","processor throttled","performance degraded","computer feels sluggish","cpu percentage low","performance state change"],tags:["cpu","power","throttling","performance","p-state","thermal"],powershell:`# Processor Performance State Events
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
} | Sort-Object Time -Descending | Format-Table -AutoSize`,related_ids:[238,37,41],ms_docs:null},{id:51,source:"disk",channel:"System",severity:"Warning",skill_level:"Intermediate",title:"Disk I/O Error During Paging Operation",short_desc:"Windows detected an error reading or writing to the disk during a paging (virtual memory) operation.",description:'Event ID 51 from the disk driver is generated when a read or write error occurs on the disk during a paging operation — meaning Windows was trying to swap data between RAM and the page file (or read a mapped file) and the disk returned an error. This is a significant warning. A single Event 51 can be a transient glitch; repeated Event 51 entries almost always indicate a failing disk, a loose SATA/NVMe cable, or a failing disk controller. The machine may still appear to function normally while accumulating these errors, then fail suddenly. Event 51 is one of the most common events found in logs from computers that are "randomly slow" or "randomly freeze."',why_it_happens:"Paging operations are constant on a busy system — Windows uses virtual memory to extend RAM by writing data to disk. When the disk returns an error on one of these operations, Event 51 is written. The OS retries the operation, so the user often sees only a brief freeze or slowdown. The underlying cause is almost always hardware: bad disk sectors, a failing drive, a loose cable, an overheating disk, or a failing disk controller.",what_good_looks_like:"Absence is normal. Even a single Event 51 warrants checking disk SMART data. Multiple Event 51 entries in a short window means the disk is likely failing and data is at risk.",common_mistakes:["Dismissing Event 51 as a one-off without checking SMART data","Not checking the physical cable — a loose SATA cable is a very common cause and a 10-second fix","Waiting for the disk to fail completely before acting — backups should start now","Forgetting that Event 51 causes user-visible symptoms: freezing, slowness, application crashes"],causes:["Failing hard disk (bad sectors, mechanical failure)","Loose or failing SATA/NVMe data cable","Failing disk controller or motherboard storage port","Overheating disk (check drive temperature)","Failing SSD (NAND wear, controller issues)","External USB drive with a poor connection"],steps:["Count Event 51 occurrences — frequency and pattern matter","Identify which disk: check the device path in the event (e.g., \\Device\\Harddisk0)","Check disk SMART data immediately: Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object DeviceId, ReadErrorsTotal, WriteErrorsTotal, Wear","Use CrystalDiskInfo or manufacturer tool for full SMART attribute read","Physically check cables — reseat SATA data cable at both ends (drive and motherboard)","Check Event 7 (disk) and Event 11 (disk) nearby — hardware malfunction markers","Check Event 129 (StorPort) — disk reset events alongside 51 = imminent failure","Backup immediately if SMART shows reallocated sectors or pending sectors > 0"],symptoms:["computer randomly freezes","computer randomly slow","random hangs","blue screen of death","disk error","hard drive failing","applications crashing randomly","file system corruption","computer lags then recovers","disk making clicking noise"],tags:["disk","storage","hardware","paging","failure","critical","sata","nvme"],powershell:`# Disk I/O Error Investigation
# Eventful

# Count recent disk errors
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'disk'
    Id           = @(51, 7, 11)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Group-Object Id |
    Select-Object Name, Count |
    Format-Table -AutoSize

# SMART reliability data
Get-PhysicalDisk | ForEach-Object {
    $rel = $_ | Get-StorageReliabilityCounter
    [PSCustomObject]@{
        Disk              = $_.FriendlyName
        MediaType         = $_.MediaType
        HealthStatus      = $_.HealthStatus
        ReadErrors        = $rel.ReadErrorsTotal
        WriteErrors       = $rel.WriteErrorsTotal
        Wear              = "$($rel.Wear)%"
        Temperature       = "$($rel.Temperature) C"
        PowerOnHours      = $rel.PowerOnHours
    }
} | Format-Table -AutoSize`,related_ids:[129,153,7,11,55,41],ms_docs:null},{id:129,source:"storahci",channel:"System",severity:"Warning",skill_level:"Intermediate",title:"StorPort: Reset to Device Initiated",short_desc:"The storage controller timed out waiting for a disk response and issued a hardware reset.",description:'Event ID 129 from storahci (or StorPort) means the storage controller sent a command to the disk and the disk did not respond within the timeout window, forcing the controller to reset the device to recover. This is a serious hardware warning. Unlike Event 51 which happens during paging I/O, Event 129 indicates the disk stopped responding entirely — even briefly. The user typically experiences a multi-second freeze followed by recovery, a BSOD, or a "delayed write failed" error. On an SSD this almost always means the drive is failing or has a firmware bug. On a spinning disk it usually means imminent mechanical failure.',why_it_happens:"The AHCI/NVMe controller expects the disk to respond to commands within a set timeout (usually 30 seconds for AHCI). If the disk stalls — due to bad sectors forcing repeated read retries, a mechanical head stall, thermal shutdown, or firmware hang — the controller times out and issues a bus reset. The OS recovers the I/O but logs the reset. On healthy hardware this never happens.",what_good_looks_like:"Absence is normal. Any occurrence of Event 129 is abnormal and requires investigation. A single Event 129 on a spinning disk after years of service may be a one-off; any recurrence means replace the disk.",common_mistakes:["Treating Event 129 as low priority — it is not, the drive is telling you it is struggling","Not checking whether the machine uses AHCI vs NVMe — source will be storahci or stornvme respectively","Replacing the cable but not checking SMART — the drive itself may be the problem","Missing that Event 129 during a backup job means the backup may be corrupt"],causes:["Failing hard disk (mechanical failure, bad sectors exhausting retry budget)","Failing or poorly firmware-updated SSD","Overheating drive entering thermal protection","Failing SATA/NVMe cable or connector","Failing disk controller or motherboard storage chip","Firmware bug in the drive (check manufacturer for firmware update)"],steps:["Check the device path in the event to identify which disk","Run SMART immediately — Event 129 is a high-priority disk failure indicator","Check Event 51 nearby — combination of 51 + 129 = near-certain disk failure","Check drive temperature: Get-PhysicalDisk | Get-StorageReliabilityCounter | Select Temperature","Check for pending/reallocated sectors in SMART (any non-zero = replace soon)","Update disk firmware from manufacturer — some 129 events are firmware bugs","Back up immediately and plan disk replacement"],symptoms:["computer freezes for several seconds","system hangs then recovers","blue screen inaccessible boot device","delayed write failed error","drive not responding","ssd freezing","hard drive hang","disk reset","storage controller error"],tags:["disk","storage","hardware","reset","storahci","nvme","failure","critical"],powershell:`# StorPort Reset Investigation
# Eventful

# Check for disk reset events
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = @(129, 51, 153)
    StartTime = (Get-Date).AddDays(-14)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, ProviderName, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# SMART health check
Get-PhysicalDisk | ForEach-Object {
    $rel = $_ | Get-StorageReliabilityCounter
    [PSCustomObject]@{
        Disk          = $_.FriendlyName
        Health        = $_.HealthStatus
        Temperature   = "$($rel.Temperature) C"
        ReadErrors    = $rel.ReadErrorsTotal
        WriteErrors   = $rel.WriteErrorsTotal
        Wear          = "$($rel.Wear)%"
    }
} | Format-Table -AutoSize`,related_ids:[51,153,7,11,55,41],ms_docs:null},{id:153,source:"disk",channel:"System",severity:"Warning",skill_level:"Intermediate",title:"Disk Retriable I/O Error",short_desc:"A disk I/O operation failed but was retried successfully — an early warning of disk problems.",description:"Event ID 153 from the disk driver indicates a disk I/O operation failed on the first attempt but succeeded on retry. The OS handles this transparently so the user typically notices nothing — this is what makes Event 153 particularly dangerous. It is an early warning sign that appears weeks or months before a disk starts producing Event 51 (paging errors) and Event 129 (disk resets). Seeing Event 153 in a log is the best opportunity to catch a failing disk before it causes data loss or a system crash. Treat it as a yellow flag: investigate, check SMART, increase backup frequency.",why_it_happens:"Magnetic hard disks can fail to read a sector on first pass due to a weak magnetic signal, a vibration, or early-stage surface degradation. The drive retries internally (up to several times) and then the OS driver also retries. If a later retry succeeds, Event 153 is written rather than Event 51. SSDs can produce 153 during early NAND cell degradation. The key insight: a disk that needs retries to succeed is a disk that is getting worse.",what_good_looks_like:"Absence is normal for a healthy drive. Even one or two Event 153 entries justifies checking SMART. A cluster of 153 entries or 153 appearing alongside 51 or 129 means the disk is in an active failure mode.",causes:["Early-stage disk surface degradation (HDD)","Weak magnetic sectors starting to fail (HDD)","SSD NAND cell wear approaching end of life","Vibration or physical shock causing temporary read failure","Marginal power delivery to the disk","Loose data or power cable causing intermittent contact"],steps:["Note how many Event 153 entries appear and over what time period","Check SMART data: reallocated sectors, pending sectors, uncorrectable sectors","Compare 153 frequency over time — increasing rate = accelerating failure","Check Event 51 and 129 — if those appear alongside 153, disk failure is active not just early","Increase backup frequency immediately","Plan disk replacement even if SMART looks clean — 153 can precede SMART-reported failures"],symptoms:["disk errors in event log","hard drive warnings","early disk failure","smart warning","drive health warning","occasional disk errors","disk slowly failing"],tags:["disk","storage","hardware","warning","early-warning","smart","failure"],powershell:`# Disk Health - Early Warning Check
# Eventful

# Disk error event frequency (last 30 days)
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'disk'
    Id           = @(153, 51, 7, 11)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Group-Object Id |
    Select-Object @{N='EventId'; E={$_.Name}},
                  @{N='Count';   E={$_.Count}} |
    Format-Table -AutoSize

# SMART data
Get-PhysicalDisk | ForEach-Object {
    $rel = $_ | Get-StorageReliabilityCounter
    [PSCustomObject]@{
        Disk              = $_.FriendlyName
        Health            = $_.HealthStatus
        ReadErrors        = $rel.ReadErrorsTotal
        WriteErrors       = $rel.WriteErrorsTotal
        Wear              = "$($rel.Wear)%"
        PowerOnHours      = $rel.PowerOnHours
    }
} | Format-Table -AutoSize`,related_ids:[51,129,7,11],ms_docs:null},{id:37,source:"Microsoft-Windows-Kernel-Processor-Power",channel:"System",severity:"Warning",skill_level:"Intermediate",title:"CPU Speed Limited by Firmware",short_desc:"The processor is running slower than its rated speed due to a firmware-imposed limit — most commonly overheating.",description:'Event ID 37 from Kernel-Processor-Power is the single most important event for diagnosing "my computer got suddenly slow" tickets. It means the CPU firmware (BIOS/UEFI) has capped the processor speed below its rated maximum. The event records the processor number, the current performance percentage (100% = full speed, lower values = throttled), and optionally the reason. The most common cause by far is overheating — when a CPU hits its thermal limit, the firmware reduces its clock speed to protect it, causing an immediate and dramatic performance drop that the user experiences as the computer becoming unusably slow.',why_it_happens:'Modern CPUs have built-in thermal protection: when die temperature hits the TjMax threshold (typically 90–105°C depending on CPU model), the firmware reduces the clock multiplier to cut heat output. This "thermal throttling" keeps the CPU alive but makes it run at a fraction of its rated speed. Other causes: the active power plan is set to Power Saver or Balanced (which caps CPU performance), a laptop is running on battery, BIOS power settings are misconfigured, or a virtualisation host is constraining the guest.',what_good_looks_like:"Absence is normal on a healthy desktop. On laptops under power plans, occasional 37 entries with modest throttling are normal. Investigate: Event 37 showing performance at 30% or lower, Event 37 appearing repeatedly during normal workloads, or a sudden onset of Event 37 after months of none (thermal paste dried out, heatsink clogged with dust).",common_mistakes:["Not checking the CPU temperature — the event alone does not tell you the temperature","Fixing the power plan without checking if overheating is the actual cause — if it is, changing the power plan just masks the problem","Forgetting laptops throttle on battery — always test on mains power before diagnosing hardware","Not checking whether the heatsink fan is spinning — a failed fan causes immediate sustained throttling"],causes:["CPU overheating — dried thermal paste, dust-blocked heatsink, failed fan","Power plan set to Balanced or Power Saver","Laptop running on battery (power-saving throttle)","BIOS power management settings restricting TDP","Virtualisation host CPU resource limit","High ambient temperature in the room or enclosure"],steps:["Check the performance percentage in the event — below 50% sustained is a serious problem","Check CPU temperature with HWMonitor, Core Temp, or PowerShell (ACPI thermal zones)","If temp > 85°C under light load: clean heatsink fins and replace thermal paste","Check the active power plan: powercfg /getactivescheme — switch to High Performance for testing","Check fan operation: physically listen and use BIOS fan monitor","On a laptop: test on mains power — if throttling stops, it was a battery power policy","Check BIOS for power/performance settings — some have a Power Limit that is set too low"],symptoms:["computer suddenly slow","computer became slow overnight","cpu running slow","processor throttled","computer sluggish","everything is slow","computer slow after a while","laptop slow on battery","performance dropped","computer slow when hot"],tags:["cpu","performance","throttling","thermal","overheating","slowness","power"],powershell:`# CPU Throttling Investigation
# Eventful

# Check for throttling events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
    Id           = 37
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Processor   = ($data | Where-Object Name -eq 'ProcessorNumber').'#text'
        PerfPercent = ($data | Where-Object Name -eq 'TargetProcessorThrottle').'#text'
    }
} | Sort-Object Time -Descending | Format-Table -AutoSize

# Current power plan
powercfg /getactivescheme

# CPU temperature via ACPI (not all hardware exposes this)
Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root/wmi -ErrorAction SilentlyContinue |
    Select-Object InstanceName,
        @{N='TempC'; E={ [math]::Round(($_.CurrentTemperature - 2732) / 10, 1) }} |
    Format-Table -AutoSize`,related_ids:[238,247,41],ms_docs:"https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/cpu-frequency-limited-firmware"},{id:7026,source:"Service Control Manager",channel:"System",severity:"Error",skill_level:"Intermediate",title:"Boot-Start or System-Start Driver Failed to Load",short_desc:"A driver that is supposed to load at boot failed — can cause BSODs, missing hardware, or system instability.",description:"Event ID 7026 from the Service Control Manager is written when a driver configured to load at boot time (boot-start or system-start type) fails to initialise. These are some of the earliest drivers loaded — storage controllers, file system drivers, hardware abstraction drivers. A failed boot-start driver can cause BSODs during or after boot, missing hardware devices, system instability, or degraded performance. The event names the driver that failed. Critical drivers (disk controller, NTFS) failing will usually result in a BSOD before Windows fully loads; less critical drivers result in Event 7026 with Windows still functional but a hardware component non-functional.",why_it_happens:"Boot-start drivers fail for several reasons: the driver binary is missing or corrupt (Windows Update gone wrong, malware damage), the hardware the driver supports is no longer present (USB device was unplugged), a driver update introduced a bug, or the driver is incompatible with the current OS version. After a Windows upgrade, old third-party drivers for hardware that was not migrated cleanly are a common source.",what_good_looks_like:"No Event 7026 in a healthy system. A single occurrence after a driver update or hardware change is worth investigating but may resolve on reboot. Repeated Event 7026 for the same driver = persistent problem requiring remediation.",common_mistakes:["Ignoring 7026 because Windows boots fine — the failed driver may control a device that looks functional but is running degraded","Not checking Device Manager after seeing 7026 — the failed device will usually show a yellow warning","Reinstalling drivers before checking if the underlying hardware is present and recognised in BIOS"],causes:["Driver binary missing or corrupt","Incompatible or outdated driver after Windows Update","Hardware removed but driver still registered","Third-party driver conflict","Malware corrupting driver files","Failed Windows in-place upgrade leaving stale drivers"],steps:["Note the driver name from the event","Open Device Manager — look for yellow warning triangles (devmgmt.msc)","Right-click the affected device → Update Driver or Roll Back Driver","If driver is for removed hardware: uninstall the device in Device Manager","Check Windows Update — a pending driver update may fix the issue","Run: sfc /scannow to check for and repair corrupt system files","If after a Windows upgrade: use compatibility mode or download the latest driver from the manufacturer"],symptoms:["driver failed to load","device not working after reboot","blue screen on boot","hardware not detected","driver error on startup","device missing after update","system instability after driver update"],tags:["driver","boot","hardware","service","bsod","scm","stability"],powershell:`# Boot Driver Failure Investigation
# Eventful

# Failed boot drivers (last 30 days)
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = 7026
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Devices with errors in Device Manager
Get-PnpDevice | Where-Object { $_.Status -ne 'OK' } |
    Select-Object Status, Class, FriendlyName, InstanceId |
    Format-Table -AutoSize`,related_ids:[7e3,7001,7034,41,1001],ms_docs:null},{id:10016,source:"Microsoft-Windows-DistributedCOM",channel:"System",severity:"Warning",skill_level:"Beginner",title:"DCOM Permission Error (Usually Harmless)",short_desc:"A process tried to start a DCOM server without the required permissions. Appears constantly in most Windows logs — almost always harmless noise.",description:"Event ID 10016 from DistributedCOM is one of the most common events in Windows System logs and is responsible for an enormous amount of wasted diagnostic time. It means a process attempted to activate or call a DCOM (Distributed Component Object Model) server and was denied due to missing launch or activation permissions. Despite appearing as a Warning and sometimes an Error, this event is almost never the cause of user-reported problems. Microsoft itself ships Windows with several built-in components that generate 10016 continuously — the permissions gap is intentional or a long-standing unfixed bug in many cases. In practice: if a user reports crashes, slowness, or application failure, Event 10016 is almost certainly not the cause. Look elsewhere.",why_it_happens:"Windows is built extensively on COM/DCOM — nearly every system component uses it for inter-process communication. Many COM servers have fine-grained security descriptors that restrict which accounts can launch or activate them. When an app or service (including built-in Windows processes like Explorer, Taskbar, or Update Orchestrator) tries to activate a COM server and lacks explicit permission, Event 10016 is written. Microsoft has never fixed many of these permission mismatches because the underlying operations succeed through fallback paths.",what_good_looks_like:"Present in virtually every Windows system log — this is normal. Only investigate 10016 if: the event is from a third-party application that is actually broken, the CLSID/AppID matches an application you are actively troubleshooting, or it correlates precisely with user-reported errors from that same application.",common_mistakes:["Assuming Event 10016 is causing the problem the user reported — it almost never is",'Spending time "fixing" 10016 by editing DCOM permissions in Component Services — this is risky and rarely necessary',"Not looking past 10016 to find the actual cause (disk errors, application crashes, driver failures)"],causes:["Built-in Windows components with unfixed permission mismatches (expected, ignore)","Third-party software with misconfigured DCOM registration (investigate if the app is broken)","Application running under a restricted account trying to access DCOM server (check if the app is misbehaving)"],steps:["Identify the application or service generating the event from the AppID/CLSID field","If it is a Windows built-in component (Taskbar, Explorer, Update, BrokerInfrastructure): ignore it","If it is a third-party app that the user says is broken: check the vendor's known issues","Look past 10016 for other events that correlate with the actual reported problem","Do NOT edit DCOM security in Component Services unless specifically directed by a vendor KB"],symptoms:["dcom error","event 10016","distributed com error","lots of warnings in event log","event log full of warnings"],tags:["dcom","com","permissions","noise","warning","harmless","common"],powershell:`# DCOM Error Summary (to assess volume and source)
# Eventful — These are almost always harmless. Check the source AppID.

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DistributedCOM'
    Id           = 10016
    StartTime    = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Group-Object { ($_ | Select-Object -ExpandProperty Message).Substring(0, 80) } |
    Select-Object Count, Name |
    Sort-Object Count -Descending |
    Format-Table -AutoSize`,related_ids:[],ms_docs:null},{id:1,source:"Microsoft-Windows-Power-Troubleshooter",channel:"System",severity:"Information",skill_level:"Beginner",title:"System Resumed from Sleep",short_desc:"The system woke from sleep (S3) and logged the sleep duration and wake source.",description:"Event ID 1 from Power-Troubleshooter is written every time the system resumes from sleep (S3 suspend-to-RAM). It records the time the system entered sleep, the time it woke, and the wake source (what triggered the wakeup — a keyboard press, mouse movement, network packet, scheduled task, or Wake-on-LAN). In a healthy system this is informational. It becomes diagnostic when investigating sleep-related crashes (system does not resume, resumes to BSOD, or resumes with corrupted state), unexpected wakeups keeping a machine awake all night, or correlating crash events against sleep/wake cycles.",why_it_happens:"Written by the Power Troubleshooter component on every S3 resume. The SleepTime and WakeTime fields give exact duration. The WakeSourceType and WakeSourceText fields identify what triggered the resume — this is the key data for diagnosing unwanted wakeups.",what_good_looks_like:"Present on any machine using sleep mode — normal. Investigate: Event 1 followed immediately by Event 41 or 1001 (crash on resume), Event 1 entries at unexpected hours (machine waking overnight), missing Event 1 when user says the machine would not wake (possibly hung in sleep state).",causes:["Normal user wakeup (keyboard, mouse, power button)","Network adapter Wake-on-LAN packet","Scheduled task configured to wake the system","Windows Update waking machine to install updates","USB device activity triggering resume","Automatic Maintenance task waking the machine"],steps:["Check WakeSourceText field — identifies exactly what woke the machine","For overnight wakeups: check scheduled tasks and Windows Update settings","To list all wake timers: powercfg /waketimers","To check last wake source: powercfg /lastwake","If crashes on resume: check Event 41 and 1001 immediately after Event 1 timestamps",'To disable Wake-on-LAN: Device Manager → Network Adapter → Power Management → uncheck "Allow this device to wake the computer"',"For a machine that will not resume: check Event 42 (entered sleep) then look for a missing Event 1"],symptoms:["computer wakes up by itself","pc turns on overnight","computer woke unexpectedly","crash after sleep","blue screen after waking","computer wont wake from sleep","machine on when i arrive","sleep not working"],tags:["sleep","power","resume","wake","wakeup","s3"],powershell:`# Sleep/Wake History and Wake Sources
# Eventful

# Recent wake events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Power-Troubleshooter'
    Id           = 1
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        WakeTime   = $_.TimeCreated
        SleepTime  = ($data | Where-Object Name -eq 'SleepTime').'#text'
        WakeSource = ($data | Where-Object Name -eq 'WakeSourceText').'#text'
    }
} | Sort-Object WakeTime -Descending | Format-Table -AutoSize

# Current wake timers
powercfg /waketimers

# Last wake source
powercfg /lastwake`,related_ids:[42,107,41,6008],ms_docs:null},{id:42,source:"Microsoft-Windows-Kernel-Power",channel:"System",severity:"Information",skill_level:"Beginner",title:"System Entering Sleep",short_desc:"The system is transitioning into a sleep state (S3 or S4 hibernate).",description:'Event ID 42 from Kernel-Power is logged when the system begins a sleep transition. The TargetSleepState field indicates the target state: 3 = sleep (S3, suspend-to-RAM), 4 = hibernate (S4, suspend-to-disk). This event pairs with Event 1 (resume from sleep) and Event 107 (resume from hibernate) to build a complete sleep/wake timeline. Its diagnostic value is in detecting unexpected sleep entries (machine going to sleep unexpectedly during use) and as the "last checkpoint" before a machine that failed to resume — if Event 42 exists but no Event 1 follows, the machine may have crashed during sleep or failed to wake.',why_it_happens:"Written by the Kernel-Power component when the OS commits to entering a sleep state, after all pre-sleep notifications have been sent to drivers and applications. The actual system state change happens immediately after this event is written.",what_good_looks_like:"Appears on every sleep entry — normal. Investigate: Event 42 (sleep) with no following Event 1 (wake) — machine may have hard-crashed during sleep. Event 42 occurring unexpectedly during active use — could be an aggressive power plan timeout or a driver triggering sleep.",causes:["User-initiated sleep (Start → Sleep, closing laptop lid)","Power plan idle timeout","Windows Automatic Maintenance triggering sleep after completion","Remote management or policy forcing sleep","Low battery threshold on laptop triggering hibernation"],steps:["Check TargetSleepState: 3 = sleep, 4 = hibernate","If Event 42 exists but no Event 1 follows: machine likely crashed in sleep — check Event 41","If machine sleeps unexpectedly: check power plan idle timeout settings (powercfg /query)","Check for wake after Event 42: look for Event 1 or 107 with matching timestamp","For laptops sleeping unexpectedly: check battery threshold settings in power plan"],symptoms:["computer goes to sleep by itself","pc keeps going to sleep","computer slept and wont wake","machine powered off during sleep","laptop sleeping unexpectedly","computer sleeps too quickly"],tags:["sleep","hibernate","power","s3","s4","kernel-power"],powershell:`# Sleep Transition History
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id           = @(42, 107)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml   = [xml]$_.ToXml()
    $data  = $xml.Event.EventData.Data
    $state = ($data | Where-Object Name -eq 'TargetSleepState').'#text'
    $desc  = switch ($_.Id) {
        42  { if ($state -eq '4') {'ENTERING HIBERNATE'} else {'ENTERING SLEEP'} }
        107 { 'RESUMED FROM HIBERNATE' }
    }
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        EventId   = $_.Id
        Transition = $desc
    }
} | Sort-Object Time -Descending | Format-Table -AutoSize`,related_ids:[1,107,41,6008],ms_docs:null},{id:107,source:"Microsoft-Windows-Kernel-Power",channel:"System",severity:"Information",skill_level:"Beginner",title:"System Resumed from Hibernation",short_desc:"The system woke from hibernation (S4) — the OS was restored from the hibernation file on disk.",description:"Event ID 107 from Kernel-Power is written when the system resumes from hibernation (S4 suspend-to-disk), where system state was saved to hiberfil.sys and full power was cut. Unlike sleep (S3) which only cuts power to non-essential components, hibernation cuts all power — so resume requires reading the entire system state back from disk. This makes hibernate resume slower than sleep resume and more dependent on disk health. If Event 107 is absent after an Event 42 with TargetSleepState=4, the machine failed to resume from hibernation — check for disk errors (Event 51, 129) and Event 41.",why_it_happens:'Hibernate is triggered by a power plan low-battery threshold, an explicit hibernate command, or "Fast Startup" on Windows 10/11 (which hibernates the kernel session on shutdown). Fast Startup means that on most Windows 10/11 machines, every normal shutdown is followed by a hibernate-style resume on next boot — Event 107 will appear on machines using Fast Startup even without user-initiated hibernation.',what_good_looks_like:"Present on machines with hibernate or Fast Startup enabled — normal. On Windows 10/11 with Fast Startup, expect Event 107 on most boots instead of Event 12 (clean OS start). Investigate: Event 107 absent when expected (failed hibernate resume), Event 107 followed by application instability (state corruption during restore), or Event 107 taking unusually long (slow disk causing slow resume).",causes:["Laptop reaching critical battery threshold","User explicitly choosing Hibernate from Start menu","Fast Startup on Windows 10/11 (normal shutdown uses hibernate)","Hybrid sleep resuming from disk after power loss"],steps:["If machine fails to resume from hibernate: check Event 41 (crash) and disk health events (51, 129)","If applications are unstable after resume: Fast Startup may be restoring a corrupt session — disable it and do a full shutdown",'To disable Fast Startup: Control Panel → Power Options → Choose what the power buttons do → uncheck "Turn on fast startup"',"If hibernate file corrupt: run powercfg /h off then powercfg /h on to rebuild it","Check disk read speed — slow hibernate resume is almost always a disk health or interface speed issue"],symptoms:["computer wont come back from hibernate","resume from hibernate failed","slow to wake from hibernate","fast startup issue","shutdown and restart slow","hibernate not working","applications broken after resume"],tags:["hibernate","power","resume","s4","fast-startup","kernel-power"],powershell:`# Hibernate Resume History
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Power'
    Id           = 107
    StartTime    = (Get-Date).AddDays(-14)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# Check if Fast Startup is enabled
$fss = (Get-ItemProperty 'HKLM:SYSTEMCurrentControlSetControlSession ManagerPower' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
"Fast Startup enabled: $($fss -eq 1)"

# Hibernate file status
powercfg /h`,related_ids:[42,1,41,51,129],ms_docs:null},{id:7,source:"disk",channel:"System",severity:"Warning",skill_level:"Intermediate",title:"Disk Bad Block Detected",short_desc:"The disk driver confirmed a bad block — a sector that cannot be reliably read. Immediate action required.",description:"Event ID 7 from the disk driver means the drive has a confirmed bad sector — a physical location on the disk that cannot be read even after exhausting all internal retries. This is more severe than Event 51 (paging I/O error, which may recover) and more definitive than Event 153 (retriable error). A bad block is unrecoverable at the current sector. The OS will attempt to remap the sector using the drive's spare sector pool, but the underlying cause — media degradation, mechanical damage, or NAND cell failure — is progressive. Any appearance of Event 7 means the disk is failing. Data backup should begin immediately and disk replacement should be planned.",why_it_happens:"Hard disks and SSDs maintain a pool of spare sectors to remap bad blocks. When a sector fails all read retries (in-drive and OS-level), the driver logs Event 7 and requests remapping. On an HDD this indicates physical media degradation — the magnetic coating has failed at that location. On an SSD it indicates NAND cell wear or a controller fault. The drive may continue to function for days or months after the first Event 7, but the failure is confirmed and progressive.",what_good_looks_like:"Absence is normal for a healthy drive — even one occurrence is significant. Any Event 7 means the disk has confirmed unrecoverable media damage.",common_mistakes:["Running chkdsk and thinking it fixed the problem — chkdsk marks bad sectors but the drive is still failing","Not starting a backup immediately upon seeing Event 7","Waiting for more symptoms before acting — bad blocks multiply, not stay singular","Assuming the data on the bad block was unimportant"],causes:["Physical media degradation (HDD platter surface damage)","NAND cell wear-out (SSD)","Mechanical shock or vibration damage","Overheating causing write errors that corrupt sectors permanently","Drive age — HDD sectors degrade over time under normal use"],steps:["Start a backup immediately — this drive is failing","Check SMART: reallocated sector count (attribute 5) should now be non-zero","Run chkdsk /r to mark bad sectors and attempt data recovery from affected areas: chkdsk C: /r /x","Check Event 51 and 129 nearby — if all three present, drive failure is active and accelerating","Order a replacement drive — do not wait","After data backup, consider running manufacturer diagnostic tool for a full surface scan"],symptoms:["bad sector","hard drive bad block","disk failing","chkdsk found errors","hard drive error","file system errors","disk read error","drive dying","data corruption","files corrupted"],tags:["disk","storage","bad-block","bad-sector","hardware","critical","failure","data-loss"],powershell:`# Bad Block and Disk Error Investigation
# Eventful

# Disk error events (last 30 days)
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'disk'
    Id           = @(7, 11, 51, 153)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# SMART — check reallocated sectors
Get-PhysicalDisk | ForEach-Object {
    $rel = $_ | Get-StorageReliabilityCounter
    [PSCustomObject]@{
        Disk         = $_.FriendlyName
        Health       = $_.HealthStatus
        ReadErrors   = $rel.ReadErrorsTotal
        WriteErrors  = $rel.WriteErrorsTotal
        Wear         = "$($rel.Wear)%"
    }
} | Format-Table -AutoSize`,related_ids:[11,51,129,153,55],ms_docs:null},{id:11,source:"disk",channel:"System",severity:"Error",skill_level:"Intermediate",title:"Disk Controller Error",short_desc:"The disk driver detected a controller-level error on a storage device — hardware fault in the drive, cable, or controller.",description:"Event ID 11 from the disk driver indicates a controller error — the disk or the controller responsible for communicating with it returned an error that the driver could not handle through normal I/O retry. The event identifies the affected device path (e.g., \\Device\\Harddisk0\\DR0). This is distinct from Event 51 (paging I/O error) and Event 7 (bad block) — Event 11 points more specifically to a hardware communication failure rather than a media read failure. Common sources: a failing disk, a bad SATA cable, a failing SATA port on the motherboard, or an overloaded/failing disk controller. On a machine reporting random crashes or freezes, Event 11 paired with Event 51 is a strong indicator of imminent drive failure.",why_it_happens:"The disk driver communicates with drives via AHCI/NVMe commands. When the drive reports an internal error condition (not just a read retry failure, but an actual hardware error status), the driver logs Event 11. Causes include: the drive reporting an unrecoverable command error, the SATA/NVMe interface experiencing signal integrity issues (bad cable, bent pin, marginal power), or the drive controller itself failing.",what_good_looks_like:"Absence is normal. Any occurrence warrants investigation. Event 11 on an HDD with multiple occurrences over days or weeks means replace the drive. Event 11 on an SSD may indicate a firmware or controller issue — check for firmware updates before replacing.",common_mistakes:["Assuming it is always the drive — a bad SATA cable is a very common cause and takes 30 seconds to replace","Not checking which disk the error is on (the device path in the event)","Replacing the drive without testing the cable first — replacing the drive then getting the same error from the cable is frustrating and expensive"],causes:["Failing hard disk or SSD (most common)","Loose or failing SATA data cable","Failing SATA port on motherboard","Insufficient or noisy power to the drive","Failing disk controller chip","Drive overheating"],steps:["Identify the affected disk from the device path in the event","Reseat SATA cable at both ends — replace if possible (cheapest fix first)","Check SMART data for the identified disk","Move the drive to a different SATA port on the motherboard to rule out a bad port","Check drive temperature — Get-PhysicalDisk | Get-StorageReliabilityCounter | Select Temperature","Check Event 7 and 51 nearby — triple combination means replace immediately","Back up data before doing further testing"],symptoms:["disk error","hard drive error","controller error","drive not responding","random crashes","computer freezing","disk read write error","storage device error","sata error"],tags:["disk","storage","controller","hardware","cable","error","failure"],powershell:`# Disk Controller Error Investigation
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'disk'
    Id           = @(11, 7, 51)
    StartTime    = (Get-Date).AddDays(-14)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Physical disk health
Get-PhysicalDisk | ForEach-Object {
    $rel = $_ | Get-StorageReliabilityCounter
    [PSCustomObject]@{
        Disk        = $_.FriendlyName
        Health      = $_.HealthStatus
        Temperature = "$($rel.Temperature) C"
        ReadErrors  = $rel.ReadErrorsTotal
        WriteErrors = $rel.WriteErrorsTotal
        Wear        = "$($rel.Wear)%"
    }
} | Format-Table -AutoSize`,related_ids:[7,51,129,153,55],ms_docs:null}],s=[{id:1e3,source:"Application Error",channel:"Application",severity:"Error",skill_level:"Fundamental",title:"Application Crash (Faulting Application)",short_desc:"An application crashed — records the faulting process, module, and exception code.",description:'Event ID 1000 from "Application Error" is the primary event for application crashes. It records the name and version of the crashing application, the specific DLL or module that faulted, the exception code (e.g., 0xc0000005 = access violation, 0xe0434352 = .NET exception), and the offset within the module where the fault occurred. This event is generated for any crash in user-mode that Windows Error Reporting (WER) captures — not kernel crashes (those are Event 41/1001 in System log). It is your starting point for any "application keeps crashing" investigation.',why_it_happens:"When an application throws an unhandled exception — typically an access violation (reading/writing invalid memory), a null pointer dereference, a stack overflow, or an uncaught software exception — Windows Error Reporting intercepts the crash, creates a minidump, and logs Event 1000. The faulting module identifies which specific library caused the crash, which is often more useful than the application name since third-party DLLs frequently cause crashes in the host process.",what_good_looks_like:"Occasional crashes during extreme edge cases are normal for complex applications. Investigate: repeated crashes at the same offset in the same module (reliable reproduction means there is a deterministic bug), crashes beginning after an update (regression), crashes of critical business applications affecting productivity, crashes caused by known-malicious modules.",common_mistakes:["Only looking at the application name and ignoring the faulting module — the faulting module is usually the actual culprit","Not correlating with 1001 (WER bucket) or 1002 (hang) for related events","Trying to fix the application without checking for updates first — many crashes are fixed by vendor patches","Not checking if antivirus is injecting into the process (shell extensions and AV DLLs frequently cause crashes in other apps)","Ignoring that 0xe0434352 means a .NET exception — look for Event 1026 for more detail"],causes:["Bug in application code causing access violation or unhandled exception","Incompatible third-party DLL injected into process (shell extensions, AV)","Corrupt application installation","Missing or incompatible dependency (DLL, .NET runtime version)","Hardware memory fault causing random corruption","Application updated and introduced a regression","Incompatible Windows update affecting application APIs"],steps:["Filter Application log for Event 1000",'Note the "Faulting Application Name" and "Faulting Module Name"','Note the "Exception Code": 0xc0000005 = access violation, 0xe0434352 = .NET unhandled',"If faulting module is the app itself: check vendor for updates or known issues","If faulting module is a third-party DLL: investigate if it is an AV, shell extension, or inject","Check for pending Windows Update that may include a fix","If .NET exception (0xe0434352): check Event 1026 for more detail","Reproduce the crash and capture a full dump with ProcDump: procdump -e 1 <pid> C:\\crashes\\"],symptoms:["application crashed","program keeps crashing","app crashes","application keeps closing","program stopped working","this application has stopped working","application error popup","program crashes randomly","app closes itself","software keeps crashing"],tags:["crash","application","exception","faulting-module","wer","reliability"],powershell:`# Application Crash Investigation
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
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[1001,1002,1026,7031],ms_docs:"https://learn.microsoft.com/en-us/windows/win32/wer/about-wer"},{id:1001,source:"Windows Error Reporting",channel:"Application",severity:"Info",skill_level:"Intermediate",title:"Windows Error Reporting: Fault Bucket",short_desc:"WER grouped a crash into a fault bucket for reporting — may include Watson report details.",description:"Event ID 1001 from Windows Error Reporting (note: this is Application log, different from the System log 1001 which is BugCheck) records a fault bucket assignment for a crash. WER groups similar crashes by fault signature (Bucket ID) so that crash patterns can be identified. The Bucket ID can be used to look up known issues in Microsoft's crash database. This event may appear alongside 1000 (crash) and provides additional context including whether a crash report was sent to Microsoft and whether a solution exists.",why_it_happens:"After WER captures a crash (triggering Event 1000), it analyses the crash data and assigns it to a fault bucket based on the crash signature. If crash reporting is enabled, WER may send the crash to Microsoft's crash analysis service. Event 1001 records this bucket assignment and any solutions found.",what_good_looks_like:"Look for the Bucket ID when searching Microsoft knowledge base or support forums — the ID can help find relevant patches or workarounds. If a solution is available, WER may display it in Action Center.",common_mistakes:["Ignoring this event because it looks informational — the Bucket ID is useful for research","Not checking Windows Action Center for WER-recommended solutions"],causes:["Generated automatically by WER alongside any crash event","Triggered for both application crashes and non-fatal faults"],steps:["Find Event 1001 that corresponds to a known crash (same time as 1000)","Note the Bucket ID","Search Microsoft support and knowledge base with the Bucket ID","Check Windows Action Center for any recommended solutions"],symptoms:["windows error reporting","fault bucket","crash report","wer report","watson report","error reporting crash"],tags:["wer","crash","fault-bucket","reporting","watson"],powershell:`# Windows Error Reporting Fault Bucket Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddDays(-7)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Windows Error Reporting'
    Id           = 1001
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[1e3,1002,1026],ms_docs:"https://learn.microsoft.com/en-us/windows/win32/wer/about-wer"},{id:1002,source:"Application Hang",channel:"Application",severity:"Error",skill_level:"Fundamental",title:"Application Hang",short_desc:"An application stopped responding and Windows terminated it or it was killed by the user.",description:'Event ID 1002 from "Application Hang" is generated when a GUI application stops processing messages on its main thread for more than 5 seconds, causing the "(Not Responding)" state. Unlike 1000 (crash), the application has not crashed — it is alive but stuck. Windows may generate this event when the user clicks "Close" on a hung window and confirms termination, or after an extended period of unresponsiveness. The event records the application name, version, and the time it stopped responding.',why_it_happens:"Windows applications use a message loop on the main thread to handle user input and window updates. If the main thread is blocked — waiting on a slow file I/O, a network call, a database query, a mutex, or an infinite loop — it cannot process messages, and the window goes (Not Responding). Windows detects this by sending a WM_NULL message and waiting for a response. If no response comes within 5 seconds, the application is considered hung.",what_good_looks_like:"Occasional hangs during heavy operations are tolerable. Investigate: repeated hangs of the same application at the same operation, hangs affecting many users simultaneously, hangs that began after an update or configuration change, hangs during operations that involve file servers or databases (may indicate network/storage latency).",common_mistakes:["Treating hangs and crashes identically — hung processes often have different root causes (I/O blocking, deadlock) vs crashes (memory corruption)","Not checking if the hang correlates with disk or network latency events","Not capturing a dump of the hung process to see which thread is blocked and what it's waiting for","Ignoring that Outlook hangs often correlate with Exchange or network issues, not Outlook bugs"],causes:["Main thread blocked on slow I/O (disk, network, database)","Deadlock between two threads","Infinite loop in application code","Waiting on a COM object or shell extension that is hung","Slow antivirus scanning during file access","Memory pressure causing heavy paging","Remote file share latency causing synchronous operations to block"],steps:["Filter Application log for Event 1002","Note application name and time of hang","Check if hangs correlate with disk, network, or database events in System log","Check resource usage at time of hang: CPU, RAM, disk queue length","If recurring: capture hung process dump with Task Manager (Create dump file)","Analyse dump with WinDbg: !analyze -v, ~* k (all thread stacks)","Check if antivirus is scanning the directories the app accesses","Test network path latency if the app accesses file shares"],symptoms:["application not responding","app hangs","program freezes","not responding","application froze","outlook hangs","program stuck","app freezes","application becomes unresponsive","software stops responding"],tags:["hang","application","frozen","not-responding","reliability","performance"],powershell:`# Application Hang Investigation
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
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[1e3,1001,1026],ms_docs:"https://learn.microsoft.com/en-us/windows/win32/wer/about-wer"},{id:1026,source:".NET Runtime",channel:"Application",severity:"Error",skill_level:"Intermediate",title:".NET Runtime Error",short_desc:"A .NET application threw an unhandled exception — includes full exception type and stack trace.",description:'Event ID 1026 from the ".NET Runtime" source is logged when a .NET application encounters an unhandled exception and crashes. Unlike Event 1000 (which gives low-level Windows crash data), Event 1026 provides the full .NET exception type (e.g., System.NullReferenceException, System.OutOfMemoryException), the full stack trace in managed code, and the thread that threw the exception. This is extremely valuable for .NET developers and MSPs dealing with business application crashes.',why_it_happens:"When a .NET application throws an exception that is not caught anywhere in the call stack, the CLR (Common Language Runtime) invokes the unhandled exception handler. If no application-level handler is registered, the CLR logs Event 1026 with the full exception information and then terminates the process. This also generates a companion Event 1000 (Application Error) with exception code 0xe0434352.",what_good_looks_like:"No Event 1026 events for production applications. In development or test environments, they are acceptable during debugging. For MSP-managed clients: 1026 for a business application (ERP, accounting, line-of-business) is a vendor support escalation item.",common_mistakes:["Looking only at Event 1000 for .NET crashes — 1000 gives exception code 0xe0434352 (useless) but 1026 gives the real exception type and stack","Not providing the stack trace to the software vendor — they need 1026 detail to diagnose the issue",'Missing that "System.OutOfMemoryException" needs memory investigation, not application reinstall'],causes:[".NET application bug — null reference, argument out of range, etc.","Out of memory (System.OutOfMemoryException)","Corrupt application installation or missing assembly","Incompatible .NET runtime version","Database connection failure causing exception in data access layer","File system permission error throwing UnauthorizedAccessException"],steps:["Filter Application log for Event 1026","Read the full event message — it contains the exception type and stack trace","Note the exception type: NullReferenceException, OutOfMemoryException, etc.","Note the innermost exception and the stack frame it occurred in","If OutOfMemoryException: investigate available memory and application memory usage","Provide the full exception and stack trace to the software vendor","Check for application updates that may have fixed the bug","Correlate with .NET version: [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription"],symptoms:[".net error","dotnet crash",".net application crashed",".net runtime error","net framework error","application error 1026","managed code crash","c# application crash","asp.net error",".net exception"],tags:["dotnet","runtime","exception","application-crash","managed-code"],powershell:`# .NET Runtime Error Investigation
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
    Format-List`,related_ids:[1e3,1001,1002],ms_docs:"https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run"},{id:1530,source:"Microsoft-Windows-User Profiles Service",channel:"Application",severity:"Warning",skill_level:"Beginner",title:"User Profile Registry Still In Use at Logoff",short_desc:"Windows could not cleanly unload a user's registry hive at logoff — can cause slow logins, profile corruption, and temporary profiles.",description:`Event ID 1530 from the User Profiles Service is generated when a user logs off but Windows cannot fully unload their registry hive (NTUSER.DAT) because one or more processes still have it open. Windows logs the offending processes in the event details. The immediate consequence is that the profile is not cleanly saved — on the next login, Windows may load a temporary profile instead of the user's real profile, causing the user to lose desktop settings, saved passwords, and application preferences. This event is responsible for the common support complaint: "all my settings are gone and my desktop is blank." Recurring Event 1530 means the offending process should be identified and addressed.`,why_it_happens:"When a user logs off, Windows attempts to unload the user registry hive. If any process (antivirus, backup agent, indexing service, or a misbehaving application) still has a handle to any key in HKEY_CURRENT_USER, the unload fails. Windows proceeds with logoff but cannot flush the hive cleanly. Subsequent logins may find the hive locked and load a fresh temporary profile instead. Common offenders: antivirus real-time scanning, Outlook holding its profile key, Windows Search indexing, and background sync agents.",what_good_looks_like:'Occasional single occurrences (e.g., during a forced logoff) are low priority. Investigate: recurring Event 1530 for the same user, users reporting blank desktops or missing settings after login, or Event 1530 immediately before a user reports a "temporary profile" login.',common_mistakes:["Rebuilding the user profile without first finding and fixing the root cause — Event 1530 will keep occurring","Not reading the event details — the offending process is listed in the event, which tells you exactly what to fix","Not restarting the offending service before attempting profile repair"],causes:["Antivirus scanning NTUSER.DAT at logoff","Outlook or Office holding profile registry keys open","Windows Search (SearchIndexer) indexing the profile","Backup agent with handles to user registry","Application crashed and left handles open","Remote desktop session not cleanly terminated"],steps:["Read the event details — it lists the process(es) holding the registry hive open","If it is antivirus: add NTUSER.DAT to the AV exclusion list, or configure the AV to release handles at logoff","If it is SearchIndexer: restart the Windows Search service or rebuild the index","If the user is already getting temporary profiles: copy their real profile data from C:\\Users\\<username>.bak","To force a clean profile copy: log in as admin, copy settings from the old profile to the new one","For recurring issue: use Process Monitor (Sysinternals) filtered to NTUSER.DAT to catch the offending process in real time"],symptoms:["blank desktop after login","all settings gone","temporary profile","desktop is empty","profile not loading","settings reset after reboot","user profile error","slow login","my documents missing","preferences lost"],tags:["profile","registry","logoff","login","settings","temporary-profile","corruption"],powershell:`# User Profile Registry Issue Investigation
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
    Format-Table -AutoSize`,related_ids:[1e3],ms_docs:"https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/fix-user-profile-corrupted"},{id:1008,source:"Microsoft-Windows-Perflib",channel:"Application",severity:"Warning",skill_level:"Beginner",title:"Performance Counter Provider Error (Usually Harmless)",short_desc:"A performance counter provider returned an error. Appears constantly in most Application logs — almost always harmless noise.",description:"Event ID 1008 from Perflib (Performance Library) is generated when a performance counter provider — a component that feeds data to Performance Monitor, Task Manager, or third-party monitoring tools — returns an error or fails to respond. Like Event 10016 (DCOM), this event appears in nearly every Windows Application log and is almost never the cause of user-reported problems. Windows has many built-in performance counter providers; some are buggy or register but provide no data, generating 1008 continuously. The event names the provider that failed. In the vast majority of IT support cases, 1008 is background noise. It only warrants investigation if a monitoring tool or application that specifically uses performance counters is broken.",why_it_happens:"Third-party software installs performance counter providers during installation and sometimes fails to cleanly remove them on uninstall, leaving broken registrations. Windows built-in providers can also fail if the underlying service they monitor is not running. The Perflib subsystem logs 1008 whenever it calls a provider and gets back an unexpected error or timeout.",what_good_looks_like:"Present in virtually every Windows Application log — this is normal. Only investigate 1008 if: Performance Monitor or a monitoring application that uses perf counters is broken, or the named provider matches a recently uninstalled application.",common_mistakes:["Assuming Event 1008 is causing the reported problem — it almost never is","Spending time rebuilding performance counters when the user's complaint is unrelated"],causes:["Broken performance counter registration left by uninstalled software (expected after uninstalls)","Built-in provider for a service that is stopped or disabled","Corrupted performance counter database"],steps:["Check if Event 1008 matches a recently uninstalled application — if so, ignore it","If Performance Monitor or monitoring tools are actually broken: rebuild perf counters","Rebuild performance counters: lodctr /r (run as admin from elevated command prompt)","If specific provider named: check if the associated service/application is installed and running","Otherwise: look elsewhere for the actual cause of the user's complaint"],symptoms:["performance counter error","perflib error","lots of warnings in application log","event log warnings","performance monitor not working","task manager shows 0"],tags:["performance","perflib","noise","harmless","counter","warning","common"],powershell:`# Performance Counter Error Summary
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
# Run as admin: lodctr /r`,related_ids:[1e3],ms_docs:null}],o=[{id:21,source:"Microsoft-Windows-TerminalServices-LocalSessionManager",channel:"RDS",severity:"Info",skill_level:"Fundamental",title:"RDS: Session Logon Successful",short_desc:"A user successfully logged on to a Remote Desktop Services session.",description:"Event ID 21 from the TerminalServices-LocalSessionManager is generated on the RDS host when a user successfully establishes and logs on to a Remote Desktop session. It records the username, domain, session ID, and the source network address of the connecting client. This is the RDS-specific equivalent of Security Event 4624 Type 10, and provides more RDS-specific context. It is the primary event to check when verifying who has connected to an RDS server.",why_it_happens:"The Local Session Manager (LSM) on the RDS host manages all session lifecycle events. When a user completes authentication (handled by 1149 and Security events) and their session is created and initialized, the LSM logs Event 21 to record the successful logon. The session ID in this event can be used to correlate with other RDS events (22, 23, 24, 25, 40) for the full session lifecycle.",what_good_looks_like:"Expected: known users connecting during business hours from known IP ranges. Investigate: logons outside business hours for non-on-call staff, logons from unexpected IP addresses (not corporate VPN or known client locations), a user logging on to many sessions simultaneously, admin accounts logging on via RDS to servers they don't normally manage.",common_mistakes:["Only checking Security Event 4624 and missing the RDS-specific session detail in Event 21","Not using the Session ID to correlate the full session timeline (21 → 22 → 24/25/40 → 23)","Ignoring the Source Network Address field which tells you where the connection came from"],causes:["Authorised user connecting for work","Admin connecting for management","Automated process using RDP","Attacker using compromised credentials to connect","Session reconnection (look for Event 25 instead)"],steps:["Filter Microsoft-Windows-TerminalServices-LocalSessionManager log for Event 21",'Note "User", "Session ID", and "Source Network Address"',"Verify user is authorised and the source IP is expected","Track the session lifecycle using Session ID with Events 22, 24, 25, 40, 23","Correlate Source Network Address with your asset/user inventory","If suspicious: check concurrent sessions from same account or IP"],symptoms:["rdp login","remote desktop logon","rds session started","who connected via rdp","terminal services logon","remote desktop session started","rds user connected"],tags:["rdp","rds","remote-desktop","logon","terminal-services","session"],powershell:`# RDS Session Logon Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[22,23,24,25,40,1149,4624],ms_docs:"https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-outside-access"},{id:22,source:"Microsoft-Windows-TerminalServices-LocalSessionManager",channel:"RDS",severity:"Info",skill_level:"Fundamental",title:"RDS: Shell Start Notification",short_desc:"The user's shell (Explorer or application) started in their RDS session.",description:"Event ID 22 is generated when the user's shell or initial application starts within their Remote Desktop session. It typically follows Event 21 (logon) immediately and indicates the session is fully established and the user has access to their desktop environment. This event is useful for measuring session start time (time between Event 21 and 22 indicates logon processing duration) and for confirming the session progressed past simple authentication to full desktop access.",why_it_happens:"After the session is created and logon succeeds (Event 21), the Session Manager starts the user's shell process — typically explorer.exe or, in RemoteApp mode, the published application. Event 22 is logged when this process successfully initialises. A significant gap between 21 and 22 indicates slow logon processing (profile loading, Group Policy, logon scripts).",what_good_looks_like:"Normal: Event 22 appears within a few seconds of Event 21. Investigate: sessions where 22 never appears after 21 (session may be stuck in logon), large time gaps between 21 and 22 (slow logon — investigate GPO, profile, or slow profile path).",common_mistakes:["Not measuring the gap between Events 21 and 22 to diagnose slow logon times","Confusing slow shell start with slow authentication — if 21 is quick but 22 is delayed, the authentication is fine but logon is slow"],causes:["Normal session establishment following successful authentication","Slow logon scripts or Group Policy (causes delay between 21 and 22)","Large roaming profile loading slowly","Antivirus scanning profile on first load"],steps:["Filter TerminalServices-LocalSessionManager log for Event 22","Correlate with Event 21 using Session ID","Calculate time delta between 21 and 22 — more than 30 seconds warrants investigation","If slow: check GPO processing (Event 4001 in System log), profile size, and logon scripts","Use UE-V or FSLogix profiling if large profiles are causing delays"],symptoms:["rdp logon slow","remote desktop slow to load","rds desktop slow to appear","remote desktop login takes forever","terminal services slow logon","rdp session slow to start"],tags:["rdp","rds","shell","logon","performance","session"],powershell:`# RDS Shell Start Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[21,23,24,25,40],ms_docs:null},{id:23,source:"Microsoft-Windows-TerminalServices-LocalSessionManager",channel:"RDS",severity:"Info",skill_level:"Fundamental",title:"RDS: Session Logoff",short_desc:"A user fully logged off from an RDS session — session resources released.",description:'Event ID 23 records a complete logoff from an RDS session — the user has signed out, all their session processes have terminated, and the session has been destroyed. This is distinct from a disconnect (Event 24) — a disconnect leaves the session alive. Event 23 is the definitive "session ended" event. Use it to calculate session duration (time between Event 21 and Event 23) and to confirm users are logging off rather than disconnecting (disconnected sessions consume memory on the RDS host).',why_it_happens:"When a user logs off via Start → Sign Out, closes all RemoteApp windows, or is logged off by a session policy, the LSM terminates all session processes, cleans up the session, and logs Event 23. Sessions can also be forcibly logged off by an administrator.",what_good_looks_like:"Expected: Event 23 should follow every Event 21 eventually. Users should log off, not just disconnect. Investigate: sessions with no Event 23 after disconnect (accumulating disconnected sessions), very short sessions (may indicate authentication or configuration problems), admin logging off other users' sessions.",common_mistakes:["Not distinguishing between logoff (23) and disconnect (24) — disconnected sessions linger and consume RAM","Not having session timeout policies to force logoff of long-disconnected sessions"],causes:["User manually logging off","Admin forcibly logging off a session","Session idle timeout policy logging off disconnected session","RemoteApp session closed when last published app closed"],steps:["Filter TerminalServices-LocalSessionManager log for Event 23","Correlate with Event 21 using Session ID to calculate session duration","Count Event 24 (disconnects) vs Event 23 (logoffs) — high disconnect ratio means users aren't logging off","Check session timeout policy: Get-RDSessionCollectionConfiguration -CollectionName <name>","Query active/disconnected sessions: qwinsta /server:<server>"],symptoms:["user logged off rdp","rdp session ended","remote desktop session closed","rds logoff","terminal session ended","rdp disconnected and logged off"],tags:["rdp","rds","logoff","session","lifecycle"],powershell:`# RDS Session Logoff Investigation
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
} | Sort-Object SessionID, TimeCreated | Format-Table -AutoSize`,related_ids:[21,22,24,25,40],ms_docs:null},{id:24,source:"Microsoft-Windows-TerminalServices-LocalSessionManager",channel:"RDS",severity:"Info",skill_level:"Fundamental",title:"RDS: Session Disconnected",short_desc:"A user disconnected from their RDS session without logging off — session remains in memory.",description:"Event ID 24 records when a user disconnects from an RDS session without logging off. The session remains alive on the server — all their applications continue running, all their documents remain open. The user can reconnect later and pick up where they left off (Event 25). While convenient for users, accumulated disconnected sessions consume significant RAM on RDS servers. Event 24 should be monitored to detect users who are not logging off as required by policy.",why_it_happens:'A disconnect occurs when the RDP client closes without sending a logoff (closing the RDP window with the X button, network interruption, or locking the client machine). The RDS host detects the loss of the RDP channel and transitions the session to "Disconnected" state while keeping all session processes running. The Session ID is preserved for potential reconnection.',what_good_looks_like:"Some disconnects are normal (network blips, laptop lid close). Investigate: sessions that have been disconnected for days without reconnecting (likely abandoned), a pattern of users disconnecting but never logging off (consuming unnecessary resources), disconnects at unusual times that may indicate network issues.",common_mistakes:["Treating disconnect (24) as the same as logoff (23) — disconnected sessions keep running and consuming memory","Not having session timeout policies that log off long-disconnected sessions","Not querying qwinsta to find the current state of sessions on the RDS server"],causes:["User closed RDP window without logging off","Network interruption breaking the RDP connection","Client machine locked or suspended","RDP client crashed","Admin-initiated disconnect"],steps:["Filter TerminalServices-LocalSessionManager log for Event 24","Check if Event 25 (reconnect) follows — if not, the session is still disconnected","Query current session state: qwinsta /server:<server>","If sessions are accumulating as Disconnected: enforce logoff policy via GPO","Forcibly log off stale sessions: logoff <sessionid> /server:<server>","Set session policies: Computer Configuration → Policies → Admin Templates → Windows Components → Remote Desktop Services"],symptoms:["rdp disconnected","remote desktop session disconnected","rds session dropped","rdp keeps disconnecting","remote desktop connection dropped","rdp session disconnected unexpectedly","rds session drops randomly"],tags:["rdp","rds","disconnect","session","memory","lifecycle"],powershell:`# RDS Session Disconnect Investigation
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
qwinsta /server:$computer 2>$null | Where-Object { $_ -match 'Disc' }`,related_ids:[21,23,25,40,4779],ms_docs:null},{id:25,source:"Microsoft-Windows-TerminalServices-LocalSessionManager",channel:"RDS",severity:"Info",skill_level:"Fundamental",title:"RDS: Session Reconnected",short_desc:"A user reconnected to a previously disconnected RDS session.",description:"Event ID 25 records when a user successfully reconnects to a previously disconnected RDS session. The existing session (with all its running applications) is resumed from the disconnected state. This is the expected follow-up to Event 24 (disconnect). The session ID remains the same as the original session. Event 25 is important for security because it can reveal when an attacker or other user reconnects to an existing session — especially if the connecting IP differs from the original session.",why_it_happens:"When an RDP client connects to an RDS server and the server finds an existing disconnected session for that user, it reconnects the client to the existing session rather than creating a new one. The LSM logs Event 25 and the session state changes from Disconnected back to Active.",what_good_looks_like:"Normal: Event 25 from the same IP as the original Event 21/24 logon. Investigate: Event 25 where the reconnecting IP differs from the original connection IP (possible session takeover), reconnections to sessions that were disconnected for an extended period, reconnections at unusual hours.",common_mistakes:["Not comparing the source IP in Event 25 with the source IP in the original Event 21 — a change may indicate session hijacking","Not correlating Event 25 with Security Event 4778 (both record RDP session reconnection)"],causes:["User reconnecting after network interruption","User reconnecting after laptop lid open","Admin reconnecting to their own disconnected session","Another user reconnecting to an abandoned session (if policies allow)"],steps:["Filter TerminalServices-LocalSessionManager log for Event 25","Match with preceding Event 24 using Session ID","Compare Source Network Address in Event 25 vs original Event 21","If IPs differ: investigate potential session hijacking","Calculate how long the session was disconnected before reconnection"],symptoms:["rdp reconnected","remote desktop reconnected","rds session resumed","reconnected to rdp","remote session came back","rdp reconnection"],tags:["rdp","rds","reconnect","session","lifecycle"],powershell:`# RDS Session Reconnect Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[21,23,24,40,4778],ms_docs:null},{id:40,source:"Microsoft-Windows-TerminalServices-LocalSessionManager",channel:"RDS",severity:"Warning",skill_level:"Intermediate",title:"RDS: Session Disconnected with Reason Code",short_desc:"An RDS session was disconnected — includes a reason code explaining why.",description:"Event ID 40 records an RDS session disconnection with a specific reason code that explains the cause. The reason code is the most valuable part — it distinguishes between user-initiated disconnects, network failures, timeout-based disconnects, and protocol errors. This event appears in the TerminalServices-LocalSessionManager log and the RemoteConnectionManager log. Key reason codes: 0 = no information, 5 = client disconnect (user closed window), 11 = client disconnected with admin disconnected, 12 = session timeout, 5 = RPC error, 9 = RDP protocol error.",why_it_happens:"When an RDS session disconnects, the terminal services stack determines why and records a reason code. This mechanism exists specifically to help administrators distinguish between expected disconnects (user closed window, timeout) and unexpected ones (network failure, protocol error, server resource issue).",what_good_looks_like:"Reason code 5 (client disconnect) is entirely normal — user closed window. Investigate: reason code 9 (RDP protocol error — possible network issue), reason code 2 (server out of resources — RAM or session limit), reason codes in the 256+ range (application-specific or custom RDP infrastructure codes), any reason code that repeats for many users simultaneously.",common_mistakes:["Treating all Event 40s as problems — reason code 5 (normal user disconnect) is not a problem","Not looking up the reason code — each code has a specific meaning that guides the investigation","Ignoring the user and session fields that identify which session disconnected"],causes:["User closed RDP window (reason 5)","Session idle timeout reached (reason 12)","Network interruption (reason 9 or protocol errors)","Server out of resources (reason 2)","Admin disconnected the session","RDP protocol negotiation failure"],steps:["Filter TerminalServices-LocalSessionManager log for Event 40","Note the Reason Code and look it up (common: 5=normal, 9=protocol error, 12=timeout)","If reason 9 or other error codes: check network connectivity and RDP port availability","If reason 2: check server RAM and session license count","Correlate with Event 24 for the same session to see the full disconnect record"],symptoms:["rdp disconnecting with reason","remote desktop dropped with error","rdp session ended reason code","why did rdp disconnect","rdp connection dropped reason","rds session disconnected with code"],tags:["rdp","rds","disconnect","reason-code","troubleshooting","session"],powershell:`# RDS Session Disconnect with Reason Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[21,23,24,25,41],ms_docs:null},{id:41,source:"Microsoft-Windows-TerminalServices-LocalSessionManager",channel:"RDS",severity:"Warning",skill_level:"Intermediate",title:"RDS: Session Connection Failed",short_desc:"A Remote Desktop session connection attempt failed before a session was created.",description:"Event ID 41 from TerminalServices-LocalSessionManager records a connection failure before a session was established. Note this is distinct from Event 41 in the System log (Kernel Power) — same ID, different source. In the RDS context, this event indicates a pre-session failure: the connection was refused or failed before the user was authenticated or a session was created. This can indicate authentication failures, licensing issues, or server resource problems.",why_it_happens:"The RDS connection broker or local session manager refuses or fails the connection attempt before creating a session. Common causes include NLA (Network Level Authentication) pre-authentication failures, the RDS server being at its session limit, the user not having Remote Desktop access rights, or a server-side issue.",what_good_looks_like:"Occasional failures are expected (wrong password, user not in RD Users group). Investigate: many failures from one IP (brute-force scan), failures for accounts that should have access (misconfiguration), failures after a change to RDS configuration.",common_mistakes:["Confusing this Event 41 (RDS connection failed) with System Event 41 (Kernel Power unexpected reboot)","Not checking if the user is a member of Remote Desktop Users group","Missing that NLA pre-auth failures here won't have a corresponding 4625 in Security log if NLA was fully rejected"],causes:["Authentication failure (NLA pre-auth)","User not in Remote Desktop Users group","RDS server at session or license limit","Firewall blocking RDP port 3389","Server resource exhaustion","RDP Restricted Admin mode misconfiguration"],steps:["Filter TerminalServices-LocalSessionManager log for Event 41","Note the error code and username (if available)","Check if user is in Remote Desktop Users or Administrators group","Check session limit: qwinsta /server:<server> (count sessions)",'Check RDP firewall rules: Get-NetFirewallRule -Name "RemoteDesktop*"',"Check RDS Licensing if in an RDS farm environment"],symptoms:["rdp connection refused","cannot connect rdp","remote desktop connection failed","rdp not accepting connections","remote desktop access denied","rds connection error","cant connect via remote desktop"],tags:["rdp","rds","connection-failed","authentication","access-denied","troubleshooting"],powershell:`# RDS Connection Failure Investigation
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
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Select-Object -First 10 | Format-List`,related_ids:[21,1149,4625,4771],ms_docs:null},{id:1149,source:"Microsoft-Windows-TerminalServices-RemoteConnectionManager",channel:"RDS",severity:"Info",skill_level:"Intermediate",title:"RDS: User Authentication Succeeded",short_desc:"Network Level Authentication (NLA) pre-authentication succeeded for an RDP connection.",description:"Event ID 1149 from the TerminalServices-RemoteConnectionManager records that a user successfully passed Network Level Authentication (NLA) before their RDS session was created. NLA is the pre-authentication step that occurs before the full RDS session is established — it validates credentials at the network level to prevent unauthenticated users from reaching the login screen. Event 1149 means NLA passed; it does not guarantee a session was created (Event 21 confirms the session).",why_it_happens:"When an RDP client connects with NLA enabled (the default for modern Windows), it authenticates at the protocol level using CredSSP before the RDS session stack is initialized. The RemoteConnectionManager logs 1149 when NLA validation succeeds. This event appears even if the subsequent session creation fails for other reasons (license limit, session policy).",what_good_looks_like:"Expected: 1149 events from known users and IPs during business hours. Event 1149 without a corresponding Event 21 may indicate a session creation failure after successful NLA. Investigate: 1149 events from unexpected IP ranges, 1149 for accounts that should not have RDP access, 1149 at unusual hours for non-on-call accounts.",common_mistakes:["Confusing 1149 (NLA passed) with Event 21 (session created) — both should appear for a successful connection","Not checking the client IP in 1149 — this is where the connection physically came from before any load balancer or broker","Not having NLA enabled on RDS servers — without NLA, unauthenticated users reach the login screen and can exploit pre-auth vulnerabilities"],causes:["Legitimate user successfully pre-authenticated via NLA","Admin connecting to manage the server","Automated process with valid credentials connecting via RDP"],steps:["Filter Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational for Event 1149","Note the username and source IP","Correlate with Event 21 to confirm a session was created","If 1149 exists but no Event 21: session creation failed — investigate license or policy","If the source IP is unexpected: investigate who has those credentials"],symptoms:["rdp authentication succeeded","nla authentication","network level authentication passed","rdp pre auth succeeded","rds nla success"],tags:["rdp","rds","nla","authentication","network-level-authentication","security"],powershell:`# RDS NLA Authentication Investigation
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
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,related_ids:[21,41,4624,4625],ms_docs:null}],i=[{id:1014,source:"Microsoft-Windows-DNS-Client",channel:"Network",severity:"Warning",skill_level:"Fundamental",title:"DNS Name Resolution Timeout",short_desc:"A DNS query timed out — the DNS server did not respond within the timeout period.",description:`Event ID 1014 from the DNS-Client source is generated when a DNS name resolution attempt times out — the query was sent to a DNS server but no response was received within the configured timeout. This is distinct from a DNS NXDOMAIN response (the name exists but the record doesn't) — a timeout means the DNS infrastructure itself is unreachable or overloaded. Repeated 1014 events cause slow application startups, web browsing delays, and network connectivity issues that users describe as "the internet is slow" or "file shares are slow to open".`,why_it_happens:"The Windows DNS Client Resolver sends queries to the configured DNS server(s) and waits for a response. If the primary DNS server doesn't respond within the timeout period, it retries, then falls back to secondary DNS server(s). If all configured servers time out, Event 1014 is logged. Common causes include the DNS server being unreachable (network issue), the DNS server being overloaded, a firewall blocking UDP/TCP port 53, or the DNS server service itself having problems.",what_good_looks_like:"No Event 1014 events on a healthy machine. Occasional 1014 events during network changes are acceptable. Investigate: repeated 1014 events (the DNS server is consistently unreachable), 1014 events that correlate with user complaints about slow network, 1014 for internal names only (internal DNS server issue), 1014 for external names only (external DNS unreachable, possibly after DHCP change).",common_mistakes:["Concluding the DNS server is down without checking if the DNS server is reachable (ping, Test-NetConnection)","Fixing only the DNS setting and not finding why the DNS server became unreachable","Not checking whether internal vs external names are timing out — this isolates whether the internal DNS server or upstream forwarder is the issue","Ignoring 1014 during network speed investigations — DNS timeout adds latency to every hostname resolution"],causes:["DNS server IP is wrong (changed DHCP scope, manual misconfiguration)","DNS server service stopped or crashed","Network path to DNS server blocked by firewall or routing issue","DNS server overloaded or unresponsive","VPN connected and split tunneling routing DNS incorrectly","DHCP lease renewed with different DNS server IPs"],steps:["Find Event 1014 and note which hostname was failing and which DNS server was queried","Test DNS server reachability: Test-NetConnection -ComputerName <dns-ip> -Port 53","Test DNS resolution manually: Resolve-DnsName <hostname> -Server <dns-ip>","Check configured DNS servers: Get-DnsClientServerAddress","Check if the DNS server service is running on the DNS server itself","If VPN: check if DNS is being routed through VPN tunnel correctly","If DHCP: check if DNS server IPs in DHCP scope are correct"],symptoms:["internet is slow","websites slow to load","dns not working","cant resolve dns","dns lookup failing","name resolution failing","dns timeout","slow network","network drives slow to open","websites timing out"],tags:["dns","network","resolution","timeout","connectivity","fundamental"],powershell:`# DNS Resolution Timeout Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Find DNS timeout events
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DNS-Client'
    Id           = 1014
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Check current DNS configuration
Write-Host "
--- Current DNS Configuration ---" -ForegroundColor Cyan
Get-DnsClientServerAddress -ComputerName $computer -AddressFamily IPv4 |
    Where-Object { $_.ServerAddresses.Count -gt 0 } | Format-Table -AutoSize

# Test DNS resolution
Write-Host "
--- DNS Resolution Test ---" -ForegroundColor Cyan
Resolve-DnsName google.com -ErrorAction SilentlyContinue | Select-Object Name, Type, IPAddress | Format-Table -AutoSize`,related_ids:[1032,1030],ms_docs:"https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-overview"},{id:1032,source:"Microsoft-Windows-DNS-Client",channel:"Network",severity:"Warning",skill_level:"Intermediate",title:"DNS Query Failed",short_desc:"A DNS query returned an error — the record does not exist or the server returned a failure.",description:"Event ID 1032 records a DNS query that failed with an error response from the DNS server — as opposed to a timeout (1014). A failure response means the DNS server responded, but the response indicated an error: NXDOMAIN (the name does not exist), SERVFAIL (the server had an internal error), REFUSED (the server declined to answer), or NOTIMP (not implemented). Understanding the specific error code helps diagnose whether the problem is a missing DNS record, a configuration issue, or a server-side problem.",why_it_happens:"The DNS server processes the query and returns a negative response code. NXDOMAIN means the queried name has no records anywhere in the DNS hierarchy. SERVFAIL typically means the DNS server couldn't complete recursive resolution (often a problem with its forwarders or internet connectivity). REFUSED means the server is not configured to answer queries from this client.",what_good_looks_like:"NXDOMAIN for external internet names is entirely normal — users and applications query names that simply don't exist. Investigate: NXDOMAIN for internal names that should exist (misconfigured internal DNS zone, missing record), SERVFAIL responses (the DNS server itself has a problem), repeated failures for names that should resolve (broken delegation or zone configuration).",common_mistakes:["Assuming every DNS failure is a network problem — NXDOMAIN just means the name doesn't exist and is normal for typos","Not distinguishing NXDOMAIN from SERVFAIL — they have completely different causes","Not checking the internal DNS zone for missing records when internal names fail to resolve"],causes:["NXDOMAIN: the queried DNS name does not exist","SERVFAIL: DNS server internal error, often forwarder unreachable","REFUSED: client not authorised to query this DNS server","Missing internal DNS record after a server rename or IP change","Split-brain DNS misconfiguration"],steps:["Find Event 1032 and note the queried hostname and error code","Test manually: Resolve-DnsName <hostname> -Type A","If internal name: check the DNS zone for the missing record","If SERVFAIL: check the DNS server's forwarder configuration","Add missing DNS records if appropriate: Add-DnsServerResourceRecordA","Flush DNS cache after fixing: Clear-DnsClientCache"],symptoms:["dns lookup failed","dns error","name not found dns","internal dns not resolving","server not found dns","nxdomain error","dns resolution error","cannot find server dns"],tags:["dns","network","resolution","nxdomain","servfail","connectivity"],powershell:`# DNS Query Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DNS-Client'
    Id           = 1032
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[1014,1030],ms_docs:null},{id:1020,source:"Microsoft-Windows-Dhcp-Client",channel:"Network",severity:"Warning",skill_level:"Intermediate",title:"DHCP: IP Address Conflict Detected",short_desc:"The DHCP client detected that another device is already using the assigned IP address.",description:"Event ID 1020 from the DHCP Client is generated when ARP (Address Resolution Protocol) probing detects that the IP address assigned by DHCP is already in use by another device. Windows declines the offered IP address and requests a new one. If all available IPs are in conflict or the DHCP server exhauster its pool, the machine will fall back to APIPA (169.254.x.x). This event indicates an IP conflict — two devices trying to use the same IP — which causes intermittent connectivity for both devices.",why_it_happens:"When a DHCP client receives an IP address offer, it sends ARP probes to verify the address is not in use. If another device responds to the ARP, the DHCP client detects the conflict and logs 1020. Common causes: a device was manually configured with a static IP that falls inside the DHCP scope, an expired DHCP lease was reassigned while the original device was offline and returns, or DHCP scope management is incorrect.",what_good_looks_like:"No Event 1020 events. Any IP conflict should be resolved immediately as it causes network disruption for the affected devices.",common_mistakes:["Not checking the DHCP server's active leases to find the conflicting device","Not creating DHCP exclusions for statically configured devices","Not using DHCP reservations for printers and servers instead of static IPs"],causes:["Device with static IP in the DHCP scope range","DHCP lease expired and address reassigned while original device was offline","DHCP scope not configured with proper exclusions for static devices","Rogue DHCP server assigning overlapping addresses","Duplicate MAC address cloning (VMs)"],steps:["Find Event 1020 and note the conflicting IP address","Check DHCP server active leases for that IP: Get-DhcpServerv4Lease -ScopeId <scope> | Where IPAddress -eq <ip>","Use ARP to find the conflicting device: arp -a | findstr <ip>","Identify the device with the static IP and either change it or create a DHCP exclusion","Add exclusions in DHCP for all statically configured devices","Consider using DHCP reservations for infrastructure devices instead of static IPs"],symptoms:["ip conflict","ip address conflict","duplicate ip","two devices same ip","address conflict dhcp","network conflict ip","cant connect network ip conflict","intermittent network ip"],tags:["dhcp","ip-conflict","network","arp","connectivity"],powershell:`# DHCP IP Conflict Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Find IP conflict events
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Dhcp-Client'
    Id           = 1020
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Check current IP and ARP cache
Write-Host "
--- Current Network Configuration ---" -ForegroundColor Cyan
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Format-Table -AutoSize

Write-Host "
--- ARP Cache (find conflicting device) ---" -ForegroundColor Cyan
Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } | Format-Table -AutoSize`,related_ids:[1030,1048,1063,1014],ms_docs:null},{id:1030,source:"Microsoft-Windows-Dhcp-Client",channel:"Network",severity:"Error",skill_level:"Fundamental",title:"DHCP: Unable to Obtain IP Address",short_desc:"The DHCP client could not get an IP address — may fall back to APIPA (169.254.x.x).",description:`Event ID 1030 is generated when the DHCP client fails to obtain an IP address from a DHCP server after multiple attempts. When this happens, the machine typically falls back to an APIPA address (169.254.x.x) which means it cannot communicate with other network devices. This is a critical network failure event. Users will report "no internet", "can't access file shares", or "limited connectivity".`,why_it_happens:"The DHCP client broadcasts DHCPDISCOVER packets and waits for a DHCPOFFER from a server. If no server responds after several retries (across multiple boot/retry cycles), 1030 is logged. Causes: DHCP server is down, the client is isolated from the DHCP server by a firewall or VLAN misconfiguration, the DHCP scope is exhausted (all IPs leased out), or the network cable/WiFi is not actually connected.",what_good_looks_like:"No Event 1030 events. Any Event 1030 is a network connectivity problem requiring immediate investigation.",common_mistakes:["Not checking the physical layer first — a disconnected cable or wrong VLAN causes 1030","Trying to diagnose DHCP server issues without first verifying the client can reach the DHCP server subnet","Not checking the DHCP scope for exhaustion: Get-DhcpServerv4ScopeStatistics"],causes:["Physical network disconnection (cable, port, WiFi)","DHCP server offline or service stopped","DHCP scope exhausted (all IPs leased)","Firewall or ACL blocking DHCP traffic (UDP 67/68)","VLAN or switch misconfiguration isolating the client","DHCP relay agent not configured for the client's VLAN"],steps:["Check physical connectivity: is the cable plugged in, is the link light on the switch port active?","Check if machine is in the correct VLAN: check switch port configuration","Check if DHCP server is reachable (once you have an IP): ping dhcp-server","Check DHCP scope statistics for exhaustion: Get-DhcpServerv4ScopeStatistics -ComputerName <dhcp-server>","Force a DHCP release and renew: ipconfig /release && ipconfig /renew","If APIPA address (169.254.x.x): the machine got no DHCP response at all","Check DHCP server event log for related errors"],symptoms:["cant get ip address","no ip address","169.254 ip address","limited connectivity","dhcp failed","no network","apipa address","cannot connect to network","no internet dhcp","network limited"],tags:["dhcp","ip-address","connectivity","apipa","network","fundamental"],powershell:`# DHCP IP Assignment Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Find DHCP failure events
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Dhcp-Client'
    Id           = @(1030, 1020, 1048)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Check current IP state
Write-Host "
--- Current IP Configuration ---" -ForegroundColor Cyan
Get-NetIPConfiguration -ComputerName $computer -ErrorAction SilentlyContinue | Format-List`,related_ids:[1020,1048,1063,1014],ms_docs:null},{id:1048,source:"Microsoft-Windows-Dhcp-Client",channel:"Network",severity:"Warning",skill_level:"Intermediate",title:"DHCP: Lease Renewal Failed",short_desc:"The DHCP client failed to renew its existing IP address lease.",description:"Event ID 1048 is generated when the DHCP client has an existing lease but fails to renew it when the lease expires. At 50% of the lease duration, the client tries to renew with the original DHCP server. At 87.5%, it broadcasts to any DHCP server. If both fail, the lease expires and the client may lose its IP. This event indicates that the DHCP server has become unreachable since the lease was first obtained — a more subtle failure than 1030 which occurs on initial DHCP acquisition.",why_it_happens:"The DHCP client contacts the DHCP server (by unicast first, then broadcast) to renew its lease before expiry. If the server doesn't respond, the client retries until the lease expires. The failure could be because the DHCP server changed, moved, or crashed since the lease was first obtained, or because the network path to the DHCP server has changed.",what_good_looks_like:"No Event 1048 events. When 1048 appears, investigate whether the DHCP server is still reachable and whether its IP or configuration has changed.",common_mistakes:["Not realising the machine may still have network connectivity if the lease hasn't expired yet","Not checking if the DHCP server IP address changed (server moved or reIPed)"],causes:["DHCP server offline or IP changed","Network path to DHCP server changed","DHCP service stopped on server","Firewall change blocking DHCP renewal traffic"],steps:["Find Event 1048 and note the DHCP server address from the event","Check if that DHCP server is still reachable: Test-NetConnection -ComputerName <dhcp-ip> -Port 67","Force renewal: ipconfig /renew","If failure: check DHCP server status","Check DHCP server event log for service issues"],symptoms:["dhcp renewal failed","ip lease renewal failed","dhcp lease expired","network connectivity dropped after a while","ip address renewal failed"],tags:["dhcp","lease-renewal","network","connectivity"],powershell:`# DHCP Lease Renewal Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Dhcp-Client'
    Id           = 1048
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,related_ids:[1030,1020,1063],ms_docs:null},{id:1063,source:"Microsoft-Windows-Dhcp-Client",channel:"Network",severity:"Warning",skill_level:"Intermediate",title:"DHCP: Lost Contact with Domain Controller",short_desc:"The DHCP client could not contact a domain controller — may affect domain authentication.",description:"Event ID 1063 indicates that the DHCP client could not reach a domain controller, which is logged as part of the domain join and DHCP registration process. When a domain-joined machine gets a DHCP lease, it attempts to register its DNS record with the domain-integrated DNS server, which requires DC connectivity. Failure to contact the DC may indicate DNS misconfiguration, network segmentation issues, or that the DC itself is unreachable.",why_it_happens:"During DHCP address acquisition or renewal on a domain-joined machine, the DHCP client service attempts to locate and contact a domain controller for DNS dynamic update authorisation. If the DC is unreachable (wrong DNS server, DC down, or network issue), Event 1063 is logged. This does not necessarily mean authentication will fail immediately (Kerberos tickets and credentials may be cached), but it indicates a domain connectivity problem.",what_good_looks_like:"No Event 1063 events on a healthy domain-joined machine. If 1063 appears: the machine cannot reach a DC. Domain authentication will work if credentials are cached but will fail after cache expiry.",common_mistakes:["Not realising 1063 can appear during transient boot-time network unavailability and not always indicating a persistent problem","Ignoring 1063 on laptops that frequently move between networks","Not correlating with 1014 (DNS timeout) which often precedes 1063"],causes:["DNS server not configured or unreachable (can't find DC)","Domain Controller offline","Network segmentation preventing DC communication","VPN not connected (for remote workers)","Firewall blocking DC communication ports"],steps:["Find Event 1063 and check if 1014 (DNS timeout) events also appear","Test DC connectivity: Test-ComputerSecureChannel","Find a DC: nltest /dsgetdc:<domain>","Test DC ports: Test-NetConnection -ComputerName <dc> -Port 389","Check DNS is configured correctly: Get-DnsClientServerAddress","If VPN dependent: confirm VPN is connected"],symptoms:["cant contact domain controller","domain controller unreachable","dhcp domain controller","lost contact with dc","domain connectivity issue"],tags:["dhcp","domain-controller","dns","network","domain-join"],powershell:`# DHCP Domain Controller Contact Loss Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Dhcp-Client'
    Id           = 1063
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Test domain controller connectivity
Write-Host "
--- DC Connectivity Test ---" -ForegroundColor Cyan
Test-ComputerSecureChannel -Verbose`,related_ids:[1014,1030,1048],ms_docs:null},{id:10317,source:"Microsoft-Windows-WLAN-AutoConfig",channel:"Network",severity:"Warning",skill_level:"Fundamental",title:"WLAN: Network Disconnection",short_desc:"The wireless adapter disconnected from a Wi-Fi network.",description:"Event ID 10317 from the WLAN-AutoConfig service records a wireless network disconnection. It includes the SSID of the network, the reason code for the disconnection, and the network adapter. This is the primary event for investigating intermittent WiFi connectivity issues. The disconnection reason code distinguishes between normal disconnects (user action) and unexpected ones (signal loss, authentication failure, deauthentication from AP, or driver issues).",why_it_happens:"WLAN disconnections occur when the association with the access point is lost. This can be caused by moving out of range, a 802.1X authentication failure (wrong certificate, expired password), the access point deauthenticating the client (roaming, load balancing, channel change), driver bugs, or Windows attempting to roam to a better AP and failing. The DisconnectReason field (or Reason Code) is crucial for root cause identification.",what_good_looks_like:"Occasional brief disconnections while roaming between APs are normal. Investigate: frequent disconnections in a fixed location (signal, interference, or driver issue), disconnections followed by long reconnect times, disconnections with reason codes indicating authentication failure (802.1X), many clients disconnecting from the same AP simultaneously.",common_mistakes:['Not checking the reason code — "disconnected" could mean user action or AP rejection',"Blaming the WiFi driver without first checking signal strength and channel utilisation","Not checking if multiple devices disconnect from the same AP simultaneously (AP issue) vs one device (client issue)","Not checking if the issue is with roaming between APs vs staying connected to one AP"],causes:["User or application disconnecting intentionally","Signal loss — too far from AP or interference","802.1X authentication failure (certificate, RADIUS server)","AP deauthentication for load balancing or channel change","WiFi driver bug","Power management putting NIC to sleep (aggressive power saving)","Roaming failure between APs"],steps:["Filter System log for Event 10317","Note the SSID, adapter name, and disconnect reason code","Check signal strength at the time of disconnect (may need AP or NMS)","Check WiFi driver version: Get-NetAdapter -Name Wi-Fi | Select-Object DriverVersion","Disable aggressive WiFi power management: Set-NetAdapterPowerManagement -Name Wi-Fi -AllowComputerToTurnOffDevice Disabled","Check if 802.1X authentication is used and if certificates are valid","Check channel utilisation on the AP if signal is adequate"],symptoms:["wifi drops","wireless disconnects","wifi keeps disconnecting","wireless connection drops","wifi unstable","wireless keeps dropping","wifi falls off","laptop wifi disconnecting","intermittent wifi","wifi drops every few minutes"],tags:["wifi","wireless","wlan","connectivity","disconnect","network"],powershell:`# WiFi Disconnection Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Find WiFi disconnect events
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WLAN-AutoConfig'
    Id           = 10317
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Check current WiFi adapter power management
Write-Host "
--- WiFi Power Management ---" -ForegroundColor Cyan
Get-NetAdapter | Where-Object { $_.MediaType -like '*802.11*' } | ForEach-Object {
    Get-NetAdapterPowerManagement -Name $_.Name | Select-Object Name, AllowComputerToTurnOffDevice
} | Format-Table -AutoSize

# Current WiFi state
Write-Host "
--- Current WiFi Connections ---" -ForegroundColor Cyan
netsh wlan show interfaces`,related_ids:[10400,1014,1030],ms_docs:null},{id:10400,source:"Microsoft-Windows-WLAN-AutoConfig",channel:"Network",severity:"Error",skill_level:"Intermediate",title:"WLAN: Association Failed",short_desc:"The wireless adapter could not associate with a Wi-Fi access point.",description:"Event ID 10400 records a failure to associate with a Wi-Fi access point. This is different from a disconnection (10317) — association failure occurs when the device is trying to connect but the 802.11 association exchange fails. This can happen because the SSID doesn't exist at that location, the authentication method is mismatched, the PSK (password) is wrong, or the AP is rejecting the client. After a successful association, authentication happens separately; if authentication then fails, that generates a different event.",why_it_happens:"Wi-Fi association is the 802.11 handshake where a client requests to join an AP's BSS. The AP can reject the association for several reasons: the authentication type isn't supported, the client is blocked (MAC filtering), the AP is at capacity (maximum associations reached), or there is a mismatch in security settings (WPA2 vs WPA3). After association, 802.1X or PSK authentication occurs.",what_good_looks_like:"No Event 10400 events. Any 10400 indicates the WiFi join process failed before authentication could even complete.",common_mistakes:["Not distinguishing between association failure (10400) and authentication failure (different event) — they require different fixes","Trying to fix PSK when the issue is an association-level rejection (MAC filter, capacity)","Not checking if the SSID is broadcast or hidden and whether the client has the correct SSID configured"],causes:["Wrong or missing PSK for WPA2-Personal networks","Security type mismatch (WPA2 vs WPA3)","AP at maximum association capacity","MAC address filtering on AP rejecting the client","SSID moved to a different frequency band client doesn't support","Driver not supporting the AP's 802.11 standard (e.g., WiFi 6E without WiFi 6 driver)"],steps:["Filter System log for Event 10400","Note the SSID and reason code in the event","Check if the SSID is visible in wireless networks: netsh wlan show networks","Verify the PSK is correct by forgetting and re-entering the network","Check for MAC filtering on the AP if PSK is definitely correct","Update WiFi driver: check device manager for updates","Check if other devices can connect to the same SSID from the same location"],symptoms:["wifi wont connect","cant connect to wifi","wifi association failed","wireless connection failed","cant join wifi network","wifi authentication failed","wrong wifi password even though correct","wifi refuses to connect"],tags:["wifi","wireless","wlan","association","connectivity","authentication"],powershell:`# WiFi Association Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WLAN-AutoConfig'
    Id           = 10400
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# List available WiFi networks
Write-Host "
--- Available WiFi Networks ---" -ForegroundColor Cyan
netsh wlan show networks mode=bssid`,related_ids:[10317,1014,1030],ms_docs:null},{id:4226,source:"Tcpip",channel:"Network",severity:"Warning",skill_level:"Advanced",title:"TCP Connection Limit Reached",short_desc:"Windows reached the limit for simultaneous incomplete outbound TCP connection attempts.",description:"Event ID 4226 from the Tcpip source records that the system reached the limit on simultaneous half-open TCP connection attempts. Windows limits incomplete outbound connections to throttle connection-rate-based malware (worms). On modern Windows 10/11 and Server, this limit was significantly increased (from 10 per second on XP to effectively unlimited on modern versions). If you see this event on a modern Windows system, it is unusual and may indicate aggressive scanning software, peer-to-peer applications, or malware performing port scans or rapid connection attempts.",why_it_happens:"TCP half-open connections (SYN sent, SYN-ACK not yet received) are counted by the TCP/IP stack. The limit exists to prevent a single compromised machine from participating in SYN-flood attacks or worm propagation by limiting how fast it can initiate outbound connections. On modern Windows, this limit only triggers for very aggressive connection rates, so seeing this event warrants investigation of what is generating so many simultaneous connections.",what_good_looks_like:"This event should essentially never appear on normal workstations or servers. If it does: immediately investigate what process is initiating so many connections. This is a strong indicator of malware, a misconfigured P2P application, or a security scanner.",common_mistakes:["On Windows XP: this event was commonly triggered by legitimate P2P software and the limit was a nuisance. On modern Windows, it should not appear in normal operation.","Assuming any process hitting this limit is malicious — security scanners and some backup tools can also trigger it"],causes:["Malware performing port scanning or worm propagation","P2P application (BitTorrent) with many simultaneous connections","Security scanner running on the endpoint","Backup or network monitoring software making many simultaneous connections","A browser loading a page with hundreds of parallel connections (rare)"],steps:["Filter System log for Event 4226","Note the time of the event","Check what process was generating connections around that time (Event 4688)","Use netstat to check current connections: netstat -anob","If malware suspected: isolate the machine and perform AV scan","Check for port scanning activity in firewall logs"],symptoms:["tcp connection limit","too many connections","network connection limit reached","tcp half open connections","connection rate limit","port scan detected"],tags:["tcp","network","connection-limit","malware","scanning","advanced"],powershell:`# TCP Connection Limit Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

# Find TCP limit events
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Tcpip'
    Id           = 4226
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List

# Check current TCP connections (run locally or via PSRemoting)
Write-Host "
--- Active TCP Connections (top talkers by process) ---" -ForegroundColor Cyan
Get-NetTCPConnection -State Established |
    Group-Object OwningProcess |
    Sort-Object Count -Descending |
    Select-Object -First 10 Count,
        @{N='Process'; E={ (Get-Process -Id $_.Name -ErrorAction SilentlyContinue).ProcessName }} |
    Format-Table -AutoSize`,related_ids:[4688,4624],ms_docs:null}],n=[...e,...t,...s,...o,...i];export{n as a};
