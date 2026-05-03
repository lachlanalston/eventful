export const tasksEvents = [
  {
    id: 4698,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Scheduled Task Created',
    short_desc: 'A new scheduled task was created — captures task name, XML definition, and creating account.',
    description: 'Event 4698 is generated in the Security log when a new scheduled task is created. It captures the full task XML definition including the action (what runs), trigger (when it runs), and principal (what account it runs as). Scheduled task creation is one of the most common persistence mechanisms used by malware and attackers — any unexpected task creation, especially from unusual accounts or with tasks running from Temp/AppData directories, should be investigated immediately.',
    why_it_happens: 'Scheduled tasks are created by software installers (for update checks), by IT automation tools, by Group Policy, and by attackers establishing persistence. The Task Scheduler operational log also captures task events (Events 106, 107, 200, 201), but Security Event 4698 is the authoritative creation record and includes the full task XML.',
    what_good_looks_like: 'Task creations correlate with software installs or known automation scripts. No tasks created from temp directories, no tasks running cmd.exe/powershell.exe with encoded commands, no tasks created by user accounts outside provisioning.',
    common_mistakes: [
      'Not reading the task XML in the event — the action field shows exactly what command will run',
      'Not checking the task path — malware often uses names similar to legitimate Windows tasks',
      'Forgetting that Task Scheduler Event 4698 requires "Audit Other Object Access Events" to be enabled'
    ],
    causes: [
      'Software installer creating an update or maintenance task',
      'IT admin deploying an automation task',
      'Group Policy creating software deployment task',
      'Malware creating persistence task',
      'Attacker creating task for lateral movement or payload execution'
    ],
    steps: [
      'Enable Task Scheduler auditing: auditpol /set /subcategory:"Other Object Access Events" /success:enable',
      'Filter Security log for Event 4698',
      'Read the task XML in the event — check the Action command carefully',
      'Check Task Path — suspicious: \\Microsoft\\Windows\\* tasks with non-Microsoft names',
      'Check the creating account — was it a user account or SYSTEM?',
      'Verify the task binary is signed: Get-AuthenticodeSignature "<taskPath>"',
      'Cross-reference with 4688 (process create) for the process that created the task'
    ],
    symptoms: [
      'new scheduled task created',
      'unknown scheduled task appeared',
      'malware persistence task',
      'scheduled task audit',
      'who created scheduled task',
      'task scheduler new task',
      'suspicious scheduled task',
      'unauthorized task created'
    ],
    tags: ['scheduled-task', 'persistence', 'malware', 'security', 'audit', 'automation'],
    powershell: `# Scheduled Task Creation and Execution Audit
# Eventful

# Task creation events from Security log
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4698, 4699, 4700, 4701, 4702)
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $action = switch ($_.Id) {
        4698 { 'CREATED' } 4699 { 'DELETED' } 4700 { 'ENABLED' }
        4701 { 'DISABLED' } 4702 { 'MODIFIED' }
    }
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Action      = $action
        TaskName    = ($data | Where-Object Name -eq 'TaskName').'#text'
        CreatedBy   = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# All current scheduled tasks with their actions
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
    Select-Object TaskPath, TaskName, @{N='Action'; E={$_.Actions.Execute}} |
    Where-Object { $_.Action -notlike '' } |
    Sort-Object TaskPath | Format-Table -AutoSize`,
    related_ids: [4699, 4702, 4688, 106, 201],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698'
  },

  {
    id: 106,
    source: 'Microsoft-Windows-TaskScheduler',
    channel: 'Microsoft-Windows-TaskScheduler/Operational',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Scheduled Task Registered',
    short_desc: 'A scheduled task was registered with Task Scheduler — operational log record of task creation.',
    description: 'Event 106 from the Task Scheduler operational log is generated when a task is registered (created or modified). This is the operational log counterpart to Security Event 4698. While 4698 requires audit policy configuration, Event 106 is always logged in the Task Scheduler operational log. For quick task creation monitoring without configuring audit policy, 106 is easier to check.',
    why_it_happens: 'Logged whenever a task object is written to the Task Scheduler service, whether via the GUI, schtasks.exe, PowerShell Register-ScheduledTask, or Group Policy. This log is valuable for rapid triage because it is always on.',
    what_good_looks_like: 'Task registrations during software installs or IT deployment windows. Task names and paths match known software. No tasks registered by unexpected accounts.',
    common_mistakes: [
      'Relying solely on 106 — it shows the task name but not the full XML action; check 4698 for the command that will run'
    ],
    causes: [
      'Software installer registering a maintenance task',
      'IT automation deploying tasks',
      'Malware registering a persistence task',
      'Admin using Task Scheduler GUI'
    ],
    steps: [
      'Open Event Viewer → Applications and Services Logs → Microsoft → Windows → TaskScheduler → Operational',
      'Filter for Event 106',
      'Note the task name and user that registered it',
      'Inspect the task: Get-ScheduledTask -TaskName "<name>" | Select-Object -ExpandProperty Actions'
    ],
    symptoms: [
      'scheduled task registered',
      'new task appeared',
      'task scheduler event',
      'task created log',
      'who registered task',
      'task scheduler audit'
    ],
    tags: ['scheduled-task', 'task-scheduler', 'audit', 'persistence'],
    powershell: `# Task Scheduler Operational Events
# Eventful

# Task registrations and deletions
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(106, 141) -and $_.TimeCreated -gt (Get-Date).AddDays(-7) } |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 106) {'REGISTERED'} else {'DELETED'} }},
        Message |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4698, 201, 200],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page'
  },

  {
    id: 201,
    source: 'Microsoft-Windows-TaskScheduler',
    channel: 'Microsoft-Windows-TaskScheduler/Operational',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Scheduled Task Execution Completed',
    short_desc: 'A scheduled task finished execution — includes result code indicating success or failure.',
    description: 'Event 201 is generated when a scheduled task finishes executing. It includes the task name, the action that was executed, and the result code. Result code 0 = success; any non-zero code indicates failure. For critical automated jobs (backups, maintenance scripts, deployments), monitoring Event 201 with non-zero result codes is the quickest way to detect silent task failures that are not otherwise reported.',
    why_it_happens: 'Every task execution that completes (or fails) generates Event 201. The preceding Event 200 records task start. By pairing 200 and 201, you can determine the execution duration and outcome for any scheduled job.',
    what_good_looks_like: 'All critical scheduled tasks complete with result code 0. Task execution times are consistent. Failed tasks (non-zero result) trigger investigation.',
    common_mistakes: [
      'Not checking result codes — most IT teams check if a task ran, not if it succeeded',
      'Not knowing which result codes are acceptable for a specific task (some tasks use non-zero codes for expected conditions)'
    ],
    causes: [
      'Task completed successfully (result 0)',
      'Task action failed — script error, missing file, access denied',
      'Task was stopped before completion (result 0xC000013A = operation aborted)',
      'Task ran but the executable returned an error code'
    ],
    steps: [
      'Filter Task Scheduler Operational log for Event 201',
      'Check Result Value — 0 = success; anything else = investigate',
      'For failed tasks: check the task action command and run it manually to see the error',
      'Common codes: 0x1 = general error, 0x2 = file not found, 0x5 = access denied',
      'Pair with Event 200 (task started) to see execution duration'
    ],
    symptoms: [
      'scheduled task failed',
      'task not completing',
      'scheduled job failed',
      'backup task failed',
      'task result error code',
      'scheduled task error',
      'automation task failing',
      'cron job failed windows'
    ],
    tags: ['scheduled-task', 'task-scheduler', 'execution', 'failure', 'automation'],
    powershell: `# Scheduled Task Execution Results
# Eventful

# Failed task executions (non-zero result codes)
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 201 -and $_.TimeCreated -gt (Get-Date).AddDays(-7) } |
    ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TaskName    = ($data | Where-Object Name -eq 'TaskName').'#text'
            Action      = ($data | Where-Object Name -eq 'ActionName').'#text'
            ResultCode  = ($data | Where-Object Name -eq 'ResultCode').'#text'
        }
    } | Where-Object { $_.ResultCode -ne '0' } |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [200, 4698, 106],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page'
  },

  {
    id: 4699,
    source: 'Microsoft-Windows-Security-Auditing',
    channel: 'Security',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'Scheduled Task Deleted',
    short_desc: 'A scheduled task was deleted — attackers delete persistence tasks to cover tracks.',
    description: 'Event 4699 records the deletion of a scheduled task. While routine task cleanup is normal, unexpected task deletions — especially of tasks that were recently created — can indicate an attacker cleaning up their persistence mechanism before investigators arrive. Alternatively, unauthorized deletion of legitimate maintenance tasks can silently break backup jobs, monitoring agents, or patch deployment routines.',
    why_it_happens: 'Tasks are deleted via the Task Scheduler GUI, schtasks /delete, Unregister-ScheduledTask, or by software uninstallers. An attacker cleaning up will typically delete tasks they created earlier (look for 4698 followed by 4699 for the same task name).',
    what_good_looks_like: 'Task deletions correlate with software uninstalls. No deletion of Microsoft or antivirus maintenance tasks. No deletion of tasks that were recently created outside of normal provisioning.',
    common_mistakes: [
      'Not correlating 4699 (delete) with a previous 4698 (create) from the same session — this pattern is a strong indicator of attacker cleanup'
    ],
    causes: [
      'Software uninstaller removing its scheduled task',
      'IT admin cleaning up old tasks',
      'Attacker deleting their persistence task to cover tracks',
      'Automated cleanup script removing expired tasks'
    ],
    steps: [
      'Filter Security log for Event 4699',
      'Note the Task Name — was this a legitimate system or application task?',
      'Look for a preceding Event 4698 (task created) with the same name from the same session',
      'Check the deleting account — was it the same account that created it?',
      'If a critical maintenance task was deleted: re-create it and investigate who deleted it'
    ],
    symptoms: [
      'scheduled task deleted',
      'backup task disappeared',
      'task removed',
      'who deleted scheduled task',
      'maintenance task gone',
      'task scheduler deletion',
      'attacker cleaning up tasks'
    ],
    tags: ['scheduled-task', 'deletion', 'audit', 'security', 'cleanup'],
    powershell: `# Scheduled Task Deletion Audit
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4698, 4699)
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Event       = if ($_.Id -eq 4698) { 'CREATED' } else { 'DELETED' }
        TaskName    = ($data | Where-Object Name -eq 'TaskName').'#text'
        Account     = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize`,
    related_ids: [4698, 4702, 106],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4699'
  }
];
