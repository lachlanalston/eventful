export const printEvents = [
  {
    id: 307,
    source: 'Microsoft-Windows-PrintService',
    channel: 'PrintService/Operational',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Document Printed Successfully',
    short_desc: 'A document completed printing — records who printed, which printer, page count, and document name.',
    description: 'Event 307 from PrintService is written every time a document finishes printing successfully. It captures the submitting user, document name, printer name, port, byte size, and page count. This is the primary audit source for print activity and is invaluable when investigating who printed a sensitive document, building a print usage report, or confirming a job actually completed. The catch: the PrintService/Operational log is disabled by default and must be enabled before any events appear.',
    why_it_happens: 'The Windows Print Spooler writes Event 307 to the PrintService/Operational log after a job completes all rendering and despooling. The log must be manually enabled — go to Event Viewer → Applications and Services Logs → Microsoft → Windows → PrintService → Operational → right-click → Enable Log.',
    what_good_looks_like: 'Regular Event 307 entries matching expected business printing. Investigate: large jobs from unexpected users, printing outside business hours, jobs from accounts that should not access certain documents.',
    common_mistakes: [
      'Not enabling the PrintService/Operational log first — it is off by default and generates zero events until enabled',
      'Assuming no Event 307 means no printing occurred — the log may simply be disabled',
      'Not checking the document name field, which often reveals what was printed'
    ],
    causes: [
      'User successfully printed a document from any application',
      'A service or scheduled task generated a print job (reports, invoices, etc.)'
    ],
    steps: [
      'Enable the log first: Event Viewer → Apps and Services Logs → Microsoft → Windows → PrintService → Operational → Enable Log',
      'Filter for Event ID 307 in PrintService/Operational',
      'Check Document Name, User Name, and Printer Name fields in each event',
      'To audit a specific user or printer: use PowerShell snippet below with a Where-Object filter',
      'Cross-reference with Event 6161 if jobs were expected but did not complete'
    ],
    symptoms: [
      'who printed this document',
      'print audit log',
      'print job history',
      'who sent job to printer',
      'document print record',
      'see all print jobs',
      'print activity log',
      'who used the printer',
      'print history',
      'audit what was printed',
      'print job audit trail',
      'track printing activity'
    ],
    tags: ['print', 'audit', 'document', 'printer', 'operational', 'history'],
    powershell: `# Print Job Audit — last 7 days
# Eventful
# Note: PrintService/Operational log must be enabled first

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PrintService/Operational'
    Id        = 307
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        User        = $_.UserId
        Message     = $_.Message
    }
} | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [372, 808, 6161, 1111],
    ms_docs: null
  },

  {
    id: 372,
    source: 'Microsoft-Windows-PrintService',
    channel: 'PrintService/Admin',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Print Driver Failed to Initialize',
    short_desc: 'A printer driver module failed to load — commonly causes the printer to stop working or the spooler to crash.',
    description: 'Event 372 means the print spooler failed to load or initialize a printer driver module (a plug-in DLL). This commonly follows a driver update, driver corruption, or adding a new printer with an incompatible driver. When a driver fails to initialize, print jobs through it fail silently or remain stuck in the queue. In persistent cases the Print Spooler service itself crashes (Event 7031) and restarts in a loop. The event message names the specific driver module, pointing you directly at which printer is the culprit.',
    why_it_happens: 'Printer drivers consist of a UI DLL, rendering DLL, and configuration DLL. If any fails to load — due to a missing file, corrupt registry key, architecture mismatch (32-bit driver on 64-bit spooler), or a missing dependency — Event 372 fires. Windows Server print servers are especially vulnerable after cumulative updates that ship new spooler binaries incompatible with older third-party drivers.',
    what_good_looks_like: 'No Event 372 in a healthy environment. Any occurrence warrants investigation — even if printing appears to work, a partially-initialized driver causes intermittent failures.',
    common_mistakes: [
      'Restarting the print spooler without addressing the driver — it will fail again immediately on restart',
      'Reinstalling the printer without removing the driver from the driver store — the corrupt driver gets reused',
      'Not checking which specific driver is failing — the event names the module, telling you exactly which printer to target',
      'Forgetting to also remove the driver from the driver store (pnputil), not just uninstall the printer'
    ],
    causes: [
      'Corrupt or incomplete printer driver installation',
      'Windows Update modified spooler components incompatible with an existing third-party driver',
      'Driver architecture mismatch — 32-bit driver on a 64-bit spooler or vice versa',
      'Missing driver dependency DLL',
      'Driver version conflict when two printers share the same driver',
      'Antivirus quarantining a driver DLL'
    ],
    steps: [
      'Note the driver name and module from the Event 372 message',
      'Check if the spooler is crash-looping: look for Event 7031 with "Print Spooler" around the same time',
      'Open Print Management or Devices and Printers — identify which printer uses the failing driver',
      'Remove the printer and driver: printui /s /t2, select the driver, click Remove',
      'Remove from driver store: pnputil /enum-drivers — find the matching INF, then pnputil /delete-driver <inf> /uninstall',
      'Restart the Print Spooler: Restart-Service Spooler',
      'Reinstall the latest driver from the manufacturer website',
      'On a print server: check Print Management → Drivers for orphaned or duplicate drivers'
    ],
    symptoms: [
      'print driver failed',
      'printer stopped working',
      'printer driver error',
      'driver failed to load',
      'print driver crash',
      'printer not working after windows update',
      'spooler crashing with driver error',
      'printer driver initialization failed',
      'printer broken after update',
      'print driver plug-in error',
      'printer stopped printing after update',
      'driver load failure print'
    ],
    tags: ['print', 'driver', 'error', 'spooler', 'print-service', 'crash'],
    powershell: `# Check for print driver and spooler errors — last 7 days
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PrintService/Admin'
    Id        = @(372, 808, 1111, 6161)
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Also check if spooler has been crashing
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = @(7031, 7034)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like '*Print Spooler*' } |
    Select-Object TimeCreated, Message | Format-List`,
    related_ids: [808, 1111, 6161, 307, 7031],
    ms_docs: null
  },

  {
    id: 808,
    source: 'Microsoft-Windows-PrintService',
    channel: 'PrintService/Admin',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Print Spooler Failed to Share Printer',
    short_desc: 'The spooler could not publish a printer as a network share — other computers cannot connect to it.',
    description: 'Event 808 means the Windows Print Spooler failed to share a printer on the network. When sharing is configured, the spooler tries to register the printer as a network share (and optionally publish it in Active Directory). Failure means clients cannot connect via UNC path (\\\\servername\\printername). The error code in the message is the key diagnostic — common codes point to the Server service being stopped, firewall blocking sharing ports, or insufficient permissions to publish in AD.',
    why_it_happens: 'Printer sharing relies on the Server (LanmanServer) service and the RPC endpoint mapper. Failures occur when the Server service is stopped, when the spooler account lacks AD publish permissions, when firewall rules block ports TCP 139/445, or when the share name conflicts with an existing share.',
    what_good_looks_like: 'No Event 808. If sharing is expected, confirm success by verifying the printer appears to remote clients with no 808 in the log.',
    common_mistakes: [
      'Seeing "Shared" checked in printer properties and assuming sharing worked — that flag just means sharing is configured, not that it succeeded',
      'Not checking if the Server service (LanmanServer) is running',
      'Forgetting that the spooler account needs specific AD rights to publish printers in the directory'
    ],
    causes: [
      'Server service (LanmanServer) stopped or disabled',
      'Windows Firewall blocking File and Printer Sharing ports (TCP 139, 445)',
      'Print spooler service account lacks permission to create the share or publish in AD',
      'Share name conflicts with an existing network share',
      'RPC service not responding',
      'Group Policy blocking network sharing'
    ],
    steps: [
      'Check the error code in the Event 808 message body',
      'Verify the Server service is running: Get-Service LanmanServer',
      'Check firewall allows File and Printer Sharing: netsh advfirewall firewall show rule name="File and Printer Sharing*"',
      'Try resharing: open Printer Properties → Sharing → uncheck Shared → OK → re-check → OK',
      'Check System log for Service Control Manager errors at the same timestamp',
      'If publishing to AD is required: verify the machine account has rights to create printerQueue objects in the OU'
    ],
    symptoms: [
      'printer not showing on network',
      'cannot connect to shared printer',
      'printer share failed',
      'other computers cannot see printer',
      'shared printer unavailable',
      'network printer not accessible',
      'printer share not working',
      'printer disappeared from network',
      'cannot map network printer',
      'printer not published in active directory',
      'shared printer not visible',
      'printer share error'
    ],
    tags: ['print', 'sharing', 'network', 'spooler', 'print-service', 'server', 'active-directory'],
    powershell: `# Check printer sharing and spooler/server service status
# Eventful

# Service status
Get-Service Spooler, LanmanServer | Select-Object Name, Status, StartType

# Printer sharing errors — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PrintService/Admin'
    Id        = 808
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Format-List

# All shared printers and their current status
Get-Printer | Where-Object Shared |
    Select-Object Name, ShareName, PortName, DriverName, PrinterStatus`,
    related_ids: [372, 1111, 6161, 307, 7031],
    ms_docs: null
  },

  {
    id: 1111,
    source: 'Microsoft-Windows-PrintService',
    channel: 'PrintService/Admin',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Printer Driver Failed During Job Processing',
    short_desc: 'The printer driver crashed or errored while rendering a print job — the job failed and the driver likely needs reinstalling.',
    description: 'Event 1111 fires when a printer driver fails during the actual processing of a print job. Unlike Event 372 (driver fails to initialize at spooler start), Event 1111 fires mid-job: the spooler has loaded the driver, the job has started, and then the driver crashes or returns an unexpected error code. The driver name and error code in the event message identify which printer is affected. Repeated Event 1111 for the same driver almost always means a corrupt or incompatible driver that must be removed and reinstalled.',
    why_it_happens: 'Print jobs are rendered inside the spooler process by the driver\'s rendering DLL. This DLL transforms the job data into the printer\'s page description language (PCL, PostScript, XPS, etc.). If the DLL has a bug, memory corruption, or an incompatibility with the document format or a recent Windows update, it returns an error and the spooler marks the job as failed.',
    what_good_looks_like: 'No Event 1111. A single isolated occurrence after a malformed document may be benign. Repeated failures for the same driver are always a driver problem.',
    common_mistakes: [
      'Retrying the same print job without fixing the driver — it will fail every time',
      'Reinstalling the printer without purging the driver from the driver store — the corrupt driver is reused',
      'Missing that Event 1111 on a shared print server affects every user of that shared printer'
    ],
    causes: [
      'Corrupt printer driver rendering DLL',
      'Driver incompatibility with the current spooler version after a Windows update',
      'Document format that the driver cannot render (specific font, oversized PDF, etc.)',
      'Insufficient spool disk space preventing job staging',
      'Antivirus blocking driver DLL execution in-process'
    ],
    steps: [
      'Note the driver name from the Event 1111 message',
      'Clear the stuck queue: net stop Spooler → del /Q /F /S C:\\Windows\\System32\\spool\\PRINTERS\\* → net start Spooler',
      'Remove and reinstall the driver: printui /s /t2 → select driver → Remove',
      'Remove from driver store: pnputil /enum-drivers, find the INF, then pnputil /delete-driver <inf> /uninstall',
      'Check disk space on the spool drive — full disk prevents spooling',
      'Test with a simple one-page document to rule out document-specific corruption',
      'On a print server: determine if multiple users are affected (server driver) vs just one user (may be client-side)'
    ],
    symptoms: [
      'print job failed',
      'document wont print',
      'print job disappears without printing',
      'printer driver error mid job',
      'printer keeps failing on same document',
      'print job error',
      'document stuck in print queue',
      'printing fails every time',
      'print job removed from queue automatically',
      'printer driver crashed during printing',
      'job deleted from queue without printing',
      'printer driver failing repeatedly'
    ],
    tags: ['print', 'driver', 'error', 'job', 'spooler', 'print-service', 'rendering'],
    powershell: `# Driver failures and current print queue
# Eventful

# Recent driver job failures
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PrintService/Admin'
    Id        = @(1111, 372)
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Current jobs in all queues
Get-PrintJob -PrinterName * |
    Select-Object PrinterName, DocumentName, JobStatus, UserName, SubmittedTime`,
    related_ids: [372, 808, 6161, 307, 7031],
    ms_docs: null
  },

  {
    id: 6161,
    source: 'Microsoft-Windows-PrintService',
    channel: 'PrintService/Admin',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'Document Failed to Print',
    short_desc: 'A specific print job failed — records who submitted it, which document, which printer, and why.',
    description: 'Event 6161 is the most visible print failure event — it fires when a document queued for printing fails to complete. It records the document name, submitting user, printer, and an error description. This is the first event to check when a user reports "I tried to print but nothing came out." It can be caused by driver errors (correlate with 1111 or 372), the printer going offline, a port timeout, or the spooler crashing. Event 6161 is the symptom — Events 1111, 372, and 7031 nearby will tell you the cause.',
    why_it_happens: 'A print job progresses through spooling (write to disk), despooling (send to driver), and rendering (convert to printer language). Failure at any stage produces Event 6161. Common triggers: printer offline mid-job, driver crash (see 1111), port timeout, spooler restart, or insufficient spool disk space.',
    what_good_looks_like: 'No Event 6161. Even a single occurrence is worth investigating — the user sent a job that never printed.',
    common_mistakes: [
      'Telling users to retry without first verifying the printer is actually online and ready',
      'Not reading the error description in the event message body — it states the specific failure reason',
      'Not correlating with Event 1111 (driver failure) or 7031 (spooler crash) — 6161 is the symptom, not the cause',
      'Forgetting to check if the printer has paper, toner, and is not in error/offline state'
    ],
    causes: [
      'Printer offline, out of paper, out of toner, or showing an error state',
      'Printer driver failed during rendering — check Event 1111',
      'Print Spooler service crashed mid-job — check Event 7031',
      'Printer port connection timeout or network printer unreachable',
      'Insufficient disk space in the spool folder (C:\\Windows\\System32\\spool\\PRINTERS)',
      'Document corrupted or in an unsupported format for the target driver'
    ],
    steps: [
      'Check the document name, user, and error description in Event 6161',
      'Verify the printer is online and not showing a hardware error (paper, toner, error light)',
      'Look for Event 1111 or 372 near the same timestamp — driver failure is the most common cause',
      'Look for Event 7031 with "Print Spooler" — spooler crash kills in-progress jobs',
      'Check spool disk space: Get-PSDrive C',
      'Clear the queue and retry: net stop Spooler → delete spool files → net start Spooler',
      'If a network printer: confirm it is reachable — ping or open its web UI in a browser'
    ],
    symptoms: [
      'document failed to print',
      'print job disappeared',
      'nothing came out of printer',
      'print job not printing',
      'sent to printer no output',
      'document deleted from print queue',
      'print job failed to complete',
      'user cannot print',
      'print jobs keep failing',
      'printer not printing documents',
      'job vanishes from queue',
      'printing nothing comes out'
    ],
    tags: ['print', 'error', 'job', 'document', 'spooler', 'print-service', 'fundamental'],
    powershell: `# Recent print failures
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PrintService/Admin'
    Id        = 6161
    StartTime = (Get-Date).AddDays(-3)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message |
    Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1111, 372, 808, 307, 7031],
    ms_docs: null
  }
];
