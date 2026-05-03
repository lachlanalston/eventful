export const adReplicationEvents = [
  {
    id: 1311,
    source: 'NTDS Replication',
    channel: 'Directory Service',
    severity: 'Error',
    skill_level: 'Advanced',
    title: 'AD Replication: Replication with Source DC Failed',
    short_desc: 'Active Directory replication has failed between domain controllers — objects may be out of sync.',
    description: 'Event 1311 from NTDS Replication in the Directory Service log indicates that Active Directory replication has failed with a specific partner domain controller. This means the two DCs cannot synchronize changes — new users, password changes, policy updates, and other AD changes made on one DC will not propagate to the partner. In a multi-DC environment, persistent replication failures can result in divergent AD databases, authentication inconsistencies, and eventual tombstone lifetime violations.',
    why_it_happens: 'Replication failures are caused by: network connectivity issues between DCs (firewall blocking AD replication ports TCP/UDP 389, 135, 49152–65535), DNS resolution failures (DCs cannot resolve each other by name), RPC endpoint mapper failures, time skew > 5 minutes, or a DC with a corrupted AD database.',
    what_good_looks_like: 'repadmin /replsummary shows no failures. All DCs replicate all partitions successfully. No 1311 errors in Directory Service log. repadmin /showrepl shows "Consecutive Failures: 0".',
    common_mistakes: [
      'Not checking replication on all DCs — a failure on one pair does not mean all replication is broken',
      'Not checking time synchronization — Kerberos (used for replication) requires < 5 min clock skew',
      'Checking only the System log and missing the Directory Service log where replication events live',
      'Waiting too long — if replication fails for longer than the tombstone lifetime (default 180 days), deleted objects can "come back" (lingering objects)'
    ],
    causes: [
      'Firewall blocking RPC/LDAP ports between DCs',
      'DNS resolution failure — DC cannot resolve partner by FQDN',
      'Time skew > 5 minutes between DCs (Kerberos authentication fails)',
      'Network connectivity failure between DC sites',
      'DC taken offline and not properly demoted before being removed'
    ],
    steps: [
      'Run repadmin /replsummary on any DC to get a quick overview of replication health',
      'Identify the failing pair: repadmin /showrepl <failingDC>',
      'Check network connectivity: Test-NetConnection -ComputerName <partnerDC> -Port 389',
      'Check DNS resolution: Resolve-DnsName <partnerDC.domain.fqdn>',
      'Check time sync: w32tm /query /status on both DCs',
      'Check AD replication: repadmin /replicate <destDC> <sourceDC> <NC>',
      'Force replication: repadmin /syncall /AdeP'
    ],
    symptoms: [
      'AD replication failed',
      'domain controller not replicating',
      'Active Directory out of sync',
      'replication error',
      'AD changes not propagating',
      'users not showing on all DCs',
      'password change not syncing',
      'AD replication broken',
      'DCs out of sync'
    ],
    tags: ['active-directory', 'replication', 'domain-controller', 'ntds', 'sync'],
    powershell: `# Active Directory Replication Health
# Eventful

# Quick replication summary (run on any DC)
repadmin /replsummary

# Detailed replication status per DC
repadmin /showrepl

# Force sync all partitions
# repadmin /syncall /AdeP

# Recent replication errors in Directory Service log
Get-WinEvent -FilterHashtable @{
    LogName      = 'Directory Service'
    Id           = @(1311, 1388, 1864, 2042)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1388, 1864, 2042],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/diagnose-replication-failures'
  },

  {
    id: 1388,
    source: 'NTDS Replication',
    channel: 'Directory Service',
    severity: 'Error',
    skill_level: 'Advanced',
    title: 'AD Replication: Lingering Object Detected',
    short_desc: 'A domain controller has objects that do not exist on other DCs — indicates replication was broken for longer than the tombstone lifetime.',
    description: 'Event 1388 indicates that during replication, the receiving DC was offered an object by the source DC that the receiving DC believes was deleted (a tombstone exists or the object is absent beyond the tombstone lifetime). This "lingering object" situation means the source DC was offline or disconnected during the tombstone lifetime (default 180 days) and was never properly demoted. When it came back online, it is sending objects that the rest of the domain has already deleted. This requires immediate resolution — lingering objects can cause directory inconsistencies and access problems.',
    why_it_happens: 'Lingering objects occur when a DC is offline for longer than the AD tombstone lifetime (typically 60 days in older environments, 180 days in newer ones), then brought back online without being properly demoted. The DC\'s database contains objects that the rest of the forest has deleted, and it tries to replicate them back in.',
    what_good_looks_like: 'No 1388 events. All DCs replicate continuously. Any DC that has been offline for > 60 days is not brought back online without first being demoted and re-promoted.',
    common_mistakes: [
      'Bringing a DC back online after extended offline time without checking tombstone lifetime',
      'Not promptly demoting a DC before decommissioning — a DC\'s machine account sitting in AD creates lingering object risk if the DC is later re-imaged and rejoined',
      'Not monitoring replication health — lingering objects are a symptom of long-running replication failure'
    ],
    causes: [
      'DC was offline longer than the tombstone lifetime and brought back online',
      'VM snapshot restored on a DC after tombstone lifetime elapsed',
      'Site link failure caused a DC to be isolated for extended period',
      'DR failover restored a DC from an old backup'
    ],
    steps: [
      'Identify the source DC with lingering objects from the event message',
      'Do NOT let the source DC inbound-replicate from any DC until resolved',
      'Identify all lingering objects: repadmin /removelingeringobjects <destDC> <sourceGUID> <NC> /advisorymode',
      'Remove lingering objects: repadmin /removelingeringobjects <destDC> <sourceGUID> <NC>',
      'If the problematic DC is severely out of date: demote and re-promote it',
      'Enable strict replication consistency to prevent future lingering objects: repadmin /regkey <DC> +strict'
    ],
    symptoms: [
      'lingering objects AD',
      'replication consistency error',
      'AD objects coming back after deletion',
      'domain controller tombstone',
      'objects reappearing in Active Directory',
      'replication object error',
      'DC been offline too long',
      'old DC brought back online replication error'
    ],
    tags: ['active-directory', 'replication', 'lingering-objects', 'domain-controller', 'tombstone'],
    powershell: `# Lingering Object and Replication Consistency Check
# Eventful

# Check for 1388 (lingering objects) and 1311 (replication failure)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Directory Service'
    Id           = @(1311, 1388, 1865)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Identify lingering objects (advisory mode — no changes made)
# repadmin /removelingeringobjects <DestDCName> <SourceDCGuid> <NC> /advisorymode

# Check tombstone lifetime
# (Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$(([ADSI]'LDAP://RootDSE').configurationNamingContext)" -Properties tombstoneLifetime).tombstoneLifetime`,
    related_ids: [1311, 1864, 2042],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-objects-remain-ad-replication'
  },

  {
    id: 1864,
    source: 'NTDS Replication',
    channel: 'Directory Service',
    severity: 'Warning',
    skill_level: 'Advanced',
    title: 'AD Replication: Partner Has Not Replicated Within Tombstone Lifetime Warning',
    short_desc: 'A replication partner has not replicated for an extended time — approaching tombstone lifetime limit.',
    description: 'Event 1864 is a proactive warning generated when a domain controller has not replicated with a partner DC for more than half the tombstone lifetime. This is your early warning before 1388 (lingering objects) and 2042 (replication stopped due to tombstone exceeded). Resolving the underlying replication failure before the tombstone lifetime is exceeded prevents the much more serious lingering object problem.',
    why_it_happens: 'This warning fires automatically based on time-since-last-replication tracking in NTDS. It means a persistent replication failure has been present for an extended period and has not been resolved. By this point, automatic recovery may no longer be possible if the failure continues.',
    what_good_looks_like: 'No 1864 events. All DCs replicating successfully. Replication interval appropriate for the environment (maximum 24 hours for intra-site, longer for slow WAN links).',
    common_mistakes: [
      'Not acting immediately on 1864 — waiting for full tombstone lifetime expiry makes recovery much harder',
      'Not checking whether the DC is in a remote branch office site with an intermittent WAN link',
      'Not verifying that the failing DC has not already been decommissioned without being formally demoted'
    ],
    causes: [
      'Ongoing replication failure since before 1864 threshold',
      'WAN link to remote site DC persistently down',
      'DC in isolated network segment unable to reach other DCs',
      'DC decommissioned without proper demotion'
    ],
    steps: [
      'Treat as emergency — tombstone may be approaching expiry',
      'Run repadmin /replsummary to confirm which partner has the failure',
      'Check underlying cause: network, DNS, time, RPC errors',
      'Forcibly replicate: repadmin /syncall /AdeP',
      'Check tombstone lifetime: Get-ADObject with tombstoneLifetime attribute',
      'If replication cannot be restored before tombstone lifetime: plan to demote and re-promote the isolated DC'
    ],
    symptoms: [
      'DC not replicating for long time',
      'replication tombstone warning',
      'partner not replicated',
      'AD replication extended failure',
      'domain controller replication silent failure',
      'AD replication warning extended time'
    ],
    tags: ['active-directory', 'replication', 'tombstone', 'domain-controller', 'warning'],
    powershell: `# Check Replication Failure Duration
# Eventful

# Time since last successful replication per partner
repadmin /showrepl * /csv | ConvertFrom-Csv |
    Select-Object 'Destination DSA', 'Naming Context', 'Number of Failures', 'Last Failure Time', 'Last Success Time' |
    Where-Object { [int]$_.'Number of Failures' -gt 0 } |
    Sort-Object 'Last Failure Time' | Format-Table -AutoSize`,
    related_ids: [1311, 1388, 2042],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/diagnose-replication-failures'
  },

  {
    id: 2042,
    source: 'NTDS Replication',
    channel: 'Directory Service',
    severity: 'Error',
    skill_level: 'Advanced',
    title: 'AD Replication: Stopped — Tombstone Lifetime Exceeded',
    short_desc: 'AD replication has been forcibly halted because the replication gap exceeds the tombstone lifetime.',
    description: 'Event 2042 is the most critical Active Directory replication event — it means Windows has halted replication with a partner DC because the time since last successful replication exceeds the tombstone lifetime. At this point, the partner DC likely has lingering objects (deleted objects that were not tombstoned on it). Windows stops replication to prevent these lingering objects from flooding back into the directory. The affected DC is effectively isolated and must be manually remediated or re-promoted.',
    why_it_happens: 'When a DC has been isolated from replication for longer than the tombstone lifetime (typically 180 days), Windows refuses to resume replication automatically because it cannot safely merge the diverged databases. This is a failsafe to prevent corruption of the entire AD forest.',
    what_good_looks_like: 'No 2042 events, ever. Active monitoring of 1864 (early warning) to catch and fix issues before they escalate to 2042.',
    common_mistakes: [
      'Forcing replication to resume with /force flag without first removing lingering objects — this can corrupt the AD database forest-wide',
      'Not involving all DC administrators in the remediation — changes on one DC affect all DCs in the domain'
    ],
    causes: [
      'A DC was isolated from replication for longer than the tombstone lifetime',
      'Replication failure existed since before 1864 was generated and was not resolved',
      'A DC was restored from backup that is older than the tombstone lifetime'
    ],
    steps: [
      'Do NOT force replication without first removing lingering objects',
      'Identify and remove lingering objects on the affected DC: repadmin /removelingeringobjects',
      'Re-enable replication after lingering objects removed: repadmin /regkey <DC> -allowDivergent',
      'If the DC is severely outdated or has too many lingering objects: graceful demotion and re-promotion is cleaner',
      'After resolution: enable strict replication consistency on all DCs'
    ],
    symptoms: [
      'AD replication stopped',
      'replication tombstone exceeded',
      'domain controller isolation replication',
      'AD replication halted',
      'lingering objects replication stopped',
      'DC tombstone violation'
    ],
    tags: ['active-directory', 'replication', 'tombstone', 'domain-controller', 'critical'],
    powershell: `# Critical: AD Replication Tombstone Exceeded
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName      = 'Directory Service'
    Id           = 2042
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending | Format-List

# Check tombstone lifetime (days)
(Get-ADObject -Identity (
    "CN=Directory Service,CN=Windows NT,CN=Services," +
    ([ADSI]"LDAP://RootDSE").configurationNamingContext
) -Properties tombstoneLifetime -ErrorAction SilentlyContinue).tombstoneLifetime

# Show replication failures with age
repadmin /showrepl * /errorsonly`,
    related_ids: [1388, 1864, 1311],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-objects-remain-ad-replication'
  },

  {
    id: 1925,
    source: 'NTDS Replication',
    channel: 'Directory Service',
    severity: 'Warning',
    skill_level: 'Advanced',
    title: 'AD Replication: Attempt to Establish Replication Link Failed',
    short_desc: 'A domain controller could not establish a replication link with a partner — new connection setup failed.',
    description: 'Event 1925 is generated when a DC attempts to create or re-establish a replication link (connection object) to another DC and fails. This is typically a DNS or RPC connectivity issue. Unlike 1311 (ongoing failure), 1925 often indicates a new or intermittent connectivity problem. The event message includes the specific Windows error code that caused the failure, which is the most useful diagnostic field.',
    why_it_happens: 'Replication link setup requires: DNS name resolution of the partner, RPC endpoint mapper (port 135) access, and negotiated RPC dynamic port access. Failure at any of these steps produces 1925 with a specific error code. Error 8524 = DNS lookup failure, Error 1722 = RPC server unavailable, Error 5 = Access denied.',
    what_good_looks_like: 'No 1925 events. All DCs can resolve each other by DNS FQDN and communicate on required ports.',
    common_mistakes: [
      'Not reading the error code — different codes mean completely different root causes',
      'Checking only firewall rules without checking DNS — error 8524 is DNS, not firewall'
    ],
    causes: [
      'DNS failure — partner DC not resolvable by FQDN',
      'Firewall blocking RPC port 135 or dynamic RPC ports',
      'RPC service stopped on partner DC',
      'Access denied — Kerberos authentication failure between DCs',
      'Time skew preventing Kerberos authentication'
    ],
    steps: [
      'Note the error code from the event message',
      'Error 8524: run dcdiag /test:dns on both DCs',
      'Error 1722: check RPC service and firewall on the partner DC',
      'Error 5: check time sync and Kerberos authentication',
      'Run: dcdiag /test:replications for a comprehensive check',
      'Run: netdiag to check general DC network health'
    ],
    symptoms: [
      'AD replication connection failed',
      'DC cannot connect to partner',
      'replication link error',
      'AD replication RPC error',
      'DNS replication failure',
      'replication access denied',
      'cannot establish replication AD'
    ],
    tags: ['active-directory', 'replication', 'dns', 'rpc', 'domain-controller'],
    powershell: `# AD Replication Link Failure Diagnosis
# Eventful

# Replication link failure events
Get-WinEvent -FilterHashtable @{
    LogName      = 'Directory Service'
    Id           = @(1925, 1926)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# DNS check on DC (run as admin on affected DC)
dcdiag /test:dns /DnsBasic

# RPC connectivity test
# portqry -n <partnerDCIP> -e 135`,
    related_ids: [1311, 1388, 2042],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/diagnose-replication-failures'
  }
];
