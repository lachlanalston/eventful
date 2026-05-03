export const dnsEvents = [
  {
    id: 2,
    source: 'DNS',
    channel: 'DNS Server',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'DNS Server Started',
    short_desc: 'The DNS Server service started — useful for pinpointing when DNS came back online after an outage.',
    description: 'Event 2 in the DNS Server log records when the DNS service starts. On its own it is informational, but its timing is valuable in incident analysis: confirming when DNS came back after an outage, verifying DNS started after a server reboot, or identifying if DNS was stopped and restarted mid-session. The gap between Event 3 (stopped) and Event 2 (started) is the exact DNS downtime window. Note: DNS events are written to the "DNS Server" event log, not the System log.',
    why_it_happens: 'Windows DNS Server writes this event to its own DNS Server log whenever the DNS service starts — whether from a system boot, a manual restart, or automatic recovery after a crash.',
    what_good_looks_like: 'Event 2 appearing shortly after a system boot (matching Event 6005 in the System log). An Event 2 without a preceding Event 3 from the same session may indicate the service was restarted or recovered mid-session.',
    common_mistakes: [
      'Looking for DNS start events in the System log — DNS writes to its own "DNS Server" log (Windows Logs → DNS Server in Event Viewer)',
      'Not correlating Event 2 timestamps with client DNS failure windows — the gap between Events 3 and 2 is the outage duration'
    ],
    causes: [
      'System boot sequence starting all services',
      'Administrator manually restarted the DNS service',
      'Automatic service recovery after a crash',
      'DNS restarted after a configuration change'
    ],
    steps: [
      'Open Event Viewer → Windows Logs → DNS Server',
      'Filter for Event IDs 2 (start) and 3 (stop) to build a DNS availability timeline',
      'Correlate with System Events 6005/6008 to determine if DNS started with the OS or was restarted separately',
      'If investigating a client DNS outage: the gap between Event 3 and the next Event 2 is the exact downtime window'
    ],
    symptoms: [
      'when did dns server start',
      'dns server restarted',
      'dns came back online',
      'dns availability timeline',
      'dns service restart time',
      'when was dns restored',
      'dns start time',
      'dns service recovery'
    ],
    tags: ['dns', 'service', 'start', 'availability', 'server', 'timeline'],
    powershell: `# DNS Server start/stop history — last 30 days
# Eventful

Get-WinEvent -FilterHashtable @{
    LogName   = 'DNS Server'
    Id        = @(2, 3)
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 2) {'STARTED'} else {'STOPPED'} }} |
    Sort-Object TimeCreated | Format-Table -AutoSize`,
    related_ids: [3, 4000, 4007],
    ms_docs: null
  },

  {
    id: 3,
    source: 'DNS',
    channel: 'DNS Server',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'DNS Server Stopped',
    short_desc: 'The DNS Server service stopped — clients using this server for name resolution will fail until it restarts.',
    description: 'Event 3 in the DNS Server log records when the DNS service stops. This covers both clean stops (admin action, planned maintenance) and stops caused by a crash or service failure. If DNS stops and does not immediately restart, all clients using this server for name resolution begin failing. On a domain controller, DNS stopping also breaks Kerberos authentication and AD replication, which both rely on DNS. Event 3 without a following Event 2 means the service stayed down.',
    why_it_happens: 'DNS Server service stops when: an administrator explicitly stops it, the server is shutting down, the service crashes and is not configured to auto-restart, or a configuration corruption causes start failure.',
    what_good_looks_like: 'Event 3 should only appear during planned maintenance or server shutdown. Any Event 3 outside a maintenance window should be investigated immediately — check whether Event 2 follows quickly (auto-recovery) or the service stayed stopped.',
    common_mistakes: [
      'Not checking if DNS auto-restarted — look for Event 2 immediately after the Event 3',
      'Forgetting that DNS stopping on a DC causes Kerberos failures and domain authentication outages for all clients',
      'Not checking System log for Event 7034 or 7031 with "DNS Server" which would show why it crashed'
    ],
    causes: [
      'Administrator manually stopped the service for maintenance',
      'Service crash — check System log for Event 7034 naming "DNS Server"',
      'Server shutdown or restart in progress',
      'DNS configuration corruption causing start failure on recovery attempt'
    ],
    steps: [
      'Note the timestamp and check if Event 2 follows shortly — if not, DNS was down for an extended period',
      'Check System log for Event 7034 or 7031 with "DNS Server" around the same time',
      'Restart DNS if stopped: Start-Service DNS or net start dns',
      'Verify zones loaded after restart: Get-DnsServerZone — check no zones are in a failed state',
      'If on a DC: check AD replication health with repadmin /replsummary after DNS is restored'
    ],
    symptoms: [
      'dns server stopped',
      'dns service stopped',
      'dns not responding',
      'dns server down',
      'dns outage',
      'name resolution stopped working',
      'dns service crashed',
      'clients cannot resolve dns',
      'dns went offline',
      'no dns resolution',
      'domain name lookup failing',
      'dns server unavailable'
    ],
    tags: ['dns', 'service', 'stop', 'outage', 'server', 'availability', 'critical'],
    powershell: `# DNS service status and recent stop/start history
# Eventful

# Current DNS service status
Get-Service DNS | Select-Object Name, Status, StartType

# Stop and start history — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName   = 'DNS Server'
    Id        = @(2, 3)
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 2) {'STARTED'} else {'STOPPED'} }} |
    Sort-Object TimeCreated | Format-Table -AutoSize`,
    related_ids: [2, 4000, 4007],
    ms_docs: null
  },

  {
    id: 4000,
    source: 'DNS',
    channel: 'DNS Server',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'DNS Server Cannot Access Active Directory',
    short_desc: 'The DNS server cannot read zone data from Active Directory — all AD-integrated DNS zones will fail to load.',
    description: 'Event 4000 means the DNS Server service could not open or connect to Active Directory to load DNS zone data. Windows DNS servers in an AD environment store zone records in AD (AD-integrated zones). If DNS cannot reach AD, it cannot load those zones, and resolution fails for any AD-integrated zone. On a domain controller, this almost always indicates an AD DS service problem rather than a DNS problem — DNS is the symptom, the AD DS service or database is the cause.',
    why_it_happens: 'AD-integrated zone data is stored in the AD database (NTDS.DIT) and accessed by DNS via LDAP. If the AD DS service (ntds) is not running, if LDAP is unavailable, or if AD replication left the DC with corrupt partition data, DNS cannot read zone information and logs Event 4000.',
    what_good_looks_like: 'Event 4000 should never appear in a healthy environment. Its presence always warrants investigation into AD DS health on that domain controller.',
    common_mistakes: [
      'Restarting the DNS service without first confirming AD DS is running — DNS will fail again immediately',
      'Treating DNS as the root cause when the actual problem is AD DS service failure',
      'Not checking AD replication health alongside Event 4000 — they often occur together'
    ],
    causes: [
      'Active Directory Domain Services (NTDS) service not running',
      'LDAP port unavailable on the local machine',
      'AD database corruption',
      'AD replication failure leaving partition data unavailable',
      'DNS service starting before AD DS completes initialization on boot (usually self-resolves)'
    ],
    steps: [
      'Check if AD DS is running: Get-Service NTDS',
      'If NTDS stopped: Start-Service NTDS, then check the Directory Service event log for errors',
      'Run AD replication health: repadmin /replsummary',
      'Test LDAP connectivity locally: Test-NetConnection 127.0.0.1 -Port 389',
      'Once AD DS is confirmed healthy: Restart-Service DNS',
      'Verify zones loaded: Get-DnsServerZone — check for failed zones',
      'Run full DNS/AD diagnostic: dcdiag /test:dns /v'
    ],
    symptoms: [
      'dns cannot access active directory',
      'ad integrated dns zone not loading',
      'dns zones failed to load',
      'dns server cannot read active directory',
      'dns zones missing on domain controller',
      'active directory dns failure',
      'dns zone load error on dc',
      'dns broken after ad problem',
      'dns zones empty after reboot',
      'all dns zones missing'
    ],
    tags: ['dns', 'active-directory', 'zone', 'error', 'domain-controller', 'ad-integrated'],
    powershell: `# DNS and Active Directory health check
# Eventful

# Service status
Get-Service NTDS, DNS | Select-Object Name, Status

# DNS zone status
Get-DnsServerZone |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, ZoneFile, IsReverseLookupZone

# AD replication summary
repadmin /replsummary

# Recent DNS AD errors
Get-WinEvent -FilterHashtable @{
    LogName   = 'DNS Server'
    Id        = @(4000, 4007)
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List`,
    related_ids: [3, 4007, 2],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-server-event-4000-4007'
  },

  {
    id: 4007,
    source: 'DNS',
    channel: 'DNS Server',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'DNS Zone Not Loaded from Active Directory',
    short_desc: 'A specific DNS zone failed to load from AD — records for that zone are unavailable until the zone loads.',
    description: 'Event 4007 is zone-specific: DNS connected to Active Directory successfully but could not load data for a particular zone. The zone name is in the event message. This is more targeted than Event 4000 (which means AD is completely unreachable). With Event 4007, AD is accessible but the specific zone partition has a problem — common on newly promoted DCs that have not yet received zone data via replication, or when a zone was deleted on one DC and the deletion is replicating.',
    why_it_happens: 'AD-integrated DNS zones are stored in specific AD partition objects (ForestDNSZones or DomainDNSZones). If the zone object is corrupt, missing from the local replica, or if replication has not yet delivered the zone data to this DC, Event 4007 fires.',
    what_good_looks_like: 'No Event 4007. A newly promoted DC may briefly log 4007 for zones not yet replicated — this normally resolves after initial replication completes. Persistent 4007 for an active zone requires investigation.',
    common_mistakes: [
      'Assuming all DNS is broken when only one specific zone failed — check which zone name appears in the message',
      'Not checking AD replication to see whether zone data has actually arrived on this DC',
      'Deleting and recreating a zone without checking whether other DCs have already replicated the original'
    ],
    causes: [
      'Zone data not yet replicated to this DC after zone creation or DC promotion',
      'AD replication failure leaving zone partition out of sync',
      'Zone object deleted on another DC with the deletion replicating here',
      'Corrupt zone object in the local AD database',
      'ForestDNSZones or DomainDNSZones partition not fully mounted'
    ],
    steps: [
      'Note the zone name from the Event 4007 message',
      'Check replication: repadmin /showrepl to see if this DC is receiving updates',
      'Verify the zone exists on another DC: Get-DnsServerZone -ComputerName <other-dc>',
      'Force replication: repadmin /syncall /Ade',
      'After sync, restart DNS: Restart-Service DNS — check if 4007 reoccurs',
      'If zone is genuinely missing everywhere: recreate it as an AD-integrated zone',
      'Run dcdiag /test:dns for full DNS/AD diagnostic'
    ],
    symptoms: [
      'dns zone not loading',
      'specific dns zone failed',
      'zone missing from dns',
      'dns zone load failure ad',
      'ad dns zone error',
      'dns zone not replicating',
      'dns zone unavailable',
      'records not resolving for specific domain',
      'dns zone failed after replication issue',
      'new dc missing dns zones',
      'zone empty after dc promotion'
    ],
    tags: ['dns', 'zone', 'active-directory', 'replication', 'error', 'domain-controller'],
    powershell: `# DNS zone errors and replication status
# Eventful

# Zone load errors — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName   = 'DNS Server'
    Id        = 4007
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List

# All DNS zones and status
Get-DnsServerZone |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, ZoneFile, IsReverseLookupZone

# Replication summary
repadmin /replsummary`,
    related_ids: [4000, 2, 3],
    ms_docs: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-server-event-4000-4007'
  },

  {
    id: 6527,
    source: 'DNS',
    channel: 'DNS Server',
    severity: 'Warning',
    skill_level: 'Advanced',
    title: 'DNS Zone Transfer Failed',
    short_desc: 'A zone transfer from this DNS server to a secondary failed — the secondary may serve stale records.',
    description: 'Event 6527 means an attempt to transfer a DNS zone to a secondary DNS server (AXFR full transfer or IXFR incremental) did not complete. Zone transfers keep secondary DNS servers in sync with the primary. Repeated transfer failures mean the secondary serves outdated records to clients. This is most relevant in environments with secondary DNS servers outside the primary AD environment (ISPs, DMZ secondaries, external resolvers). Note: AD-integrated zone sync between DCs uses AD replication, not zone transfers — this event does not apply to DC-to-DC DNS sync.',
    why_it_happens: 'Zone transfers fail when: the requesting secondary\'s IP is not listed in the zone\'s transfer permission list, TCP port 53 is blocked between primary and secondary, the zone is very large causing a connection timeout, or the secondary server is decommissioned but still configured.',
    what_good_looks_like: 'No Event 6527 for legitimate secondaries. Persistent 6527 from an IP you don\'t recognize may indicate an unauthorized transfer attempt.',
    common_mistakes: [
      'Not checking if the secondary server IP is in the zone transfer permission list — this is the most common cause',
      'Testing connectivity with ping — zone transfers require TCP 53, not ICMP',
      'Confusing DC-to-DC AD replication with zone transfers — DCs do not use zone transfers to sync, they use AD replication'
    ],
    causes: [
      'Secondary server IP not listed in the zone\'s allowed transfer list',
      'Firewall blocking TCP port 53 between primary and secondary',
      'Secondary server decommissioned but still configured in zone notifications',
      'Zone is too large causing the transfer connection to time out'
    ],
    steps: [
      'Note the secondary server IP from the Event 6527 message',
      'Check zone transfer permissions: DNS Manager → Zone → Properties → Zone Transfers tab',
      'Test TCP port 53 to the secondary: Test-NetConnection <secondary-IP> -Port 53',
      'If the secondary is valid: add its IP to the zone transfer list',
      'Force a test transfer: dnscmd /ZoneRefresh <zonename>',
      'If the secondary is decommissioned: remove it from transfer and notify lists'
    ],
    symptoms: [
      'dns zone transfer failed',
      'secondary dns not updating',
      'dns zone not syncing to secondary',
      'zone transfer error',
      'secondary dns has stale records',
      'secondary dns out of date',
      'dns secondary server not syncing',
      'zone transfer refused'
    ],
    tags: ['dns', 'zone-transfer', 'secondary', 'replication', 'warning', 'server'],
    powershell: `# DNS zone transfer configuration and errors
# Eventful

# Zone transfer settings
Get-DnsServerZone |
    Select-Object ZoneName, TransferServersSpecified, SecondaryServers, NotifyServers

# Zone transfer errors — last 7 days
Get-WinEvent -FilterHashtable @{
    LogName   = 'DNS Server'
    Id        = @(6527, 6702)
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Format-List`,
    related_ids: [2, 3, 4007],
    ms_docs: null
  }
];
