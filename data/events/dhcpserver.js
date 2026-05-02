export const dhcpServerEvents = [
  {
    id: 1046,
    source: 'Microsoft-Windows-DHCP-Server',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'DHCP Server Not Authorized in Active Directory',
    short_desc: 'DHCP server is not authorized in AD and has shut down to prevent IP address conflicts.',
    description: 'Event 1046 from the DHCP Server service indicates the server has determined it is not authorized in Active Directory and has stopped serving IP addresses to prevent rogue DHCP from disrupting the network. This is a built-in AD protection that stops unauthorized DHCP servers from handing out incorrect IP configurations. Any clients that arrive at the unauthorized server will fail to obtain a lease.',
    why_it_happens: 'Windows DHCP servers check Active Directory to verify they are authorized to serve addresses on the domain. A server fails authorization if: it was never authorized by a Domain Admin using the DHCP MMC console or netsh, the server\'s IP address changed after authorization, or the server cannot reach a domain controller to verify its authorization status.',
    what_good_looks_like: 'No 1046 events. DHCP service running in Authorized state. Clients obtain leases normally. DHCP MMC shows the server with a green icon (authorized).',
    common_mistakes: [
      'Adding a new DHCP server and forgetting to authorize it before going live',
      'Cloning a DHCP server VM without re-authorizing the new IP address in AD',
      'Not checking that the DHCP server can reach a domain controller — if AD is unreachable, it may also stop serving addresses'
    ],
    causes: [
      'DHCP server was never authorized in Active Directory by a Domain Admin',
      'Server IP address changed after authorization',
      'Server cannot reach a domain controller to verify authorization (network issue)',
      'Server was deauthorized accidentally or intentionally',
      'Rogue DHCP server detection triggered on a legitimate server in a workgroup'
    ],
    steps: [
      'Log on to the DHCP server with a Domain Admin account',
      'Open DHCP MMC console (dhcpmgmt.msc)',
      'Right-click the server name → Authorize',
      'Wait 30–60 seconds, then right-click → Refresh — the server should show as Authorized (green icon)',
      'If the icon remains red: verify DNS resolves the server name and it can reach a DC: nltest /dsgetdc:<domain>',
      'Alternatively via command line: netsh dhcp add server <serverFQDN> <serverIP>',
      'After authorization, verify clients can obtain leases: ipconfig /release && ipconfig /renew on a test client'
    ],
    symptoms: [
      'DHCP server not giving out IPs',
      'clients cannot get IP address from DHCP',
      'DHCP server unauthorized',
      'computers getting APIPA 169.254 addresses',
      'DHCP stopped working',
      'no DHCP leases being issued',
      'DHCP server shut itself down',
      'clients not getting IP after server added',
      'DHCP not authorized AD'
    ],
    tags: ['dhcp', 'ip-addressing', 'active-directory', 'authorization', 'network'],
    powershell: `# DHCP Server Authorization Status
# Eventful

# Check DHCP service status
Get-Service DHCPServer -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType

# Recent DHCP Server errors (1046, 1047 = unauthorized events)
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DHCP-Server'
    Id           = @(1046, 1047, 1048)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Check authorized DHCP servers in AD (requires DHCP or Domain Admin rights)
# netsh dhcp show server

# Check DC reachability for DHCP authorization
# nltest /dsgetdc:<yourdomain.com>`,
    related_ids: [1047, 1048, 1063],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-deploy-wps'
  },

  {
    id: 1020,
    source: 'Microsoft-Windows-DHCP-Server',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'DHCP Scope Address Pool Exhausted',
    short_desc: 'DHCP scope has run out of available IP addresses — new clients will fail to get a lease.',
    description: 'Event 1020 indicates that a DHCP scope has exhausted its available IP address pool. New clients requesting an address will receive no offer from the server and will fall back to APIPA (169.254.x.x) or fail to connect to the network. Existing leases are unaffected until they expire. This event is critical for any environment where devices regularly join the network.',
    why_it_happens: 'Scope exhaustion occurs when the number of concurrent clients exceeds the number of addresses in the scope, or when stale leases from decommissioned devices have not expired. Short lease times can cause exhaustion on busy networks (conference rooms, wireless), and malicious DHCP starvation attacks can deliberately exhaust a scope.',
    what_good_looks_like: 'Scope utilization below 80%. Lease duration appropriate for the environment (1 day for stable clients, shorter for guest Wi-Fi). Regular lease cleanup for stale/inactive entries.',
    common_mistakes: [
      'Setting lease duration too long (e.g., 8 days) — stale leases from decommissioned PCs fill the pool',
      'Not expanding the scope or adding a superscope when the network grows',
      'Not monitoring scope utilization; 1020 is the emergency alert, not a proactive warning'
    ],
    causes: [
      'Network has grown beyond the scope\'s address range',
      'Stale leases from decommissioned devices holding addresses',
      'Lease duration too long relative to client turnover rate',
      'DHCP starvation attack (malicious client requesting all available leases)',
      'Scope exclusions and reservations consuming too much of the range'
    ],
    steps: [
      'Open DHCP MMC → expand the scope → Address Pool — check how many addresses remain',
      'View active leases: DHCP MMC → Leases — identify inactive or stale entries',
      'Short-term: delete stale leases manually for decommissioned devices',
      'Medium-term: expand the scope address range if subnet permits',
      'Consider reducing lease duration for dynamic clients to reclaim addresses faster',
      'Add a secondary scope or expand the subnet if the network has genuinely grown',
      'Monitor scope utilization: Get-DhcpServerv4ScopeStatistics -ComputerName <server>'
    ],
    symptoms: [
      'DHCP scope full',
      'clients not getting IP address',
      'computers getting 169.254 address',
      'DHCP ran out of addresses',
      'new devices cannot join network',
      'DHCP pool exhausted',
      'IP address pool full',
      'APIPA address all computers',
      'no DHCP lease available'
    ],
    tags: ['dhcp', 'ip-addressing', 'scope', 'exhaustion', 'network', 'leases'],
    powershell: `# DHCP Scope Utilization and Stale Leases
# Eventful

$dhcpServer = $env:COMPUTERNAME  # Replace with DHCP server name if remote

# Scope utilization summary
Get-DhcpServerv4ScopeStatistics -ComputerName $dhcpServer |
    Select-Object ScopeId, AddressesFree, AddressesInUse,
        @{N='UtilPct'; E={ [math]::Round($_.AddressesInUse / ($_.AddressesFree + $_.AddressesInUse) * 100, 1) }} |
    Sort-Object UtilPct -Descending | Format-Table -AutoSize

# Leases not seen for more than 30 days (potential stale)
Get-DhcpServerv4Lease -ComputerName $dhcpServer -ScopeId <scopeId> -ErrorAction SilentlyContinue |
    Where-Object { $_.LeaseExpiryTime -lt (Get-Date).AddDays(-30) } |
    Select-Object IPAddress, HostName, ClientId, LeaseExpiryTime |
    Sort-Object LeaseExpiryTime | Format-Table -AutoSize`,
    related_ids: [1063, 1046],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-deploy-wps'
  },

  {
    id: 1063,
    source: 'Microsoft-Windows-DHCP-Server',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'DHCP DNS Update Failed',
    short_desc: 'DHCP server could not dynamically update DNS records for a client lease.',
    description: 'Event 1063 is logged when the DHCP server attempts to register or update a DNS A record on behalf of a client (DDNS — Dynamic DNS) and the DNS server refuses or is unreachable. Clients whose DNS records are not updated will not be resolvable by hostname on the network, causing failures in any application or script that resolves names. This is common in environments with misconfigured DNS zones or after DHCP service account changes.',
    why_it_happens: 'DHCP dynamic DNS updates require the DHCP server to have permission to write DNS records on behalf of clients. For Active Directory-integrated zones, the DHCP Administrators group or the DnsUpdateProxy group must be configured. If the DHCP server computer account lacks permission to create/modify records in the DNS zone, all DDNS updates fail.',
    what_good_looks_like: 'DHCP server registers A (and PTR) records for clients on lease issue/renewal. Clients resolvable by hostname from DNS. No 1063 events in System log.',
    common_mistakes: [
      'Forgetting to add the DHCP server to the DnsUpdateProxy group for secure DNS updates',
      'Using the DHCP server computer account for DNS updates instead of a dedicated credential',
      'Not checking if the DNS zone is configured for "Secure and nonsecure" or "Secure only" updates',
      'Not updating the DHCP DNS credentials after a service account password change'
    ],
    causes: [
      'DHCP server lacks permission to write to AD-integrated DNS zone',
      'DNS server is offline or unreachable from DHCP server',
      'DNS zone configured for secure-only updates and DHCP uses wrong credentials',
      'DHCP service account credentials used for DNS updates have expired',
      'DNS zone does not allow dynamic updates (set to None)'
    ],
    steps: [
      'Open DHCP MMC → right-click server → Properties → DNS tab — review DDNS settings',
      'Check the credentials used for DNS updates: DHCP MMC → server Properties → Advanced → Credentials',
      'Verify the DNS zone allows dynamic updates: DNS MMC → zone Properties → General → Dynamic updates',
      'Add DHCP server to DnsUpdateProxy group in AD (for multi-DHCP environments)',
      'Test DNS update manually: ipconfig /registerdns on a test client',
      'Check DNS server reachability from DHCP server: Resolve-DnsName <clienthostname>'
    ],
    symptoms: [
      'DHCP DNS update failed',
      'computers not registering in DNS',
      'hostname not resolving on network',
      'DDNS not working',
      'DNS A record not created by DHCP',
      'clients not showing in DNS',
      'dynamic DNS update error',
      'computers missing from DNS'
    ],
    tags: ['dhcp', 'dns', 'ddns', 'dynamic-update', 'network', 'name-resolution'],
    powershell: `# DHCP DNS Update Failure Investigation
# Eventful

# Recent DHCP DNS update errors
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DHCP-Server'
    Id           = @(1063, 1064, 1065)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending |
    Select-Object -First 20 | Format-List

# Test DNS resolution for a specific client
# Resolve-DnsName "workstation01.contoso.com" -ErrorAction SilentlyContinue`,
    related_ids: [1020, 1046, 4001],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-dns-integration'
  },

  {
    id: 20080,
    source: 'Microsoft-Windows-DHCP-Server',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'DHCP Failover Partner Unreachable',
    short_desc: 'DHCP failover partner server is not responding — failover relationship at risk.',
    description: 'Event 20080 from the DHCP Server service is logged when a Windows DHCP failover partner becomes unreachable. DHCP failover allows two DHCP servers to serve the same scope for redundancy. When the partners lose communication, the active server enters a communication-interrupted state and may not be able to issue new leases from the partner\'s address pool. If the partner remains unreachable, the server may eventually enter PARTNER-DOWN state and take over the full scope.',
    why_it_happens: 'DHCP failover uses a TCP connection between partners for health checks and lease synchronization. If the partner server is offline, the network path is broken, or a firewall blocks the DHCP failover port (TCP 647), the partners lose communication and 20080 is logged. During maintenance windows, this is expected; in production without a planned maintenance, it indicates a server or network problem.',
    what_good_looks_like: 'No 20080 events outside of planned maintenance. Both DHCP servers in "Normal" failover state. DHCP MMC shows the partner as reachable. Leases are being synchronized between partners.',
    common_mistakes: [
      'Not setting the DHCP server to PARTNER-DOWN mode before planned maintenance — if the partner is offline for longer than the MCLT (Maximum Client Lead Time), the server will stop issuing addresses from the partner\'s pool',
      'Forgetting that firewall rules must allow TCP port 647 between the two DHCP servers',
      'Not monitoring DHCP failover state — a failed partner in COMMUNICATION-INTERRUPTED state for hours means clients may not renew leases correctly'
    ],
    causes: [
      'DHCP partner server is offline or the DHCP service has stopped on it',
      'Firewall blocking TCP port 647 between DHCP servers',
      'Network connectivity failure between DHCP servers',
      'DHCP service on partner crashed or was restarted',
      'Partner server is under maintenance but not set to PARTNER-DOWN mode'
    ],
    steps: [
      'Check DHCP service on the partner: Get-Service DHCPServer -ComputerName <partnerName>',
      'Test TCP 647 connectivity: Test-NetConnection -ComputerName <partnerIP> -Port 647',
      'Open DHCP MMC → server Properties → Failover tab — check current state',
      'If partner is down for planned maintenance: set to PARTNER-DOWN mode in DHCP MMC',
      'If partner is unexpectedly offline: restore the partner service/server',
      'After restoration, force synchronization: DHCP MMC → scope → right-click → Replicate Scope'
    ],
    symptoms: [
      'DHCP failover partner offline',
      'DHCP server unreachable',
      'DHCP high availability broken',
      'DHCP partner not responding',
      'DHCP redundancy failed',
      'DHCP partner communication interrupted',
      'DHCP failover error',
      'secondary DHCP server not syncing'
    ],
    tags: ['dhcp', 'failover', 'high-availability', 'network', 'redundancy'],
    powershell: `# DHCP Failover Status
# Eventful

$dhcpServer = $env:COMPUTERNAME  # Replace with DHCP server name if remote

# DHCP failover relationship status
Get-DhcpServerv4Failover -ComputerName $dhcpServer -ErrorAction SilentlyContinue |
    Select-Object Name, PartnerServer, Mode, State, MaxClientLeadTime |
    Format-Table -AutoSize

# Recent failover communication events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DHCP-Server'
    Id           = @(20080, 20081, 20082)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Test connectivity to partner
# Test-NetConnection -ComputerName <partnerIP> -Port 647`,
    related_ids: [1046, 1020, 1048],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-failover'
  },

  {
    id: 1048,
    source: 'Microsoft-Windows-DHCP-Server',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'DHCP Server Detected Another DHCP Server on Network',
    short_desc: 'DHCP server detected a conflicting DHCP server — rogue or unauthorized server active.',
    description: 'Event 1048 is logged when the Windows DHCP server detects another DHCP server responding on the same network segment. In an AD environment, this means a server that is either unauthorized (rogue) or a failover partner is sending DHCP offers. Rogue DHCP servers can hand out incorrect IP configurations (wrong gateway, DNS servers) causing network disruption for any clients that accept their offers.',
    why_it_happens: 'DHCP servers send DHCPINFORM broadcasts to detect other servers on the network. A second server responding could be an unauthorized personal router with DHCP enabled, a misconfigured VM, a network appliance, or a legitimate failover partner that has lost synchronization.',
    what_good_looks_like: 'Only authorized DHCP servers visible on the network. All DHCP offers originate from expected servers. Event 1048 not appearing in logs.',
    common_mistakes: [
      'Forgetting that consumer routers and home network devices broadcast DHCP offers by default — any device plugged into the corporate switch can become a rogue DHCP server',
      'Not checking if a new server or VM was stood up with DHCP enabled before authorization'
    ],
    causes: [
      'Unauthorized router or device plugged into the network with DHCP enabled',
      'A new DHCP server stood up without authorization',
      'DHCP failover partner misconfigured',
      'VM cloned from DHCP server without disabling DHCP service',
      'Network appliance (ISP modem, wireless AP) with built-in DHCP server active'
    ],
    steps: [
      'Identify the rogue server IP from the event message',
      'Trace the MAC address: arp -a <rogueIP> to get MAC, then trace via switch port',
      'Use Get-DhcpServerv4Lease to find the device: look for the rogue IP in any DHCP scope',
      'Once identified, disable DHCP on the rogue device or isolate the switch port',
      'Check authorized DHCP servers in AD: netsh dhcp show server',
      'After remediation, monitor for further 1048 events'
    ],
    symptoms: [
      'rogue DHCP server detected',
      'computers getting wrong IP address',
      'computers getting wrong default gateway',
      'two DHCP servers on network',
      'unauthorized DHCP server',
      'clients getting wrong DNS from DHCP',
      'DHCP conflict on network',
      'duplicate DHCP server'
    ],
    tags: ['dhcp', 'rogue-dhcp', 'network-security', 'ip-addressing', 'network'],
    powershell: `# Detect DHCP Server Conflict
# Eventful

# Recent DHCP rogue server detection events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DHCP-Server'
    Id           = @(1048, 1049)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# List authorized DHCP servers in AD
# netsh dhcp show server

# Check ARP table to find rogue server MAC
# arp -a <rogueServerIP>`,
    related_ids: [1046, 1047, 1020],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-deploy-wps'
  }
];
