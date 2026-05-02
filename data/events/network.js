export const networkEvents = [
  // DNS Events
  {
    id: 1014,
    source: 'Microsoft-Windows-DNS-Client',
    channel: 'Network',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'DNS Name Resolution Timeout',
    short_desc: 'A DNS query timed out — the DNS server did not respond within the timeout period.',
    description: 'Event ID 1014 from the DNS-Client source is generated when a DNS name resolution attempt times out — the query was sent to a DNS server but no response was received within the configured timeout. This is distinct from a DNS NXDOMAIN response (the name exists but the record doesn\'t) — a timeout means the DNS infrastructure itself is unreachable or overloaded. Repeated 1014 events cause slow application startups, web browsing delays, and network connectivity issues that users describe as "the internet is slow" or "file shares are slow to open".',
    why_it_happens: 'The Windows DNS Client Resolver sends queries to the configured DNS server(s) and waits for a response. If the primary DNS server doesn\'t respond within the timeout period, it retries, then falls back to secondary DNS server(s). If all configured servers time out, Event 1014 is logged. Common causes include the DNS server being unreachable (network issue), the DNS server being overloaded, a firewall blocking UDP/TCP port 53, or the DNS server service itself having problems.',
    what_good_looks_like: 'No Event 1014 events on a healthy machine. Occasional 1014 events during network changes are acceptable. Investigate: repeated 1014 events (the DNS server is consistently unreachable), 1014 events that correlate with user complaints about slow network, 1014 for internal names only (internal DNS server issue), 1014 for external names only (external DNS unreachable, possibly after DHCP change).',
    common_mistakes: [
      'Concluding the DNS server is down without checking if the DNS server is reachable (ping, Test-NetConnection)',
      'Fixing only the DNS setting and not finding why the DNS server became unreachable',
      'Not checking whether internal vs external names are timing out — this isolates whether the internal DNS server or upstream forwarder is the issue',
      'Ignoring 1014 during network speed investigations — DNS timeout adds latency to every hostname resolution'
    ],
    causes: [
      'DNS server IP is wrong (changed DHCP scope, manual misconfiguration)',
      'DNS server service stopped or crashed',
      'Network path to DNS server blocked by firewall or routing issue',
      'DNS server overloaded or unresponsive',
      'VPN connected and split tunneling routing DNS incorrectly',
      'DHCP lease renewed with different DNS server IPs'
    ],
    steps: [
      'Find Event 1014 and note which hostname was failing and which DNS server was queried',
      'Test DNS server reachability: Test-NetConnection -ComputerName <dns-ip> -Port 53',
      'Test DNS resolution manually: Resolve-DnsName <hostname> -Server <dns-ip>',
      'Check configured DNS servers: Get-DnsClientServerAddress',
      'Check if the DNS server service is running on the DNS server itself',
      'If VPN: check if DNS is being routed through VPN tunnel correctly',
      'If DHCP: check if DNS server IPs in DHCP scope are correct'
    ],
    symptoms: [
      'internet is slow',
      'websites slow to load',
      'dns not working',
      'cant resolve dns',
      'dns lookup failing',
      'name resolution failing',
      'dns timeout',
      'slow network',
      'network drives slow to open',
      'websites timing out'
    ],
    tags: ['dns', 'network', 'resolution', 'timeout', 'connectivity', 'fundamental'],
    powershell: `# DNS Resolution Timeout Investigation
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
Write-Host "\n--- Current DNS Configuration ---" -ForegroundColor Cyan
Get-DnsClientServerAddress -ComputerName $computer -AddressFamily IPv4 |
    Where-Object { $_.ServerAddresses.Count -gt 0 } | Format-Table -AutoSize

# Test DNS resolution
Write-Host "\n--- DNS Resolution Test ---" -ForegroundColor Cyan
Resolve-DnsName google.com -ErrorAction SilentlyContinue | Select-Object Name, Type, IPAddress | Format-Table -AutoSize`,
    related_ids: [1032, 1030],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-overview'
  },

  {
    id: 1032,
    source: 'Microsoft-Windows-DNS-Client',
    channel: 'Network',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'DNS Query Failed',
    short_desc: 'A DNS query returned an error — the record does not exist or the server returned a failure.',
    description: 'Event ID 1032 records a DNS query that failed with an error response from the DNS server — as opposed to a timeout (1014). A failure response means the DNS server responded, but the response indicated an error: NXDOMAIN (the name does not exist), SERVFAIL (the server had an internal error), REFUSED (the server declined to answer), or NOTIMP (not implemented). Understanding the specific error code helps diagnose whether the problem is a missing DNS record, a configuration issue, or a server-side problem.',
    why_it_happens: 'The DNS server processes the query and returns a negative response code. NXDOMAIN means the queried name has no records anywhere in the DNS hierarchy. SERVFAIL typically means the DNS server couldn\'t complete recursive resolution (often a problem with its forwarders or internet connectivity). REFUSED means the server is not configured to answer queries from this client.',
    what_good_looks_like: 'NXDOMAIN for external internet names is entirely normal — users and applications query names that simply don\'t exist. Investigate: NXDOMAIN for internal names that should exist (misconfigured internal DNS zone, missing record), SERVFAIL responses (the DNS server itself has a problem), repeated failures for names that should resolve (broken delegation or zone configuration).',
    common_mistakes: [
      'Assuming every DNS failure is a network problem — NXDOMAIN just means the name doesn\'t exist and is normal for typos',
      'Not distinguishing NXDOMAIN from SERVFAIL — they have completely different causes',
      'Not checking the internal DNS zone for missing records when internal names fail to resolve'
    ],
    causes: [
      'NXDOMAIN: the queried DNS name does not exist',
      'SERVFAIL: DNS server internal error, often forwarder unreachable',
      'REFUSED: client not authorised to query this DNS server',
      'Missing internal DNS record after a server rename or IP change',
      'Split-brain DNS misconfiguration'
    ],
    steps: [
      'Find Event 1032 and note the queried hostname and error code',
      'Test manually: Resolve-DnsName <hostname> -Type A',
      'If internal name: check the DNS zone for the missing record',
      'If SERVFAIL: check the DNS server\'s forwarder configuration',
      'Add missing DNS records if appropriate: Add-DnsServerResourceRecordA',
      'Flush DNS cache after fixing: Clear-DnsClientCache'
    ],
    symptoms: [
      'dns lookup failed',
      'dns error',
      'name not found dns',
      'internal dns not resolving',
      'server not found dns',
      'nxdomain error',
      'dns resolution error',
      'cannot find server dns'
    ],
    tags: ['dns', 'network', 'resolution', 'nxdomain', 'servfail', 'connectivity'],
    powershell: `# DNS Query Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-DNS-Client'
    Id           = 1032
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [1014, 1030],
    ms_docs: null
  },

  // DHCP Events
  {
    id: 1020,
    source: 'Microsoft-Windows-Dhcp-Client',
    channel: 'Network',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'DHCP: IP Address Conflict Detected',
    short_desc: 'The DHCP client detected that another device is already using the assigned IP address.',
    description: 'Event ID 1020 from the DHCP Client is generated when ARP (Address Resolution Protocol) probing detects that the IP address assigned by DHCP is already in use by another device. Windows declines the offered IP address and requests a new one. If all available IPs are in conflict or the DHCP server exhauster its pool, the machine will fall back to APIPA (169.254.x.x). This event indicates an IP conflict — two devices trying to use the same IP — which causes intermittent connectivity for both devices.',
    why_it_happens: 'When a DHCP client receives an IP address offer, it sends ARP probes to verify the address is not in use. If another device responds to the ARP, the DHCP client detects the conflict and logs 1020. Common causes: a device was manually configured with a static IP that falls inside the DHCP scope, an expired DHCP lease was reassigned while the original device was offline and returns, or DHCP scope management is incorrect.',
    what_good_looks_like: 'No Event 1020 events. Any IP conflict should be resolved immediately as it causes network disruption for the affected devices.',
    common_mistakes: [
      'Not checking the DHCP server\'s active leases to find the conflicting device',
      'Not creating DHCP exclusions for statically configured devices',
      'Not using DHCP reservations for printers and servers instead of static IPs'
    ],
    causes: [
      'Device with static IP in the DHCP scope range',
      'DHCP lease expired and address reassigned while original device was offline',
      'DHCP scope not configured with proper exclusions for static devices',
      'Rogue DHCP server assigning overlapping addresses',
      'Duplicate MAC address cloning (VMs)'
    ],
    steps: [
      'Find Event 1020 and note the conflicting IP address',
      'Check DHCP server active leases for that IP: Get-DhcpServerv4Lease -ScopeId <scope> | Where IPAddress -eq <ip>',
      'Use ARP to find the conflicting device: arp -a | findstr <ip>',
      'Identify the device with the static IP and either change it or create a DHCP exclusion',
      'Add exclusions in DHCP for all statically configured devices',
      'Consider using DHCP reservations for infrastructure devices instead of static IPs'
    ],
    symptoms: [
      'ip conflict',
      'ip address conflict',
      'duplicate ip',
      'two devices same ip',
      'address conflict dhcp',
      'network conflict ip',
      'cant connect network ip conflict',
      'intermittent network ip'
    ],
    tags: ['dhcp', 'ip-conflict', 'network', 'arp', 'connectivity'],
    powershell: `# DHCP IP Conflict Investigation
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
Write-Host "\n--- Current Network Configuration ---" -ForegroundColor Cyan
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Format-Table -AutoSize

Write-Host "\n--- ARP Cache (find conflicting device) ---" -ForegroundColor Cyan
Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } | Format-Table -AutoSize`,
    related_ids: [1030, 1048, 1063, 1014],
    ms_docs: null
  },

  {
    id: 1030,
    source: 'Microsoft-Windows-Dhcp-Client',
    channel: 'Network',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'DHCP: Unable to Obtain IP Address',
    short_desc: 'The DHCP client could not get an IP address — may fall back to APIPA (169.254.x.x).',
    description: 'Event ID 1030 is generated when the DHCP client fails to obtain an IP address from a DHCP server after multiple attempts. When this happens, the machine typically falls back to an APIPA address (169.254.x.x) which means it cannot communicate with other network devices. This is a critical network failure event. Users will report "no internet", "can\'t access file shares", or "limited connectivity".',
    why_it_happens: 'The DHCP client broadcasts DHCPDISCOVER packets and waits for a DHCPOFFER from a server. If no server responds after several retries (across multiple boot/retry cycles), 1030 is logged. Causes: DHCP server is down, the client is isolated from the DHCP server by a firewall or VLAN misconfiguration, the DHCP scope is exhausted (all IPs leased out), or the network cable/WiFi is not actually connected.',
    what_good_looks_like: 'No Event 1030 events. Any Event 1030 is a network connectivity problem requiring immediate investigation.',
    common_mistakes: [
      'Not checking the physical layer first — a disconnected cable or wrong VLAN causes 1030',
      'Trying to diagnose DHCP server issues without first verifying the client can reach the DHCP server subnet',
      'Not checking the DHCP scope for exhaustion: Get-DhcpServerv4ScopeStatistics'
    ],
    causes: [
      'Physical network disconnection (cable, port, WiFi)',
      'DHCP server offline or service stopped',
      'DHCP scope exhausted (all IPs leased)',
      'Firewall or ACL blocking DHCP traffic (UDP 67/68)',
      'VLAN or switch misconfiguration isolating the client',
      'DHCP relay agent not configured for the client\'s VLAN'
    ],
    steps: [
      'Check physical connectivity: is the cable plugged in, is the link light on the switch port active?',
      'Check if machine is in the correct VLAN: check switch port configuration',
      'Check if DHCP server is reachable (once you have an IP): ping dhcp-server',
      'Check DHCP scope statistics for exhaustion: Get-DhcpServerv4ScopeStatistics -ComputerName <dhcp-server>',
      'Force a DHCP release and renew: ipconfig /release && ipconfig /renew',
      'If APIPA address (169.254.x.x): the machine got no DHCP response at all',
      'Check DHCP server event log for related errors'
    ],
    symptoms: [
      'cant get ip address',
      'no ip address',
      '169.254 ip address',
      'limited connectivity',
      'dhcp failed',
      'no network',
      'apipa address',
      'cannot connect to network',
      'no internet dhcp',
      'network limited'
    ],
    tags: ['dhcp', 'ip-address', 'connectivity', 'apipa', 'network', 'fundamental'],
    powershell: `# DHCP IP Assignment Failure Investigation
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
Write-Host "\n--- Current IP Configuration ---" -ForegroundColor Cyan
Get-NetIPConfiguration -ComputerName $computer -ErrorAction SilentlyContinue | Format-List`,
    related_ids: [1020, 1048, 1063, 1014],
    ms_docs: null
  },

  {
    id: 1048,
    source: 'Microsoft-Windows-Dhcp-Client',
    channel: 'Network',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'DHCP: Lease Renewal Failed',
    short_desc: 'The DHCP client failed to renew its existing IP address lease.',
    description: 'Event ID 1048 is generated when the DHCP client has an existing lease but fails to renew it when the lease expires. At 50% of the lease duration, the client tries to renew with the original DHCP server. At 87.5%, it broadcasts to any DHCP server. If both fail, the lease expires and the client may lose its IP. This event indicates that the DHCP server has become unreachable since the lease was first obtained — a more subtle failure than 1030 which occurs on initial DHCP acquisition.',
    why_it_happens: 'The DHCP client contacts the DHCP server (by unicast first, then broadcast) to renew its lease before expiry. If the server doesn\'t respond, the client retries until the lease expires. The failure could be because the DHCP server changed, moved, or crashed since the lease was first obtained, or because the network path to the DHCP server has changed.',
    what_good_looks_like: 'No Event 1048 events. When 1048 appears, investigate whether the DHCP server is still reachable and whether its IP or configuration has changed.',
    common_mistakes: [
      'Not realising the machine may still have network connectivity if the lease hasn\'t expired yet',
      'Not checking if the DHCP server IP address changed (server moved or reIPed)'
    ],
    causes: [
      'DHCP server offline or IP changed',
      'Network path to DHCP server changed',
      'DHCP service stopped on server',
      'Firewall change blocking DHCP renewal traffic'
    ],
    steps: [
      'Find Event 1048 and note the DHCP server address from the event',
      'Check if that DHCP server is still reachable: Test-NetConnection -ComputerName <dhcp-ip> -Port 67',
      'Force renewal: ipconfig /renew',
      'If failure: check DHCP server status',
      'Check DHCP server event log for service issues'
    ],
    symptoms: [
      'dhcp renewal failed',
      'ip lease renewal failed',
      'dhcp lease expired',
      'network connectivity dropped after a while',
      'ip address renewal failed'
    ],
    tags: ['dhcp', 'lease-renewal', 'network', 'connectivity'],
    powershell: `# DHCP Lease Renewal Failure Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)  # Adjust time range as needed

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Dhcp-Client'
    Id           = 1048
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List`,
    related_ids: [1030, 1020, 1063],
    ms_docs: null
  },

  {
    id: 1063,
    source: 'Microsoft-Windows-Dhcp-Client',
    channel: 'Network',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'DHCP: Lost Contact with Domain Controller',
    short_desc: 'The DHCP client could not contact a domain controller — may affect domain authentication.',
    description: 'Event ID 1063 indicates that the DHCP client could not reach a domain controller, which is logged as part of the domain join and DHCP registration process. When a domain-joined machine gets a DHCP lease, it attempts to register its DNS record with the domain-integrated DNS server, which requires DC connectivity. Failure to contact the DC may indicate DNS misconfiguration, network segmentation issues, or that the DC itself is unreachable.',
    why_it_happens: 'During DHCP address acquisition or renewal on a domain-joined machine, the DHCP client service attempts to locate and contact a domain controller for DNS dynamic update authorisation. If the DC is unreachable (wrong DNS server, DC down, or network issue), Event 1063 is logged. This does not necessarily mean authentication will fail immediately (Kerberos tickets and credentials may be cached), but it indicates a domain connectivity problem.',
    what_good_looks_like: 'No Event 1063 events on a healthy domain-joined machine. If 1063 appears: the machine cannot reach a DC. Domain authentication will work if credentials are cached but will fail after cache expiry.',
    common_mistakes: [
      'Not realising 1063 can appear during transient boot-time network unavailability and not always indicating a persistent problem',
      'Ignoring 1063 on laptops that frequently move between networks',
      'Not correlating with 1014 (DNS timeout) which often precedes 1063'
    ],
    causes: [
      'DNS server not configured or unreachable (can\'t find DC)',
      'Domain Controller offline',
      'Network segmentation preventing DC communication',
      'VPN not connected (for remote workers)',
      'Firewall blocking DC communication ports'
    ],
    steps: [
      'Find Event 1063 and check if 1014 (DNS timeout) events also appear',
      'Test DC connectivity: Test-ComputerSecureChannel',
      'Find a DC: nltest /dsgetdc:<domain>',
      'Test DC ports: Test-NetConnection -ComputerName <dc> -Port 389',
      'Check DNS is configured correctly: Get-DnsClientServerAddress',
      'If VPN dependent: confirm VPN is connected'
    ],
    symptoms: [
      'cant contact domain controller',
      'domain controller unreachable',
      'dhcp domain controller',
      'lost contact with dc',
      'domain connectivity issue'
    ],
    tags: ['dhcp', 'domain-controller', 'dns', 'network', 'domain-join'],
    powershell: `# DHCP Domain Controller Contact Loss Investigation
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
Write-Host "\n--- DC Connectivity Test ---" -ForegroundColor Cyan
Test-ComputerSecureChannel -Verbose`,
    related_ids: [1014, 1030, 1048],
    ms_docs: null
  },

  // WLAN Events
  {
    id: 10317,
    source: 'Microsoft-Windows-WLAN-AutoConfig',
    channel: 'Network',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'WLAN: Network Disconnection',
    short_desc: 'The wireless adapter disconnected from a Wi-Fi network.',
    description: 'Event ID 10317 from the WLAN-AutoConfig service records a wireless network disconnection. It includes the SSID of the network, the reason code for the disconnection, and the network adapter. This is the primary event for investigating intermittent WiFi connectivity issues. The disconnection reason code distinguishes between normal disconnects (user action) and unexpected ones (signal loss, authentication failure, deauthentication from AP, or driver issues).',
    why_it_happens: 'WLAN disconnections occur when the association with the access point is lost. This can be caused by moving out of range, a 802.1X authentication failure (wrong certificate, expired password), the access point deauthenticating the client (roaming, load balancing, channel change), driver bugs, or Windows attempting to roam to a better AP and failing. The DisconnectReason field (or Reason Code) is crucial for root cause identification.',
    what_good_looks_like: 'Occasional brief disconnections while roaming between APs are normal. Investigate: frequent disconnections in a fixed location (signal, interference, or driver issue), disconnections followed by long reconnect times, disconnections with reason codes indicating authentication failure (802.1X), many clients disconnecting from the same AP simultaneously.',
    common_mistakes: [
      'Not checking the reason code — "disconnected" could mean user action or AP rejection',
      'Blaming the WiFi driver without first checking signal strength and channel utilisation',
      'Not checking if multiple devices disconnect from the same AP simultaneously (AP issue) vs one device (client issue)',
      'Not checking if the issue is with roaming between APs vs staying connected to one AP'
    ],
    causes: [
      'User or application disconnecting intentionally',
      'Signal loss — too far from AP or interference',
      '802.1X authentication failure (certificate, RADIUS server)',
      'AP deauthentication for load balancing or channel change',
      'WiFi driver bug',
      'Power management putting NIC to sleep (aggressive power saving)',
      'Roaming failure between APs'
    ],
    steps: [
      'Filter System log for Event 10317',
      'Note the SSID, adapter name, and disconnect reason code',
      'Check signal strength at the time of disconnect (may need AP or NMS)',
      'Check WiFi driver version: Get-NetAdapter -Name Wi-Fi | Select-Object DriverVersion',
      'Disable aggressive WiFi power management: Set-NetAdapterPowerManagement -Name Wi-Fi -AllowComputerToTurnOffDevice Disabled',
      'Check if 802.1X authentication is used and if certificates are valid',
      'Check channel utilisation on the AP if signal is adequate'
    ],
    symptoms: [
      'wifi drops',
      'wireless disconnects',
      'wifi keeps disconnecting',
      'wireless connection drops',
      'wifi unstable',
      'wireless keeps dropping',
      'wifi falls off',
      'laptop wifi disconnecting',
      'intermittent wifi',
      'wifi drops every few minutes'
    ],
    tags: ['wifi', 'wireless', 'wlan', 'connectivity', 'disconnect', 'network'],
    powershell: `# WiFi Disconnection Investigation
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
Write-Host "\n--- WiFi Power Management ---" -ForegroundColor Cyan
Get-NetAdapter | Where-Object { $_.MediaType -like '*802.11*' } | ForEach-Object {
    Get-NetAdapterPowerManagement -Name $_.Name | Select-Object Name, AllowComputerToTurnOffDevice
} | Format-Table -AutoSize

# Current WiFi state
Write-Host "\n--- Current WiFi Connections ---" -ForegroundColor Cyan
netsh wlan show interfaces`,
    related_ids: [10400, 1014, 1030],
    ms_docs: null
  },

  {
    id: 10400,
    source: 'Microsoft-Windows-WLAN-AutoConfig',
    channel: 'Network',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'WLAN: Association Failed',
    short_desc: 'The wireless adapter could not associate with a Wi-Fi access point.',
    description: 'Event ID 10400 records a failure to associate with a Wi-Fi access point. This is different from a disconnection (10317) — association failure occurs when the device is trying to connect but the 802.11 association exchange fails. This can happen because the SSID doesn\'t exist at that location, the authentication method is mismatched, the PSK (password) is wrong, or the AP is rejecting the client. After a successful association, authentication happens separately; if authentication then fails, that generates a different event.',
    why_it_happens: 'Wi-Fi association is the 802.11 handshake where a client requests to join an AP\'s BSS. The AP can reject the association for several reasons: the authentication type isn\'t supported, the client is blocked (MAC filtering), the AP is at capacity (maximum associations reached), or there is a mismatch in security settings (WPA2 vs WPA3). After association, 802.1X or PSK authentication occurs.',
    what_good_looks_like: 'No Event 10400 events. Any 10400 indicates the WiFi join process failed before authentication could even complete.',
    common_mistakes: [
      'Not distinguishing between association failure (10400) and authentication failure (different event) — they require different fixes',
      'Trying to fix PSK when the issue is an association-level rejection (MAC filter, capacity)',
      'Not checking if the SSID is broadcast or hidden and whether the client has the correct SSID configured'
    ],
    causes: [
      'Wrong or missing PSK for WPA2-Personal networks',
      'Security type mismatch (WPA2 vs WPA3)',
      'AP at maximum association capacity',
      'MAC address filtering on AP rejecting the client',
      'SSID moved to a different frequency band client doesn\'t support',
      'Driver not supporting the AP\'s 802.11 standard (e.g., WiFi 6E without WiFi 6 driver)'
    ],
    steps: [
      'Filter System log for Event 10400',
      'Note the SSID and reason code in the event',
      'Check if the SSID is visible in wireless networks: netsh wlan show networks',
      'Verify the PSK is correct by forgetting and re-entering the network',
      'Check for MAC filtering on the AP if PSK is definitely correct',
      'Update WiFi driver: check device manager for updates',
      'Check if other devices can connect to the same SSID from the same location'
    ],
    symptoms: [
      'wifi wont connect',
      'cant connect to wifi',
      'wifi association failed',
      'wireless connection failed',
      'cant join wifi network',
      'wifi authentication failed',
      'wrong wifi password even though correct',
      'wifi refuses to connect'
    ],
    tags: ['wifi', 'wireless', 'wlan', 'association', 'connectivity', 'authentication'],
    powershell: `# WiFi Association Failure Investigation
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
Write-Host "\n--- Available WiFi Networks ---" -ForegroundColor Cyan
netsh wlan show networks mode=bssid`,
    related_ids: [10317, 1014, 1030],
    ms_docs: null
  },

  // TCP/IP Event
  {
    id: 4226,
    source: 'Tcpip',
    channel: 'Network',
    severity: 'Warning',
    skill_level: 'Advanced',
    title: 'TCP Connection Limit Reached',
    short_desc: 'Windows reached the limit for simultaneous incomplete outbound TCP connection attempts.',
    description: 'Event ID 4226 from the Tcpip source records that the system reached the limit on simultaneous half-open TCP connection attempts. Windows limits incomplete outbound connections to throttle connection-rate-based malware (worms). On modern Windows 10/11 and Server, this limit was significantly increased (from 10 per second on XP to effectively unlimited on modern versions). If you see this event on a modern Windows system, it is unusual and may indicate aggressive scanning software, peer-to-peer applications, or malware performing port scans or rapid connection attempts.',
    why_it_happens: 'TCP half-open connections (SYN sent, SYN-ACK not yet received) are counted by the TCP/IP stack. The limit exists to prevent a single compromised machine from participating in SYN-flood attacks or worm propagation by limiting how fast it can initiate outbound connections. On modern Windows, this limit only triggers for very aggressive connection rates, so seeing this event warrants investigation of what is generating so many simultaneous connections.',
    what_good_looks_like: 'This event should essentially never appear on normal workstations or servers. If it does: immediately investigate what process is initiating so many connections. This is a strong indicator of malware, a misconfigured P2P application, or a security scanner.',
    common_mistakes: [
      'On Windows XP: this event was commonly triggered by legitimate P2P software and the limit was a nuisance. On modern Windows, it should not appear in normal operation.',
      'Assuming any process hitting this limit is malicious — security scanners and some backup tools can also trigger it'
    ],
    causes: [
      'Malware performing port scanning or worm propagation',
      'P2P application (BitTorrent) with many simultaneous connections',
      'Security scanner running on the endpoint',
      'Backup or network monitoring software making many simultaneous connections',
      'A browser loading a page with hundreds of parallel connections (rare)'
    ],
    steps: [
      'Filter System log for Event 4226',
      'Note the time of the event',
      'Check what process was generating connections around that time (Event 4688)',
      'Use netstat to check current connections: netstat -anob',
      'If malware suspected: isolate the machine and perform AV scan',
      'Check for port scanning activity in firewall logs'
    ],
    symptoms: [
      'tcp connection limit',
      'too many connections',
      'network connection limit reached',
      'tcp half open connections',
      'connection rate limit',
      'port scan detected'
    ],
    tags: ['tcp', 'network', 'connection-limit', 'malware', 'scanning', 'advanced'],
    powershell: `# TCP Connection Limit Investigation
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
Write-Host "\n--- Active TCP Connections (top talkers by process) ---" -ForegroundColor Cyan
Get-NetTCPConnection -State Established |
    Group-Object OwningProcess |
    Sort-Object Count -Descending |
    Select-Object -First 10 Count,
        @{N='Process'; E={ (Get-Process -Id $_.Name -ErrorAction SilentlyContinue).ProcessName }} |
    Format-Table -AutoSize`,
    related_ids: [4688, 4624],
    ms_docs: null
  },

  {
    id: 4201,
    source: 'Microsoft-Windows-NDIS',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Fundamental',
    title: 'Network Adapter Connected',
    short_desc: 'A network adapter transitioned to a connected state — cable plugged in or wireless associated.',
    description: 'Event 4201 from Microsoft-Windows-NDIS (Network Driver Interface Specification) is generated when a network adapter reports that its link state has changed to connected. This includes physical cable connections, Wi-Fi associations, and virtual NIC link changes. Pairing 4201 (connect) with 4202 (disconnect) gives a timeline of NIC link flaps, which are often the root cause of intermittent network problems, brief outages, or VPN drops.',
    why_it_happens: 'Link state changes are physical events reported by the network adapter driver. A 4201 event happens when a cable is plugged in, when the switch port comes up, or when a wireless client successfully associates. Normal startup causes 4201; intermittent 4201/4202 pairs during normal operation indicate a physical layer problem.',
    what_good_looks_like: 'Single 4201 event at system boot/startup. No further 4201/4202 pairs during normal operation. NIC drivers are current and NIC hardware is healthy.',
    common_mistakes: [
      'Not correlating 4201/4202 pairs when investigating intermittent network outages — link flapping is often the root cause',
      'Not checking the cable or switch port when 4201/4202 events show repeated link flaps'
    ],
    causes: [
      'Normal system startup — NIC initializing',
      'Cable plugged in or switch port brought up',
      'Wireless client associating with access point',
      'Virtual switch or virtual NIC coming online',
      'Recovery after a link flap — often paired with 4202 just before'
    ],
    steps: [
      'Check for paired 4201/4202 events — repeated pairs indicate link flapping',
      'If flapping: inspect the cable, RJ45 connector, and switch port',
      'Update NIC driver from vendor website',
      'Check switch port statistics for errors on the port',
      'Test with a known-good cable if physical connection is suspected'
    ],
    symptoms: [
      'network adapter connected',
      'network cable plugged in',
      'NIC link state changed',
      'network link up',
      'intermittent network drops',
      'network connection flapping',
      'NIC keeps connecting disconnecting'
    ],
    tags: ['network', 'ndis', 'nic', 'link-state', 'connectivity'],
    powershell: `# Network Adapter Link State History
# Eventful

# NIC connect/disconnect events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-NDIS'
    Id           = @(4201, 4202)
    StartTime    = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 4201) {'CONNECTED'} else {'DISCONNECTED'} }},
        Message |
    Sort-Object TimeCreated | Format-Table -AutoSize`,
    related_ids: [4202, 10317],
    ms_docs: null
  },

  {
    id: 4202,
    source: 'Microsoft-Windows-NDIS',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Fundamental',
    title: 'Network Adapter Disconnected',
    short_desc: 'A network adapter lost its link — cable unplugged, switch port down, or wireless disassociated.',
    description: 'Event 4202 is the disconnection counterpart to 4201. It is generated when a network adapter reports its link state has changed to disconnected. This includes physical cable disconnections, switch port going down, wireless disassociation, or driver/power management suspending the NIC. A single 4202 at system shutdown or sleep is normal; repeated 4202 events during operation indicate a physical or driver problem.',
    why_it_happens: 'Link disconnection can be physical (cable fail, bad connector, switch port issue) or logical (driver crash, power management turning off NIC, wireless roaming event). When VPN or network-dependent services drop intermittently, 4202 events are the smoking gun showing the NIC itself dropped connection.',
    what_good_looks_like: 'Only one 4202 event at system shutdown or sleep. No 4202 events during normal operation.',
    common_mistakes: [
      'Not checking NIC power management settings — "Allow the computer to turn off this device to save power" is a common cause of random NIC disconnects',
      'Not checking the switch/access point side for errors — the NIC may be reporting disconnect because the switch port is flapping'
    ],
    causes: [
      'Cable disconnected or loose connector',
      'Switch port going down or flapping',
      'NIC driver crash causing virtual disconnect',
      'Power management turning off NIC to save power',
      'Wireless client disassociating or roaming to another AP',
      'System suspending (sleep/hibernate)'
    ],
    steps: [
      'Check for repeated 4201/4202 pairs — repeated = link flapping',
      'Disable NIC power management: Device Manager → NIC → Properties → Power Management → uncheck "Allow computer to turn off this device to save power"',
      'Inspect cable and connectors; test with known-good cable',
      'Check switch port counters for errors',
      'Update NIC driver',
      'If wireless: check signal strength and roaming aggressiveness settings'
    ],
    symptoms: [
      'network disconnected',
      'NIC disconnected',
      'network adapter link dropped',
      'intermittent network loss',
      'network drops out randomly',
      'cable unplugged event',
      'network keeps disconnecting',
      'connection drops then reconnects',
      'NIC link lost'
    ],
    tags: ['network', 'ndis', 'nic', 'link-state', 'disconnect', 'connectivity'],
    powershell: `# NIC Disconnect History and Power Management Check
# Eventful

# Link state events in the last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-NDIS'
    Id           = @(4201, 4202)
    StartTime    = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 4201) {'CONNECTED'} else {'DISCONNECTED'} }} |
    Sort-Object TimeCreated | Format-Table -AutoSize

# Check NIC power management setting (if PnP device = NIC)
Get-NetAdapter | ForEach-Object {
    $adapterName = $_.Name
    [PSCustomObject]@{
        Adapter      = $adapterName
        Status       = $_.Status
        LinkSpeed    = $_.LinkSpeed
    }
} | Format-Table -AutoSize`,
    related_ids: [4201, 10317, 10400],
    ms_docs: null
  },

  {
    id: 4199,
    source: 'Tcpip',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Fundamental',
    title: 'IP Address Conflict Detected',
    short_desc: 'Two devices on the network are using the same IP address — one or both will lose connectivity.',
    description: 'Event 4199 (or similar Tcpip events for IP conflict) is generated when the Windows TCP/IP stack detects that another device on the network is using the same IP address as this computer. This causes intermittent connectivity loss as the network switches route traffic to one device or the other. The event identifies the conflicting MAC address, which can be used to track down the other device.',
    why_it_happens: 'IP conflicts occur when: a static IP is assigned to a device that is already being used by another device, a DHCP lease is not properly expired when a device is decommissioned and the same IP is later assigned to a new device, or a DHCP server gives out overlapping addresses due to misconfiguration.',
    what_good_looks_like: 'No IP conflict events. All static IPs documented and excluded from DHCP scopes. DHCP lease times appropriate so expired leases are reclaimed before reuse.',
    common_mistakes: [
      'Not documenting static IP assignments, leading to overlaps with DHCP scope',
      'Not adding static IPs as exclusions in the DHCP scope'
    ],
    causes: [
      'Static IP assigned to a device that is already in the DHCP pool and has been leased to another device',
      'Two devices manually configured with the same static IP',
      'DHCP server giving out an address that is already statically assigned',
      'Decommissioned device\'s IP reused before the lease expired on another machine'
    ],
    steps: [
      'Note the conflicting MAC address from the event',
      'Use arp -a to find the device currently holding that IP',
      'Identify the conflicting device from its MAC address using the network switch MAC table or DHCP server',
      'Resolve: either change the static IP, add an exclusion in DHCP, or reclaim the DHCP lease',
      'ipconfig /release && ipconfig /renew to get a new IP on the affected machine'
    ],
    symptoms: [
      'IP address conflict',
      'duplicate IP address',
      'two computers same IP',
      'network conflict IP',
      'intermittent network due to IP conflict',
      'address already in use',
      'IP conflict detected',
      'DHCP IP conflict'
    ],
    tags: ['network', 'ip', 'conflict', 'dhcp', 'tcp-ip'],
    powershell: `# IP Conflict Detection
# Eventful

# IP conflict events in System log
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Tcpip'
    Id           = @(4199, 4198)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Current ARP cache (find conflicting MAC)
arp -a`,
    related_ids: [1020, 4201],
    ms_docs: null
  }
];
