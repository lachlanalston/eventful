export const certsEvents = [
  {
    id: 1002,
    source: 'Microsoft-Windows-CertificationAuthority',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Advanced',
    title: 'Certificate Services — Failed to Revoke Certificate',
    short_desc: 'Certificate Services failed to revoke a certificate — CRL or database error.',
    description: 'Event 1002 from Microsoft-Windows-CertificationAuthority indicates that the CA failed to process a revocation request. This may mean the certificate was already revoked, the CA database is inaccessible, or the serial number was not found. Clients relying on up-to-date CRL publication will be affected if revocation is blocked.',
    why_it_happens: 'Revocation failures occur when the CA database is locked or corrupt, when the certificate serial number cannot be found (already expired or wrong CA), or when the CA service lacks permissions to write to the revocation store. High-volume environments can also hit database contention.',
    what_good_looks_like: 'No 1002 errors in the Application log. CRL publications succeed on schedule. CDP extension URLs in issued certs are reachable and return a valid, non-expired CRL.',
    common_mistakes: [
      'Attempting to revoke a certificate from the wrong CA — serial numbers are unique per CA',
      'Not checking if the certificate was already expired; expired certs often cannot be revoked through the normal UI',
      'Ignoring CA database fragmentation — run certutil -databaselocations and check free space',
      'Forgetting to restart Certificate Services after database maintenance'
    ],
    causes: [
      'CA database locked or running out of space',
      'Certificate serial number not found — wrong CA or already deleted',
      'Certificate already revoked',
      'CA service account lacks write permission to the database directory',
      'CA database corruption requiring defragmentation'
    ],
    steps: [
      'Open Event Viewer → Windows Logs → Application, filter for source Microsoft-Windows-CertificationAuthority',
      'Note the serial number and reason code from the event message',
      'Verify the certificate exists: certutil -view -out "SerialNumber" -restrict "SerialNumber=<serial>"',
      'Check CA database free space: certutil -databaselocations',
      'Check CA service account permissions on the CA database directory',
      'If database is corrupt: stop CerSvc, run certutil -f -databaserecover, restart service',
      'Review CA Application log for events 100–200 indicating service issues'
    ],
    symptoms: [
      'cannot revoke certificate',
      'certificate revocation failed',
      'CRL not updating',
      'certificate services error',
      'revoke cert error',
      'CA database error',
      'certificate authority failed',
      'revocation request failed'
    ],
    tags: ['certificate', 'pki', 'ca', 'revocation', 'crl', 'adcs'],
    powershell: `# Certificate Authority — check for revocation errors and CRL status
# Eventful

# Recent CA errors in Application log
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Microsoft-Windows-CertificationAuthority'
    Level        = @(1, 2)   # Critical + Error
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# CRL publication status (run on CA server)
certutil -crl

# Check CA database size and locations
certutil -databaselocations`,
    related_ids: [1003, 4870, 4896],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview'
  },

  {
    id: 1003,
    source: 'Microsoft-Windows-CertificationAuthority',
    channel: 'Application',
    severity: 'Warning',
    skill_level: 'Advanced',
    title: 'Certificate Services — CRL Distribution Point Not Reachable',
    short_desc: 'CA cannot publish the CRL to one or more distribution points.',
    description: 'Event 1003 indicates that the CA attempted to publish a new Certificate Revocation List (CRL) to a configured distribution point (CDP) and failed. Clients that cannot download a valid CRL will fail certificate validation and may be denied access to resources or HTTPS sites that perform CRL checking.',
    why_it_happens: 'CRL publication failures are usually caused by a network share being unavailable, an LDAP write permission being denied, or an HTTP/HTTPS publication target being unreachable. The CA publishes CRLs on a configured schedule and on demand when certificates are revoked.',
    what_good_looks_like: 'CRL published successfully to all CDPs on every scheduled interval. The CRL validity period should exceed the publication interval by at least 50% to allow for missed publications. Clients can retrieve the CRL without errors.',
    common_mistakes: [
      'Setting the CRL validity period too short — it should always be longer than the publication interval',
      'Not testing CRL retrieval from client machines, not just from the CA server',
      'Forgetting that LDAP CDPs require the CA computer account to have write access to the CDP object in AD',
      'Not monitoring CRL expiry — an expired CRL causes ALL certificates from that CA to fail validation'
    ],
    causes: [
      'Network share for delta/base CRL is offline or permissions changed',
      'LDAP write permission denied to CA computer account',
      'HTTP/HTTPS CDN or web server hosting CRL is unreachable',
      'CA certificate expired, blocking CRL signing',
      'DNS resolution failure for CDP hostname'
    ],
    steps: [
      'Identify which CDP is failing from the event message',
      'For file/share CDPs: verify the share is online and CA computer account has write access',
      'For LDAP CDPs: run certutil -dspublish to re-publish, check AD permissions',
      'For HTTP CDPs: verify the web server is online and the upload/copy mechanism is working',
      'Manually publish CRL: certutil -crl',
      'Check CRL validity: certutil -url <cdpUrl> or PKIView snap-in',
      'Review CDP config in CA Properties → Extensions tab'
    ],
    symptoms: [
      'CRL not published',
      'certificate validation failing',
      'clients getting certificate errors',
      'CRL distribution point unreachable',
      'certificate revocation check failed',
      'https certificate error all users',
      'PKI CRL expired',
      'certificate services CRL error'
    ],
    tags: ['certificate', 'pki', 'crl', 'cdp', 'adcs', 'ca-publish'],
    powershell: `# Check CRL publication status and reachability
# Eventful

# View current CRL details from CA
certutil -crl

# Test a specific CDP URL
# certutil -url "http://crl.contoso.com/CertEnroll/ContosoCA.crl"

# Republish CRL manually (run on CA server as admin)
# certutil -dspublish -f "C:\Windows\System32\CertSrv\CertEnroll\*.crl"

# Check CRL validity period and next update
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Microsoft-Windows-CertificationAuthority'
    Id           = 1003
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [1002, 13, 64, 65],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview'
  },

  {
    id: 64,
    source: 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment',
    channel: 'Application',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Certificate Auto-Enrollment Failed',
    short_desc: 'Automatic certificate enrollment failed — client could not enroll for or renew a certificate.',
    description: 'Event 64 from Microsoft-Windows-CertificateServicesClient-AutoEnrollment is logged when the auto-enrollment process fails to enroll for or renew a certificate. This commonly breaks machine authentication, 802.1X Wi-Fi/LAN access, email signing, or HTTPS services that rely on automatically issued certificates. The event message includes the template name and a descriptive error code.',
    why_it_happens: 'Auto-enrollment runs at user logon and on Group Policy refresh. It contacts the CA to request certificates defined by auto-enrollment Group Policy. Failures occur when the CA is unreachable, the machine lacks Enroll permission on the template, the template version is incompatible with the CA, or the SAN in the request cannot be fulfilled.',
    what_good_looks_like: 'Event 65 (successful enrollment) accompanies each issued certificate. Computers should hold a valid Machine certificate, and users a valid User certificate where templates require them. Certificate snap-in (certmgr.msc / certlm.msc) shows unexpired, valid certificates from your CA.',
    common_mistakes: [
      'Forgetting to publish the certificate template to the CA — a template can exist in AD without being published',
      'Not granting the Authenticated Users or Domain Computers group Enroll permission on the template',
      'Template requiring EKU or SAN fields the CA cannot populate automatically',
      'Not checking if the CA is reachable from the affected machine: certutil -ping <caName>'
    ],
    causes: [
      'Machine lacks Enroll or AutoEnroll permission on the certificate template',
      'Certificate template not published to the CA',
      'CA is offline or unreachable from client',
      'Template schema version incompatible with CA version',
      'Machine name longer than 15 characters causing CN truncation in certificate',
      'Certificate template requires manual approval (CA manager approval flag set)'
    ],
    steps: [
      'Open Event Viewer → Application log, filter for source Microsoft-Windows-CertificateServicesClient-AutoEnrollment, Event 64',
      'Note the template name and error message in the event',
      'Verify the template is published to the CA: certsrv.msc → Certificate Templates folder',
      'Check Enroll and AutoEnroll permissions: Certificate Templates console → template Properties → Security tab',
      'Run gpupdate /force on the client, then check for Event 65',
      'Test CA connectivity from client: certutil -ping <CAComputerName>',
      'Review GPO auto-enrollment setting: Computer/User Config → Windows Settings → Security Settings → Public Key Policies → Certificate Services Client – Auto-Enrollment'
    ],
    symptoms: [
      'certificate auto enrollment failed',
      'computers not getting certificates automatically',
      'machine cert missing',
      '802.1x wifi certificate error',
      'domain computer certificate expired',
      'auto enroll certificate error',
      'certificate template not enrolling',
      'GPO cert not deploying',
      'PKI enrollment failed',
      'certificate request failed'
    ],
    tags: ['certificate', 'pki', 'auto-enrollment', 'adcs', 'group-policy', '802.1x'],
    powershell: `# Certificate Auto-Enrollment Diagnostics
# Eventful

# Check auto-enrollment events (64=fail, 65=success)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment'
    Id           = @(64, 65)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Status'; E={ if ($_.Id -eq 65) {'SUCCESS'} else {'FAILED'} }},
        Message |
    Sort-Object TimeCreated -Descending | Format-List

# List machine certificates and expiry
Get-ChildItem Cert:\LocalMachine\My |
    Select-Object Subject, Issuer, NotAfter,
        @{N='DaysLeft'; E={ [int](($_.NotAfter - (Get-Date)).TotalDays) }} |
    Sort-Object DaysLeft | Format-Table -AutoSize

# Test CA connectivity
# certutil -ping <CAName>`,
    related_ids: [65, 1003, 6066],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-autoenrollment'
  },

  {
    id: 20,
    source: 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment',
    channel: 'Application',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Certificate Near Expiry — Auto-Renewal Pending',
    short_desc: 'Auto-enrollment detected a certificate approaching expiry and queued renewal.',
    description: 'Event 20 from the auto-enrollment client logs when a certificate reaches the renewal threshold (by default 80% of its lifetime elapsed) and renewal has been queued. If the renewal then fails, Event 64 will follow. This event itself is informational but is the first warning that a certificate chain of events is underway that could result in a service outage if not confirmed successful.',
    why_it_happens: 'Windows Certificate Services auto-enrollment monitors certificate lifetimes and initiates renewal when the renewal percentage threshold is crossed. The renewal triggers on Group Policy refresh or logon. If the CA or template is unreachable, the renewal attempt logs Event 64.',
    what_good_looks_like: 'Event 20 followed within minutes by Event 65 (enrollment success) and a new certificate in certlm.msc/certmgr.msc with extended validity. No Event 64 errors.',
    common_mistakes: [
      'Seeing Event 20 and assuming renewal was successful — always verify with Event 65 or certlm.msc',
      'Not monitoring certificate expiry proactively; Event 20 is a late warning',
      'Letting certificates expire because the CA was offline during the renewal window'
    ],
    causes: [
      'Certificate has reached 80% of its validity period',
      'Template configured with short validity (e.g. 1 year)',
      'Certificates issued with fixed end dates instead of relative lifetimes'
    ],
    steps: [
      'Verify renewal succeeded: check certlm.msc for a new certificate with updated NotAfter date',
      'If renewal failed, look for Event 64 in Application log',
      'Run gpupdate /force to trigger immediate renewal attempt',
      'Check CA health: certutil -ping <CAName>',
      'Monitor: Get-ChildItem Cert:\\LocalMachine\\My sorted by expiry'
    ],
    symptoms: [
      'certificate about to expire',
      'certificate renewal pending',
      'certificate expiring soon',
      'auto renewal certificate',
      'cert renewal queued',
      'certificate near expiry warning',
      'pki certificate expiry'
    ],
    tags: ['certificate', 'pki', 'expiry', 'renewal', 'auto-enrollment', 'adcs'],
    powershell: `# Check certificate expiry across machine store
# Eventful

# All machine certs sorted by expiry
Get-ChildItem Cert:\LocalMachine\My |
    Select-Object Subject, Issuer, NotAfter,
        @{N='DaysLeft'; E={ [int](($_.NotAfter - (Get-Date)).TotalDays) }},
        Thumbprint |
    Sort-Object DaysLeft | Format-Table -AutoSize

# Certs expiring within 30 days
Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) } |
    Select-Object Subject, Issuer, NotAfter, Thumbprint | Format-List`,
    related_ids: [64, 65, 1003],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-autoenrollment'
  },

  {
    id: 36882,
    source: 'Schannel',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'Schannel — Certificate Chain Could Not Be Built',
    short_desc: 'TLS/SSL handshake failed because the certificate chain could not be verified.',
    description: 'Event 36882 from Schannel (the Windows TLS/SSL implementation) means the system could not build a valid certificate chain from the presented certificate to a trusted root. This causes TLS connections to fail and generates errors in applications as "certificate chain error", "untrusted certificate", or connection refused. This event is logged on the client side of the TLS connection.',
    why_it_happens: 'Certificate chain building fails when an intermediate CA certificate is missing from the local store or the AIA (Authority Information Access) extension download fails, when the root CA certificate is not in the Trusted Root Certification Authorities store, when the certificate has been revoked and CRL checking fails, or when the clock is skewed causing validity period mismatches.',
    what_good_looks_like: 'No Schannel errors in the System log. Applications connect to HTTPS/LDAPS/SMTPS without certificate errors. certutil -verify <certfile> returns without errors.',
    common_mistakes: [
      'Not checking if intermediate CA certificates are present in the Intermediate Certification Authorities store',
      'Forgetting to distribute the root CA certificate via GPO to all domain machines',
      'Not checking if the server certificate AIA URLs are reachable for online chain building',
      'Ignoring time skew — a clock more than 5 minutes off can cause valid certificates to appear invalid'
    ],
    causes: [
      'Intermediate CA certificate missing from local store',
      'Root CA certificate not trusted on the client',
      'AIA URL unreachable — cannot download intermediate certificate online',
      'Certificate presented by server is expired or not yet valid',
      'System clock skewed beyond acceptable tolerance',
      'Certificate revoked and client configured to enforce CRL checking'
    ],
    steps: [
      'Identify the service/connection failing from application logs',
      'Run certutil -verify -urlfetch <certFile> to test chain building with URL fetching',
      'Check Intermediate Certification Authorities store: certlm.msc → Intermediate CAs',
      'Check Trusted Root Certification Authorities store for the root CA',
      'Verify system clock: w32tm /query /status',
      'Check AIA URL reachability from the client machine',
      'Deploy missing root or intermediate CA via GPO: Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies'
    ],
    symptoms: [
      'certificate chain error',
      'untrusted certificate',
      'TLS handshake failed',
      'SSL certificate error',
      'cannot verify certificate',
      'certificate not trusted',
      'https connection failing',
      'certificate chain could not be built',
      'intermediate certificate missing',
      'root CA not trusted'
    ],
    tags: ['certificate', 'tls', 'ssl', 'schannel', 'chain', 'pki', 'trust'],
    powershell: `# Schannel and Certificate Chain Diagnostics
# Eventful

# Recent Schannel errors in System log
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Schannel'
    Level        = @(1, 2)   # Critical + Error
    StartTime    = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated -Descending | Format-List

# Verify a certificate chain (replace path with actual cert file)
# certutil -verify -urlfetch "C:\path\to\certificate.cer"

# Check time sync status (clock skew can break TLS)
w32tm /query /status

# List trusted root CAs
Get-ChildItem Cert:\LocalMachine\Root |
    Select-Object Subject, NotAfter,
        @{N='DaysLeft'; E={ [int](($_.NotAfter - (Get-Date)).TotalDays) }} |
    Sort-Object DaysLeft | Format-Table -AutoSize`,
    related_ids: [36871, 36874, 36887, 36888, 64],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/security/tls/schannel-security-support-provider-technical-reference'
  },

  {
    id: 13,
    source: 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment',
    channel: 'Application',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'Certificate Template Not Found or Access Denied',
    short_desc: 'Auto-enrollment could not access a required certificate template.',
    description: 'Event 13 from the certificate auto-enrollment client indicates that the client found a reference to a certificate template (via Group Policy or the user/machine configuration) but either the template does not exist in Active Directory or the account does not have Read permission on the template object. Enrollment silently fails for that template until the issue is resolved.',
    why_it_happens: 'This event fires during the GPO-driven auto-enrollment refresh. It means the auto-enrollment GPO is pointing to a template name that is either misspelled, not yet created in the Certificate Templates container in AD, or has had its Read permission removed from the requesting account.',
    what_good_looks_like: 'No Event 13 errors. Auto-enrollment GPO references only published, accessible templates. All machines/users successfully receive the certificates they are configured to auto-enroll for.',
    common_mistakes: [
      'Creating a GPO referencing a template before the template is published to the CA and replicated in AD',
      'Renaming a template without updating the GPO auto-enrollment reference',
      'Accidentally removing Read permission from Authenticated Users on the template object'
    ],
    causes: [
      'Certificate template name in GPO does not match the template Common Name in AD',
      'Template exists but Read permission removed from requesting group',
      'Template not yet replicated to all AD domain controllers',
      'Template was deleted but GPO still references it'
    ],
    steps: [
      'Identify the template name from the event message',
      'Verify the template exists in AD: Certificate Templates console (certtmpl.msc)',
      'Check template Read permission: right-click template → Properties → Security tab → Authenticated Users should have Read',
      'Verify the template is published on the CA: certsrv.msc → Certificate Templates',
      'Force AD replication if recently created: repadmin /syncall /AdeP',
      'Run gpupdate /force on client after fixing permissions'
    ],
    symptoms: [
      'certificate template not found',
      'auto enrollment template missing',
      'certificate template access denied',
      'GPO cert template not working',
      'certificate enrollment template error',
      'cannot find certificate template',
      'template read permission error'
    ],
    tags: ['certificate', 'pki', 'auto-enrollment', 'template', 'adcs', 'group-policy'],
    powershell: `# List certificate templates and their enrollment permissions
# Eventful

# Auto-enrollment errors (Event 13 and 64)
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment'
    Id           = @(13, 64)
    StartTime    = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# List templates published to local CA (run on CA server)
# certutil -catemplates

# Check current machine certs
Get-ChildItem Cert:\LocalMachine\My |
    Select-Object Subject, Issuer, NotAfter | Format-Table -AutoSize`,
    related_ids: [64, 65, 1003],
    ms_docs: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-autoenrollment'
  }
];
