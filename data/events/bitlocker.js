export const bitlockerEvents = [
  {
    id: 24577,
    source: 'Microsoft-Windows-BitLocker-API',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'BitLocker Encryption Started',
    short_desc: 'BitLocker encryption has started on a volume.',
    description: 'Event 24577 from Microsoft-Windows-BitLocker-API is logged when BitLocker encryption begins on a drive volume. This marks the start of the encryption process, which can take hours for large drives. This event is useful for confirming that BitLocker deployment has been initiated (e.g., via Intune, SCCM, or Group Policy), and for auditing when drives were encrypted. The event includes the drive letter and volume GUID.',
    why_it_happens: 'BitLocker encryption starts when: a user enables BitLocker from the Control Panel, an MDM/management policy triggers silent encryption, IT enables BitLocker via PowerShell or GPO, or Windows automatically enables Device Encryption on compliant hardware (joined to AAD with a TPM).',
    what_good_looks_like: 'All laptops and desktops show 24577 followed by 24578 (encryption completed) in System log. Recovery keys escrowed to AD or Azure AD. BitLocker status: Get-BitLockerVolume shows ProtectionStatus = On.',
    common_mistakes: [
      'Not verifying recovery key escrow before deploying BitLocker — a key that is not backed up means data loss if the device is lost',
      'Confusing encryption in progress (24577 without 24578) with completed encryption',
      'Not monitoring for 24620 (encryption failed) after deploying BitLocker policy'
    ],
    causes: [
      'IT deploying BitLocker via Group Policy or MDM',
      'User manually enabling BitLocker',
      'Windows Autopilot or Intune deployment enabling encryption',
      'New drive added and encrypted',
      'BitLocker suspended then resumed (resumes from suspension generates this event)'
    ],
    steps: [
      'Verify encryption completed: Get-BitLockerVolume | Select-Object MountPoint, EncryptionPercentage, ProtectionStatus',
      'Check recovery key escrow to AD: Get-ADComputer <name> -Properties * | Select-Object msTPM-TpmInformationForComputer',
      'For Azure AD joined devices: verify key in Intune portal → Devices → Monitor → Encryption report',
      'If encryption failed or stalled: check System log for 24620 or 24621'
    ],
    symptoms: [
      'BitLocker started encrypting',
      'drive encryption started',
      'BitLocker encryption in progress',
      'disk encryption started',
      'BitLocker turned on',
      'computer encrypting drive',
      'BitLocker deployment'
    ],
    tags: ['bitlocker', 'encryption', 'security', 'drive', 'compliance'],
    powershell: `# BitLocker Encryption Status
# Eventful

# Current BitLocker status per volume
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage,
    EncryptionMethod, ProtectionStatus,
    @{N='KeyProtectors'; E={ ($_.KeyProtector | Select-Object -ExpandProperty KeyProtectorType) -join ', ' }} |
    Format-Table -AutoSize

# BitLocker events (24577=started, 24578=completed, 24620=failed)
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-BitLocker-API'
    Id           = @(24577, 24578, 24579, 24620)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List`,
    related_ids: [24578, 24620, 24621],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/'
  },

  {
    id: 24620,
    source: 'Microsoft-Windows-BitLocker-API',
    channel: 'System',
    severity: 'Error',
    skill_level: 'Intermediate',
    title: 'BitLocker Encryption Failed',
    short_desc: 'BitLocker failed to encrypt a volume — drive is unencrypted despite policy requiring encryption.',
    description: 'Event 24620 is generated when a BitLocker encryption attempt fails. The drive remains unencrypted. This is a critical compliance event — if BitLocker is required by policy and 24620 appears, the device is non-compliant and any sensitive data it holds is unprotected. The event message includes the specific error code indicating why encryption failed.',
    why_it_happens: 'Encryption failures are commonly caused by: no compatible TPM chip (or TPM not initialized), TPM errors (ownership conflict, NV memory failure), insufficient disk space for the encryption overhead, Group Policy conflict requiring a different configuration than what is currently set, or a drive that does not support the required encryption mode.',
    what_good_looks_like: 'No 24620 events. All managed devices have 24578 (encryption completed) in their event log. Compliance dashboard shows 100% encrypted.',
    common_mistakes: [
      'Not monitoring for 24620 after BitLocker policy deployment — silent failures leave machines unencrypted',
      'Not checking TPM health before deploying BitLocker — Get-Tpm on each machine',
      'Deploying BitLocker to VMs without TPM emulation enabled in the hypervisor'
    ],
    causes: [
      'No TPM chip or TPM not enabled in BIOS/UEFI',
      'TPM ownership conflict — TPM already owned with different credentials',
      'Group Policy specifying startup PIN but machine in unattended environment',
      'Insufficient disk space for encryption',
      'OS drive not formatted with NTFS or ReFS',
      'Secure Boot not enabled (required by some BitLocker configurations)',
      'Hardware drive encryption not supported on this drive type'
    ],
    steps: [
      'Check the error code from Event 24620 message',
      'Check TPM status: Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled',
      'Check TPM errors: Get-WinEvent -LogName "System" -ProviderName "TPM-WMI"',
      'Verify BIOS/UEFI has TPM enabled and Secure Boot enabled',
      'Check Group Policy: Computer Config → Admin Templates → Windows Components → BitLocker Drive Encryption',
      'For VMs: enable TPM in VM settings (Hyper-V: Security tab → Enable TPM)',
      'Clear and reinitialize TPM if ownership conflict: only with user consent (destroys TPM-protected data)'
    ],
    symptoms: [
      'BitLocker failed',
      'drive encryption failed',
      'BitLocker not working',
      'cannot encrypt drive BitLocker',
      'BitLocker error',
      'computer not encrypting',
      'BitLocker policy not applying',
      'TPM error BitLocker',
      'BitLocker compliance failure'
    ],
    tags: ['bitlocker', 'encryption', 'error', 'tpm', 'compliance', 'security'],
    powershell: `# BitLocker Failure Diagnosis
# Eventful

# Encryption failure events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-BitLocker-API'
    Id           = @(24620, 24621)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# TPM health check
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, TpmOwned

# BitLocker current status
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus | Format-Table`,
    related_ids: [24577, 24578, 24621],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-troubleshoot-devices'
  },

  {
    id: 24621,
    source: 'Microsoft-Windows-BitLocker-API',
    channel: 'System',
    severity: 'Warning',
    skill_level: 'Intermediate',
    title: 'BitLocker Protection Suspended',
    short_desc: 'BitLocker protection has been suspended — drive is temporarily unprotected.',
    description: 'Event 24621 is generated when BitLocker protection is suspended on a volume. The data remains encrypted but the encryption key is stored unprotected, meaning anyone with physical access to the drive could read the data. Suspension is required for certain maintenance operations (BIOS/UEFI updates, TPM firmware updates, disk partitioning changes). Protection must be resumed with 24622 after maintenance is complete.',
    why_it_happens: 'BitLocker suspension is triggered manually or by Windows when it detects changes that would otherwise cause a recovery key prompt on next boot (BIOS updates, secure boot changes, Autopilot configuration changes). Many endpoint management tools temporarily suspend BitLocker during OS upgrade operations.',
    what_good_looks_like: 'Suspension always followed promptly by Event 24622 (protection resumed). No extended periods of suspended protection. Suspension events correlate with planned maintenance windows.',
    common_mistakes: [
      'Performing a BIOS update and forgetting to re-enable BitLocker protection after',
      'Not monitoring for suspended-but-never-resumed states — Get-BitLockerVolume will show ProtectionStatus = Off even though the drive appears encrypted'
    ],
    causes: [
      'BIOS/UEFI firmware update requiring BitLocker suspension',
      'Disk partitioning or resize operation',
      'OS upgrade process temporarily suspending protection',
      'Admin manually suspended for maintenance',
      'TPM firmware update requiring suspension'
    ],
    steps: [
      'Check if protection was resumed: Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus',
      'If still suspended: Resume-BitLocker -MountPoint "C:"',
      'Check Event 24622 (resumed) — if not present, protection was never re-enabled',
      'Identify why it was suspended from the event message and preceding admin actions'
    ],
    symptoms: [
      'BitLocker suspended',
      'BitLocker protection off',
      'BitLocker temporarily disabled',
      'drive encryption suspended',
      'BitLocker not protecting after update',
      'BitLocker paused',
      'encryption protection suspended'
    ],
    tags: ['bitlocker', 'suspension', 'encryption', 'maintenance', 'security'],
    powershell: `# BitLocker Suspension Status
# Eventful

# Check if any volumes have suspended protection
Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq 'Off' } |
    Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus | Format-Table

# Resume protection if suspended
# Resume-BitLocker -MountPoint "C:"

# Suspension events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-BitLocker-API'
    Id           = @(24621, 24622)
    StartTime    = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{N='Event'; E={ if ($_.Id -eq 24621) {'SUSPENDED'} else {'RESUMED'} }},
        Message |
    Sort-Object TimeCreated | Format-Table -AutoSize`,
    related_ids: [24577, 24620, 24622],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/'
  },

  {
    id: 24592,
    source: 'Microsoft-Windows-BitLocker-API',
    channel: 'System',
    severity: 'Info',
    skill_level: 'Intermediate',
    title: 'BitLocker Recovery Key Backed Up to Active Directory',
    short_desc: 'BitLocker recovery key was successfully escrowed to Active Directory.',
    description: 'Event 24592 is generated when BitLocker successfully backs up a recovery key or TPM owner information to Active Directory. This is the critical escrow confirmation event — if 24592 is not present for a device, its recovery key may not be accessible if the device needs recovery. Loss of the recovery key means the encrypted data is permanently inaccessible if the primary key (TPM/PIN/password) is unavailable.',
    why_it_happens: 'When BitLocker is configured with "Do not enable BitLocker until recovery information is stored to AD DS" policy, Windows attempts to escrow the key before completing encryption. Event 24592 confirms the escrow succeeded. For Azure AD joined devices, keys are backed up to Azure AD instead (no event in System log — check Intune/Azure AD portal).',
    what_good_looks_like: 'Every BitLocker-encrypted device has a corresponding Event 24592 confirming recovery key escrow. Recovery keys queryable from AD: Get-ADObject -Filter {ObjectClass -eq "msFVE-RecoveryInformation"} -SearchBase "CN=<computer>,..." -Properties *.',
    common_mistakes: [
      'Not checking Event 24592 after BitLocker deployment — assuming the key was backed up when it was not',
      'Not requiring key escrow before encryption completes (Group Policy setting)',
      'Forgetting that Azure AD joined devices use Azure AD for key backup, not AD DS'
    ],
    causes: [
      'BitLocker successfully escrowed recovery key to AD after encryption',
      'Key regenerated and re-escrowed after TPM change',
      'BitLocker re-protection after suspension required new key escrow'
    ],
    steps: [
      'Verify key in AD: ADUC → Computer object → BitLocker Recovery tab',
      'Or PowerShell: Get-ADObject -LDAPFilter "(objectClass=msFVE-RecoveryInformation)" -SearchBase "OU=..." -Properties msFVE-RecoveryPassword',
      'If no key in AD: manually backup with: Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (Get-BitLockerVolume C:).KeyProtector[0].KeyProtectorId',
      'Verify Group Policy requires backup before encryption: Computer Config → BitLocker → Require additional authentication at startup'
    ],
    symptoms: [
      'BitLocker recovery key',
      'BitLocker key backed up',
      'BitLocker key in Active Directory',
      'recover BitLocker key',
      'BitLocker recovery key missing',
      'BitLocker AD escrow',
      'BitLocker key backup'
    ],
    tags: ['bitlocker', 'recovery-key', 'active-directory', 'escrow', 'compliance', 'security'],
    powershell: `# BitLocker Recovery Key Escrow Verification
# Eventful

# Check recovery key escrow events
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-BitLocker-API'
    Id           = @(24592, 24593, 24594)
    StartTime    = (Get-Date).AddDays(-365)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending | Format-List

# Check BitLocker key protectors (local)
Get-BitLockerVolume -MountPoint "C:" |
    Select-Object -ExpandProperty KeyProtector |
    Select-Object KeyProtectorType, KeyProtectorId, RecoveryPassword | Format-List

# Backup key to AD if missing (requires AD connectivity and permissions)
# $vol = Get-BitLockerVolume -MountPoint "C:"
# Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $vol.KeyProtector[0].KeyProtectorId`,
    related_ids: [24577, 24620, 24621],
    ms_docs: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-key-management-faq'
  }
];
