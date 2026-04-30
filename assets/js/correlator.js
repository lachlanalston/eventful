/* ── Eventful — correlator.js ────────────────────────────────────────────────
   Correlation engine: identifies anchor events, correlates preceding events,
   detects incident signatures, and generates structured reports.
──────────────────────────────────────────────────────────────────────────── */

/** Event IDs that represent a system/application failure anchor point */
const ANCHOR_IDS = new Set([
  41,    // Kernel-Power: system rebooted without cleanly shutting down
  6008,  // EventLog: previous shutdown was unexpected
  1001,  // BugCheck: BSOD / memory dump created
  1000,  // Application Error: app crashed
  7024,  // Service Control Manager: service terminated with fatal error
]);

/** Known problematic event IDs and their base score contribution */
const KNOWN_BAD_IDS = {
  // Disk
  7:   40, 11: 30, 51: 40, 52: 30, 55: 35, 57: 25, 129: 20, 153: 20,
  // GPU / Display
  4101: 50,
  // Memory
  1001: 45,
  // Application
  1000: 35, 1002: 30, 1026: 20,
  // Service
  7031: 25, 7034: 25, 7022: 20, 7023: 20, 7001: 15, 7011: 15,
  // Network
  1014: 20, 4202: 20, 4201: 15,
  // WHEA (hardware errors)
  17: 50, 18: 40, 19: 30,
  // Security
  4625: 10, 4740: 15,
};

/** Known safe/noisy providers to down-rank */
const NOISY_PROVIDERS = new Set([
  'Microsoft-Windows-Diagnostics-Performance',
  'Microsoft-Windows-TaskScheduler',
  'Microsoft-Windows-WindowsUpdateClient',
  'Microsoft-Windows-Bits-Client',
  'Microsoft-Windows-GroupPolicy',
  'Microsoft-Windows-UserPnp',
  'Microsoft-Windows-WER-SystemErrorReporting',
]);

// ── Signatures ────────────────────────────────────────────────────────────────

const SIGNATURES = [
  {
    id: 'gpu-driver-crash',
    name: 'GPU Driver Crash',
    icon: '🖥',
    category: 'Hardware Driver',
    test(events) {
      const GPU_PROVIDERS = ['nvlddmkm', 'amdkmdag', 'amd', 'igdkmd', 'dxgkrnl', 'atikmdag'];
      const has4101 = events.some(e => e.id === 4101);
      const hasGpuProvider = events.some(e =>
        GPU_PROVIDERS.some(p => e.provider?.toLowerCase().includes(p))
      );
      if (has4101) return { match: true, confidence: 'high' };
      if (hasGpuProvider) return { match: true, confidence: 'medium' };
      return { match: false };
    },
    what: 'The graphics card driver stopped responding and Windows could not recover it.',
    rootCause: 'Display driver (TDR timeout) caused the system to become unresponsive.',
    nextSteps: [
      'Update or roll back GPU drivers via Device Manager → Display Adapters',
      'Use DDU (Display Driver Uninstaller) in Safe Mode for clean reinstall',
      'Monitor GPU temperatures under load with GPU-Z or HWiNFO64',
      'Run GPU stability test with FurMark or 3DMark',
      'Check GPU power connector seating if system is recently assembled',
    ],
    technicianHint: 'NVIDIA: look for "nvlddmkm" in Event 4101 faulting module. AMD: "atikmpag" or "amdkmdag". DDU clean reinstall resolves driver corruption in ~70% of cases. If temps are fine and fresh driver fails, suspect hardware.',
  },
  {
    id: 'disk-failure',
    name: 'Storage / Disk Error',
    icon: '💾',
    category: 'Storage',
    test(events) {
      const DISK_IDS = [7, 11, 51, 52, 55, 57, 129, 153];
      const DISK_PROVIDERS = ['disk', 'atapi', 'nvme', 'storport', 'ntfs', 'fastfat', 'stornvme'];
      const matching = events.filter(e =>
        DISK_IDS.includes(e.id) ||
        DISK_PROVIDERS.some(p => e.provider?.toLowerCase().includes(p))
      );
      if (matching.length >= 3) return { match: true, confidence: 'high' };
      if (matching.length >= 1) return { match: true, confidence: 'medium' };
      return { match: false };
    },
    what: 'The storage device reported I/O errors before the incident.',
    rootCause: 'Disk hardware errors were detected — possible drive failure, bad sectors, or controller issue.',
    nextSteps: [
      'Run CrystalDiskInfo — check SMART reallocated/pending/uncorrectable sectors',
      'Run chkdsk /f /r /x on affected volume',
      'Run manufacturer disk diagnostic (SeaTools, WD Dashboard, Samsung Magician)',
      'Check SATA/power cable connections',
      'Consider imaging and replacing drive if SMART shows degradation',
    ],
    technicianHint: 'Event 7 = hardware error from disk.sys. Event 51 = error during paging (system swapping to bad sectors — urgent). Event 55 = NTFS filesystem corruption. Multiple Event 7 in a short window usually means imminent failure.',
  },
  {
    id: 'bsod-kernel-crash',
    name: 'Blue Screen of Death (BSOD)',
    icon: '🔵',
    category: 'Kernel Crash',
    test(events, anchor) {
      if (anchor.id === 1001) return { match: true, confidence: 'high' };
      if (events.some(e => e.id === 1001)) return { match: true, confidence: 'high' };
      return { match: false };
    },
    what: 'Windows detected an unrecoverable kernel error and created a memory dump.',
    rootCause: 'A kernel or driver-level fault caused Windows to stop to prevent data corruption.',
    nextSteps: [
      'Note the BugCheck code from Event 1001 details',
      'Analyse minidump with WhoCrashed (free) or WinDbg (!analyze -v)',
      'Run SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth',
      'Run Windows Memory Diagnostic for MEMORY_MANAGEMENT (0x1A) stops',
      'Update all drivers — especially GPU, NIC, and chipset',
    ],
    technicianHint: 'Common stop codes: 0x50 PAGE_FAULT (bad RAM or driver), 0x3B SYSTEM_SERVICE_EXCEPTION (driver), 0x1A MEMORY_MANAGEMENT (RAM), 0x7E SYSTEM_THREAD_EXCEPTION (driver), 0x0A IRQL_NOT_LESS_OR_EQUAL (driver/RAM). WhoCrashed gives the culprit driver in seconds.',
  },
  {
    id: 'service-crash-chain',
    name: 'Service Crash Loop',
    icon: '⚙',
    category: 'Windows Services',
    test(events) {
      const SERVICE_IDS = [7031, 7034, 7022, 7023, 7024, 7001, 7011];
      const crashes = events.filter(e => SERVICE_IDS.includes(e.id));
      if (crashes.length >= 5) return { match: true, confidence: 'high' };
      if (crashes.length >= 2) return { match: true, confidence: 'medium' };
      return { match: false };
    },
    what: 'One or more Windows services crashed or failed to start repeatedly.',
    rootCause: 'Service instability — possibly caused by a failed update, corrupted binary, or missing dependency.',
    nextSteps: [
      'Identify which service(s) crashed from the event messages',
      'Check service recovery settings: Services → right-click service → Properties → Recovery',
      'Verify the service executable exists and is not corrupted',
      'Check for related Application log events (Event 1000) for the service host',
      'Review recent Windows Updates that may have changed the service',
    ],
    technicianHint: 'Event 7031 = service terminated unexpectedly (count tells you how many times). Event 7034 = crashed without telling SCM. The service name is in the event message. If it\'s svchost-hosted, check the service group.',
  },
  {
    id: 'application-crash-loop',
    name: 'Application Crash Loop',
    icon: '💥',
    category: 'Application',
    test(events) {
      const crashes = events.filter(e => e.id === 1000);
      if (crashes.length >= 3) return { match: true, confidence: 'high' };
      if (crashes.length >= 1) return { match: true, confidence: 'medium' };
      return { match: false };
    },
    what: 'An application was crashing repeatedly before the incident.',
    rootCause: 'Application instability — possible corrupt installation, missing runtime, or incompatible update.',
    nextSteps: [
      'Identify the crashing application from the Event 1000 message',
      'Note the faulting module — it often identifies a specific DLL',
      'Update or reinstall the application',
      'Install/repair Visual C++ Redistributables if a runtime DLL faults',
      'Check crash dumps in %LocalAppData%\\CrashDumps or the application\'s folder',
    ],
    technicianHint: 'The faulting module in Event 1000 is gold — "ntdll.dll" = OS issue or heap corruption, "msvcp140.dll" / "vcruntime140.dll" = missing C++ runtime, "AppName.exe" itself = bad binary. Repeated same app + same module = deterministic, reproducible fault.',
  },
  {
    id: 'memory-hardware',
    name: 'Memory / RAM Issue',
    icon: '🧠',
    category: 'Hardware',
    test(events) {
      const MEM_PROVIDERS = ['microsoft-windows-memoryd', 'whea-logger', 'microsoft-windows-whea'];
      const MEM_IDS = [17, 18, 19, 1]; // WHEA + MemoryDiagnostics-Results
      const hasMemEvent = events.some(e =>
        MEM_IDS.includes(e.id) ||
        MEM_PROVIDERS.some(p => e.provider?.toLowerCase().includes(p))
      );
      // Also check for BSOD codes that suggest RAM
      const hasBsodWithMemCode = events.some(e =>
        e.id === 1001 && (
          e.data?.BugcheckCode === '26' ||  // 0x1A = MEMORY_MANAGEMENT
          e.data?.BugcheckCode === '80'     // 0x50 = PAGE_FAULT
        )
      );
      if (hasMemEvent || hasBsodWithMemCode) return { match: true, confidence: 'medium' };
      return { match: false };
    },
    what: 'Hardware memory errors or RAM-related faults were detected.',
    rootCause: 'Defective or misconfigured RAM caused uncorrectable memory errors.',
    nextSteps: [
      'Run MemTest86+ overnight (at least 2 passes)',
      'Test RAM sticks one at a time to isolate the faulty module',
      'Reseat RAM modules and clean contacts',
      'Check XMP/EXPO profile stability — reset to JEDEC spec in BIOS',
      'Check WHEA-Logger events for corrected/uncorrected error counts',
    ],
    technicianHint: 'WHEA Event 17/18/19 = hardware error framework caught a hardware error. Check the ErrorSource field — "MCE" (Machine Check Exception) = hardware fault, usually RAM or CPU. MemTest86+ is the definitive test. Don\'t trust Windows Memory Diagnostic for subtle faults.',
  },
  {
    id: 'unexpected-power',
    name: 'Unexpected Power Loss',
    icon: '⚡',
    category: 'Power',
    test(events, anchor) {
      // BugcheckCode 0 in Event 41 = power loss (not a software crash)
      if (anchor.id === 41) {
        const bugcheck = anchor.data?.BugcheckCode;
        if (bugcheck === '0') return { match: true, confidence: 'high' };
      }
      // Very few events before anchor = sudden power loss (no software lead-up)
      if ((anchor.id === 41 || anchor.id === 6008) && events.length <= 3) {
        return { match: true, confidence: 'medium' };
      }
      return { match: false };
    },
    what: 'The system lost power without going through a normal shutdown.',
    rootCause: 'Hard power loss — possible PSU failure, power outage, or UPS failure.',
    nextSteps: [
      'Check UPS health, battery test, and log — replace battery if > 3 years old',
      'Test PSU voltage rails with PC Power Supply Tester or multimeter',
      'Check power outlet and surge protector for faults',
      'Review Event 41 BugcheckCode: 0 = power loss, non-0 = software crash',
      'Install UPS with AVR if not present — protects against brownouts',
    ],
    technicianHint: 'Event 41 BugcheckCode=0 is definitive: the machine lost power while running (no BSOD, no clean shutdown). Very few preceding events confirms sudden loss. Multiple occurrences = PSU is failing. Check 12V rail — HDD-heavy systems are sensitive.',
  },
  {
    id: 'network-failure',
    name: 'Network / Connectivity Failure',
    icon: '🌐',
    category: 'Network',
    test(events) {
      const NET_IDS = [1014, 4202, 4201, 6100];
      const NET_PROVIDERS = ['tcpip', 'dns-client', 'dhcp', 'netbt', 'netlogon', 'rras'];
      const netEvents = events.filter(e =>
        NET_IDS.includes(e.id) ||
        NET_PROVIDERS.some(p => e.provider?.toLowerCase().includes(p))
      );
      if (netEvents.length >= 3) return { match: true, confidence: 'medium' };
      if (netEvents.length >= 1) return { match: true, confidence: 'low' };
      return { match: false };
    },
    what: 'Network or DNS errors were recorded in the period leading up to the incident.',
    rootCause: 'Network connectivity failure caused application or service faults.',
    nextSteps: [
      'Check NIC driver version — update if outdated',
      'Disable NIC power management: Device Manager → NIC → Power Management → uncheck "Allow computer to turn off"',
      'Test DNS resolution: nslookup google.com',
      'Review DHCP lease renewal logs',
      'Check switch port, cable, and NIC hardware',
    ],
    technicianHint: 'Event 1014 = DNS client resolver timeout. If you see it, look at the DNS server IP in the event — a failing DC or DNS server is a common cause. Event 4201/4202 = NIC connection state changes = intermittent cable or switch issue.',
  },
];

// ── Analysis Engine ───────────────────────────────────────────────────────────

const LOOKBACK_MINUTES = 15;
const SEVERITY_SCORES = { Critical: 30, Error: 20, Warning: 10, Info: 2, Verbose: 0 };

/**
 * Main analysis entry point.
 * @param {import('./parser.js').ParsedEvent[]} events
 * @returns {{ incidents: Incident[], healthScore: number, computerName: string, stats: Object }}
 */
export function analyzeEvents(events) {
  if (!events.length) return { incidents: [], healthScore: 100, computerName: '', stats: emptyStats() };

  const computerName = events[0]?.computer || '';
  const stats = computeStats(events);
  const anchors = findAnchorEvents(events);
  const incidents = [];

  for (const anchor of anchors) {
    const windowEvents = getWindowEvents(events, anchor, LOOKBACK_MINUTES);
    const scored = scoreEvents(windowEvents, anchor);
    const topContributors = scored.slice(0, 8);
    const signatureResult = matchSignatures(windowEvents, anchor);
    const report = buildReport(anchor, signatureResult, topContributors, windowEvents);
    incidents.push({ anchor, windowEvents, topContributors, signatureResult, report });
  }

  // Deduplicate incidents that share the same anchor timestamp (within 1s)
  const deduped = deduplicateIncidents(incidents);

  const healthScore = computeHealthScore(events, deduped);

  return { incidents: deduped, healthScore, computerName, stats };
}

/** Find events that represent a failure/crash anchor */
function findAnchorEvents(events) {
  const anchors = [];
  const seen = new Set();

  for (const ev of events) {
    if (!ANCHOR_IDS.has(ev.id)) continue;

    // Deduplicate anchors within 30 seconds of each other with same ID
    const key = `${ev.id}-${Math.floor(ev.timestamp / 30000)}`;
    if (seen.has(key)) continue;
    seen.add(key);

    anchors.push(ev);
  }

  // Sort most recent first so the most interesting incident is shown first
  return anchors.sort((a, b) => b.timestamp - a.timestamp).slice(0, 5);
}

/** Get all events in the lookback window before the anchor */
function getWindowEvents(events, anchor, minutes) {
  const start = anchor.timestamp - minutes * 60_000;
  return events.filter(e => e.timestamp >= start && e.timestamp < anchor.timestamp);
}

/** Score preceding events by their likely contribution to the incident */
function scoreEvents(events, anchor) {
  const scored = events.map(e => {
    let score = SEVERITY_SCORES[e.severity] ?? 0;

    // Known bad event ID bonus
    if (KNOWN_BAD_IDS[e.id]) score += KNOWN_BAD_IDS[e.id];

    // Same provider as anchor = higher relevance
    if (e.provider && anchor.provider && e.provider === anchor.provider) score += 8;

    // Noisy providers get penalized
    if (NOISY_PROVIDERS.has(e.provider)) score = Math.max(0, score - 15);

    // Recency bonus — events closer to anchor are more likely causally related
    const minutesBefore = (anchor.timestamp - e.timestamp) / 60_000;
    if (minutesBefore < 2) score += 10;
    else if (minutesBefore < 5) score += 5;

    return { event: e, score };
  });

  // Boost repeated events — higher frequency = more significant
  const frequencyMap = new Map();
  for (const { event } of scored) {
    const key = `${event.id}-${event.provider}`;
    frequencyMap.set(key, (frequencyMap.get(key) || 0) + 1);
  }
  for (const item of scored) {
    const key = `${item.event.id}-${item.event.provider}`;
    const freq = frequencyMap.get(key) || 1;
    if (freq >= 5) item.score += 15;
    else if (freq >= 3) item.score += 8;
    else if (freq >= 2) item.score += 4;
  }

  return scored
    .filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score)
    .map(({ event, score }) => ({ event, score }));
}

/** Run all signatures against the window events */
function matchSignatures(events, anchor) {
  const matches = [];
  for (const sig of SIGNATURES) {
    try {
      const result = sig.test(events, anchor);
      if (result.match) {
        matches.push({ signature: sig, confidence: result.confidence });
      }
    } catch (_) {}
  }
  // Return highest-confidence match first
  const order = { high: 0, medium: 1, low: 2 };
  matches.sort((a, b) => (order[a.confidence] ?? 3) - (order[b.confidence] ?? 3));
  return matches;
}

/** Generate a structured incident report */
function buildReport(anchor, signatureResults, topContributors, windowEvents) {
  const primary = signatureResults[0];
  const sig = primary?.signature;
  const confidence = primary?.confidence ?? 'low';

  const anchorDescription = ANCHOR_DESCRIPTIONS[anchor.id] ?? `Event ${anchor.id}`;

  const what = sig?.what ?? `${anchorDescription} occurred at ${formatTime(anchor.timestamp)}.`;
  const rootCause = sig?.rootCause ?? generateGenericRootCause(anchor, topContributors);
  const nextSteps = sig?.nextSteps ?? ['Review event details for more information', 'Check System and Application logs for context'];
  const technicianHint = sig?.technicianHint;

  const psaSummary = buildPSASummary(anchor, sig, topContributors, confidence);

  return {
    what,
    rootCause,
    confidence,
    nextSteps,
    technicianHint,
    psaSummary,
    alternateSignatures: signatureResults.slice(1, 3),
    evidenceCount: topContributors.length,
  };
}

const ANCHOR_DESCRIPTIONS = {
  41:   'Unexpected system reboot (Kernel-Power)',
  6008: 'Unexpected previous shutdown (EventLog)',
  1001: 'System crash / BSOD (BugCheck)',
  1000: 'Application crash (Application Error)',
  7024: 'Critical service failure',
};

function generateGenericRootCause(anchor, contributors) {
  if (!contributors.length) return 'No significant preceding events identified in the lookback window.';
  const top = contributors[0].event;
  return `Leading event: ${top.provider || 'Unknown'} Event ${top.id} (${top.severity}) recorded shortly before the incident.`;
}

function buildPSASummary(anchor, sig, contributors, confidence) {
  const ts = anchor.timestamp.toLocaleString();
  const lines = [
    `INCIDENT SUMMARY`,
    `================`,
    `Date/Time: ${ts}`,
    `Anchor Event: ${anchor.id} — ${ANCHOR_DESCRIPTIONS[anchor.id] ?? 'Unknown'}`,
    `Provider: ${anchor.provider || 'Unknown'}`,
    `Computer: ${anchor.computer || 'Unknown'}`,
    ``,
    `DIAGNOSIS`,
    `---------`,
    sig ? `Pattern: ${sig.name} (${sig.category})` : 'Pattern: No known pattern matched',
    `Confidence: ${confidence.toUpperCase()}`,
    ``,
    sig ? `What happened: ${sig.what}` : '',
    sig ? `Root cause: ${sig.rootCause}` : '',
    ``,
    `CONTRIBUTING EVENTS (top ${Math.min(contributors.length, 5)})`,
    `------------------`,
    ...contributors.slice(0, 5).map(({ event }) =>
      `  [${event.severity}] Event ${event.id} — ${event.provider || 'Unknown'} @ ${formatTime(event.timestamp)}`
    ),
    ``,
    `SUGGESTED NEXT STEPS`,
    `--------------------`,
    ...(sig?.nextSteps ?? ['Review event log for more context']).map(s => `  • ${s}`),
    ``,
    `Generated by Eventful Incident Analyzer`,
  ];
  return lines.filter(l => l !== undefined).join('\n');
}

function computeStats(events) {
  const counts = { Critical: 0, Error: 0, Warning: 0, Info: 0, Verbose: 0 };
  for (const e of events) counts[e.severity] = (counts[e.severity] || 0) + 1;
  return { total: events.length, ...counts };
}

function emptyStats() {
  return { total: 0, Critical: 0, Error: 0, Warning: 0, Info: 0, Verbose: 0 };
}

function computeHealthScore(events, incidents) {
  let score = 100;
  const stats = computeStats(events);

  // Deduct for severity counts (capped)
  score -= Math.min(stats.Critical * 15, 40);
  score -= Math.min(stats.Error * 3, 25);
  score -= Math.min(stats.Warning * 0.5, 10);

  // Deduct for each incident
  score -= incidents.length * 12;

  // Extra deduction for high-confidence incidents
  for (const inc of incidents) {
    if (inc.report.confidence === 'high') score -= 8;
    else if (inc.report.confidence === 'medium') score -= 4;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

function deduplicateIncidents(incidents) {
  const seen = new Set();
  return incidents.filter(inc => {
    const key = `${inc.anchor.id}-${Math.floor(inc.anchor.timestamp / 1000)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatTime(date) {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
