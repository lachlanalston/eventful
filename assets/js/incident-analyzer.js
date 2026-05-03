import JSZip from 'jszip';
import { parseEventXML } from './parser.js';
import { setupTheme } from './theme.js';
import { escHtml } from './utils.js';
import { copyToClipboard } from './clipboard.js';

setupTheme();

// ─── RelMon parser ────────────────────────────────────────────────────────────
const HW_PATTERNS = [
  /bad.?block/i, /disk.?error/i, /ntfs.*corrupt/i, /corrupt.*ntfs/i,
  /hardware.?error/i, /memory.*corrupt/i, /bad.?sector/i,
  /read.?error/i, /i\/o.?error/i, /chkdsk/i, /file.?system.*error/i,
];

function classifyRelEvent(problem) {
  const p = (problem || '').toLowerCase();
  if (p.includes('stopped working'))    return 'crash';
  if (p.includes('stopped responding')) return 'hang';
  if (/windows update|update/.test(p))  return 'update';
  if (/install|reconfigur|removal/.test(p)) return 'software';
  return 'info';
}

function parseRelMon(buf) {
  const bytes = new Uint8Array(buf);
  let text;
  if (bytes[0] === 0xFF && bytes[1] === 0xFE)      text = new TextDecoder('utf-16le').decode(buf);
  else if (bytes[0] === 0xFE && bytes[1] === 0xFF) text = new TextDecoder('utf-16be').decode(buf);
  else                                              text = new TextDecoder('utf-8').decode(buf);

  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.querySelector('parsererror') || doc.documentElement.tagName !== 'RelMonReport') return null;

  const generated = doc.documentElement.getAttribute('TimeGenerated') || '';
  const records = [...doc.querySelectorAll('RacEvents > Event')].map(ev => {
    const get = tag => ev.querySelector(tag)?.textContent?.trim() ?? '';
    const time = get('Time');
    return {
      time, date: time.slice(0, 10),
      source: get('Source'), message: get('Problem'),
      impact: get('Impact'), cat: classifyRelEvent(get('Problem')),
    };
  }).sort((a, b) => b.time.localeCompare(a.time));
  return records.length ? { generated, records } : null;
}

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const uploadSection     = document.getElementById('upload-section');
const processingSection = document.getElementById('processing-section');
const processingText    = document.getElementById('processing-text');
const resultsSection    = document.getElementById('results-section');
const dropZone          = document.getElementById('drop-zone');
const fileInput         = document.getElementById('file-input');
const newAnalysisBtn    = document.getElementById('new-analysis-btn');
const copyTicketBtn     = document.getElementById('copy-ticket-btn');
const resultsSub        = document.getElementById('results-sub');
const overviewGrid      = document.getElementById('overview-grid');
const findingsPanel     = document.getElementById('findings-panel');
const eventsPanel       = document.getElementById('events-panel');
const reliabilityPanel  = document.getElementById('reliability-panel');
const tabFindingsCount  = document.getElementById('tab-findings-count');
const tabEventsCount    = document.getElementById('tab-events-count');
const tabRelCount       = document.getElementById('tab-rel-count');

// ─── File handling ────────────────────────────────────────────────────────────
async function processFile(file) {
  if (!file) return;
  uploadSection.hidden     = true;
  processingSection.hidden = false;
  resultsSection.hidden    = true;
  processingText.textContent = 'Reading archive…';

  try {
    const logData = await extractZip(file);
    processingText.textContent = 'Analysing…';

    const findings = analyzeAll(logData);
    processingSection.hidden = true;
    resultsSection.hidden    = false;
    render(logData, findings);

  } catch (err) {
    processingSection.innerHTML = `
      <p class="processing-error">
        <strong>Could not read file</strong><br>
        ${escHtml(err.message)}<br>
        <span style="font-size:0.82rem;color:var(--text-muted)">
          Upload the ZIP from Get-EventLogExport.ps1, or a single XML event log.
        </span>
      </p>
      <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
    `;
    document.getElementById('retry-btn')?.addEventListener('click', resetToUpload);
  }
}

async function extractZip(file) {
  const logData = { system: [], application: [], security: [], setup: [], reliability: null, missing: [], computer: '' };

  const isZip = file.name.toLowerCase().endsWith('.zip') || file.type === 'application/zip' || file.type === 'application/x-zip-compressed';

  if (isZip) {
    const zip = await JSZip.loadAsync(file);
    const names = Object.keys(zip.files).filter(n => !zip.files[n].dir);

    const findFile = pat => names.find(n => pat.test(n.split('/').pop()));

    const sources = [
      { key: 'system',      pat: /^system\.xml$/i },
      { key: 'application', pat: /^application\.xml$/i },
      { key: 'security',    pat: /^security\.xml$/i },
      { key: 'setup',       pat: /^setup\.xml$/i },
    ];

    for (const { key, pat } of sources) {
      processingText.textContent = `Parsing ${key} log…`;
      const name = findFile(pat);
      if (name) {
        try {
          const text = await zip.files[name].async('text');
          logData[key] = parseEventXML(text);
        } catch { logData.missing.push(key); }
      } else { logData.missing.push(key); }
    }

    processingText.textContent = 'Parsing Reliability history…';
    const relName = findFile(/^reliabilityhistory\.xml$/i) || findFile(/reliability.*\.xml$/i);
    if (relName) {
      try {
        const buf = await zip.files[relName].async('arraybuffer');
        logData.reliability = parseRelMon(buf);
        if (!logData.reliability) logData.missing.push('reliability');
      } catch { logData.missing.push('reliability'); }
    } else { logData.missing.push('reliability'); }

  } else if (file.name.toLowerCase().endsWith('.xml')) {
    // Single XML — detect type by content
    processingText.textContent = 'Parsing event log…';
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let text;
    if (bytes[0] === 0xFF && bytes[1] === 0xFE)      text = new TextDecoder('utf-16le').decode(buf);
    else if (bytes[0] === 0xFE && bytes[1] === 0xFF) text = new TextDecoder('utf-16be').decode(buf);
    else                                              text = new TextDecoder('utf-8').decode(buf);

    if (text.includes('RelMonReport')) {
      logData.reliability = parseRelMon(buf);
      if (!logData.reliability) throw new Error('Could not parse Reliability Monitor XML.');
      logData.missing.push('system', 'application', 'security', 'setup');
      logData._singleFileSuggestion =
        'Only Reliability Monitor data loaded. For a full incident analysis upload the ZIP from Get-EventLogExport.ps1. ' +
        'To analyse just this file, use <a href="reliability-analyzer.html">Reliability Analyser</a>.';
    } else {
      const events = parseEventXML(text);
      const ch = events[0]?.channel?.toLowerCase() || '';
      if      (ch.includes('system'))      logData.system      = events;
      else if (ch.includes('application')) logData.application = events;
      else if (ch.includes('security'))    logData.security    = events;
      else if (ch.includes('setup'))       logData.setup       = events;
      else                                 logData.system      = events;
      logData.missing.push('application', 'security', 'setup', 'reliability');
      logData._singleFileSuggestion =
        `Single log loaded (${events[0]?.channel || 'unknown channel'}). For a full incident analysis upload the ZIP from Get-EventLogExport.ps1. ` +
        'To analyse a single log, use <a href="windows-log-analyzer.html">Windows Log Analyser</a>.';
    }
  } else {
    throw new Error('Unsupported file type. Upload a ZIP archive or an XML event log.');
  }

  logData.computer = (
    logData.system[0]?.computer ||
    logData.application[0]?.computer ||
    logData.security[0]?.computer || ''
  );
  return logData;
}

// ─── Analysis engine ──────────────────────────────────────────────────────────
function analyzeAll(logData) {
  const findings = [];
  const add = (sev, title, detail, extra = '') => findings.push({ sev, title, detail, extra });
  const { system, application, security, reliability } = logData;

  const fmtEvt = (e, src) =>
    `<div class="finding-event">` +
    `<span class="fe-time">${escHtml(e.timestamp.toISOString().replace('T', ' ').slice(0, 16))}</span>` +
    `<span class="fe-src">${escHtml(src || e.channel || e.provider || '')}</span>` +
    `<span class="fe-msg">${escHtml((e.message || '').slice(0, 120))}</span>` +
    `</div>`;

  const fmtRel = r =>
    `<div class="finding-event">` +
    `<span class="fe-time">${escHtml((r.time || '').replace('T', ' ').slice(0, 16))}</span>` +
    `<span class="fe-src">Reliability</span>` +
    `<span class="fe-msg">${escHtml((r.message || '').slice(0, 120))}</span>` +
    `</div>`;

  // ── 1. BSODs ────────────────────────────────────────────────────────────────
  const bsods = system.filter(e =>
    e.id === 1001 &&
    (e.provider?.toLowerCase().includes('wer') ||
     e.provider?.toLowerCase().includes('windows error') ||
     /bugcheck|bug.?check|stop.*code/i.test(e.message))
  );
  if (bsods.length) {
    add('crit',
      `${bsods.length} system crash (BSOD) recorded`,
      'Kernel bugcheck events detected. Note the stop codes and faulting driver/module. ' +
      'Run <code>Get-WinEvent -LogName System | Where Id -eq 1001</code> for full bugcheck details. ' +
      'Check memory with MemTest86 if the bugcheck is 0x1A or 0x24.',
      bsods.slice(0, 4).map(e => fmtEvt(e, 'System')).join(''));
  }

  // ── 2. Unexpected reboots ───────────────────────────────────────────────────
  const unexpectedReboots = system.filter(e => e.id === 41 || e.id === 6008);
  if (unexpectedReboots.length) {
    const relUnclean = (reliability?.records ?? []).filter(r =>
      /stopped unexpectedly/i.test(r.message)
    );
    const confirmed = relUnclean.length ? ` (${relUnclean.length} confirmed by Reliability Monitor)` : '';
    add(unexpectedReboots.length >= 3 ? 'crit' : 'warn',
      `${unexpectedReboots.length} unexpected reboot${unexpectedReboots.length !== 1 ? 's' : ''}${confirmed}`,
      'System rebooted without a clean shutdown. Causes: kernel crash, power loss, thermal shutdown, or hardware fault. ' +
      'Check Event 41 for last sleep state — state 0 indicates power loss or hard reset.',
      unexpectedReboots.slice(0, 4).map(e => fmtEvt(e, 'System')).join(''));
  }

  // ── 3. Hardware / disk failures ─────────────────────────────────────────────
  const DISK_IDS = new Set([7, 9, 11, 51, 52, 55, 153, 157]);
  const diskEvents = system.filter(e =>
    DISK_IDS.has(e.id) ||
    HW_PATTERNS.some(p => p.test(e.message) || p.test(e.provider))
  );
  const relHwHits = (reliability?.records ?? []).filter(r =>
    HW_PATTERNS.some(p => p.test(r.source) || p.test(r.message))
  );
  if (diskEvents.length || relHwHits.length) {
    const total = diskEvents.length + relHwHits.length;
    add('crit',
      `Hardware/disk failure indicator${total !== 1 ? 's' : ''} (${total})`,
      'Disk I/O errors, NTFS corruption, or bad sector indicators found across System log and Reliability Monitor. ' +
      'Run <code>chkdsk C: /f /r</code> and check SMART data with <code>wmic diskdrive get status</code> before any other investigation.',
      [
        ...diskEvents.slice(0, 2).map(e => fmtEvt(e, 'System')),
        ...relHwHits.slice(0, 2).map(fmtRel),
      ].join(''));
  }

  // ── 4. Audit log cleared ────────────────────────────────────────────────────
  const auditCleared = security.filter(e => e.id === 1102 || e.id === 517);
  if (auditCleared.length) {
    add('crit',
      `Security audit log cleared ${auditCleared.length} time${auditCleared.length !== 1 ? 's' : ''}`,
      'Event 1102 indicates the Security audit log was cleared. This is a strong indicator of an attacker covering tracks, or unauthorized administrative action. ' +
      'Investigate who cleared the log and when.',
      auditCleared.slice(0, 4).map(e => fmtEvt(e, 'Security')).join(''));
  }

  // ── 5. Account lockouts / brute force ───────────────────────────────────────
  const lockouts    = security.filter(e => e.id === 4740);
  const failedLogons = security.filter(e => e.id === 4625);
  if (lockouts.length) {
    const accounts = [...new Set(
      lockouts.map(e => e.data?.TargetUserName || e.data?.SubjectUserName || '?')
    )];
    add('warn',
      `${lockouts.length} account lockout${lockouts.length !== 1 ? 's' : ''} — ${failedLogons.length} failed logon${failedLogons.length !== 1 ? 's' : ''}`,
      `Affected account${accounts.length !== 1 ? 's' : ''}: ${accounts.slice(0, 6).join(', ')}${accounts.length > 6 ? ` + ${accounts.length - 6} more` : ''}. ` +
      'Check the caller workstation field on Event 4740 to identify the source of bad passwords.',
      lockouts.slice(0, 4).map(e => fmtEvt(e, 'Security')).join(''));
  } else if (failedLogons.length >= 20) {
    add('warn',
      `High failed logon count — ${failedLogons.length} failed logon${failedLogons.length !== 1 ? 's' : ''} without lockout`,
      'Elevated failed logons without triggering lockout. Could be a password spray, misconfigured service account, or RDP brute force.',
      failedLogons.slice(0, 4).map(e => fmtEvt(e, 'Security')).join(''));
  }

  // ── 6. Privilege / group changes ────────────────────────────────────────────
  const GROUP_IDS = new Set([4728, 4732, 4756, 4720, 4722, 4724]);
  const privChanges = security.filter(e => GROUP_IDS.has(e.id));
  if (privChanges.length) {
    add('info',
      `${privChanges.length} account/group membership change${privChanges.length !== 1 ? 's' : ''}`,
      'User accounts were created or added to privileged groups. Review if expected.',
      privChanges.slice(0, 3).map(e => fmtEvt(e, 'Security')).join(''));
  }

  // ── 7. Service failures ─────────────────────────────────────────────────────
  const SVC_FAIL_IDS = new Set([7023, 7024, 7031, 7034]);
  const svcFails = system.filter(e => SVC_FAIL_IDS.has(e.id));
  if (svcFails.length) {
    const byService = {};
    for (const e of svcFails) {
      const svc = e.data?.param1 || e.data?.ServiceName || e.data?.['0'] || 'Unknown';
      if (!byService[svc]) byService[svc] = [];
      byService[svc].push(e);
    }
    const sorted = Object.entries(byService).sort((a, b) => b[1].length - a[1].length);
    const summary = sorted.slice(0, 4).map(([s, evs]) => `${s} (${evs.length}×)`).join(', ');
    add('warn',
      `${svcFails.length} service failure${svcFails.length !== 1 ? 's' : ''} — ${sorted.length} service${sorted.length !== 1 ? 's' : ''} affected`,
      `Services that stopped or failed: ${summary}. Check Application log for root cause errors from the same service.`,
      svcFails.slice(0, 4).map(e => fmtEvt(e, 'System')).join(''));
  }

  // ── 8. Recurring app crashes ────────────────────────────────────────────────
  const appCrashes = application.filter(e => e.id === 1000);
  const appHangs   = application.filter(e => e.id === 1002);
  if (appCrashes.length || appHangs.length) {
    const byApp = {};
    for (const e of [...appCrashes, ...appHangs]) {
      const name = (e.data?.ApplicationName || e.data?.Application || '').replace(/\.exe$/i, '') || e.provider;
      const key = name.toLowerCase();
      if (!byApp[key]) byApp[key] = { label: name, crashes: 0, hangs: 0 };
      if (e.id === 1000) byApp[key].crashes++;
      else               byApp[key].hangs++;
    }
    const recurring = Object.values(byApp)
      .filter(v => v.crashes + v.hangs >= 2)
      .sort((a, b) => (b.crashes + b.hangs) - (a.crashes + a.hangs));
    if (recurring.length) {
      const summary = recurring.slice(0, 4).map(v => `${v.label} (${v.crashes + v.hangs}×)`).join(', ');
      add('warn',
        `Recurring application crashes — ${appCrashes.length} crash${appCrashes.length !== 1 ? 'es' : ''}, ${appHangs.length} hang${appHangs.length !== 1 ? 's' : ''}`,
        `Repeatedly failing: ${summary}. Check for pending app updates, DLL conflicts, or corrupt installations. ` +
        'Look at the faulting module in each Event 1000 — a common DLL or runtime points to a shared dependency.',
        appCrashes.slice(0, 4).map(e => fmtEvt(e, 'Application')).join(''));
    }
  }

  // ── 9. Cross-source: post-install regressions ───────────────────────────────
  const relSoftware = (reliability?.records ?? []).filter(r => r.cat === 'software');
  const relCrashes  = (reliability?.records ?? []).filter(r => r.cat === 'crash');
  const regressions = [];
  const window48h = 48 * 60 * 60 * 1000;
  for (const sw of relSoftware) {
    const swTime = new Date(sw.time);
    const after  = d => d >= swTime && d - swTime <= window48h;
    const postRel = relCrashes.filter(r => after(new Date(r.time)));
    const postApp = appCrashes.filter(e => after(e.timestamp));
    const total   = postRel.length + postApp.length;
    if (total >= 2) regressions.push({ sw, total });
  }
  if (regressions.length) {
    regressions.sort((a, b) => b.total - a.total);
    const crashTotal = regressions.reduce((s, r) => s + r.total, 0);
    add('warn',
      `${regressions.length} post-install regression${regressions.length !== 1 ? 's' : ''} — ${crashTotal} crashes after software changes`,
      'Crash clusters within 48h of software installs detected across Reliability Monitor and Application log. ' +
      'Consider rolling back the highlighted applications and retesting.',
      regressions.slice(0, 3).map(r =>
        `<div class="finding-event">` +
        `<span class="fe-time">${escHtml((r.sw.time || '').replace('T', ' ').slice(0, 16))}</span>` +
        `<span class="fe-src">Install</span>` +
        `<span class="fe-msg">${escHtml(r.sw.source)} → ${r.total} crash${r.total !== 1 ? 'es' : ''} in 48h</span>` +
        `</div>`
      ).join(''));
  }

  // ── 10. High error volume (last 24h of data) ────────────────────────────────
  const allEvts = [...system, ...application, ...security, ...(logData.setup ?? [])];
  allEvts.sort((a, b) => b.timestamp - a.timestamp);
  const newest = allEvts[0]?.timestamp;
  if (newest) {
    const recent = allEvts.filter(e =>
      newest - e.timestamp <= 24 * 60 * 60 * 1000 &&
      (e.severity === 'Critical' || e.severity === 'Error')
    );
    if (recent.length >= 10) {
      add('warn',
        `${recent.length} critical/error events in the last 24h of data`,
        'Elevated error rate in the most recent period. System may be actively degrading.',
        recent.slice(0, 4).map(e => fmtEvt(e, e.channel)).join(''));
    }
  }

  // ── 11. All quiet ────────────────────────────────────────────────────────────
  if (!findings.some(f => f.sev === 'crit' || f.sev === 'warn')) {
    add('ok', 'No significant issues detected',
      'No BSODs, unexpected reboots, hardware errors, security alerts, service failures, or recurring application crashes found.');
  }

  return findings.sort((a, b) =>
    ({ crit: 0, warn: 1, ok: 2 }[a.sev] ?? 3) - ({ crit: 0, warn: 1, ok: 2 }[b.sev] ?? 3)
  );
}

// ─── Ticket note builder ──────────────────────────────────────────────────────
function buildTicketNote(logData, findings) {
  const { system, application, security, reliability, computer, missing } = logData;
  const divider = '─'.repeat(60);
  const stripHtml = s => s.replace(/<[^>]+>/g, '');
  const total = system.length + application.length + security.length + (logData.setup?.length ?? 0);
  const sysErr  = system.filter(e => e.severity === 'Critical' || e.severity === 'Error').length;
  const appErr  = application.filter(e => e.severity === 'Critical' || e.severity === 'Error').length;
  const secWarn = security.filter(e => e.severity === 'Critical' || e.severity === 'Error' || e.severity === 'Warning').length;
  const relCrashes = (reliability?.records ?? []).filter(r => r.cat === 'crash').length;

  const lines = [
    'WINDOWS INCIDENT ANALYSIS',
    `Computer:   ${computer || 'unknown'}`,
    `Analysed via Eventful — eventful.lrfa.dev/incident-analyzer.html`,
    '',
    'LOG SOURCES',
    `  System log:       ${system.length.toLocaleString()} events (${sysErr} critical/error)`,
    `  Application log:  ${application.length.toLocaleString()} events (${appErr} critical/error)`,
    `  Security log:     ${security.length.toLocaleString()} events (${secWarn} notable)`,
    reliability ? `  Reliability:      ${reliability.records.length} records (${relCrashes} crashes)` : '',
    missing.length ? `  Missing:          ${missing.join(', ')}` : '',
    '',
    `FINDINGS (${findings.filter(f => f.sev === 'crit' || f.sev === 'warn').length} issue${findings.filter(f => f.sev === 'crit' || f.sev === 'warn').length !== 1 ? 's' : ''})`,
    divider,
  ].filter(l => l !== undefined);

  for (const f of findings.filter(f => f.sev === 'crit' || f.sev === 'warn' || f.sev === 'ok')) {
    const label = { crit: 'CRITICAL', warn: 'WARNING', ok: 'OK' }[f.sev] ?? f.sev.toUpperCase();
    lines.push(`[${label}] ${stripHtml(f.title)}`);
    lines.push(stripHtml(f.detail));
    lines.push('');
  }

  lines.push(divider);
  return lines.join('\n');
}

// ─── Render ───────────────────────────────────────────────────────────────────
function render(logData, findings) {
  const { system, application, security, reliability, computer, missing } = logData;
  const allEvts = [...system, ...application, ...security, ...(logData.setup ?? [])];
  const total = allEvts.length;

  // Sub-heading
  const parts = [];
  if (computer) parts.push(computer);
  parts.push(`${total.toLocaleString()} events across ${4 - missing.filter(m => ['system','application','security','setup'].includes(m)).length} log${4 - missing.filter(m => ['system','application','security','setup'].includes(m)).length !== 1 ? 's' : ''}`);
  if (reliability) parts.push('+ Reliability Monitor');
  resultsSub.textContent = parts.join(' · ');

  if (logData._singleFileSuggestion) {
    const note = document.createElement('p');
    note.className = 'results-sub-note';
    note.innerHTML = logData._singleFileSuggestion;
    resultsSub.insertAdjacentElement('afterend', note);
  }

  renderOverview(logData, findings);

  const importantFindings = findings.filter(f => f.sev === 'crit' || f.sev === 'warn');
  tabFindingsCount.textContent = importantFindings.length || '';
  renderFindings(findings);

  tabEventsCount.textContent = total.toLocaleString();
  tabRelCount.textContent    = reliability?.records.length || '';

  // Initial table renders
  renderEventsTable(logData, allEvts, 'all');
  if (reliability) renderRelTable(reliability.records, 'all');

  copyTicketBtn.onclick = async () => {
    const note = buildTicketNote(logData, findings);
    const ok = await copyToClipboard(note);
    if (ok) {
      copyTicketBtn.classList.add('copied');
      copyTicketBtn.textContent = '✓ Copied';
      setTimeout(() => {
        copyTicketBtn.classList.remove('copied');
        copyTicketBtn.textContent = 'Copy ticket notes';
      }, 2000);
    }
  };
}

// ─── Overview bar ─────────────────────────────────────────────────────────────
function renderOverview(logData, findings) {
  const { system, application, security, reliability } = logData;
  const allEvts = [...system, ...application, ...security, ...(logData.setup ?? [])];

  const critCount = allEvts.filter(e => e.severity === 'Critical').length;
  const errCount  = allEvts.filter(e => e.severity === 'Error').length;
  const warnCount = allEvts.filter(e => e.severity === 'Warning').length;
  const bsods     = findings.filter(f => f.title.includes('BSOD') || f.title.includes('system crash')).length;
  const secAlerts = findings.filter(f => f.sev === 'crit' && (f.title.includes('audit') || f.title.includes('lockout') || f.title.includes('logon'))).length;

  const dates = allEvts.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b);
  const earliest = dates[0]?.toLocaleDateString() ?? '—';
  const latest   = dates[dates.length - 1]?.toLocaleDateString() ?? '—';
  const dateRange = earliest === latest ? earliest : `${earliest} → ${latest}`;

  const hasAnyCrit = findings.some(f => f.sev === 'crit');
  const hasAnyWarn = findings.some(f => f.sev === 'warn');
  const healthLabel = hasAnyCrit ? 'Critical' : hasAnyWarn ? 'Degraded' : 'Healthy';
  const healthColor = hasAnyCrit ? '#f85149' : hasAnyWarn ? '#d29922' : '#3fb950';

  const stat = (num, label, cls, filter) =>
    `<div class="ob-stat ${cls}" data-filter="${filter}" style="cursor:pointer" title="Filter to ${label.toLowerCase()}">` +
    `<span class="ob-stat-num">${typeof num === 'number' ? num.toLocaleString() : num}</span>` +
    `<span class="ob-stat-label">${label}</span></div>`;

  // Source status row
  const sources = [
    { key: 'system',      label: 'System',      count: system.length },
    { key: 'application', label: 'Application',  count: application.length },
    { key: 'security',    label: 'Security',     count: security.length },
    { key: 'setup',       label: 'Setup',        count: (logData.setup ?? []).length },
    { key: 'reliability', label: 'Reliability',  count: reliability?.records.length ?? 0 },
  ];

  overviewGrid.innerHTML = `
    <div class="overview-bar">
      <div style="display:flex;flex-direction:column;gap:2px">
        <span style="font-family:var(--mono);font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">System Health</span>
        <span style="font-family:var(--mono);font-size:18px;font-weight:700;color:${healthColor}">${healthLabel}</span>
      </div>
      <div class="ob-divider"></div>
      <div class="ob-stats">
        ${stat(allEvts.length,  'Total',    'stat-total',                                         'all')}
        ${stat(critCount,       'Critical', critCount > 0 ? 'stat-critical' : 'stat-total',       'Critical')}
        ${stat(errCount,        'Errors',   errCount  > 0 ? 'stat-error'    : 'stat-total',       'Error')}
        ${stat(warnCount,       'Warnings', warnCount > 0 ? 'stat-warning'  : 'stat-total',       'Warning')}
      </div>
      <div class="ob-divider"></div>
      <div class="ia-source-status">
        ${sources.map(s => `
          <div class="ia-source-pill ${logData.missing.includes(s.key) ? 'ia-source-missing' : 'ia-source-found'}">
            <span class="ia-source-dot"></span>
            <span class="ia-source-label">${s.label}</span>
            ${!logData.missing.includes(s.key) ? `<span class="ia-source-count">${s.count.toLocaleString()}</span>` : ''}
          </div>
        `).join('')}
      </div>
      <div class="ob-divider"></div>
      <div style="display:flex;flex-direction:column;gap:2px">
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Date range</span>
        <span style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text2)">${escHtml(dateRange)}</span>
      </div>
    </div>
  `;

  overviewGrid.querySelectorAll('.ob-stat[data-filter]').forEach(el => {
    el.addEventListener('click', () => {
      switchToTab('events');
      const filter = el.dataset.filter;
      const allEvts = [
        ...(logData.system ?? []).map(e => ({ ...e, _src: 'System' })),
        ...(logData.application ?? []).map(e => ({ ...e, _src: 'Application' })),
        ...(logData.security ?? []).map(e => ({ ...e, _src: 'Security' })),
        ...(logData.setup ?? []).map(e => ({ ...e, _src: 'Setup' })),
      ].sort((a, b) => a.timestamp - b.timestamp);
      renderEventsTable(logData, allEvts, filter);
    });
  });
}

// ─── Findings cards ───────────────────────────────────────────────────────────
const SEV_HEADER_CLS = { crit: 'sev-header-critical', warn: 'sev-header-warning', ok: 'sev-header-info' };
const SEV_COLOR      = { crit: '#fb7185', warn: '#fbbf24', ok: '#3fb950' };
const SEV_LABEL      = { crit: 'CRITICAL', warn: 'WARNING', ok: 'OK' };

function renderFindings(findings) {
  const primary   = findings.filter(f => f.sev !== 'info');
  const secondary = findings.filter(f => f.sev === 'info');

  const primaryHtml = primary.map(f => `
    <div class="incident-card">
      <div class="incident-header ${SEV_HEADER_CLS[f.sev] ?? ''}" style="cursor:default">
        <span style="font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${SEV_COLOR[f.sev] ?? '#8b949e'};flex-shrink:0">${SEV_LABEL[f.sev] ?? f.sev.toUpperCase()}</span>
        <span class="incident-title">${f.title}</span>
      </div>
      <div class="incident-body">
        <div class="incident-section">
          <p class="incident-text">${f.detail}</p>
          ${f.extra ? `<div class="finding-events">${f.extra}</div>` : ''}
        </div>
      </div>
    </div>
  `).join('');

  const secondaryHtml = secondary.length ? `
    <div class="findings-notices">
      ${secondary.map(f => `
        <div class="findings-notice">
          <span class="findings-notice-label">NOTE</span>
          <span class="findings-notice-title">${f.title}</span>
          <span class="findings-notice-detail">${f.detail}</span>
        </div>
      `).join('')}
    </div>
  ` : '';

  findingsPanel.innerHTML = primaryHtml + secondaryHtml;
}

// ─── Events table (merged logs) ───────────────────────────────────────────────
const SRC_COLORS = {
  System:      '#58a6ff',
  Application: '#f78166',
  Security:    '#d29922',
  Setup:       '#3fb950',
};
const SEV_COLORS = {
  Critical: '#f85149',
  Error:    '#f85149',
  Warning:  '#d29922',
  Info:     '#8b949e',
  Verbose:  '#8b949e',
};

function renderEventsTable(logData, prebuiltEvents, activeSrc) {
  const eventsFiltersWrap = document.getElementById('events-filters-wrap');
  const eventsTableWrap   = document.getElementById('events-table-wrap');
  if (!eventsFiltersWrap || !eventsTableWrap) return;

  // Build merged events with _src tag
  const allEvts = prebuiltEvents.every(e => '_src' in e) ? prebuiltEvents : [
    ...(logData.system      ?? []).map(e => ({ ...e, _src: 'System' })),
    ...(logData.application ?? []).map(e => ({ ...e, _src: 'Application' })),
    ...(logData.security    ?? []).map(e => ({ ...e, _src: 'Security' })),
    ...(logData.setup       ?? []).map(e => ({ ...e, _src: 'Setup' })),
  ].sort((a, b) => a.timestamp - b.timestamp);

  const sources = ['all', ...new Set(allEvts.map(e => e._src).filter(Boolean))];
  const srcCount = s => s === 'all' ? allEvts.length : allEvts.filter(e => e._src === s).length;

  eventsFiltersWrap.innerHTML = `
    <div class="filter-bar">
      ${sources.map(s => `
        <button class="filter-chip${activeSrc === s ? ' active' : ''}" data-src="${s}">
          ${s === 'all' ? 'All' : s}<span class="chip-count">${srcCount(s).toLocaleString()}</span>
        </button>`).join('')}
      <div style="flex:1"></div>
      <div class="filter-bar-sev">
        ${['Critical','Error','Warning'].map(sev => {
          const n = allEvts.filter(e => e.severity === sev).length;
          return n > 0 ? `<button class="filter-chip" data-src="${sev}">${sev}<span class="chip-count">${n.toLocaleString()}</span></button>` : '';
        }).join('')}
      </div>
    </div>
  `;

  const filtered = activeSrc === 'all' ? allEvts
    : ['Critical','Error','Warning'].includes(activeSrc) ? allEvts.filter(e => e.severity === activeSrc)
    : allEvts.filter(e => e._src === activeSrc);

  if (!filtered.length) {
    eventsTableWrap.innerHTML = '<p class="no-results">No events for this filter.</p>';
    return;
  }

  const sorted = [...filtered].sort((a, b) => b.timestamp - a.timestamp);

  eventsTableWrap.innerHTML = `
    <div class="event-table-wrap">
      <table class="event-table">
        <thead><tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Source Log</th>
          <th>Event ID</th>
          <th>Provider</th>
          <th>Message</th>
        </tr></thead>
        <tbody>
          ${sorted.slice(0, 500).map(e => `
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap">
                ${escHtml(e.timestamp.toISOString().replace('T', ' ').slice(0, 16))}
              </td>
              <td><span class="cat-badge" style="color:${SEV_COLORS[e.severity] ?? '#8b949e'}">${escHtml(e.severity)}</span></td>
              <td><span class="cat-badge" style="color:${SRC_COLORS[e._src] ?? '#8b949e'}">${escHtml(e._src || '')}</span></td>
              <td style="font-family:var(--mono);font-size:12px">${e.id}</td>
              <td class="et-source">${escHtml((e.provider || '').replace(/^Microsoft-Windows-/i, ''))}</td>
              <td class="et-msg">${escHtml((e.message || '').slice(0, 200))}</td>
            </tr>`).join('')}
        </tbody>
      </table>
      ${sorted.length > 500 ? `<p class="no-results" style="margin:0.75rem 1rem;font-size:0.82rem">Showing first 500 of ${sorted.length.toLocaleString()} events. Use source/severity filters to narrow down.</p>` : ''}
    </div>
  `;

  eventsFiltersWrap.querySelectorAll('.filter-chip').forEach(btn => {
    btn.addEventListener('click', () => renderEventsTable(logData, allEvts, btn.dataset.src));
  });
}

// ─── Reliability tab ──────────────────────────────────────────────────────────
const REL_CAT_LABEL = { crash: 'App Crash', hang: 'App Hang', update: 'Update', software: 'Software', info: 'Info' };
const REL_CAT_COLOR = { crash: '#f85149', hang: '#d29922', update: '#3fb950', software: '#58a6ff', info: '#8b949e' };

function renderRelTable(records, activeFilter) {
  const relFiltersWrap = document.getElementById('rel-filters-wrap');
  const relTableWrap   = document.getElementById('rel-table-wrap');
  if (!relFiltersWrap || !relTableWrap) return;

  const cats = ['all', ...new Set(records.map(r => r.cat))];
  const catCount = c => c === 'all' ? records.length : records.filter(r => r.cat === c).length;

  relFiltersWrap.innerHTML = `
    <div class="filter-bar">
      ${cats.map(c => `
        <button class="filter-chip${activeFilter === c ? ' active' : ''}" data-cat="${c}">
          ${c === 'all' ? 'All' : (REL_CAT_LABEL[c] ?? c)}<span class="chip-count">${catCount(c)}</span>
        </button>`).join('')}
    </div>
  `;

  const filtered = activeFilter === 'all' ? records : records.filter(r => r.cat === activeFilter);

  relTableWrap.innerHTML = `
    <div class="event-table-wrap">
      <table class="event-table">
        <thead><tr>
          <th>Time</th>
          <th>Impact</th>
          <th>Category</th>
          <th>Source / Application</th>
          <th>Problem</th>
        </tr></thead>
        <tbody>
          ${filtered.map(r => `
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap">
                ${escHtml((r.time || '').replace('T', ' ').slice(0, 16))}
              </td>
              <td><span class="cat-badge" style="color:${r.impact === 'Critical' ? '#f85149' : r.impact === 'Warning' ? '#d29922' : '#8b949e'}">${escHtml(r.impact)}</span></td>
              <td><span class="cat-badge" style="color:${REL_CAT_COLOR[r.cat] ?? '#8b949e'}">${REL_CAT_LABEL[r.cat] ?? r.cat}</span></td>
              <td class="et-source">${escHtml(r.source || '')}</td>
              <td class="et-msg">${escHtml(r.message || '')}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;

  relFiltersWrap.querySelectorAll('.filter-chip').forEach(btn => {
    btn.addEventListener('click', () => renderRelTable(records, btn.dataset.cat));
  });
}

// ─── Tab switching ────────────────────────────────────────────────────────────
function switchToTab(name) {
  document.querySelectorAll('.analyzer-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  findingsPanel.hidden    = name !== 'findings';
  eventsPanel.hidden      = name !== 'events';
  reliabilityPanel.hidden = name !== 'reliability';
}

document.querySelectorAll('.analyzer-tab').forEach(tab => {
  tab.addEventListener('click', () => switchToTab(tab.dataset.tab));
});

// ─── Drop zone ────────────────────────────────────────────────────────────────
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  processFile(e.dataTransfer.files[0]);
});
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => processFile(fileInput.files[0]));
newAnalysisBtn.addEventListener('click', resetToUpload);

function resetToUpload() {
  processingSection.innerHTML = `
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Reading archive…</p>
  `;
  uploadSection.hidden     = false;
  processingSection.hidden = true;
  resultsSection.hidden    = true;
  fileInput.value          = '';
}
