import { setupTheme } from './theme.js';
import { escHtml } from './utils.js';
import { copyToClipboard } from './clipboard.js';

setupTheme();

// ─── DOM refs ────────────────────────────────────────────────────────────────
const uploadSection      = document.getElementById('upload-section');
const processingSection  = document.getElementById('processing-section');
const processingText     = document.getElementById('processing-text');
const resultsSection     = document.getElementById('results-section');
const dropZone           = document.getElementById('drop-zone');
const fileInput          = document.getElementById('file-input');
const newAnalysisBtn     = document.getElementById('new-analysis-btn');
const copyTicketBtn      = document.getElementById('copy-ticket-btn');
const resultsSub         = document.getElementById('results-sub');
const overviewGrid       = document.getElementById('overview-grid');
const findingsPanel      = document.getElementById('findings-panel');
const recordsPanel       = document.getElementById('records-panel');
const recordsFiltersWrap = document.getElementById('records-filters-wrap');
const recordsTableWrap   = document.getElementById('records-table-wrap');
const tabFindingsCount   = document.getElementById('tab-findings-count');
const tabRecordsCount    = document.getElementById('tab-records-count');

// ─── Classification ───────────────────────────────────────────────────────────
function classifyEvent(problem) {
  const p = (problem || '').toLowerCase();
  if (p.includes('stopped working'))         return 'crash';
  if (p.includes('stopped responding'))      return 'hang';
  if (/windows update|update/.test(p))       return 'update';
  if (/install|reconfigur|removal/.test(p))  return 'software';
  return 'info';
}

const CAT_LABEL = {
  crash:    'App Crash',
  hang:     'App Hang',
  update:   'Update',
  software: 'Software',
  info:     'Info',
};

const CAT_COLOR = {
  crash:    '#f85149',
  hang:     '#d29922',
  update:   '#3fb950',
  software: '#58a6ff',
  info:     '#8b949e',
};

const HW_PATTERNS = [
  /bad.?block/i, /disk.?error/i, /ntfs.*corrupt/i, /corrupt.*ntfs/i,
  /hardware.?error/i, /memory.*corrupt/i, /corrupt.*memory/i,
  /sector.?error/i, /read.?error/i, /i\/o.?error/i,
  /chkdsk/i, /file.?system.*error/i, /bad.?sector/i,
];

// ─── XML parser ───────────────────────────────────────────────────────────────
function parseXml(text) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(text, 'application/xml');

  const parseErr = doc.querySelector('parsererror');
  if (parseErr) throw new Error('Invalid XML: ' + parseErr.textContent.slice(0, 120));

  const root = doc.documentElement;
  if (root.tagName !== 'RelMonReport') {
    if (root.tagName === 'Events' || doc.querySelector('Event > System')) {
      throw new Error('WRONG_TOOL:event_log');
    }
    throw new Error(
      `Unrecognised format — root element is <${root.tagName}>. ` +
      `Expected <RelMonReport>. Open Reliability Monitor → Action → Save Reliability History.`
    );
  }

  const generated = root.getAttribute('TimeGenerated') || '';

  const records = [...doc.querySelectorAll('RacEvents > Event')].map(ev => {
    const get = tag => ev.querySelector(tag)?.textContent?.trim() ?? '';
    const time    = get('Time');
    const impact  = get('Impact');
    const source  = get('Source');
    const problem = get('Problem');
    return { time, date: time.slice(0, 10), source, product: source, message: problem, impact, cat: classifyEvent(problem) };
  }).sort((a, b) => b.time.localeCompare(a.time));

  if (!records.length) throw new Error('No events found in this Reliability Monitor export.');
  return { generated, records };
}

// ─── Findings engine ──────────────────────────────────────────────────────────
function analyse(records) {
  const findings = [];
  const add = (sev, title, detail, extra = '') =>
    findings.push({ sev, title, detail, extra });

  const crashes  = records.filter(r => r.cat === 'crash');
  const hangs    = records.filter(r => r.cat === 'hang');
  const warnings = records.filter(r => r.impact === 'Warning');

  const fmtTime = t => t ? t.replace('T', ' ').slice(0, 16) : '';
  const eventRow = r =>
    `<div class="finding-event"><span class="fe-time">${escHtml(fmtTime(r.time))}</span><span class="fe-src">${escHtml(r.source)}</span><span class="fe-msg">${escHtml(r.message)}</span></div>`;

  // 1. Hardware failure indicators
  const hwHits = records.filter(r =>
    HW_PATTERNS.some(p => p.test(r.source) || p.test(r.message))
  );
  if (hwHits.length) {
    add('crit',
      `Hardware failure indicator${hwHits.length > 1 ? 's' : ''} detected (${hwHits.length})`,
      'One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. ' +
      'Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.',
      hwHits.slice(0, 3).map(eventRow).join('')
    );
  }

  // 2. Recurring app crashes
  const crashByApp = {};
  for (const r of crashes) {
    const key = r.source.toLowerCase();
    if (!crashByApp[key]) crashByApp[key] = { label: r.source, events: [] };
    crashByApp[key].events.push(r);
  }
  for (const v of Object.values(crashByApp).sort((a, b) => b.events.length - a.events.length)) {
    if (v.events.length >= 2) {
      const times  = v.events.map(r => r.time).filter(Boolean).sort();
      const first  = times.length ? fmtTime(times[0]) : '';
      const last   = times.length > 1 ? fmtTime(times[times.length - 1]) : '';
      const range  = first && last && first !== last ? ` between ${first} and ${last}` : first ? ` at ${first}` : '';
      add('warn',
        `${escHtml(v.label)} crashed ${v.events.length} time${v.events.length > 1 ? 's' : ''}`,
        `Repeated crash pattern${range}. Check for a pending application update, conflicting DLL, or corrupt installation. ` +
        `Look for Event 1000 in the Application log for faulting module details.`,
        v.events.slice(0, 5).map(eventRow).join('')
      );
    }
  }

  // 3. Recurring app hangs
  const hangByApp = {};
  for (const r of hangs) {
    const key = r.source.toLowerCase();
    if (!hangByApp[key]) hangByApp[key] = { label: r.source, events: [] };
    hangByApp[key].events.push(r);
  }
  for (const v of Object.values(hangByApp).sort((a, b) => b.events.length - a.events.length)) {
    if (v.events.length >= 2) {
      const times = v.events.map(r => r.time).filter(Boolean).sort();
      const first = times.length ? fmtTime(times[0]) : '';
      const last  = times.length > 1 ? fmtTime(times[times.length - 1]) : '';
      const range = first && last && first !== last ? ` between ${first} and ${last}` : first ? ` at ${first}` : '';
      add('warn',
        `${escHtml(v.label)} stopped responding ${v.events.length} time${v.events.length > 1 ? 's' : ''}`,
        `Repeated hang pattern${range}. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus ` +
        `scanning files the app is trying to access. Try adding the app directory to AV exclusions as a test.`,
        v.events.slice(0, 5).map(eventRow).join('')
      );
    }
  }

  // 4. Post-install regressions — aggregate all clusters into ONE finding
  const software = records.filter(r => r.cat === 'software');
  const regressions = [];
  for (const sw of software) {
    const swTime    = new Date(sw.time);
    const window48h = new Date(swTime.getTime() + 48 * 60 * 60 * 1000);
    const postCrashes = crashes.filter(r => { const t = new Date(r.time); return t >= swTime && t <= window48h; });
    if (postCrashes.length >= 2) regressions.push({ sw, postCrashes });
  }
  if (regressions.length) {
    regressions.sort((a, b) => b.postCrashes.length - a.postCrashes.length);
    const totalCrashes = regressions.reduce((s, r) => s + r.postCrashes.length, 0);
    const top = regressions.slice(0, 3);
    add('warn',
      `${regressions.length} post-install regression${regressions.length > 1 ? 's' : ''} detected — ${totalCrashes} crash${totalCrashes > 1 ? 'es' : ''} after software changes`,
      `Crash clusters found within 48h of software installs/changes. ` +
      `Check top offenders below — consider rolling back the relevant application.`,
      top.map(({ sw: s, postCrashes: pc }) =>
        `<div class="finding-event"><span class="fe-time">${escHtml(fmtTime(s.time))}</span><span class="fe-src">${escHtml(s.source)}</span><span class="fe-msg">→ ${pc.length} crash${pc.length > 1 ? 'es' : ''} in 48h</span></div>`
      ).join('') + (regressions.length > 3 ? `<div class="finding-event" style="color:var(--text3);font-size:11px">+ ${regressions.length - 3} more</div>` : '')
    );
  }

  // 5. Recent critical events (last 24h relative to newest event in data)
  const reportTime = new Date(records[0]?.time || Date.now());
  const recent = records.filter(r => {
    const t = new Date(r.time);
    return (reportTime - t) <= 24 * 60 * 60 * 1000 && (r.cat === 'crash' || r.cat === 'hang');
  });
  if (recent.length) {
    add('warn',
      `${recent.length} crash/hang event${recent.length > 1 ? 's' : ''} in the 24h before this report`,
      `Active instability — these events are recent. Prioritise investigation.`,
      recent.map(eventRow).join('')
    );
  }

  // 6. High crash volume
  if (crashes.length >= 8 && !findings.some(f => f.sev === 'crit')) {
    add('warn',
      `High crash volume — ${crashes.length} application crashes recorded`,
      'Unusually high number of application crash events. Consider running ' +
      '<code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption.'
    );
  }

  // 7. Failed updates / installs — info severity (shown compact, excluded from ticket notes)
  if (warnings.length > 0) {
    const labels = [...new Set(warnings.map(r => r.source))];
    const preview = labels.slice(0, 5).join(', ') + (labels.length > 5 ? ` + ${labels.length - 5} more` : '');
    add('info',
      `${warnings.length} failed update${warnings.length > 1 ? 's' : ''} or installation${warnings.length > 1 ? 's' : ''}`,
      `Check Windows Update history and application installer logs. Affected: ${escHtml(preview)}.`
    );
  }

  // 8. All quiet
  if (!findings.some(f => f.sev === 'crit' || f.sev === 'warn')) {
    add('ok',
      'No significant issues detected',
      'No recurring crashes, hangs, hardware indicators, or post-install regressions found.'
    );
  }

  return findings.sort((a, b) => ({ crit: 0, warn: 1, ok: 2 }[a.sev] ?? 3) - ({ crit: 0, warn: 1, ok: 2 }[b.sev] ?? 3));
}

// ─── Ticket note builder ──────────────────────────────────────────────────────
function buildTicketNote(records, findings, generated) {
  const crashes  = records.filter(r => r.cat === 'crash').length;
  const hangs    = records.filter(r => r.cat === 'hang').length;
  const software = records.filter(r => r.cat === 'software').length;
  const warnings = records.filter(r => r.impact === 'Warning').length;
  const reportDate = generated ? generated.slice(0, 10) : 'unknown';
  const divider = '─'.repeat(60);
  const stripHtml = s => s.replace(/<[^>]+>/g, '');

  const lines = [
    'RELIABILITY ANALYSIS',
    `Report Date: ${reportDate}`,
    `Analysed via Eventful — eventful.lrfa.dev/reliability-analyzer.html`,
    '',
    'SUMMARY',
    `  Total Events:      ${String(records.length).padStart(4)}`,
    `  Crashes:           ${String(crashes).padStart(4)}`,
    `  Hangs:             ${String(hangs).padStart(4)}`,
    `  Software Changes:  ${String(software).padStart(4)}`,
    `  Warnings:          ${String(warnings).padStart(4)}`,
    '',
    `FINDINGS (${findings.filter(f => f.sev === 'crit' || f.sev === 'warn').length} issue${findings.filter(f => f.sev === 'crit' || f.sev === 'warn').length !== 1 ? 's' : ''})`,
    divider,
  ];

  for (const f of findings.filter(f => f.sev === 'crit' || f.sev === 'warn' || f.sev === 'ok')) {
    const label = { crit: 'CRITICAL', warn: 'WARNING', ok: 'OK' }[f.sev] ?? f.sev;
    lines.push(`[${label}] ${stripHtml(f.title)}`);
    lines.push(stripHtml(f.detail));
    lines.push('');
  }

  lines.push(divider);
  return lines.join('\n');
}

// ─── Render helpers ───────────────────────────────────────────────────────────
function renderOverview(records, generated) {
  const crashes  = records.filter(r => r.cat === 'crash').length;
  const hangs    = records.filter(r => r.cat === 'hang').length;
  const software = records.filter(r => r.cat === 'software').length;
  const warnings = records.filter(r => r.impact === 'Warning').length;
  const dates    = records.map(r => r.date).filter(Boolean).sort();
  const earliest = dates.length ? dates[0] : '—';
  const latest   = dates.length ? dates[dates.length - 1] : '—';
  const dateRange = earliest === latest ? earliest : `${earliest} → ${latest}`;

  const stat = (num, label, cls, filter) =>
    `<div class="ob-stat ${cls}" data-filter="${filter}" style="cursor:pointer" title="Show ${label.toLowerCase()}">` +
    `<span class="ob-stat-num">${num}</span><span class="ob-stat-label">${label}</span></div>`;

  overviewGrid.className = '';
  overviewGrid.innerHTML = `
    <div class="overview-bar">
      <div class="ob-stats">
        ${stat(records.length, 'Total',    'stat-total',                                   'all')}
        ${stat(crashes,  'Crashes',  crashes  > 0 ? 'stat-critical' : 'stat-total',        'crash')}
        ${stat(hangs,    'Hangs',    hangs    > 0 ? 'stat-error'    : 'stat-total',        'hang')}
        ${stat(software, 'Software', 'stat-info',                                          'software')}
        ${stat(warnings, 'Warnings', warnings > 0 ? 'stat-warning'  : 'stat-total',        'warning')}
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
      switchToTab('records');
      renderRecordsTable(records, el.dataset.filter);
    });
  });
}

const SEV_HEADER_CLS = { crit: 'sev-header-critical', warn: 'sev-header-warning', ok: 'sev-header-info' };
const SEV_COLOR      = { crit: '#fb7185', warn: '#fbbf24', ok: '#3fb950' };
const SEV_LABEL      = { crit: 'CRITICAL', warn: 'WARNING', ok: 'OK' };

function renderFindings(findings) {
  if (!findings.length) {
    findingsPanel.innerHTML = '<p class="no-results">No findings generated.</p>';
    return;
  }

  const primary   = findings.filter(f => f.sev === 'crit' || f.sev === 'warn' || f.sev === 'ok');
  const secondary = findings.filter(f => f.sev === 'info');

  const primaryHtml = primary.map(f => `
    <div class="incident-card">
      <div class="incident-header ${SEV_HEADER_CLS[f.sev] ?? ''}" style="cursor:default">
        <span style="font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${SEV_COLOR[f.sev] ?? '#8b949e'};flex-shrink:0">${SEV_LABEL[f.sev] ?? f.sev}</span>
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
  tabFindingsCount.textContent = primary.filter(f => f.sev === 'crit' || f.sev === 'warn').length || '';
}

function renderRecordsTable(records, activeFilter) {
  const cats = ['all', ...new Set(records.map(r => r.cat))];
  if (records.some(r => r.impact === 'Warning')) cats.push('warning');

  const chipLabel = c => c === 'all' ? 'All' : c === 'warning' ? 'Warnings' : (CAT_LABEL[c] ?? c);
  const chipCount = c => c === 'all' ? records.length
    : c === 'warning' ? records.filter(r => r.impact === 'Warning').length
    : records.filter(r => r.cat === c).length;

  recordsFiltersWrap.innerHTML = `
    <div class="filter-bar">
      ${cats.map(c => `
        <button class="filter-chip${activeFilter === c ? ' active' : ''}" data-cat="${c}">
          ${chipLabel(c)}<span class="chip-count">${chipCount(c)}</span>
        </button>
      `).join('')}
    </div>
  `;

  const filtered = activeFilter === 'all'     ? records
    : activeFilter === 'warning' ? records.filter(r => r.impact === 'Warning')
    : records.filter(r => r.cat === activeFilter);

  if (!filtered.length) {
    recordsTableWrap.innerHTML = '<p class="no-results">No records for this filter.</p>';
    return;
  }

  recordsTableWrap.innerHTML = `
    <div class="event-table-wrap">
      <table class="event-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Impact</th>
            <th>Category</th>
            <th>Source / Application</th>
            <th>Problem</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(r => `
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap">${escHtml(r.time ? r.time.replace('T', ' ').slice(0, 16) : '—')}</td>
              <td><span class="cat-badge" style="color:${r.impact === 'Critical' ? '#f85149' : r.impact === 'Warning' ? '#d29922' : '#8b949e'}">${escHtml(r.impact)}</span></td>
              <td><span class="cat-badge" style="color:${CAT_COLOR[r.cat] ?? '#8b949e'}">${CAT_LABEL[r.cat] ?? r.cat}</span></td>
              <td class="et-source">${escHtml(r.source)}</td>
              <td class="et-msg">${escHtml(r.message)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;

  recordsFiltersWrap.querySelectorAll('.filter-chip').forEach(btn => {
    btn.addEventListener('click', () => renderRecordsTable(records, btn.dataset.cat));
  });
}

// ─── Tab switching ────────────────────────────────────────────────────────────
function switchToTab(name) {
  document.querySelectorAll('.analyzer-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  findingsPanel.hidden = name !== 'findings';
  recordsPanel.hidden  = name !== 'records';
}

document.querySelectorAll('.analyzer-tab').forEach(tab => {
  tab.addEventListener('click', () => switchToTab(tab.dataset.tab));
});

// ─── File handling ────────────────────────────────────────────────────────────
function showParseError(title, bodyHtml) {
  uploadSection.hidden     = true;
  processingSection.hidden = false;
  processingSection.innerHTML = `
    <p class="processing-error">
      <strong>${escHtml(title)}</strong><br>
      ${bodyHtml}
    </p>
    <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
  `;
  document.getElementById('retry-btn')?.addEventListener('click', resetToUpload);
}

function processFile(file) {
  if (!file) return;

  if (file.name.toLowerCase().endsWith('.zip')) {
    showParseError('Wrong file type',
      'This looks like a ZIP archive — use <a href="incident-analyzer.html">Windows Incident Analyser</a> to analyse multiple logs together.');
    return;
  }

  uploadSection.hidden     = true;
  processingSection.hidden = false;
  resultsSection.hidden    = true;
  processingText.textContent = 'Parsing reliability records…';

  const reader = new FileReader();
  reader.onload = e => {
    try {
      processingText.textContent = 'Analysing…';

      const buf   = e.target.result;
      const bytes = new Uint8Array(buf);
      let text;
      if (bytes[0] === 0xFF && bytes[1] === 0xFE) {
        text = new TextDecoder('utf-16le').decode(buf);
      } else if (bytes[0] === 0xFE && bytes[1] === 0xFF) {
        text = new TextDecoder('utf-16be').decode(buf);
      } else {
        text = new TextDecoder('utf-8').decode(buf);
      }

      const { generated, records } = parseXml(text);

      processingSection.hidden = true;
      resultsSection.hidden    = false;

      resultsSub.textContent = `${records.length} events · Report generated ${generated || 'unknown'}`;

      renderOverview(records, generated);

      const findings = analyse(records);
      renderFindings(findings);
      tabRecordsCount.textContent = records.length;
      renderRecordsTable(records, 'all');

      // Wire copy button with current analysis data
      copyTicketBtn.onclick = async () => {
        const note = buildTicketNote(records, findings, generated);
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

    } catch (err) {
      if (err.message === 'WRONG_TOOL:event_log') {
        showParseError('Wrong file type',
          'This looks like a Windows Event Log export — use <a href="windows-log-analyzer.html">Windows Log Analyser</a> instead.');
      } else {
        showParseError('Could not parse file',
          `${escHtml(err.message)}<br>` +
          `<span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>`);
      }
    }
  };
  reader.readAsArrayBuffer(file);
}

function resetToUpload() {
  processingSection.innerHTML = `
    <div class="processing-spinner"></div>
    <p id="processing-text" class="processing-text">Parsing reliability records…</p>
  `;
  uploadSection.hidden     = false;
  processingSection.hidden = true;
  resultsSection.hidden    = true;
  fileInput.value          = '';
}

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
