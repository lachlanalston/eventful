import { setupTheme } from './theme.js';
import { escHtml } from './utils.js';

setupTheme();

// ─── DOM refs ────────────────────────────────────────────────────────────────
const uploadSection     = document.getElementById('upload-section');
const processingSection = document.getElementById('processing-section');
const processingText    = document.getElementById('processing-text');
const resultsSection    = document.getElementById('results-section');
const dropZone          = document.getElementById('drop-zone');
const fileInput         = document.getElementById('file-input');
const newAnalysisBtn    = document.getElementById('new-analysis-btn');
const resultsSub        = document.getElementById('results-sub');
const overviewGrid      = document.getElementById('overview-grid');
const findingsPanel     = document.getElementById('findings-panel');
const recordsPanel      = document.getElementById('records-panel');
const recordsFiltersWrap = document.getElementById('records-filters-wrap');
const recordsTableWrap   = document.getElementById('records-table-wrap');
const tabFindingsCount  = document.getElementById('tab-findings-count');
const tabRecordsCount   = document.getElementById('tab-records-count');

// ─── Category classification ─────────────────────────────────────────────────
function classify(sourceName) {
  const s = (sourceName || '').toLowerCase();
  if (/application error/.test(s))                    return 'crash';
  if (/application hang/.test(s))                     return 'hang';
  if (/windows error reporting/.test(s))              return 'wer';
  if (/msiinstaller|install|setup|uninstall/i.test(s)) return 'software';
  if (/windows update|windowsupdate|updateclient/i.test(s)) return 'update';
  if (/windows|microsoft/.test(s))                    return 'windows';
  return 'info';
}

const CAT_LABEL = {
  crash:    'App Crash',
  hang:     'App Hang',
  wer:      'WER',
  software: 'Software',
  update:   'Update',
  windows:  'Windows',
  info:     'Info',
};

const CAT_COLOR = {
  crash:    '#f85149',
  hang:     '#d29922',
  wer:      '#d29922',
  software: '#58a6ff',
  update:   '#3fb950',
  windows:  '#bc8cff',
  info:     '#8b949e',
};

// Hardware failure keywords in message text
const HW_PATTERNS = [
  /bad.?block/i, /disk.?error/i, /ntfs.*corrupt/i, /corrupt.*ntfs/i,
  /hardware.?error/i, /memory.*corrupt/i, /corrupt.*memory/i,
  /sector.?error/i, /read.?error/i, /i\/o.?error/i,
  /chkdsk/i, /file.?system.*error/i, /bad.?sector/i,
];

function isHardwareIndicator(msg) {
  return HW_PATTERNS.some(p => p.test(msg));
}

// ─── XML parser ──────────────────────────────────────────────────────────────
function parseXml(text) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(text, 'application/xml');

  const parseErr = doc.querySelector('parsererror');
  if (parseErr) throw new Error('Invalid XML: ' + parseErr.textContent.slice(0, 120));

  const root = doc.querySelector('ReliabilityRecords');
  if (!root) throw new Error('Not a ReliabilityHistory.xml file — missing <ReliabilityRecords> root element.');

  const computer  = root.getAttribute('computer') || '';
  const generated = root.getAttribute('generated') || '';

  const records = [...doc.querySelectorAll('Record')].map(r => {
    const get = tag => r.querySelector(tag)?.textContent?.trim() ?? '';
    const time = get('TimeGenerated');
    return {
      time,
      date:    time.slice(0, 10),
      source:  get('SourceName'),
      product: get('ProductName'),
      message: get('Message'),
      eventId: get('EventIdentifier'),
      user:    get('User'),
      cat:     classify(get('SourceName')),
    };
  }).sort((a, b) => b.time.localeCompare(a.time));

  return { computer, generated, records };
}

// ─── Findings engine ─────────────────────────────────────────────────────────
function analyse(records) {
  const findings = [];

  // Helper: add finding
  const add = (sev, title, detail, extra = '') =>
    findings.push({ sev, title, detail, extra });

  const crashes  = records.filter(r => r.cat === 'crash');
  const hangs    = records.filter(r => r.cat === 'hang');
  const software = records.filter(r => r.cat === 'software');

  // 1. Hardware failure indicators
  const hwHits = records.filter(r => isHardwareIndicator(r.message));
  if (hwHits.length) {
    add('crit',
      `Hardware failure indicator${hwHits.length > 1 ? 's' : ''} detected (${hwHits.length})`,
      'One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. ' +
      'Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.',
      hwHits.slice(0, 3).map(r =>
        `<div class="finding-event"><span class="fe-time">${escHtml(r.time)}</span> <span class="fe-src">${escHtml(r.source)}</span> — ${escHtml(r.message.slice(0, 120))}</div>`
      ).join('')
    );
  }

  // 2. Recurring app crashes
  const crashByApp = {};
  for (const r of crashes) {
    const key = (r.product || r.source).toLowerCase();
    if (!crashByApp[key]) crashByApp[key] = { label: r.product || r.source, events: [] };
    crashByApp[key].events.push(r);
  }
  for (const [, v] of Object.entries(crashByApp).sort((a, b) => b[1].events.length - a[1].events.length)) {
    if (v.events.length >= 3) {
      const first = v.events[v.events.length - 1].time.slice(0, 10);
      const last  = v.events[0].time.slice(0, 10);
      add('warn',
        `${escHtml(v.label)} crashed ${v.events.length} times`,
        `Repeated crash pattern from ${first} to ${last}. Check for a pending application update, ` +
        `conflicting DLL, or corrupt installation. Look for Event 1000 in the Application log for faulting module details.`,
        v.events.slice(0, 3).map(r =>
          `<div class="finding-event"><span class="fe-time">${escHtml(r.time)}</span> ${escHtml(r.message.slice(0, 100))}</div>`
        ).join('')
      );
    }
  }

  // 3. Recurring app hangs
  const hangByApp = {};
  for (const r of hangs) {
    const key = (r.product || r.source).toLowerCase();
    if (!hangByApp[key]) hangByApp[key] = { label: r.product || r.source, events: [] };
    hangByApp[key].events.push(r);
  }
  for (const [, v] of Object.entries(hangByApp).sort((a, b) => b[1].events.length - a[1].events.length)) {
    if (v.events.length >= 2) {
      add('warn',
        `${escHtml(v.label)} stopped responding ${v.events.length} times`,
        `Repeated hang pattern. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning ' +
        'files the app is trying to access. Try disabling AV exclusions for the app directory as a test.`,
        v.events.slice(0, 3).map(r =>
          `<div class="finding-event"><span class="fe-time">${escHtml(r.time)}</span> ${escHtml(r.message.slice(0, 100))}</div>`
        ).join('')
      );
    }
  }

  // 4. Post-install regressions — crash cluster appearing within 48h of a software change
  for (const sw of software) {
    const swTime = new Date(sw.time);
    const window48h = new Date(swTime.getTime() + 48 * 60 * 60 * 1000);
    const postCrashes = crashes.filter(r => {
      const t = new Date(r.time);
      return t >= swTime && t <= window48h;
    });
    if (postCrashes.length >= 2) {
      const apps = [...new Set(postCrashes.map(r => r.product || r.source))].join(', ');
      add('warn',
        `${postCrashes.length} crash${postCrashes.length > 1 ? 'es' : ''} within 48h of software change`,
        `<strong>${escHtml(sw.product || sw.source)}</strong> was installed/changed on ${escHtml(sw.time.slice(0, 10))}. ` +
        `${postCrashes.length} crashes followed involving: ${escHtml(apps)}. ` +
        `Consider rolling back or checking for compatibility issues introduced by the change.`,
        postCrashes.slice(0, 3).map(r =>
          `<div class="finding-event"><span class="fe-time">${escHtml(r.time)}</span> ${escHtml(r.product || r.source)} — ${escHtml(r.message.slice(0, 80))}</div>`
        ).join('')
      );
    }
  }

  // 5. Recent critical events (last 24h)
  const now = new Date();
  const recent = records.filter(r => {
    const t = new Date(r.time);
    return (now - t) <= 24 * 60 * 60 * 1000 && (r.cat === 'crash' || r.cat === 'hang');
  });
  if (recent.length) {
    add('warn',
      `${recent.length} crash/hang event${recent.length > 1 ? 's' : ''} in the last 24 hours`,
      `Active instability — these issues are recent and likely still occurring. Prioritise investigation.`,
      recent.map(r =>
        `<div class="finding-event"><span class="fe-time">${escHtml(r.time)}</span> <span class="fe-src">${escHtml(CAT_LABEL[r.cat])}</span> ${escHtml(r.product || r.source)}</div>`
      ).join('')
    );
  }

  // 6. High overall crash volume
  if (crashes.length >= 10 && !findings.some(f => f.sev === 'crit')) {
    add('warn',
      `High crash volume — ${crashes.length} application crashes recorded`,
      `This machine has an unusually high number of application crash events. Consider running ` +
      `SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth to check for system file corruption.`
    );
  }

  // 7. All quiet
  if (findings.length === 0) {
    add('ok',
      'No significant issues detected',
      'No recurring crashes, hangs, hardware indicators, or post-install regressions found in the reliability history.'
    );
  }

  return findings.sort((a, b) => {
    const order = { crit: 0, warn: 1, ok: 2 };
    return (order[a.sev] ?? 3) - (order[b.sev] ?? 3);
  });
}

// ─── Render helpers ──────────────────────────────────────────────────────────
function renderOverview(records, computer) {
  const crashes  = records.filter(r => r.cat === 'crash').length;
  const hangs    = records.filter(r => r.cat === 'hang').length;
  const software = records.filter(r => r.cat === 'software').length;
  const dates    = records.map(r => r.date).filter(Boolean);
  const earliest = dates.length ? dates[dates.length - 1] : '—';
  const latest   = dates.length ? dates[0] : '—';

  const stat = (label, value, color = '') =>
    `<div class="overview-stat">${color ? `<span class="overview-value" style="color:${color}">${value}</span>` : `<span class="overview-value">${value}</span>`}<span class="overview-label">${label}</span></div>`;

  overviewGrid.className = 'overview-grid';
  overviewGrid.innerHTML =
    stat('Total Records', records.length) +
    stat('Crashes', crashes, crashes > 0 ? '#f85149' : '') +
    stat('Hangs', hangs, hangs > 0 ? '#d29922' : '') +
    stat('Software Changes', software, '#58a6ff') +
    stat('Date Range', earliest === latest ? earliest : `${earliest} → ${latest}`);
}

function renderFindings(findings) {
  if (!findings.length) {
    findingsPanel.innerHTML = '<p class="no-results">No findings generated.</p>';
    return;
  }

  const sevLabel = { crit: 'CRITICAL', warn: 'WARNING', ok: 'OK' };
  const sevColor = { crit: '#f85149', warn: '#d29922', ok: '#3fb950' };

  findingsPanel.innerHTML = findings.map(f => `
    <div class="incident-card">
      <div class="incident-header">
        <span class="incident-sev" style="color:${sevColor[f.sev] ?? '#8b949e'}">${sevLabel[f.sev] ?? f.sev}</span>
        <span class="incident-title">${f.title}</span>
      </div>
      <p class="incident-desc">${f.detail}</p>
      ${f.extra ? `<div class="finding-events">${f.extra}</div>` : ''}
    </div>
  `).join('');

  const warnCount = findings.filter(f => f.sev === 'crit' || f.sev === 'warn').length;
  tabFindingsCount.textContent = warnCount > 0 ? warnCount : '';
}

function renderRecordsTable(records, activeFilter) {
  // Filter bar
  const cats = ['all', ...new Set(records.map(r => r.cat))];
  recordsFiltersWrap.innerHTML = `
    <div class="filter-bar">
      ${cats.map(c => `
        <button class="filter-chip${activeFilter === c ? ' active' : ''}" data-cat="${c}">
          ${c === 'all' ? 'All' : (CAT_LABEL[c] ?? c)}
          <span class="chip-count">${c === 'all' ? records.length : records.filter(r => r.cat === c).length}</span>
        </button>
      `).join('')}
    </div>
  `;

  const filtered = activeFilter === 'all' ? records : records.filter(r => r.cat === activeFilter);

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
            <th>Category</th>
            <th>Product / Application</th>
            <th>Source</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(r => `
            <tr>
              <td class="et-time">${escHtml(r.time)}</td>
              <td><span class="cat-badge" style="color:${CAT_COLOR[r.cat] ?? '#8b949e'}">${CAT_LABEL[r.cat] ?? r.cat}</span></td>
              <td class="et-source">${escHtml(r.product || '—')}</td>
              <td class="et-source">${escHtml(r.source)}</td>
              <td class="et-msg">${escHtml(r.message.slice(0, 200))}${r.message.length > 200 ? '…' : ''}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;

  // Filter chip click handlers
  recordsFiltersWrap.querySelectorAll('.filter-chip').forEach(btn => {
    btn.addEventListener('click', () => renderRecordsTable(records, btn.dataset.cat));
  });
}

// ─── Tab switching ────────────────────────────────────────────────────────────
document.querySelectorAll('.analyzer-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.analyzer-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const target = tab.dataset.tab;
    findingsPanel.hidden  = target !== 'findings';
    recordsPanel.hidden   = target !== 'records';
  });
});

// ─── File handling ───────────────────────────────────────────────────────────
function processFile(file) {
  if (!file) return;

  uploadSection.hidden     = true;
  processingSection.hidden = false;
  resultsSection.hidden    = true;
  processingText.textContent = 'Parsing reliability records…';

  const reader = new FileReader();
  reader.onload = e => {
    try {
      processingText.textContent = 'Analysing…';
      const { computer, generated, records } = parseXml(e.target.result);

      if (!records.length) throw new Error('No <Record> elements found in this file.');

      processingSection.hidden = true;
      resultsSection.hidden    = false;

      const subtitle = [
        computer ? `Host: ${computer}` : '',
        `${records.length} records`,
        generated ? `Generated ${generated}` : '',
      ].filter(Boolean).join('  ·  ');
      resultsSub.textContent = subtitle;

      renderOverview(records, computer);

      const findings = analyse(records);
      renderFindings(findings);
      tabRecordsCount.textContent = records.length;
      renderRecordsTable(records, 'all');

    } catch (err) {
      processingSection.hidden = false;
      processingText.textContent = '';
      processingSection.innerHTML = `
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${escHtml(err.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Expected a ReliabilityHistory.xml produced by Get-EventLogExport.ps1</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `;
      document.getElementById('retry-btn')?.addEventListener('click', resetToUpload);
    }
  };
  reader.readAsText(file);
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

// ─── Drop zone ───────────────────────────────────────────────────────────────
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
