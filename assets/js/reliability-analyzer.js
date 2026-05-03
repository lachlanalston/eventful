import { setupTheme } from './theme.js';
import { escHtml } from './utils.js';

setupTheme();

// ─── DOM refs ────────────────────────────────────────────────────────────────
const uploadSection      = document.getElementById('upload-section');
const processingSection  = document.getElementById('processing-section');
const processingText     = document.getElementById('processing-text');
const resultsSection     = document.getElementById('results-section');
const dropZone           = document.getElementById('drop-zone');
const fileInput          = document.getElementById('file-input');
const newAnalysisBtn     = document.getElementById('new-analysis-btn');
const resultsSub         = document.getElementById('results-sub');
const overviewGrid       = document.getElementById('overview-grid');
const findingsPanel      = document.getElementById('findings-panel');
const recordsPanel       = document.getElementById('records-panel');
const recordsFiltersWrap = document.getElementById('records-filters-wrap');
const recordsTableWrap   = document.getElementById('records-table-wrap');
const tabFindingsCount   = document.getElementById('tab-findings-count');
const tabRecordsCount    = document.getElementById('tab-records-count');

// ─── Category classification (RelMonReport Problem field) ─────────────────────
function classifyEvent(problem) {
  const p = (problem || '').toLowerCase();
  if (p.includes('stopped working'))                         return 'crash';
  if (p.includes('stopped responding'))                      return 'hang';
  if (/windows update|update/.test(p))                      return 'update';
  if (/install|reconfigur|removal/.test(p))                 return 'software';
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

// Hardware failure keywords
const HW_PATTERNS = [
  /bad.?block/i, /disk.?error/i, /ntfs.*corrupt/i, /corrupt.*ntfs/i,
  /hardware.?error/i, /memory.*corrupt/i, /corrupt.*memory/i,
  /sector.?error/i, /read.?error/i, /i\/o.?error/i,
  /chkdsk/i, /file.?system.*error/i, /bad.?sector/i,
];

// ─── XML parser — RelMonReport format (native Windows GUI export) ─────────────
function parseXml(text) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(text, 'application/xml');

  const parseErr = doc.querySelector('parsererror');
  if (parseErr) throw new Error('Invalid XML: ' + parseErr.textContent.slice(0, 120));

  const root = doc.documentElement;
  if (root.tagName !== 'RelMonReport') {
    throw new Error(
      `Unrecognised format — root element is <${root.tagName}>. ` +
      `Expected <RelMonReport> from the Windows Reliability Monitor GUI export. ` +
      `Open Reliability Monitor → Action → Save Reliability History.`
    );
  }

  const generated = root.getAttribute('TimeGenerated') || '';

  const records = [...doc.querySelectorAll('RacEvents > Event')].map(ev => {
    const get = tag => ev.querySelector(tag)?.textContent?.trim() ?? '';
    const impact  = get('Impact');
    const source  = get('Source');
    const problem = get('Problem');
    return {
      source,
      product: source,
      message: problem,
      impact,
      cat: classifyEvent(problem),
    };
  });

  if (!records.length) throw new Error('No events found in this Reliability Monitor export.');
  return { generated, records };
}

// ─── Findings engine ─────────────────────────────────────────────────────────
function analyse(records) {
  const findings = [];
  const add = (sev, title, detail, extra = '') =>
    findings.push({ sev, title, detail, extra });

  const crashes  = records.filter(r => r.cat === 'crash');
  const hangs    = records.filter(r => r.cat === 'hang');
  const warnings = records.filter(r => r.impact === 'Warning');

  // 1. Hardware failure indicators
  const hwHits = records.filter(r =>
    HW_PATTERNS.some(p => p.test(r.source) || p.test(r.message))
  );
  if (hwHits.length) {
    add('crit',
      `Hardware failure indicator${hwHits.length > 1 ? 's' : ''} detected (${hwHits.length})`,
      'One or more records contain keywords associated with disk I/O errors, NTFS corruption, bad sectors, or memory faults. ' +
      'Run <code>chkdsk C: /f /r</code> and check SMART data before any other investigation.',
      hwHits.slice(0, 3).map(r =>
        `<div class="finding-event"><span class="fe-src">${escHtml(r.source)}</span> — ${escHtml(r.message)}</div>`
      ).join('')
    );
  }

  // 2. Recurring app crashes
  const crashByApp = {};
  for (const r of crashes) {
    const key = r.source.toLowerCase();
    if (!crashByApp[key]) crashByApp[key] = { label: r.source, count: 0 };
    crashByApp[key].count++;
  }
  for (const v of Object.values(crashByApp).sort((a, b) => b.count - a.count)) {
    if (v.count >= 2) {
      add('warn',
        `${escHtml(v.label)} crashed ${v.count} time${v.count > 1 ? 's' : ''}`,
        `Repeated crash pattern. Check for a pending application update, conflicting DLL, or corrupt installation. ` +
        `Look for Event 1000 in the Application log for faulting module details.`
      );
    }
  }

  // 3. Recurring app hangs
  const hangByApp = {};
  for (const r of hangs) {
    const key = r.source.toLowerCase();
    if (!hangByApp[key]) hangByApp[key] = { label: r.source, count: 0 };
    hangByApp[key].count++;
  }
  for (const v of Object.values(hangByApp).sort((a, b) => b.count - a.count)) {
    if (v.count >= 2) {
      add('warn',
        `${escHtml(v.label)} stopped responding ${v.count} time${v.count > 1 ? 's' : ''}`,
        `Repeated hang pattern. Common causes: main thread blocked on slow disk/network, deadlock, or antivirus scanning ` +
        `files the app is trying to access. Try adding the app directory to AV exclusions as a test.`
      );
    }
  }

  // 4. Failed updates / installs
  if (warnings.length >= 3) {
    const labels = [...new Set(warnings.slice(0, 5).map(r => r.source))].join(', ');
    add('warn',
      `${warnings.length} failed update${warnings.length > 1 ? 's' : ''} or installation${warnings.length > 1 ? 's' : ''}`,
      `Multiple Warning-impact events detected. Check Windows Update history and application installer logs. ` +
      `Affected: ${escHtml(labels)}${warnings.length > 5 ? ` + ${warnings.length - 5} more` : ''}.`
    );
  }

  // 5. High crash volume
  if (crashes.length >= 8 && !findings.some(f => f.sev === 'crit')) {
    add('warn',
      `High crash volume — ${crashes.length} application crashes recorded`,
      `Unusually high number of application crash events. Consider running ` +
      `<code>sfc /scannow</code> and <code>DISM /Online /Cleanup-Image /RestoreHealth</code> to check for system file corruption.`
    );
  }

  // 6. All quiet
  if (findings.length === 0) {
    add('ok',
      'No significant issues detected',
      'No recurring crashes, hangs, hardware indicators, or failed updates found in the reliability history.'
    );
  }

  return findings.sort((a, b) => {
    const order = { crit: 0, warn: 1, ok: 2 };
    return (order[a.sev] ?? 3) - (order[b.sev] ?? 3);
  });
}

// ─── Render helpers ──────────────────────────────────────────────────────────
function renderOverview(records, generated) {
  const crashes  = records.filter(r => r.cat === 'crash').length;
  const hangs    = records.filter(r => r.cat === 'hang').length;
  const software = records.filter(r => r.cat === 'software').length;
  const warnings = records.filter(r => r.impact === 'Warning').length;

  const reportDate = generated ? generated.slice(0, 10) : '—';

  const stat = (label, value, color = '') =>
    `<div class="overview-stat">${color ? `<span class="overview-value" style="color:${color}">${value}</span>` : `<span class="overview-value">${value}</span>`}<span class="overview-label">${label}</span></div>`;

  overviewGrid.className = 'overview-grid';
  overviewGrid.innerHTML =
    stat('Total Events', records.length) +
    stat('Crashes', crashes, crashes > 0 ? '#f85149' : '') +
    stat('Hangs', hangs, hangs > 0 ? '#d29922' : '') +
    stat('Software Changes', software, '#58a6ff') +
    stat('Warnings', warnings, warnings > 0 ? '#d29922' : '') +
    stat('Report Date', reportDate);
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
            <th>Impact</th>
            <th>Category</th>
            <th>Source / Application</th>
            <th>Problem</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(r => `
            <tr>
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
document.querySelectorAll('.analyzer-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.analyzer-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const target = tab.dataset.tab;
    findingsPanel.hidden = target !== 'findings';
    recordsPanel.hidden  = target !== 'records';
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

      // Detect UTF-16 BOM and decode — native Windows GUI export is UTF-16 LE
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

    } catch (err) {
      processingSection.hidden = false;
      processingText.textContent = '';
      processingSection.innerHTML = `
        <p class="processing-error">
          <strong>Could not parse file</strong><br>
          ${escHtml(err.message)}<br>
          <span style="font-size:0.82rem;color:var(--text-muted)">Open Reliability Monitor → Action → Save Reliability History to export the correct file.</span>
        </p>
        <button class="btn-secondary" style="margin-top:1rem" id="retry-btn">← Try another file</button>
      `;
      document.getElementById('retry-btn')?.addEventListener('click', resetToUpload);
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
