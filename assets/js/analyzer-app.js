/* ── Eventful — analyzer-app.js ──────────────────────────────────────────────
   Incident Analyzer page controller. Handles file upload, parsing, analysis,
   and rendering of results.
──────────────────────────────────────────────────────────────────────────── */

import { parseEventXML, clusterEvents } from './parser.js';
import { analyzeEvents } from './correlator.js';
import { initTheme, toggleTheme } from './theme.js';

initTheme();
document.querySelectorAll('.theme-btn').forEach(b => b.addEventListener('click', toggleTheme));

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $uploadSection      = document.getElementById('upload-section');
const $processingSection  = document.getElementById('processing-section');
const $resultsSection     = document.getElementById('results-section');
const $dropZone           = document.getElementById('drop-zone');
const $fileInput          = document.getElementById('file-input');
const $processingText     = document.getElementById('processing-text');
const $overviewGrid       = document.getElementById('overview-grid');
const $incidentsSection   = document.getElementById('incidents-section');
const $eventTableWrap     = document.getElementById('event-table-wrap');
const $eventLogFiltersWrap = document.getElementById('event-log-filters-wrap');
const $newAnalysisBtn     = document.getElementById('new-analysis-btn');
const $resultsSub         = document.getElementById('results-sub');

// ── State ─────────────────────────────────────────────────────────────────────
let allParsedEvents = [];

// ── File Upload ───────────────────────────────────────────────────────────────
$fileInput?.addEventListener('change', e => {
  const file = e.target.files?.[0];
  if (file) processFile(file);
});

$dropZone?.addEventListener('dragover', e => {
  e.preventDefault();
  $dropZone.classList.add('drag-over');
});
$dropZone?.addEventListener('dragleave', () => $dropZone.classList.remove('drag-over'));
$dropZone?.addEventListener('drop', e => {
  e.preventDefault();
  $dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files?.[0];
  if (file) processFile(file);
});

$newAnalysisBtn?.addEventListener('click', resetToUpload);

// ── Process File ──────────────────────────────────────────────────────────────
async function processFile(file) {
  if (!file.name.toLowerCase().endsWith('.xml') && file.type !== 'text/xml' && file.type !== 'application/xml') {
    showUploadError('Please upload an XML file exported from Windows Event Viewer.');
    return;
  }

  showProcessing(`Reading ${file.name}…`);

  try {
    const text = await file.text();
    showProcessing('Parsing events…');

    // Yield to browser to update UI before heavy parse
    await yieldToUI();
    const events = parseEventXML(text);

    showProcessing(`Analysing ${events.length.toLocaleString()} events…`);
    await yieldToUI();

    const analysis = analyzeEvents(events);
    allParsedEvents = events;

    showProcessing('Building report…');
    await yieldToUI();

    renderResults(analysis, file.name);
  } catch (err) {
    showUploadError(err.message || 'Failed to parse file.');
    showSection($uploadSection);
  }
}

function yieldToUI() {
  return new Promise(resolve => setTimeout(resolve, 16));
}

// ── Section Visibility ────────────────────────────────────────────────────────
function showSection(section) {
  [$uploadSection, $processingSection, $resultsSection].forEach(s => {
    if (s) s.hidden = true;
  });
  if (section) section.hidden = false;
}

function showProcessing(text) {
  if ($processingText) $processingText.textContent = text;
  showSection($processingSection);
}

function resetToUpload() {
  allParsedEvents = [];
  if ($fileInput) $fileInput.value = '';
  showSection($uploadSection);
}

// ── Render Results ────────────────────────────────────────────────────────────
function renderResults(analysis, fileName) {
  const { incidents, healthScore, computerName, stats } = analysis;

  // Sub-header
  if ($resultsSub) {
    const parts = [];
    if (computerName) parts.push(computerName);
    parts.push(`${stats.total.toLocaleString()} events`);
    if (incidents.length) parts.push(`${incidents.length} incident${incidents.length !== 1 ? 's' : ''} detected`);
    $resultsSub.textContent = parts.join(' · ');
  }

  renderOverview(healthScore, stats);
  renderIncidents(incidents);
  renderEventTable(allParsedEvents);

  showSection($resultsSection);
}

// ── Overview Grid ─────────────────────────────────────────────────────────────
function renderOverview(score, stats) {
  if (!$overviewGrid) return;

  const scoreColor = score >= 80 ? '#34d399' : score >= 60 ? '#f59e0b' : '#f43f5e';
  const scoreLabel = score >= 80 ? 'Good' : score >= 60 ? 'Degraded' : 'Critical';

  $overviewGrid.innerHTML = `
    <div class="overview-score-card">
      <div class="score-ring" style="--score-color: ${scoreColor}">
        <span class="score-num">${score}</span>
        <span class="score-denom">/100</span>
      </div>
      <div class="score-label">System Health</div>
      <div class="score-status" style="color: ${scoreColor}">${scoreLabel}</div>
    </div>

    <div class="overview-stats">
      ${statCard('Critical', stats.Critical, 'stat-critical')}
      ${statCard('Error', stats.Error, 'stat-error')}
      ${statCard('Warning', stats.Warning, 'stat-warning')}
      ${statCard('Info', stats.Info, 'stat-info')}
      ${statCard('Total Events', stats.total, 'stat-total')}
    </div>
  `;
}

function statCard(label, count, cls) {
  return `
    <div class="stat-card ${cls}">
      <span class="stat-count">${count.toLocaleString()}</span>
      <span class="stat-label">${label}</span>
    </div>
  `;
}

// ── Incidents ─────────────────────────────────────────────────────────────────
function renderIncidents(incidents) {
  if (!$incidentsSection) return;

  if (!incidents.length) {
    $incidentsSection.innerHTML = `
      <div class="no-incidents">
        <div class="no-incidents-icon">✓</div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;
    return;
  }

  $incidentsSection.innerHTML = `
    <h2 class="section-heading">Detected Incidents</h2>
    ${incidents.map((inc, i) => renderIncidentCard(inc, i)).join('')}
  `;

  // Wire up copy buttons
  $incidentsSection.querySelectorAll('.copy-summary-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const text = btn.dataset.summary;
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = 'Copy for ticket';
          btn.classList.remove('copied');
        }, 2000);
      });
    });
  });

  // Wire up event ID lookup links
  $incidentsSection.querySelectorAll('[data-lookup-id]').forEach(el => {
    el.addEventListener('click', () => {
      const id = el.dataset.lookupId;
      window.open(`results.html?q=${id}`, '_blank');
    });
  });
}

function renderIncidentCard(inc, index) {
  const { anchor, windowEvents, topContributors, signatureResult, report } = inc;
  const sig = signatureResult[0]?.signature;
  const confidence = report.confidence;

  const severityClass = severityToClass(anchor.severity);
  const confidenceClass = confidence === 'high' ? 'conf-high' : confidence === 'medium' ? 'conf-medium' : 'conf-low';

  return `
    <div class="incident-card">
      <div class="incident-header ${severityClass}">
        <div class="incident-header-left">
          <span class="incident-icon">${sig?.icon ?? '⚠'}</span>
          <div>
            <div class="incident-title">${sig?.name ?? anchorTitle(anchor)}</div>
            <div class="incident-meta">
              <span class="incident-time">${anchor.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${esc(anchor.provider)}</span>
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${confidenceClass}">${confidence} confidence</span>
          <span class="event-id-pill" data-lookup-id="${anchor.id}" title="Look up Event ${anchor.id}">
            Event ${anchor.id}
          </span>
        </div>
      </div>

      <div class="incident-body">
        <!-- What happened -->
        <div class="incident-section">
          <div class="incident-section-label">What happened</div>
          <p class="incident-text">${esc(report.what)}</p>
        </div>

        <!-- Root cause -->
        <div class="incident-section">
          <div class="incident-section-label">Likely root cause</div>
          <p class="incident-text">${esc(report.rootCause)}</p>
        </div>

        <!-- Evidence events -->
        ${topContributors.length ? `
        <div class="incident-section">
          <div class="incident-section-label">Contributing events (${topContributors.length} found)</div>
          <div class="evidence-list">
            ${topContributors.slice(0, 6).map(({ event, score }) => `
              <div class="evidence-item">
                <span class="ev-sev-dot sev-${event.severity.toLowerCase()}"></span>
                <span class="ev-id" data-lookup-id="${event.id}" title="Look up Event ${event.id}">
                  ${event.id}
                </span>
                <span class="ev-provider">${esc(shortProvider(event.provider))}</span>
                <span class="ev-time">${formatTime(event.timestamp)}</span>
                <span class="ev-score" title="Relevance score">${score}</span>
              </div>
            `).join('')}
          </div>
        </div>
        ` : ''}

        <!-- Timeline -->
        ${windowEvents.length ? renderMiniTimeline(windowEvents, anchor) : ''}

        <!-- Next steps -->
        ${report.nextSteps.length ? `
        <div class="incident-section">
          <div class="incident-section-label">Suggested next steps</div>
          <ol class="next-steps-list">
            ${report.nextSteps.map(s => `<li>${esc(s)}</li>`).join('')}
          </ol>
        </div>
        ` : ''}

        <!-- Technician hint -->
        ${report.technicianHint ? `
        <div class="incident-section">
          <div class="technician-hint">
            <span class="hint-label">Tech Hint</span>
            <span class="hint-text">${esc(report.technicianHint)}</span>
          </div>
        </div>
        ` : ''}

        <!-- Copy for ticket -->
        <div class="incident-footer">
          <button class="copy-summary-btn" data-summary="${esc(report.psaSummary)}">
            Copy for ticket
          </button>
          ${report.alternateSignatures?.length ? `
          <span class="alt-signatures">
            Also possible: ${report.alternateSignatures.map(m => m.signature.name).join(', ')}
          </span>
          ` : ''}
        </div>
      </div>
    </div>
  `;
}

function renderMiniTimeline(events, anchor) {
  const all = [...events, anchor].sort((a, b) => a.timestamp - b.timestamp);
  const MAX_ITEMS = 12;
  const shown = all.length > MAX_ITEMS
    ? [...all.slice(0, 6), { _ellipsis: true, count: all.length - 10 }, ...all.slice(-4)]
    : all;

  return `
    <div class="incident-section">
      <div class="incident-section-label">Timeline (${events.length} events in ${LOOKBACK_MINUTES}-min window)</div>
      <div class="mini-timeline">
        ${shown.map(ev => {
          if (ev._ellipsis) {
            return `<div class="timeline-ellipsis">· · · ${ev.count} more events · · ·</div>`;
          }
          const isAnchor = ev === anchor;
          return `
            <div class="timeline-item ${isAnchor ? 'timeline-anchor' : ''}">
              <div class="tl-dot sev-${ev.severity?.toLowerCase()}"></div>
              <div class="tl-content">
                <span class="tl-time">${formatTime(ev.timestamp)}</span>
                <span class="tl-id" data-lookup-id="${ev.id}">${ev.id}</span>
                <span class="tl-provider">${esc(shortProvider(ev.provider))}</span>
                ${isAnchor ? '<span class="tl-anchor-label">ANCHOR</span>' : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

const LOOKBACK_MINUTES = 15;

// ── Table State & Constants ───────────────────────────────────────────────────
const NOISY_PROVIDERS = new Set([
  'Microsoft-Windows-TaskScheduler',
  'Microsoft-Windows-WindowsUpdateClient',
  'Microsoft-Windows-Bits-Client',
  'Microsoft-Windows-GroupPolicy',
  'Microsoft-Windows-UserPnp',
  'Microsoft-Windows-WER-SystemErrorReporting',
  'Microsoft-Windows-Diagnostics-Performance',
  'Microsoft-Windows-DistributedCOM',
  'Microsoft-Windows-Security-SPP',
  'Microsoft-Windows-Defrag',
  'Microsoft-Windows-Power-Troubleshooter',
]);

const SEVERITY_ORDER = { Critical: 0, Error: 1, Warning: 2, Info: 3, Verbose: 4 };

const tbl = {
  sortCol: 'timestamp', sortDir: 'asc',
  page: 0, pageSize: 100,
  query: '', severity: '', provider: '', channel: '',
  fromTime: '', toTime: '',
  hideNoisy: false,
  expandedIds: new Set(),
};

// ── Event Table ───────────────────────────────────────────────────────────────
function renderEventTable(events) {
  if (!$eventLogFiltersWrap || !$eventTableWrap) return;

  // Reset state
  Object.assign(tbl, {
    sortCol: 'timestamp', sortDir: 'asc', page: 0,
    query: '', severity: '', provider: '', channel: '',
    fromTime: '', toTime: '', hideNoisy: false,
    expandedIds: new Set(),
  });

  const providers = [...new Set(events.map(e => e.provider).filter(Boolean))].sort();
  const channels  = [...new Set(events.map(e => e.channel).filter(Boolean))].sort();
  const toLocalISO = d => d ? new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '';
  const minTime = events[0]?.timestamp;
  const maxTime = events[events.length - 1]?.timestamp;

  $eventLogFiltersWrap.innerHTML = `
    <div class="event-log-filters">
      <input type="search" id="tbl-query" class="filter-control filter-control-search"
        placeholder="Search ID, provider, message…" autocomplete="off" spellcheck="false" />

      <select id="tbl-severity" class="filter-control filter-control-select">
        <option value="">All severities</option>
        <option>Critical</option><option>Error</option>
        <option>Warning</option><option>Info</option><option>Verbose</option>
      </select>

      <select id="tbl-provider" class="filter-control filter-control-select">
        <option value="">All providers</option>
        ${providers.map(p => `<option value="${esc(p)}">${esc(shortProvider(p))}</option>`).join('')}
      </select>

      <select id="tbl-channel" class="filter-control filter-control-select">
        <option value="">All channels</option>
        ${channels.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('')}
      </select>

      <div class="filter-date-group">
        <span class="filter-date-label">From</span>
        <input type="datetime-local" id="tbl-from" class="filter-control filter-control-date"
          value="${toLocalISO(minTime)}" />
      </div>
      <div class="filter-date-group">
        <span class="filter-date-label">To</span>
        <input type="datetime-local" id="tbl-to" class="filter-control filter-control-date"
          value="${toLocalISO(maxTime)}" />
      </div>

      <div class="filter-spacer"></div>
      <button id="tbl-noise" class="filter-noise-btn">Hide noise</button>
      <button id="tbl-csv"   class="filter-csv-btn">↓ CSV</button>
    </div>
  `;

  const on = (id, evt, fn) => document.getElementById(id)?.addEventListener(evt, fn);
  on('tbl-query',    'input',  e => { tbl.query    = e.target.value; tbl.page = 0; redrawTable(); });
  on('tbl-severity', 'change', e => { tbl.severity = e.target.value; tbl.page = 0; redrawTable(); });
  on('tbl-provider', 'change', e => { tbl.provider = e.target.value; tbl.page = 0; redrawTable(); });
  on('tbl-channel',  'change', e => { tbl.channel  = e.target.value; tbl.page = 0; redrawTable(); });
  on('tbl-from',     'change', e => { tbl.fromTime = e.target.value; tbl.page = 0; redrawTable(); });
  on('tbl-to',       'change', e => { tbl.toTime   = e.target.value; tbl.page = 0; redrawTable(); });
  on('tbl-noise', 'click', e => {
    tbl.hideNoisy = !tbl.hideNoisy;
    tbl.page = 0;
    e.target.classList.toggle('active', tbl.hideNoisy);
    e.target.textContent = tbl.hideNoisy ? 'Show noise' : 'Hide noise';
    redrawTable();
  });
  on('tbl-csv', 'click', () => exportCSV(filteredSortedEvents()));

  redrawTable();
}

function filteredSortedEvents() {
  const q      = tbl.query.toLowerCase();
  const fromMs = tbl.fromTime ? new Date(tbl.fromTime).getTime() : null;
  const toMs   = tbl.toTime   ? new Date(tbl.toTime).getTime()   : null;

  let events = allParsedEvents.filter(e => {
    if (tbl.severity && e.severity !== tbl.severity) return false;
    if (tbl.provider && e.provider !== tbl.provider) return false;
    if (tbl.channel  && e.channel  !== tbl.channel)  return false;
    if (fromMs !== null && e.timestamp < fromMs) return false;
    if (toMs   !== null && e.timestamp > toMs)   return false;
    if (tbl.hideNoisy && NOISY_PROVIDERS.has(e.provider)) return false;
    if (q) {
      const hay = `${e.id} ${e.provider} ${e.channel} ${e.message} ${e.severity}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  events.sort((a, b) => {
    let v = 0;
    switch (tbl.sortCol) {
      case 'timestamp': v = a.timestamp - b.timestamp; break;
      case 'severity':  v = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9); break;
      case 'id':        v = a.id - b.id; break;
      case 'provider':  v = (a.provider || '').localeCompare(b.provider || ''); break;
    }
    return tbl.sortDir === 'asc' ? v : -v;
  });

  return events;
}

function redrawTable() {
  if (!$eventTableWrap) return;
  const filtered = filteredSortedEvents();
  const total    = filtered.length;
  const maxPage  = Math.max(0, Math.ceil(total / tbl.pageSize) - 1);
  tbl.page = Math.min(tbl.page, maxPage);
  const start    = tbl.page * tbl.pageSize;
  const pageRows = filtered.slice(start, start + tbl.pageSize);

  if (!total) {
    $eventTableWrap.innerHTML = `<div class="table-empty">No events match the current filters.</div>`;
    return;
  }

  const sortArrow = col =>
    `<span class="sort-arrow ${tbl.sortCol === col ? 'active' : ''}">${tbl.sortCol === col ? (tbl.sortDir === 'asc' ? '↑' : '↓') : '↕'}</span>`;
  const thCls = col => tbl.sortCol === col ? 'sort-active' : '';

  $eventTableWrap.innerHTML = `
    <div class="table-info-bar">
      <span class="table-count-text">
        ${(start + 1).toLocaleString()}–${Math.min(start + tbl.pageSize, total).toLocaleString()} of ${total.toLocaleString()} event${total !== 1 ? 's' : ''}
        ${total < allParsedEvents.length ? ` (${allParsedEvents.length.toLocaleString()} total)` : ''}
      </span>
      <div class="table-pagination">
        <button class="page-btn" id="pg-first" ${tbl.page === 0 ? 'disabled' : ''}>«</button>
        <button class="page-btn" id="pg-prev"  ${tbl.page === 0 ? 'disabled' : ''}>‹ Prev</button>
        <span class="page-info">Page ${tbl.page + 1} / ${maxPage + 1}</span>
        <button class="page-btn" id="pg-next"  ${tbl.page >= maxPage ? 'disabled' : ''}>Next ›</button>
        <button class="page-btn" id="pg-last"  ${tbl.page >= maxPage ? 'disabled' : ''}>»</button>
      </div>
    </div>
    <table class="event-table">
      <thead><tr>
        <th style="width:18px"></th>
        <th data-sort="timestamp" class="${thCls('timestamp')}">Time ${sortArrow('timestamp')}</th>
        <th data-sort="severity"  class="${thCls('severity')}">Sev ${sortArrow('severity')}</th>
        <th data-sort="id"        class="${thCls('id')}">ID ${sortArrow('id')}</th>
        <th data-sort="provider"  class="${thCls('provider')}">Provider ${sortArrow('provider')}</th>
        <th>Channel</th>
        <th>Message</th>
      </tr></thead>
      <tbody>${pageRows.map(ev => buildTableRow(ev)).join('')}</tbody>
    </table>
  `;

  // Sort clicks
  $eventTableWrap.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      tbl.sortDir = tbl.sortCol === col && tbl.sortDir === 'asc' ? 'desc' : 'asc';
      tbl.sortCol = col;
      tbl.page = 0;
      redrawTable();
    });
  });

  // Pagination
  const pg = (id, fn) => document.getElementById(id)?.addEventListener('click', fn);
  pg('pg-first', () => { tbl.page = 0;       redrawTable(); });
  pg('pg-prev',  () => { tbl.page--;          redrawTable(); });
  pg('pg-next',  () => { tbl.page++;          redrawTable(); });
  pg('pg-last',  () => { tbl.page = maxPage;  redrawTable(); });

  // Row expand/collapse
  $eventTableWrap.querySelectorAll('tbody tr[data-record]').forEach(tr => {
    tr.addEventListener('click', e => {
      if (e.target.closest('.table-event-id')) return;
      const rid = parseInt(tr.dataset.record, 10);
      if (tbl.expandedIds.has(rid)) tbl.expandedIds.delete(rid);
      else tbl.expandedIds.add(rid);
      redrawTable();
    });
  });

  // Event ID lookup links
  $eventTableWrap.querySelectorAll('.table-event-id').forEach(el => {
    el.addEventListener('click', e => {
      e.stopPropagation();
      window.open(`results.html?q=${el.dataset.lookupId}`, '_blank');
    });
  });
}

function buildTableRow(ev) {
  const isExpanded = tbl.expandedIds.has(ev.recordId);
  const sev = ev.severity.toLowerCase();
  const dataKeys = Object.keys(ev.data || {});

  const mainRow = `
    <tr class="ev-row-${sev}${isExpanded ? ' row-expanded' : ''}" data-record="${ev.recordId}">
      <td class="ev-col-expand">${isExpanded ? '▼' : '▶'}</td>
      <td class="ev-col-time">${formatDateTime(ev.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${sev}">${ev.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${ev.id}" title="Look up Event ${ev.id}">${ev.id}</span></td>
      <td class="ev-col-provider" title="${esc(ev.provider)}">${esc(shortProvider(ev.provider))}</td>
      <td class="ev-col-channel">${esc(ev.channel)}</td>
      <td class="ev-col-message">${esc(ev.message.substring(0, 150))}</td>
    </tr>`;

  if (!isExpanded) return mainRow;

  return mainRow + `
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          <div class="ev-detail-message">${esc(ev.message || '(no message)')}</div>
          <div class="ev-detail-meta">
            ${[['Provider', ev.provider], ['Channel', ev.channel], ['Computer', ev.computer], ['Record ID', ev.recordId || '—']]
              .filter(([, v]) => v)
              .map(([k, v]) => `<div class="ev-detail-field"><span class="ev-detail-key">${k}</span><span class="ev-detail-val">${esc(String(v))}</span></div>`)
              .join('')}
          </div>
          ${dataKeys.length ? `
          <div class="ev-detail-data">
            <div class="ev-detail-data-title">Event Data</div>
            ${dataKeys.map(k => `
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key">${esc(k)}</span>
                <span class="ev-detail-data-val">${esc(String(ev.data[k]))}</span>
              </div>`).join('')}
          </div>` : ''}
          <div class="ev-detail-actions">
            <span class="ev-detail-lookup-btn table-event-id" data-lookup-id="${ev.id}">
              Look up Event ${ev.id} →
            </span>
          </div>
        </div>
      </td>
    </tr>`;
}

function exportCSV(events) {
  const cols = ['Time (UTC)', 'Severity', 'EventID', 'Provider', 'Channel', 'Computer', 'RecordID', 'Message'];
  const q = s => `"${String(s ?? '').replace(/"/g, '""').replace(/\r?\n/g, ' ')}"`;
  const rows = events.map(e => [
    e.timestamp.toISOString(), e.severity, e.id,
    q(e.provider), q(e.channel), q(e.computer), e.recordId, q(e.message),
  ].join(','));
  const csv = [cols.join(','), ...rows].join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
  const a = Object.assign(document.createElement('a'), {
    href: url, download: `eventful-${new Date().toISOString().slice(0, 10)}.csv`,
  });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Error Display ─────────────────────────────────────────────────────────────
function showUploadError(msg) {
  const existing = $dropZone?.querySelector('.upload-error');
  if (existing) existing.remove();

  const el = document.createElement('div');
  el.className = 'upload-error';
  el.textContent = msg;
  $dropZone?.appendChild(el);
  showSection($uploadSection);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function shortProvider(provider) {
  if (!provider) return '—';
  // Strip "Microsoft-Windows-" prefix for readability
  return provider.replace(/^Microsoft-Windows-/i, '').replace(/^Microsoft-/i, '');
}

function formatTime(date) {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDateTime(date) {
  return date.toLocaleString([], {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function severityToClass(severity) {
  return `sev-header-${severity?.toLowerCase() ?? 'info'}`;
}

function anchorTitle(anchor) {
  const titles = {
    41:   'Unexpected System Reboot',
    6008: 'Unexpected Shutdown Detected',
    1001: 'System Crash (BSOD)',
    1000: 'Application Crash',
    7024: 'Critical Service Failure',
  };
  return titles[anchor.id] ?? `Event ${anchor.id}`;
}
