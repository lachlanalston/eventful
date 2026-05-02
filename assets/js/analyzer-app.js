/* ── Eventful — analyzer-app.js ──────────────────────────────────────────────
   Incident Analyzer page controller. Handles file upload, parsing, analysis,
   and rendering of results.
──────────────────────────────────────────────────────────────────────────── */

import { parseEventXML, clusterEvents } from './parser.js';
import { analyzeEvents } from './correlator.js';
import { initTheme, toggleTheme } from './theme.js';
import { allEvents } from '../../data/events/index.js';

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
let idCountMap      = new Map(); // eventId → occurrence count in loaded file

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

// ── Lookup Panel wiring (always-on) ──────────────────────────────────────────
document.getElementById('lp-backdrop')?.addEventListener('click', closeLookupPanel);
document.getElementById('lp-close')?.addEventListener('click', closeLookupPanel);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeLookupPanel(); });

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
    idCountMap = new Map();
    for (const ev of events) idCountMap.set(ev.id, (idCountMap.get(ev.id) || 0) + 1);

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
  idCountMap      = new Map();
  if ($fileInput) $fileInput.value = '';
  showSection($uploadSection);
}

// ── Render Results ────────────────────────────────────────────────────────────
function renderResults(analysis, fileName) {
  const { incidents, healthScore, computerName, stats } = analysis;

  const titleEl = document.querySelector('.results-title');
  if (titleEl) titleEl.textContent = fileName.replace(/\.xml$/i, '');

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

  // Update tab counts
  const $incCount = document.getElementById('tab-inc-count');
  const $evtCount = document.getElementById('tab-evt-count');
  if ($incCount) $incCount.textContent = incidents.length;
  if ($evtCount) $evtCount.textContent = stats.total.toLocaleString();

  // Wire tab switching
  document.querySelectorAll('.analyzer-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.analyzer-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const target = tab.dataset.tab;
      document.getElementById('incidents-section').hidden = target !== 'incidents';
      document.getElementById('events-panel').hidden = target !== 'events';
    });
  });

  showSection($resultsSection);
}

// ── Overview Bar ──────────────────────────────────────────────────────────────
function renderOverview(score, stats) {
  if (!$overviewGrid) return;

  const scoreColor = score >= 80 ? '#34d399' : score >= 60 ? '#f59e0b' : '#f43f5e';
  const scoreLabel = score >= 80 ? 'Good' : score >= 60 ? 'Degraded' : 'Critical';

  $overviewGrid.innerHTML = `
    <div class="overview-bar">
      <div class="overview-health">
        <span class="ob-score" style="color:${scoreColor}">${score}</span>
        <span class="ob-denom">/100</span>
        <span class="ob-label">System Health</span>
        <span class="ob-status" style="color:${scoreColor}">${scoreLabel}</span>
      </div>
      <div class="ob-divider"></div>
      <div class="ob-stats">
        <div class="ob-stat stat-critical"><span class="ob-stat-num">${stats.Critical.toLocaleString()}</span><span class="ob-stat-label">Critical</span></div>
        <div class="ob-stat stat-error">   <span class="ob-stat-num">${stats.Error.toLocaleString()}</span>   <span class="ob-stat-label">Error</span></div>
        <div class="ob-stat stat-warning"> <span class="ob-stat-num">${stats.Warning.toLocaleString()}</span> <span class="ob-stat-label">Warning</span></div>
        <div class="ob-stat stat-info">    <span class="ob-stat-num">${stats.Info.toLocaleString()}</span>    <span class="ob-stat-label">Info</span></div>
        <div class="ob-stat stat-total">   <span class="ob-stat-num">${stats.total.toLocaleString()}</span>   <span class="ob-stat-label">Total</span></div>
      </div>
    </div>
  `;
}

// ── Incidents ─────────────────────────────────────────────────────────────────
function renderIncidents(incidents) {
  if (!$incidentsSection) return;

  if (!incidents.length) {
    $incidentsSection.innerHTML = `
      <div class="no-incidents">
        <div class="no-incidents-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
        <div class="no-incidents-title">No incidents detected</div>
        <div class="no-incidents-sub">No known crash or failure anchor events were found in this log.</div>
      </div>
    `;
    return;
  }

  $incidentsSection.innerHTML = incidents.map((inc, i) => renderIncidentCard(inc, i)).join('');

  // Wire collapsible headers
  $incidentsSection.querySelectorAll('.incident-toggle').forEach(header => {
    header.addEventListener('click', e => {
      if (e.target.closest('[data-lookup-id]')) return; // let pill handle its own click
      const card = header.closest('.incident-card');
      const body = card.querySelector('.incident-body');
      const chevron = header.querySelector('.incident-chevron');
      const open = !body.hidden;
      body.hidden = open;
      chevron.classList.toggle('open', !open);
    });
  });

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

  // Wire evidence expand/collapse
  $incidentsSection.querySelectorAll('.evidence-item').forEach(item => {
    item.addEventListener('click', e => {
      e.stopPropagation();
      if (e.target.closest('[data-lookup-id]')) return;
      const wrap = item.closest('.evidence-wrap');
      const detail = wrap.querySelector('.evidence-detail');
      const chevron = item.querySelector('.ev-expand-chevron');
      const isOpen = !detail.hidden;
      detail.hidden = isOpen;
      item.classList.toggle('expanded', !isOpen);
      if (chevron) chevron.textContent = isOpen ? '▶' : '▼';
    });
  });

  // Wire timeline expand/collapse
  $incidentsSection.querySelectorAll('.timeline-item').forEach(item => {
    item.addEventListener('click', e => {
      e.stopPropagation();
      if (e.target.closest('[data-lookup-id]')) return;
      const wrap = item.closest('.timeline-item-wrap');
      if (!wrap) return;
      const detail = wrap.querySelector('.timeline-detail');
      if (!detail) return;
      const chevron = item.querySelector('.tl-expand-chevron');
      const isOpen = !detail.hidden;
      detail.hidden = isOpen;
      if (chevron) chevron.textContent = isOpen ? '▶' : '▼';
    });
  });

  // Wire advanced toggles inside inline event details
  $incidentsSection.querySelectorAll('.ev-advanced-toggle').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const section = btn.closest('.ev-inline-detail').querySelector('.ev-advanced-section');
      const open = section.classList.toggle('ev-advanced-open');
      btn.textContent = open ? 'Advanced ▲' : 'Advanced ▼';
    });
  });

  // Wire copy buttons inside inline event details
  $incidentsSection.querySelectorAll('.ev-copy-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      navigator.clipboard?.writeText(btn.dataset.copy).then(() => {
        btn.classList.add('copied');
        setTimeout(() => btn.classList.remove('copied'), 2000);
      });
    });
  });

  // Wire up event ID lookup links
  $incidentsSection.querySelectorAll('[data-lookup-id]').forEach(el => {
    el.addEventListener('click', e => {
      e.stopPropagation();
      openLookupPanel(el.dataset.lookupId);
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
      <div class="incident-header ${severityClass} incident-toggle">
        <div class="incident-header-left">
          <span class="incident-icon">${sig?.icon ?? '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'}</span>
          <div>
            <div class="incident-title">${sig?.name ?? anchorTitle(anchor)}</div>
            <div class="incident-meta">
              <span class="incident-time">${anchor.timestamp.toLocaleString()}</span>
              <span class="incident-provider">${esc(anchor.provider)}</span>
              ${report.confidenceReason ? `<span class="conf-reason">${esc(report.confidenceReason)}</span>` : ''}
            </div>
          </div>
        </div>
        <div class="incident-header-right">
          <span class="conf-badge ${confidenceClass}">${confidence}</span>
          <span class="event-id-pill" data-lookup-id="${anchor.id}" title="Look up Event ${anchor.id}">
            EVT-${anchor.id}
          </span>
          <span class="incident-chevron">▶</span>
        </div>
      </div>

      <div class="incident-body" hidden>
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
              <div class="evidence-wrap">
                <div class="evidence-item">
                  <span class="ev-sev-dot sev-${event.severity.toLowerCase()}"></span>
                  <span class="ev-id" data-lookup-id="${event.id}" title="Look up Event ${event.id}">${event.id}</span>
                  <span class="ev-provider">${esc(shortProvider(event.provider))}</span>
                  <span class="ev-time">${formatTime(event.timestamp)}</span>
                  <span class="ev-score" title="Relevance score">${score}</span>
                  <span class="ev-expand-chevron">▶</span>
                </div>
                <div class="evidence-detail" hidden>${buildEventDetail(event)}</div>
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
            <div class="timeline-item-wrap">
              <div class="timeline-item ${isAnchor ? 'timeline-anchor' : ''}">
                <div class="tl-dot sev-${ev.severity?.toLowerCase()}"></div>
                <div class="tl-content">
                  <span class="tl-time">${formatTime(ev.timestamp)}</span>
                  <span class="tl-id" data-lookup-id="${ev.id}" title="Look up Event ${ev.id}">${ev.id}</span>
                  <span class="tl-provider">${esc(shortProvider(ev.provider))}</span>
                  ${isAnchor ? '<span class="tl-anchor-label">ANCHOR</span>' : ''}
                </div>
                <span class="tl-expand-chevron">▶</span>
              </div>
              <div class="timeline-detail" hidden>${buildEventDetail(ev)}</div>
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
  query: '', severities: new Set(), providers: new Set(), channel: '',
  fromTime: '', toTime: '',
  hideNoisy: false,
  expandedIds: new Set(),
};

// Close provider dropdown when clicking outside (single persistent listener)
document.addEventListener('click', e => {
  const panel = document.getElementById('tbl-provider-panel');
  const btn   = document.getElementById('tbl-provider-btn');
  if (panel && !panel.hidden && !panel.contains(e.target) && !btn?.contains(e.target)) {
    panel.hidden = true;
    btn?.classList.remove('open');
  }
});

// ── Event Table ───────────────────────────────────────────────────────────────
function renderEventTable(events) {
  if (!$eventLogFiltersWrap || !$eventTableWrap) return;

  // Reset state
  Object.assign(tbl, {
    sortCol: 'timestamp', sortDir: 'asc', page: 0,
    query: '', severities: new Set(), providers: new Set(), channel: '',
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

      <div class="tbl-sev-chips">
        ${['Critical','Error','Warning','Info','Verbose'].map(s => `
          <label class="sev-chip" data-severity="${s}">
            <input type="checkbox" class="sev-cb tbl-sev-cb" value="${s}" />
            <span class="chip-dot dot-${s}"></span>
            <span>${s}</span>
          </label>`).join('')}
      </div>

      <div class="provider-dropdown" id="tbl-provider-wrap">
        <button class="provider-dropdown-btn" id="tbl-provider-btn" type="button">
          <span id="tbl-provider-label">All providers</span>
          <span class="provider-dropdown-arrow">▾</span>
        </button>
        <div class="provider-dropdown-panel" id="tbl-provider-panel" hidden>
          <div class="provider-panel-header">
            <button class="provider-bulk-btn" id="tbl-provider-select-all" type="button">Select all</button>
            <button class="provider-bulk-btn" id="tbl-provider-clear" type="button">Clear</button>
          </div>
          ${providers.length > 6 ? `<input type="search" class="provider-search" id="tbl-provider-search" placeholder="Filter…" autocomplete="off" />` : ''}
          <div class="provider-option-list">
            ${providers.map(p => `
              <label class="provider-option">
                <input type="checkbox" class="provider-cb" value="${esc(p)}" />
                <span class="provider-option-name" title="${esc(p)}">${esc(shortProvider(p))}</span>
              </label>`).join('')}
          </div>
        </div>
      </div>

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
  $eventLogFiltersWrap.querySelectorAll('.tbl-sev-cb').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) tbl.severities.add(cb.value);
      else tbl.severities.delete(cb.value);
      cb.closest('.sev-chip').classList.toggle('active', cb.checked);
      tbl.page = 0;
      updateProviderAvailability();
      redrawTable();
    });
  });
  // Provider multi-select dropdown
  const providerBtn       = document.getElementById('tbl-provider-btn');
  const providerPanel     = document.getElementById('tbl-provider-panel');
  const providerLabel     = document.getElementById('tbl-provider-label');
  const providerClear     = document.getElementById('tbl-provider-clear');
  const providerSelectAll = document.getElementById('tbl-provider-select-all');

  providerBtn?.addEventListener('click', e => {
    e.stopPropagation();
    const open = providerPanel.hidden;
    providerPanel.hidden = !open;
    providerBtn.classList.toggle('open', open);
  });

  function updateProviderLabel() {
    const n = tbl.providers.size;
    providerLabel.textContent = n === 0 ? 'All providers' : `${n} provider${n !== 1 ? 's' : ''}`;
    providerBtn?.classList.toggle('filtered', n > 0);
  }

  function updateProviderAvailability() {
    const fromMs = tbl.fromTime ? new Date(tbl.fromTime).getTime() : null;
    const toMs   = tbl.toTime   ? new Date(tbl.toTime).getTime()   : null;
    const available = new Set(
      allParsedEvents.filter(e => {
        if (tbl.severities.size > 0 && !tbl.severities.has(e.severity)) return false;
        if (tbl.channel && e.channel !== tbl.channel) return false;
        if (fromMs !== null && e.timestamp < fromMs) return false;
        if (toMs   !== null && e.timestamp > toMs)   return false;
        if (tbl.hideNoisy && NOISY_PROVIDERS.has(e.provider)) return false;
        return true;
      }).map(e => e.provider).filter(Boolean)
    );
    $eventLogFiltersWrap.querySelectorAll('.provider-option').forEach(opt => {
      const cb = opt.querySelector('.provider-cb');
      const avail = available.has(cb.value);
      opt.classList.toggle('provider-option-unavailable', !avail);
      cb.disabled = !avail;
      if (!avail && cb.checked) {
        cb.checked = false;
        tbl.providers.delete(cb.value);
      }
    });
    updateProviderLabel();
  }

  $eventLogFiltersWrap.querySelectorAll('.provider-cb').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) tbl.providers.add(cb.value);
      else tbl.providers.delete(cb.value);
      updateProviderLabel();
      tbl.page = 0;
      redrawTable();
    });
  });

  providerClear?.addEventListener('click', e => {
    e.stopPropagation();
    tbl.providers.clear();
    $eventLogFiltersWrap.querySelectorAll('.provider-cb').forEach(cb => cb.checked = false);
    updateProviderLabel();
    tbl.page = 0;
    redrawTable();
  });

  providerSelectAll?.addEventListener('click', e => {
    e.stopPropagation();
    $eventLogFiltersWrap.querySelectorAll('.provider-option:not([hidden]) .provider-cb').forEach(cb => {
      cb.checked = true;
      tbl.providers.add(cb.value);
    });
    updateProviderLabel();
    tbl.page = 0;
    redrawTable();
  });

  on('tbl-provider-search', 'input', e => {
    const q = e.target.value.toLowerCase();
    $eventLogFiltersWrap.querySelectorAll('.provider-option').forEach(opt => {
      opt.hidden = q ? !opt.querySelector('.provider-option-name').textContent.toLowerCase().includes(q) : false;
    });
  });
  on('tbl-channel',  'change', e => { tbl.channel  = e.target.value; tbl.page = 0; updateProviderAvailability(); redrawTable(); });
  on('tbl-from',     'change', e => { tbl.fromTime = e.target.value; tbl.page = 0; updateProviderAvailability(); redrawTable(); });
  on('tbl-to',       'change', e => { tbl.toTime   = e.target.value; tbl.page = 0; updateProviderAvailability(); redrawTable(); });
  on('tbl-noise', 'click', e => {
    tbl.hideNoisy = !tbl.hideNoisy;
    tbl.page = 0;
    e.target.classList.toggle('active', tbl.hideNoisy);
    e.target.textContent = tbl.hideNoisy ? 'Show noise' : 'Hide noise';
    updateProviderAvailability();
    redrawTable();
  });
  on('tbl-csv', 'click', () => exportCSV(filteredSortedEvents()));

  updateProviderAvailability();
  redrawTable();
}

function filteredSortedEvents() {
  const q      = tbl.query.toLowerCase();
  const fromMs = tbl.fromTime ? new Date(tbl.fromTime).getTime() : null;
  const toMs   = tbl.toTime   ? new Date(tbl.toTime).getTime()   : null;

  let events = allParsedEvents.filter(e => {
    if (tbl.severities.size > 0 && !tbl.severities.has(e.severity)) return false;
    if (tbl.providers.size > 0 && !tbl.providers.has(e.provider)) return false;
    if (tbl.channel  && e.channel  !== tbl.channel)  return false;
    if (fromMs !== null && e.timestamp < fromMs) return false;
    if (toMs   !== null && e.timestamp > toMs)   return false;
    if (tbl.hideNoisy && NOISY_PROVIDERS.has(e.provider)) return false;
    if (q) {
      const exactId = /^\d+$/.test(q) ? parseInt(q, 10) : null;
      if (exactId !== null) {
        if (e.id !== exactId) return false;
      } else {
        const hay = `${e.id} ${e.provider} ${e.channel} ${e.message} ${e.severity}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
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
      openLookupPanel(el.dataset.lookupId);
    });
  });

  // Advanced toggle (event delegation — survives no redraw)
  $eventTableWrap.querySelectorAll('.ev-advanced-toggle').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const section = btn.closest('.ev-detail-inner').querySelector('.ev-advanced-section');
      const open = section.classList.toggle('ev-advanced-open');
      btn.textContent = open ? 'Advanced ▲' : 'Advanced ▼';
    });
  });

  // Copy button (message clipboard)
  $eventTableWrap.querySelectorAll('.ev-copy-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      navigator.clipboard?.writeText(btn.dataset.copy).then(() => {
        btn.classList.add('copied');
        setTimeout(() => btn.classList.remove('copied'), 2000);
      });
    });
  });
}

function buildTableRow(ev) {
  const isExpanded = tbl.expandedIds.has(ev.recordId);
  const sev = ev.severity.toLowerCase();
  const dataKeys = Object.keys(ev.data || {});
  const msgPreview = ev.message
    ? esc(ev.message.substring(0, 150)) + (ev.message.length > 150 ? '…' : '')
    : '<span style="color:var(--text3);font-style:italic">no message</span>';

  const mainRow = `
    <tr class="ev-row-${sev}${isExpanded ? ' row-expanded' : ''}" data-record="${ev.recordId}">
      <td class="ev-col-expand">${isExpanded ? '▼' : '▶'}</td>
      <td class="ev-col-time">${formatDateTime(ev.timestamp)}</td>
      <td><span class="sev-badge sev-badge-${sev}">${ev.severity}</span></td>
      <td><span class="table-event-id" data-lookup-id="${ev.id}" title="Look up Event ${ev.id}">${ev.id}</span></td>
      <td class="ev-col-provider" title="${esc(ev.provider)}">${esc(shortProvider(ev.provider))}</td>
      <td class="ev-col-channel">${esc(ev.channel)}</td>
      <td class="ev-col-message">${msgPreview}</td>
    </tr>`;

  if (!isExpanded) return mainRow;

  const taskDisplay     = ev.taskName || ev.task || null;
  const opcodeDisplay   = decodeOpcode(ev.opcode, ev.opcodeName);
  const keywordsDisplay = decodeKeywords(ev.keywords, ev.keywordNames);
  const sidDisplay      = decodeSid(ev.userSID);
  const count           = idCountMap.get(ev.id) || 1;
  const nearbyCount     = allParsedEvents.filter(
    e => e.recordId !== ev.recordId && Math.abs(e.timestamp - ev.timestamp) <= 30000
  ).length;

  const metaFields = [
    ['Time (local)',    ev.timestamp.toLocaleString()],
    ['Time (UTC)',      ev.timestamp.toISOString()],
    ['Provider',        ev.provider],
    ['Channel',         ev.channel],
    ['Computer',        ev.computer],
    ['Record ID',       ev.recordId || null],
    ['User SID',        sidDisplay],
    ['Process ID',      ev.processId || null],
    ['Thread ID',       ev.threadId || null],
    ['Activity ID',     ev.activityId],
    ['Related Act. ID', ev.relatedActivityId],
    ['Task',            taskDisplay],
    ['Opcode',          opcodeDisplay],
    ['Keywords',        keywordsDisplay],
  ].filter(([, v]) => v);

  const advancedFields = [
    ['Raw Level',        String(ev.levelNum)],
    ['Raw Task',         ev.task],
    ['Raw Opcode',       ev.opcode],
    ['Raw Keywords',     ev.keywords],
    ['Version',          ev.version],
    ['Qualifiers',       ev.qualifiers],
    ['Provider Desc.',   ev.providerDescription],
  ].filter(([, v]) => v);

  const decodedMsg = decodeWinErrMsg(ev.message);
  const messageHtml = decodedMsg
    ? `<div class="ev-detail-message-wrap">
        <div class="ev-detail-message">${esc(decodedMsg)}</div>
        <button class="ev-copy-btn" data-copy="${esc(ev.message)}" title="Copy message">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
       </div>`
    : `<div class="ev-detail-message ev-no-message">
        Message not rendered — Windows message templates are stored on the source machine.
        Export directly from the affected computer to see full event messages.
       </div>`;

  const anonKeys = ev.dataAnon || [];

  return mainRow + `
    <tr class="ev-detail-row">
      <td colspan="7">
        <div class="ev-detail-inner">
          ${count > 1 || nearbyCount > 0 ? `
          <div class="ev-occurrence-bar">
            ${count > 1 ? `Event ${ev.id} appears <strong>${count}×</strong> in this log` : ''}
            ${count > 1 && nearbyCount > 0 ? ' &nbsp;·&nbsp; ' : ''}
            ${nearbyCount > 0 ? `<strong>${nearbyCount}</strong> other event${nearbyCount !== 1 ? 's' : ''} within ±30s` : ''}
          </div>` : ''}
          ${messageHtml}
          <div class="ev-detail-meta">
            ${metaFields.map(([k, v]) => `
              <div class="ev-detail-field">
                <span class="ev-detail-key">${k}</span>
                <span class="ev-detail-val">${esc(String(v))}</span>
              </div>`).join('')}
          </div>
          ${dataKeys.length || anonKeys.length ? `
          <div class="ev-detail-data">
            <div class="ev-detail-data-title">Event Data</div>
            ${dataKeys.map(k => `
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key">${esc(k)}</span>
                <span class="ev-detail-data-val">${esc(String(ev.data[k]))}</span>
              </div>`).join('')}
            ${anonKeys.map((v, i) => `
              <div class="ev-detail-data-row">
                <span class="ev-detail-data-key ev-detail-data-key--anon">[${i}]</span>
                <span class="ev-detail-data-val">${esc(String(v))}</span>
              </div>`).join('')}
          </div>` : ''}
          <div class="ev-detail-actions">
            <span class="ev-detail-lookup-btn table-event-id" data-lookup-id="${ev.id}">
              Look up Event ${ev.id} →
            </span>
            ${advancedFields.length ? `<button class="ev-advanced-toggle">Advanced ▼</button>` : ''}
          </div>
          ${advancedFields.length ? `
          <div class="ev-advanced-section">
            <div class="ev-detail-data-title">Advanced / Raw</div>
            ${advancedFields.map(([k, v]) => `
              <div class="ev-detail-field">
                <span class="ev-detail-key">${k}</span>
                <span class="ev-detail-val">${esc(String(v))}</span>
              </div>`).join('')}
          </div>` : ''}
        </div>
      </td>
    </tr>`;
}

function exportCSV(events) {
  const cols = [
    'Time (UTC)', 'Severity', 'EventID', 'Provider', 'Channel', 'Computer',
    'RecordID', 'ProcessID', 'ThreadID', 'UserSID', 'ActivityID', 'RelatedActivityID',
    'Task', 'TaskName', 'Opcode', 'OpcodeName', 'Keywords', 'KeywordNames',
    'Version', 'Qualifiers', 'ProviderDescription',
    'Message', 'EventData', 'EventDataAnon',
  ];
  const q = s => `"${String(s ?? '').replace(/"/g, '""').replace(/\r?\n/g, ' ')}"`;
  const rows = events.map(e => [
    e.timestamp.toISOString(), e.severity, e.id,
    q(e.provider), q(e.channel), q(e.computer),
    e.recordId, e.processId || '', e.threadId || '',
    q(e.userSID), q(e.activityId), q(e.relatedActivityId),
    q(e.task), q(e.taskName), q(e.opcode), q(e.opcodeName),
    q(e.keywords), q((e.keywordNames || []).join('; ')),
    q(e.version), q(e.qualifiers), q(e.providerDescription),
    q(e.message),
    q(Object.entries(e.data || {}).map(([k, v]) => `${k}=${v}`).join('; ')),
    q((e.dataAnon || []).join('; ')),
  ].join(','));
  const csv = [cols.join(','), ...rows].join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
  const a = Object.assign(document.createElement('a'), {
    href: url, download: `eventful-${new Date().toISOString().slice(0, 10)}.csv`,
  });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Lookup Panel ─────────────────────────────────────────────────────────────

function openLookupPanel(eventId) {
  const id = parseInt(eventId, 10);
  const $panel = document.getElementById('lookup-panel');
  const $body  = document.getElementById('lp-body');
  if (!$panel || !$body) return;

  const dbEntry    = allEvents.find(e => e.id === id);
  const rawMatches = allParsedEvents.filter(e => e.id === id);

  $body.innerHTML = buildPanelContent(id, dbEntry, rawMatches);
  $panel.hidden = false;

  // Wire PS copy buttons
  $body.querySelectorAll('.lp-copy-ps').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.code).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      });
    });
  });

  // Wire "Show all in log" button
  $body.querySelectorAll('.lp-show-in-log').forEach(btn => {
    btn.addEventListener('click', () => {
      const filterId = btn.dataset.filterId;
      closeLookupPanel();
      document.querySelectorAll('.analyzer-tab').forEach(t => t.classList.remove('active'));
      const eventsTab = document.querySelector('.analyzer-tab[data-tab="events"]');
      if (eventsTab) eventsTab.classList.add('active');
      document.getElementById('incidents-section').hidden = true;
      document.getElementById('events-panel').hidden = false;
      tbl.query = filterId;
      tbl.page = 0;
      const qi = document.getElementById('tbl-query');
      if (qi) qi.value = filterId;
      redrawTable();
    });
  });
}

function closeLookupPanel() {
  const $panel = document.getElementById('lookup-panel');
  if ($panel) $panel.hidden = true;
}

function buildPanelContent(id, dbEntry, rawMatches) {
  const showAllBtn = rawMatches.length
    ? `<button class="lp-show-in-log" data-filter-id="${id}">Show all ${rawMatches.length} occurrence${rawMatches.length !== 1 ? 's' : ''} in All Events →</button>`
    : '';

  if (dbEntry) {
    const sev = dbEntry.severity?.toLowerCase() ?? 'info';
    return `
      <div class="lp-section">
        <div class="lp-section-label">Knowledge Base</div>
        <div class="lp-doc-header">
          <span class="lp-id-badge">${id}</span>
          <div>
            <div class="lp-doc-title">${esc(dbEntry.title)}</div>
            <div class="lp-doc-meta">
              <span class="sev-badge sev-badge-${sev}">${esc(dbEntry.severity)}</span>
              <span class="lp-channel">${esc(dbEntry.channel || dbEntry.source || '')}</span>
            </div>
          </div>
        </div>
        <p class="lp-description">${esc(dbEntry.description || dbEntry.short_desc || '')}</p>
        ${dbEntry.causes?.length ? `
          <div class="lp-subsection-label">Causes</div>
          <ul class="lp-causes">
            ${dbEntry.causes.map(c => `<li>${esc(c)}</li>`).join('')}
          </ul>` : ''}
        ${dbEntry.steps?.length ? `
          <div class="lp-subsection-label">Investigation Steps</div>
          <ol class="lp-steps">
            ${dbEntry.steps.map(s => `<li>${esc(s)}</li>`).join('')}
          </ol>` : ''}
        ${dbEntry.powershell ? `
          <div class="lp-subsection-label">PowerShell</div>
          <div class="lp-ps-block">
            <pre>${esc(dbEntry.powershell)}</pre>
            <button class="lp-copy-ps" data-code="${esc(dbEntry.powershell)}">Copy</button>
          </div>` : ''}
        <div class="lp-doc-footer">
          <a href="results.html?q=${id}" target="_blank" rel="noopener" class="lp-full-docs-btn">
            Open full docs →
          </a>
          ${showAllBtn}
        </div>
      </div>`;
  }

  return `
    <div class="lp-section">
      <div class="lp-section-label">Knowledge Base</div>
      <div class="lp-no-doc-state">
        <div class="lp-no-doc-title">No documentation for Event ${id}</div>
        <div class="lp-no-doc-sub">This event ID is not in the Eventful knowledge base.</div>
      </div>
      ${showAllBtn}
    </div>`;
}

function buildEventDetail(ev) {
  const taskDisp     = ev.taskName || ev.task || null;
  const opcodeDisp   = decodeOpcode(ev.opcode, ev.opcodeName);
  const kwDisp       = decodeKeywords(ev.keywords, ev.keywordNames);
  const sidDisp      = decodeSid(ev.userSID);
  const anonData     = ev.dataAnon || [];
  const dataKeys     = Object.keys(ev.data || {});
  const count        = idCountMap.get(ev.id) || 1;
  const nearbyCount  = allParsedEvents.filter(
    e => e.recordId !== ev.recordId && Math.abs(e.timestamp - ev.timestamp) <= 30000
  ).length;
  const decodedMsg   = decodeWinErrMsg(ev.message);

  const metaFields = [
    ['Time (local)',    ev.timestamp.toLocaleString()],
    ['Time (UTC)',      ev.timestamp.toISOString()],
    ['Provider',        ev.provider],
    ['Channel',         ev.channel],
    ['Computer',        ev.computer],
    ['Record ID',       ev.recordId || null],
    ['User SID',        sidDisp],
    ['Process ID',      ev.processId || null],
    ['Thread ID',       ev.threadId || null],
    ['Activity ID',     ev.activityId],
    ['Task',            taskDisp],
    ['Opcode',          opcodeDisp],
    ['Keywords',        kwDisp],
  ].filter(([, v]) => v);

  const advancedFields = [
    ['Raw Level',    String(ev.levelNum)],
    ['Raw Task',     ev.task],
    ['Raw Opcode',   ev.opcode],
    ['Raw Keywords', ev.keywords],
    ['Version',      ev.version],
  ].filter(([, v]) => v);

  return `
    <div class="ev-inline-detail">
      ${count > 1 || nearbyCount > 0 ? `
      <div class="ev-occurrence-bar">
        ${count > 1 ? `Event ${ev.id} fired <strong>${count}×</strong> in this log` : ''}
        ${count > 1 && nearbyCount > 0 ? ' &nbsp;·&nbsp; ' : ''}
        ${nearbyCount > 0 ? `<strong>${nearbyCount}</strong> other event${nearbyCount !== 1 ? 's' : ''} within ±30s` : ''}
      </div>` : ''}
      ${decodedMsg
        ? `<div class="ev-detail-message-wrap">
             <div class="ev-detail-message">${esc(decodedMsg)}</div>
             <button class="ev-copy-btn" data-copy="${esc(ev.message)}" title="Copy message">
               <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
             </button>
           </div>`
        : `<div class="ev-detail-message ev-no-message">Message not rendered — Windows message templates are stored on the source machine. Export from the affected computer to see full messages.</div>`}
      <div class="ev-inline-grid">
        <div class="ev-detail-meta">
          ${metaFields.map(([k, v]) => `
            <div class="ev-detail-field">
              <span class="ev-detail-key">${k}</span>
              <span class="ev-detail-val">${esc(String(v))}</span>
            </div>`).join('')}
        </div>
        ${dataKeys.length || anonData.length ? `
        <div class="ev-detail-data">
          <div class="ev-detail-data-title">Event Data</div>
          ${dataKeys.map(k => `
            <div class="ev-detail-data-row">
              <span class="ev-detail-data-key">${esc(k)}</span>
              <span class="ev-detail-data-val">${esc(String(ev.data[k]))}</span>
            </div>`).join('')}
          ${anonData.map((v, i) => `
            <div class="ev-detail-data-row">
              <span class="ev-detail-data-key ev-detail-data-key--anon">[${i}]</span>
              <span class="ev-detail-data-val">${esc(String(v))}</span>
            </div>`).join('')}
        </div>` : ''}
      </div>
      <div class="ev-detail-actions">
        <span class="ev-detail-lookup-btn" data-lookup-id="${ev.id}">Look up Event ${ev.id} →</span>
        ${advancedFields.length ? `<button class="ev-advanced-toggle">Advanced ▼</button>` : ''}
      </div>
      ${advancedFields.length ? `
      <div class="ev-advanced-section">
        <div class="ev-detail-data-title">Advanced / Raw</div>
        ${advancedFields.map(([k, v]) => `
          <div class="ev-detail-field">
            <span class="ev-detail-key">${k}</span>
            <span class="ev-detail-val">${esc(String(v))}</span>
          </div>`).join('')}
      </div>` : ''}
    </div>`;
}

function lpField(label, value) {
  return `
    <div class="lp-raw-field">
      <span class="lp-raw-key">${label}</span>
      <span class="lp-raw-val">${value}</span>
    </div>`;
}

// ── Event Detail Decoders ─────────────────────────────────────────────────────

const KNOWN_SIDS = {
  'S-1-1-0':      'Everyone',
  'S-1-5-7':      'Anonymous',
  'S-1-5-18':     'SYSTEM',
  'S-1-5-19':     'LOCAL SERVICE',
  'S-1-5-20':     'NETWORK SERVICE',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
};

function decodeSid(sid) {
  if (!sid) return null;
  const name = KNOWN_SIDS[sid];
  return name ? `${name} (${sid})` : sid;
}

const WIN_ERRORS = {
  2:    'The system cannot find the file specified',
  3:    'The system cannot find the path specified',
  5:    'Access is denied',
  32:   'The process cannot access the file because it is being used by another process',
  1053: 'The service did not respond to the start or control request in a timely fashion',
  1055: 'The service database is locked',
  1056: 'An instance of the service is already running',
  1058: 'The service cannot be started — it is disabled or has no enabled devices associated with it',
  1060: 'The specified service does not exist as an installed service',
  1061: 'The service cannot accept control messages at this time',
  1067: 'The process terminated unexpectedly',
  1068: 'The dependency service or group failed to start',
  1069: 'The service did not start due to a logon failure',
  1072: 'The specified service has been marked for deletion',
  1073: 'The specified service already exists',
  1326: 'Logon failure: unknown user name or bad password',
};

function decodeWinErrMsg(msg) {
  if (!msg) return msg;
  return msg.replace(/%%(\d+)/g, (m, n) => {
    const txt = WIN_ERRORS[+n];
    return txt ? `${txt} (%%${n})` : m;
  });
}

const OPCODE_MAP = {
  '0': 'Info', '1': 'Start', '2': 'Stop', '3': 'DC Start',
  '4': 'DC Stop', '5': 'Extension', '6': 'Reply', '7': 'Resume',
  '8': 'Suspend', '9': 'Send', '240': 'Disconnect', '241': 'Connect',
};

function decodeOpcode(raw, name) {
  if (name) return name;
  if (raw == null || raw === '') return null;
  return OPCODE_MAP[String(raw)] || String(raw);
}

const KEYWORD_MAP = {
  '0x8000000000000000': 'Audit Failure',
  '0x4000000000000000': 'Audit Success',
  '0x8080000000000000': 'Classic, Audit Failure',
  '0x4080000000000000': 'Classic, Audit Success',
  '0x0080000000000000': 'Classic',
  '0x0000000000000000': 'None',
};

function decodeKeywords(raw, names) {
  if (names?.length) return names.join(', ');
  if (!raw) return null;
  return KEYWORD_MAP[raw.toLowerCase()] ?? raw;
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
