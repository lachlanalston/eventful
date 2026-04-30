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
const $uploadSection     = document.getElementById('upload-section');
const $processingSection = document.getElementById('processing-section');
const $resultsSection    = document.getElementById('results-section');
const $dropZone          = document.getElementById('drop-zone');
const $fileInput         = document.getElementById('file-input');
const $processingText    = document.getElementById('processing-text');
const $overviewGrid      = document.getElementById('overview-grid');
const $incidentsSection  = document.getElementById('incidents-section');
const $eventTableWrap    = document.getElementById('event-table-wrap');
const $eventFilter       = document.getElementById('event-filter');
const $severityFilter    = document.getElementById('severity-filter');
const $newAnalysisBtn    = document.getElementById('new-analysis-btn');
const $resultsSub        = document.getElementById('results-sub');

// ── State ─────────────────────────────────────────────────────────────────────
let allParsedEvents = [];
let eventFilterQuery = '';
let eventFilterSeverity = '';

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

// ── Event Table ───────────────────────────────────────────────────────────────
function renderEventTable(events) {
  if (!$eventTableWrap) return;

  eventFilterQuery = '';
  eventFilterSeverity = '';
  if ($eventFilter) $eventFilter.value = '';
  if ($severityFilter) $severityFilter.value = '';

  redrawTable(events);
}

function redrawTable(events) {
  const q = eventFilterQuery.toLowerCase();
  const sev = eventFilterSeverity;

  const filtered = events.filter(e => {
    if (sev && e.severity !== sev) return false;
    if (q) {
      const haystack = `${e.id} ${e.provider} ${e.channel} ${e.message} ${e.severity}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    $eventTableWrap.innerHTML = `<div class="table-empty">No events match the current filter.</div>`;
    return;
  }

  const MAX_ROWS = 500;
  const truncated = filtered.length > MAX_ROWS;
  const rows = filtered.slice(0, MAX_ROWS);

  $eventTableWrap.innerHTML = `
    ${truncated ? `<div class="table-notice">Showing first ${MAX_ROWS} of ${filtered.length.toLocaleString()} matching events.</div>` : ''}
    <table class="event-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Sev</th>
          <th>ID</th>
          <th>Provider</th>
          <th>Channel</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(ev => `
          <tr class="ev-row-${ev.severity.toLowerCase()}">
            <td class="ev-col-time">${formatDateTime(ev.timestamp)}</td>
            <td><span class="sev-badge sev-badge-${ev.severity.toLowerCase()}">${ev.severity}</span></td>
            <td>
              <span class="table-event-id" data-lookup-id="${ev.id}" title="Look up Event ${ev.id}">
                ${ev.id}
              </span>
            </td>
            <td class="ev-col-provider">${esc(shortProvider(ev.provider))}</td>
            <td class="ev-col-channel">${esc(ev.channel)}</td>
            <td class="ev-col-message">${esc(ev.message.substring(0, 120))}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  // Wire up event ID lookup links in table
  $eventTableWrap.querySelectorAll('[data-lookup-id]').forEach(el => {
    el.addEventListener('click', () => window.open(`results.html?q=${el.dataset.lookupId}`, '_blank'));
  });
}

$eventFilter?.addEventListener('input', e => {
  eventFilterQuery = e.target.value;
  redrawTable(allParsedEvents);
});

$severityFilter?.addEventListener('change', e => {
  eventFilterSeverity = e.target.value;
  redrawTable(allParsedEvents);
});

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
