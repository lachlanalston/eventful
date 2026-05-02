import Fuse from 'fuse.js';
import { allEvents } from '../../data/events/index.js';
import { initTheme, toggleTheme } from './theme.js';

initTheme();

document.querySelectorAll('.theme-btn').forEach(btn => {
  btn.addEventListener('click', toggleTheme);
});

// ── Search setup ──────────────────────────────────────────────────────────────
const fuse = new Fuse(allEvents, {
  keys: [
    { name: 'symptoms',    weight: 0.4 },
    { name: 'tags',        weight: 0.3 },
    { name: 'title',       weight: 0.2 },
    { name: 'description', weight: 0.1 },
  ],
  threshold: 0.4,
  ignoreLocation: true,
  minMatchCharLength: 2,
});

// ── DOM ───────────────────────────────────────────────────────────────────────
const $search = document.getElementById('search');
const $list   = document.getElementById('list');
const $count  = document.getElementById('count');
const $detail = document.getElementById('detail');

// ── State ─────────────────────────────────────────────────────────────────────
let activeId     = null;
let checkedSteps = JSON.parse(localStorage.getItem('ef_steps') || '{}');
function saveSteps() { localStorage.setItem('ef_steps', JSON.stringify(checkedSteps)); }

// ── Query ─────────────────────────────────────────────────────────────────────
function getResults(query) {
  const q = query.trim();

  let results;
  if (!q) {
    // No search — show all events (so filters work standalone)
    results = allEvents;
  } else if (/^\d+$/.test(q)) {
    results = allEvents.filter(e => e.id === parseInt(q, 10));
  } else {
    results = fuse.search(q).map(r => r.item);
  }

  return results;
}

// ── Render list ───────────────────────────────────────────────────────────────
const SEV_ORDER = ['Critical', 'Error', 'Warning', 'Info', 'Verbose'];

function buildRow(event) {
  const row = document.createElement('div');
  row.className = `result-row${event.id === activeId ? ' active' : ''}`;
  row.dataset.id = event.id;
  row.dataset.severity = event.severity;
  row.innerHTML = `
    <span class="row-dot dot-${event.severity}"></span>
    <div class="row-body">
      <div class="row-top">
        <span class="row-id">${event.id}</span>
        <span class="row-channel">${escHtml(event.channel)}</span>
      </div>
      <span class="row-title">${escHtml(event.title)}</span>
    </div>
  `;
  row.addEventListener('click', () => selectEvent(event, row));
  return row;
}

function render(query) {
  const results = getResults(query);
  const q = query.trim();

  if (!results.length) {
    $list.innerHTML = `<div class="list-empty"><p>No results</p></div>`;
    $count.textContent = '';
    showEmptyDetail();
    return;
  }

  $count.textContent = `${results.length} result${results.length !== 1 ? 's' : ''}`;
  $list.innerHTML = '';

  // Group by severity in canonical order
  const groups = SEV_ORDER
    .map(sev => ({ sev, items: results.filter(e => e.severity === sev) }))
    .filter(g => g.items.length > 0);

  const showHeaders = groups.length > 1;

  groups.forEach(({ sev, items }) => {
    if (showHeaders) {
      const hdr = document.createElement('div');
      hdr.className = 'sev-group-header';
      hdr.dataset.severity = sev;
      hdr.innerHTML = `
        <span class="row-dot dot-${sev}"></span>
        <span class="sev-group-label">${sev}</span>
        <span class="sev-group-count">${items.length}</span>
      `;
      $list.appendChild(hdr);
    }
    items.forEach(event => $list.appendChild(buildRow(event)));
  });

  // Auto-select first result
  if (!activeId || !results.find(e => e.id === activeId)) {
    const first = results[0];
    const firstRow = $list.querySelector('.result-row');
    if (first && firstRow) selectEvent(first, firstRow);
  }
}

// ── Select event → show detail ─────────────────────────────────────────────────
function selectEvent(event, row) {
  // Update active row
  $list.querySelectorAll('.result-row').forEach(r => r.classList.remove('active'));
  row.classList.add('active');
  activeId = event.id;

  // Render detail panel
  $detail.innerHTML = buildDetail(event);
  wireDetail($detail, event);
  $detail.scrollTop = 0;
}

function showEmptyDetail() {
  activeId = null;
  $detail.innerHTML = `
    <div class="detail-empty">
      <p class="detail-empty-text">Select an event to view details</p>
    </div>
  `;
}

// ── Build detail panel HTML ───────────────────────────────────────────────────
function buildDetail(event) {
  const steps = event.steps.map((s, i) => {
    const key     = `${event.id}-${i}`;
    const checked = checkedSteps[key] ? 'checked' : '';
    return `<label class="step"><input type="checkbox" data-key="${key}" ${checked}/><span>${escHtml(s)}</span></label>`;
  }).join('');

  const causes = event.causes.map(c => `<div class="cause">${escHtml(c)}</div>`).join('');

  const related = event.related_ids.length
    ? event.related_ids.map(id => `<button class="pill" data-id="${id}">${id}</button>`).join('')
    : '<span class="docs-none">None</span>';

  const docsLink = event.ms_docs
    ? `<a class="docs-link" href="${event.ms_docs}" target="_blank" rel="noopener">Microsoft Docs ↗</a>`
    : `<span class="docs-none">No official docs</span>`;

  return `
    <div class="detail-header">
      <div class="detail-meta">
        <span class="detail-eid">EVT-${event.id}</span>
        <span class="sev-badge sev-${event.severity}">${event.severity}</span>
        <span class="meta-tag">${escHtml(event.channel)}</span>
        <span class="meta-tag">${escHtml(event.source)}</span>
      </div>
      <h2 class="detail-title">${escHtml(event.title)}</h2>
    </div>

    <div class="detail-section">
      <div class="section-label">Description</div>
      <p class="detail-desc">${escHtml(event.description)}</p>
    </div>

    <div class="detail-section">
      <div class="section-label">Common Causes</div>
      <div class="causes">${causes}</div>
    </div>

    <div class="detail-section">
      <div class="section-label">Investigation Steps</div>
      <div class="steps">${steps}</div>
    </div>

    <div class="detail-section">
      <div class="section-label">PowerShell</div>
      <div class="ps-terminal">
        <div class="ps-titlebar">
          <div class="ps-title-icon">PS</div>
          <span class="ps-title-text">Windows PowerShell</span>
          <div class="ps-win-controls">
            <button class="ps-win-btn" tabindex="-1">&#x2212;</button>
            <button class="ps-win-btn" tabindex="-1">&#x25A1;</button>
            <button class="ps-win-btn close" tabindex="-1">&#x2715;</button>
          </div>
        </div>
        <div class="ps-toolbar">
          <span class="ps-filename">Event-${event.id}.ps1</span>
          <button class="copy-btn" data-ps>Copy</button>
        </div>
        <pre class="ps-code">${escHtml(event.powershell)}</pre>
      </div>
    </div>

    <div class="detail-section">
      <div class="section-label">Related Events</div>
      <div class="pills">${related}</div>
    </div>

    <div class="detail-section">
      <div class="section-label">Reference</div>
      ${docsLink}
    </div>
  `;
}

// ── Wire detail interactivity ─────────────────────────────────────────────────
function wireDetail(panel, event) {
  // Checkboxes
  panel.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) checkedSteps[cb.dataset.key] = true;
      else delete checkedSteps[cb.dataset.key];
      saveSteps();
    });
  });

  // Copy button
  const copyBtn = panel.querySelector('[data-ps]');
  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      await navigator.clipboard.writeText(event.powershell).catch(() => {});
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('ok');
      setTimeout(() => { copyBtn.textContent = 'Copy'; copyBtn.classList.remove('ok'); }, 2000);
    });
  }

  // Related pills → search for that ID
  panel.querySelectorAll('.pill[data-id]').forEach(pill => {
    pill.addEventListener('click', () => {
      const id = pill.dataset.id;
      $search.value = id;
      updateUrl(id);
      render(id);
    });
  });
}

// ── Search input ──────────────────────────────────────────────────────────────
let timer;

$search.addEventListener('input', () => {
  clearTimeout(timer);
  timer = setTimeout(() => {
    activeId = null;
    const v = $search.value.trim();
    updateUrl(v);
    if (v) { render($search.value); $search.focus(); }
    else window.location.href = 'event-lookup.html';
  }, 120);
});

$search.addEventListener('keydown', e => {
  if (e.key === 'Escape') window.location.href = 'event-lookup.html';
});

// ── URL helpers ───────────────────────────────────────────────────────────────
function updateUrl(q) {
  const url = new URL(window.location);
  if (q) url.searchParams.set('q', q); else url.searchParams.delete('q');
  history.replaceState(null, '', url);
}

// ── Init from URL ─────────────────────────────────────────────────────────────
const params = new URLSearchParams(location.search);
const initQ  = params.get('q') || '';

if (initQ) {
  $search.value = initQ;
  render(initQ);
  $search.focus();
} else {
  window.location.href = 'event-lookup.html';
}

// ── Utility ───────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
