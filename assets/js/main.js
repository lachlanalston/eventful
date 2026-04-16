import Fuse from 'fuse.js';
import { allEvents } from '../../data/events/index.js';

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
const $search  = document.getElementById('search');
const $results = document.getElementById('results');
const $count   = document.getElementById('count');
const $home    = document.getElementById('home-content');

// ── State ─────────────────────────────────────────────────────────────────────
let openId      = null;
let checkedSteps = JSON.parse(localStorage.getItem('ef_steps') || '{}');

function saveSteps() {
  localStorage.setItem('ef_steps', JSON.stringify(checkedSteps));
}

// ── Search ────────────────────────────────────────────────────────────────────
function getResults(query) {
  const q = query.trim();
  if (!q) return [];
  if (/^\d+$/.test(q)) return allEvents.filter(e => e.id === parseInt(q, 10));
  return fuse.search(q).map(r => r.item);
}

function render(query) {
  const results = getResults(query);
  const q = query.trim();

  if (!q) {
    $results.innerHTML = '';
    $count.textContent = '';
    $home.style.display = '';
    return;
  }

  $home.style.display = 'none';

  if (!results.length) {
    $results.innerHTML = `<div class="empty"><h2>No results for "${q}"</h2><p>Try different keywords or an Event ID number</p></div>`;
    $count.textContent = '';
    return;
  }

  $count.textContent = `${results.length} event${results.length !== 1 ? 's' : ''} found`;
  $results.innerHTML = '';

  results.forEach(event => {
    const isOpen = event.id === openId;
    const card = buildCard(event, isOpen);
    $results.appendChild(card);
  });
}

// ── Build card ────────────────────────────────────────────────────────────────
function buildCard(event, isOpen) {
  const el = document.createElement('div');
  el.className = `card${isOpen ? ' open' : ''}`;
  el.dataset.id = event.id;

  // Collapsed row
  const row = document.createElement('div');
  row.className = 'card-row';
  row.innerHTML = `
    <span class="card-id">${event.id}</span>
    <span class="card-title">${event.title}</span>
    <span class="card-short">${event.short_desc}</span>
    <span class="badge badge-${event.severity}">${event.severity}</span>
    <span class="chevron">▶</span>
  `;

  // Expanded body
  const body = document.createElement('div');
  body.className = 'card-body';
  if (isOpen) body.innerHTML = buildBody(event);

  row.addEventListener('click', () => {
    const nowOpen = !el.classList.contains('open');
    openId = nowOpen ? event.id : null;

    el.classList.toggle('open', nowOpen);
    if (nowOpen && !body.innerHTML) {
      body.innerHTML = buildBody(event);
      wireBody(body, event);
    }

    // Scroll into view
    if (nowOpen) {
      setTimeout(() => el.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
    }
  });

  if (isOpen) wireBody(body, event);

  el.appendChild(row);
  el.appendChild(body);
  return el;
}

// ── Build expanded body HTML ──────────────────────────────────────────────────
function buildBody(event) {
  const steps = event.steps.map((s, i) => {
    const key     = `${event.id}-${i}`;
    const checked = checkedSteps[key] ? 'checked' : '';
    return `<label class="step"><input type="checkbox" data-key="${key}" ${checked}/><span>${s}</span></label>`;
  }).join('');

  const causes = event.causes.map(c => `<div class="cause">${c}</div>`).join('');

  const related = event.related_ids.length
    ? event.related_ids.map(id => `<button class="pill" data-id="${id}">${id}</button>`).join('')
    : '<span style="color:#334155;font-size:13px">None</span>';

  const docsLink = event.ms_docs
    ? `<a href="${event.ms_docs}" target="_blank" rel="noopener" style="color:#7dd3fc;font-family:'JetBrains Mono',monospace;font-size:12px;">Microsoft Docs ↗</a>`
    : `<span style="color:#334155;font-size:12px;font-family:'JetBrains Mono',monospace">No official docs</span>`;

  return `
    <div class="card-header-strip">
      <div class="card-header-id">${event.id}</div>
      <div class="card-header-info">
        <div class="card-header-title">${event.title}</div>
        <div class="card-header-meta">
          <span class="badge badge-${event.severity}">${event.severity}</span>
          <span class="card-source">${event.channel}</span>
          <span class="card-source">${event.source}</span>
        </div>
      </div>
    </div>

    <div class="card-section">
      <div class="section-title">Description</div>
      <p class="card-desc">${event.description}</p>
    </div>

    <div class="card-section">
      <div class="section-title">Common Causes</div>
      <div class="causes">${causes}</div>
    </div>

    <div class="card-section">
      <div class="section-title">Investigation Steps</div>
      <div class="steps">${steps}</div>
    </div>

    <div class="card-section">
      <div class="section-title">PowerShell</div>
      <div class="ps-terminal">
        <div class="ps-bar">
          <span class="dot dot-r"></span>
          <span class="dot dot-y"></span>
          <span class="dot dot-g"></span>
          <span class="ps-name">Event-${event.id}.ps1</span>
          <button class="copy-btn" data-ps>Copy</button>
        </div>
        <pre class="ps-code">${escHtml(event.powershell)}</pre>
      </div>
    </div>

    <div class="card-section">
      <div class="section-title">Related Events</div>
      <div class="pills">${related}</div>
    </div>

    <div class="card-section">
      <div class="section-title">Reference</div>
      ${docsLink}
    </div>
  `;
}

// ── Wire interactive elements inside an open card ─────────────────────────────
function wireBody(body, event) {
  // Checkboxes
  body.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) checkedSteps[cb.dataset.key] = true;
      else delete checkedSteps[cb.dataset.key];
      saveSteps();
    });
  });

  // Copy button
  const copyBtn = body.querySelector('[data-ps]');
  if (copyBtn) {
    copyBtn.addEventListener('click', async e => {
      e.stopPropagation();
      await navigator.clipboard.writeText(event.powershell).catch(() => {});
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('ok');
      setTimeout(() => { copyBtn.textContent = 'Copy'; copyBtn.classList.remove('ok'); }, 2000);
    });
  }

  // Related event pills — search for that ID
  body.querySelectorAll('.pill[data-id]').forEach(pill => {
    pill.addEventListener('click', e => {
      e.stopPropagation();
      const id = pill.dataset.id;
      $search.value = id;
      openId = parseInt(id, 10);
      render(id);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  });
}

// ── Search input wiring ───────────────────────────────────────────────────────
let timer;
$search.addEventListener('input', () => {
  clearTimeout(timer);
  timer = setTimeout(() => render($search.value), 120);
});

$search.addEventListener('keydown', e => {
  if (e.key === 'Escape') { $search.value = ''; render(''); }
});

// Check URL for initial query
const params = new URLSearchParams(location.search);
const init   = params.get('q') || location.hash.replace('#', '');
if (init) { $search.value = init; render(init); }

$search.focus();

// ── Quick-search chips ────────────────────────────────────────────────────────
document.querySelectorAll('.chip[data-q]').forEach(chip => {
  chip.addEventListener('click', () => {
    $search.value = chip.dataset.q;
    render(chip.dataset.q);
    $search.focus();
  });
});

// ── Utility ───────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
