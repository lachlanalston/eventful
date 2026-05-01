/**
 * UI rendering for Eventful — all DOM manipulation lives here
 */

import { attachCopyButton, copyShareURL } from './clipboard.js';

// ─── Severity / channel badge colours ────────────────────────────────────────
const SEVERITY_CLASS = {
  Critical: 'badge-critical',
  Error:    'badge-error',
  Warning:  'badge-warning',
  Info:     'badge-info',
  Verbose:  'badge-verbose'
};

const SKILL_META = {
  Fundamental:  { dot: '🟢', class: 'skill-fundamental' },
  Intermediate: { dot: '🟡', class: 'skill-intermediate' },
  Advanced:     { dot: '🔴', class: 'skill-advanced' }
};

// ─── Skeleton loaders ─────────────────────────────────────────────────────────
export function renderSkeletons(container, count = 6) {
  container.innerHTML = Array.from({ length: count }, () => `
    <div class="skeleton-row">
      <span class="skeleton skeleton-badge"></span>
      <span class="skeleton skeleton-id"></span>
      <span class="skeleton skeleton-text"></span>
    </div>
  `).join('');
}

// ─── Result count string ──────────────────────────────────────────────────────
export function renderResultCount(el, { results, total, query, mode }) {
  if (!el) return;
  if (mode === 'id') {
    el.textContent = results.length ? `Event ${results[0].id} found` : 'No event found for that ID';
  } else if (mode === 'symptom') {
    el.textContent = `${results.length} result${results.length !== 1 ? 's' : ''} for "${query}"`;
  } else {
    el.textContent = `Showing ${results.length} of ${total} events`;
  }
}

// ─── Empty state ──────────────────────────────────────────────────────────────
export function renderEmpty(container, { onSuggestionClick } = {}) {
  const suggestions = ['account lockout', 'blue screen', 'rdp disconnecting', 'service crash', 'slow machine'];
  container.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">⚡</div>
      <p class="empty-title">Start typing to find events</p>
      <p class="empty-sub">Type a symptom, error description, or event ID</p>
      <div class="suggestions">
        ${suggestions.map(s => `<button class="suggestion-chip" data-query="${s}">${s}</button>`).join('')}
      </div>
    </div>
  `;
  if (onSuggestionClick) {
    container.querySelectorAll('.suggestion-chip').forEach(btn => {
      btn.addEventListener('click', () => onSuggestionClick(btn.dataset.query));
    });
  }
}

// ─── No results state ─────────────────────────────────────────────────────────
export function renderNoResults(container, query) {
  container.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">🔍</div>
      <p class="empty-title">No events match "${query}"</p>
      <p class="empty-sub">Try different keywords, an event ID number, or adjust the filters</p>
    </div>
  `;
}

// ─── Single result row (collapsed) ───────────────────────────────────────────
function buildResultRow(event, isExpanded, onToggle, onRelatedClick) {
  const row = document.createElement('div');
  row.className = `result-row${isExpanded ? ' expanded' : ''}`;
  row.dataset.id = event.id;

  row.innerHTML = `
    <div class="row-header" role="button" tabindex="0" aria-expanded="${isExpanded}">
      <span class="badge ${SEVERITY_CLASS[event.severity] || ''}">${event.severity.toUpperCase()}</span>
      <span class="event-id">${event.id}</span>
      <span class="channel-badge">${event.channel}</span>
      <span class="event-title">${event.title}</span>
      <span class="skill-dot" title="${event.skill_level}">${SKILL_META[event.skill_level]?.dot || ''}</span>
      <span class="row-arrow">${isExpanded ? '▼' : '▶'}</span>
    </div>
    <div class="row-short-desc">${event.short_desc}</div>
    <div class="event-card" aria-hidden="${!isExpanded}">
      ${buildEventCard(event, onRelatedClick)}
    </div>
  `;

  const header = row.querySelector('.row-header');

  const toggle = () => {
    const nowExpanded = !row.classList.contains('expanded');
    onToggle(event.id, nowExpanded);
  };

  header.addEventListener('click', toggle);
  header.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
  });

  return row;
}

// Event IDs commonly found in crash/incident logs → show Incident Analyzer hint
const CRASH_RELATED_IDS = new Set([41, 6008, 1001, 1000, 1002, 4101, 7, 11, 51, 55, 7031, 7034, 7022, 7023, 7024]);

// ─── Full event card (expanded content) ──────────────────────────────────────
function buildEventCard(event, onRelatedClick) {
  const skill = SKILL_META[event.skill_level] || {};
  const steps = event.steps.map((s, i) => `
    <li class="step-item">
      <label class="step-label">
        <input type="checkbox" class="step-check" data-event="${event.id}" data-step="${i}">
        <span>${s}</span>
      </label>
    </li>
  `).join('');

  const causes = event.causes.map(c => `<li>${c}</li>`).join('');
  const mistakes = event.common_mistakes.map(m => `<li>${m}</li>`).join('');

  const relatedPills = event.related_ids.map(id => `
    <button class="related-pill" data-related="${id}">${id}</button>
  `).join('');

  const docsLink = event.ms_docs
    ? `<a href="${event.ms_docs}" target="_blank" rel="noopener" class="docs-link">Microsoft Documentation ↗</a>`
    : '<span class="no-docs">No official docs link</span>';

  return `
    <div class="card-header">
      <div class="card-id-block">
        <span class="card-id">${event.id}</span>
      </div>
      <div class="card-title-block">
        <h2 class="card-title">${event.title}</h2>
        <div class="card-meta">
          <span class="badge ${SEVERITY_CLASS[event.severity] || ''}">${event.severity.toUpperCase()}</span>
          <span class="channel-badge">${event.channel}</span>
          <span class="card-source">${event.source}</span>
        </div>
      </div>
    </div>

    <section class="card-section">
      <p class="card-description">${event.description}</p>
    </section>

    <section class="card-section">
      <h3 class="section-label">Causes</h3>
      <ul class="causes-list">${causes}</ul>
    </section>

    <section class="card-section">
      <h3 class="section-label">Investigation Steps</h3>
      <ol class="steps-list">${steps}</ol>
    </section>

    <section class="card-section powershell-section">
      <h3 class="section-label">PowerShell</h3>
      <div class="ps-wrapper">
        <div class="ps-titlebar">
          <span class="ps-dot ps-dot-red"></span>
          <span class="ps-dot ps-dot-yellow"></span>
          <span class="ps-dot ps-dot-green"></span>
          <span class="ps-filename">Event-${event.id}-Investigation.ps1</span>
          <button class="copy-btn ps-copy-btn">Copy</button>
        </div>
        <pre class="ps-block"><code class="ps-code">${escapeHtml(event.powershell)}</code></pre>
      </div>
    </section>

    <section class="card-section">
      <h3 class="section-label">Related Events</h3>
      <div class="related-pills">${relatedPills}</div>
    </section>

    ${CRASH_RELATED_IDS.has(event.id) ? `
    <div class="analyzer-hint-strip">
      <span class="ahs-icon">🔬</span>
      <span class="ahs-text">This event commonly appears in crash &amp; incident logs.</span>
      <a href="analyzer.html" class="ahs-link">Analyze a log file →</a>
    </div>
    ` : ''}

    <details class="learn-more">
      <summary class="learn-more-toggle">Learn More <span class="lm-arrow">▶</span></summary>
      <div class="learn-more-body">
        <div class="lm-section">
          <h4>Why It Happens</h4>
          <p>${event.why_it_happens}</p>
        </div>
        <div class="lm-section">
          <h4>What Good Looks Like</h4>
          <p>${event.what_good_looks_like}</p>
        </div>
        <div class="lm-section">
          <h4>Common Mistakes</h4>
          <ul>${mistakes}</ul>
        </div>
        <div class="lm-section">
          ${docsLink}
        </div>
      </div>
    </details>

    <div class="card-footer">
      <span class="skill-indicator ${skill.class || ''}">
        ${skill.dot || ''} ${event.skill_level}
      </span>
      <button class="share-btn" data-event-id="${event.id}" title="Copy link to this event">⎘ Share</button>
    </div>
  `;
}

// ─── Render results list ──────────────────────────────────────────────────────
export function renderResults(container, events, { expandedId, checkedSteps, onToggle, onRelatedClick }) {
  // Fade out before re-render
  container.classList.add('results-fading');

  requestAnimationFrame(() => {
    container.innerHTML = '';
    events.forEach(event => {
      const isExpanded = event.id === expandedId;
      const row = buildResultRow(event, isExpanded, onToggle, onRelatedClick);
      container.appendChild(row);

      // Wire up PowerShell copy button
      const psBtn = row.querySelector('.ps-copy-btn');
      if (psBtn) {
        attachCopyButton(psBtn, () => event.powershell);
      }

      // Wire up share button
      const shareBtn = row.querySelector('.share-btn');
      if (shareBtn) {
        shareBtn.addEventListener('click', async (e) => {
          e.stopPropagation();
          await copyShareURL(event.id);
          shareBtn.textContent = '✓ Copied';
          setTimeout(() => { shareBtn.textContent = '⎘ Share'; }, 2000);
        });
      }

      // Wire up related-pill clicks
      row.querySelectorAll('.related-pill').forEach(pill => {
        pill.addEventListener('click', (e) => {
          e.stopPropagation();
          onRelatedClick(parseInt(pill.dataset.related, 10));
        });
      });

      // Restore checked steps from state
      row.querySelectorAll('.step-check').forEach(cb => {
        const key = `${event.id}-${cb.dataset.step}`;
        cb.checked = !!checkedSteps[key];
        cb.addEventListener('change', () => {
          cb.dispatchEvent(new CustomEvent('step-change', {
            bubbles: true,
            detail: { eventId: event.id, step: parseInt(cb.dataset.step, 10), checked: cb.checked }
          }));
        });
      });

      // Expand if needed
      if (isExpanded) {
        const card = row.querySelector('.event-card');
        if (card) {
          row.classList.add('expanded');
          card.setAttribute('aria-hidden', 'false');
          row.querySelector('.row-arrow').textContent = '▼';
          row.querySelector('.row-header').setAttribute('aria-expanded', 'true');
        }
      }
    });

    container.classList.remove('results-fading');
    container.classList.add('results-visible');
  });
}

// ─── Sidebar: filter chips ────────────────────────────────────────────────────
export function renderFilters(container, filters, onChange) {
  const severities = ['All', 'Critical', 'Error', 'Warning', 'Info', 'Verbose'];
  const channels   = ['All', 'Security', 'System', 'Application', 'RDS', 'Network'];
  const skills     = ['All', 'Fundamental', 'Intermediate', 'Advanced'];

  function group(label, key, options) {
    return `
      <div class="filter-group">
        <span class="filter-label">${label}</span>
        <div class="filter-chips">
          ${options.map(o => `
            <button class="filter-chip ${filters[key] === o ? 'active' : ''}"
                    data-key="${key}" data-value="${o}">${o}</button>
          `).join('')}
        </div>
      </div>
    `;
  }

  container.innerHTML = `
    <div class="filters-panel">
      ${group('Severity', 'severity', severities)}
      ${group('Source', 'channel', channels)}
      ${group('Skill Level', 'skill_level', skills)}
    </div>
  `;

  container.querySelectorAll('.filter-chip').forEach(btn => {
    btn.addEventListener('click', () => {
      const { key, value } = btn.dataset;
      onChange({ ...filters, [key]: value });
    });
  });
}

// ─── Sidebar: recent searches ─────────────────────────────────────────────────
export function renderRecentSearches(container, searches, { onSelect, onRemove }) {
  if (!searches.length) {
    container.innerHTML = '<p class="recent-empty">No recent searches</p>';
    return;
  }

  container.innerHTML = `
    <ul class="recent-list">
      ${searches.map(s => `
        <li class="recent-item">
          <button class="recent-query" data-query="${s}">⏱ ${s}</button>
          <button class="recent-remove" data-query="${s}" title="Remove">×</button>
        </li>
      `).join('')}
    </ul>
  `;

  container.querySelectorAll('.recent-query').forEach(btn => {
    btn.addEventListener('click', () => onSelect(btn.dataset.query));
  });

  container.querySelectorAll('.recent-remove').forEach(btn => {
    btn.addEventListener('click', () => onRemove(btn.dataset.query));
  });
}

// ─── Sidebar: bundle navigation ───────────────────────────────────────────────
export function renderBundleNav(container, bundles, { activeBundle, onSelect }) {
  container.innerHTML = `
    <ul class="bundle-nav-list">
      ${bundles.map(b => `
        <li class="bundle-nav-item ${activeBundle === b.id ? 'active' : ''}">
          <button class="bundle-nav-btn" data-bundle="${b.id}">
            <span class="bundle-nav-icon">${b.icon}</span>
            <span class="bundle-nav-title">${b.title}</span>
          </button>
        </li>
      `).join('')}
    </ul>
  `;

  container.querySelectorAll('.bundle-nav-btn').forEach(btn => {
    btn.addEventListener('click', () => onSelect(btn.dataset.bundle));
  });
}

// ─── Bundle card ──────────────────────────────────────────────────────────────
export function renderBundleCard(container, bundle, allEvents, { onEventClick }) {
  const relatedEvents = allEvents.filter(e => bundle.event_ids.includes(e.id));

  const eventPills = bundle.event_ids.map(id => {
    const ev = allEvents.find(e => e.id === id);
    return `<button class="bundle-event-pill" data-id="${id}" title="${ev ? ev.title : ''}">${id}</button>`;
  }).join('');

  const escalateItems = bundle.escalate_if.map(e => `<li class="escalate-item">${e}</li>`).join('');

  container.innerHTML = `
    <div class="bundle-card">
      <div class="bundle-card-header">
        <span class="bundle-icon">${bundle.icon}</span>
        <div>
          <h2 class="bundle-title">${bundle.title}</h2>
          <p class="bundle-description">${bundle.description}</p>
        </div>
      </div>

      <div class="bundle-body">
        <div class="bundle-section">
          <h3 class="bundle-section-label">Overview</h3>
          <p class="bundle-brief">${bundle.brief}</p>
        </div>

        <div class="bundle-section">
          <h3 class="bundle-section-label">Start Here</h3>
          <p class="bundle-start-here">${bundle.start_here}</p>
        </div>

        <div class="bundle-section">
          <h3 class="bundle-section-label">Event IDs in This Bundle</h3>
          <div class="bundle-event-pills">${eventPills}</div>
        </div>

        <div class="bundle-section escalate-section">
          <h3 class="bundle-section-label escalate-label">⚠ Escalate If</h3>
          <ul class="escalate-list">${escalateItems}</ul>
        </div>

        <div class="bundle-section">
          <h3 class="bundle-section-label">Composite PowerShell Script</h3>
          <div class="ps-wrapper">
            <div class="ps-titlebar">
              <span class="ps-dot ps-dot-red"></span>
              <span class="ps-dot ps-dot-yellow"></span>
              <span class="ps-dot ps-dot-green"></span>
              <span class="ps-filename">${bundle.id}-investigation.ps1</span>
              <button class="copy-btn bundle-ps-copy">Copy</button>
            </div>
            <pre class="ps-block"><code class="ps-code">${escapeHtml(bundle.composite_powershell)}</code></pre>
          </div>
        </div>
      </div>
    </div>
  `;

  // Wire copy button
  const copyBtn = container.querySelector('.bundle-ps-copy');
  if (copyBtn) {
    attachCopyButton(copyBtn, () => bundle.composite_powershell);
  }

  // Wire event pill clicks
  container.querySelectorAll('.bundle-event-pill').forEach(pill => {
    pill.addEventListener('click', () => onEventClick(parseInt(pill.dataset.id, 10)));
  });
}

// ─── Keyboard navigation ──────────────────────────────────────────────────────
export function setupKeyboardNav(searchInput, getResults, onExpandResult) {
  let focusIndex = -1;

  document.addEventListener('keydown', e => {
    // '/' focuses search
    if (e.key === '/' && document.activeElement !== searchInput) {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
      return;
    }

    // Escape clears search
    if (e.key === 'Escape' && document.activeElement === searchInput) {
      searchInput.value = '';
      searchInput.dispatchEvent(new Event('input'));
      return;
    }

    const rows = Array.from(document.querySelectorAll('.result-row'));
    if (!rows.length) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      focusIndex = Math.min(focusIndex + 1, rows.length - 1);
      rows[focusIndex]?.querySelector('.row-header')?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      focusIndex = Math.max(focusIndex - 1, 0);
      rows[focusIndex]?.querySelector('.row-header')?.focus();
    }
  });

  // Reset focus index when search changes
  searchInput.addEventListener('input', () => { focusIndex = -1; });
}

// ─── Syntax highlighting for PowerShell ──────────────────────────────────────
export function highlightPowerShell(code) {
  return code
    .replace(/(&lt;|&gt;|&amp;)/g, m => m) // already escaped
    .replace(/(#[^\n]*)/g, '<span class="ps-comment">$1</span>')
    .replace(/\b(Get-WinEvent|Get-CimInstance|Get-Service|Get-ADDomain|Get-ADUser|Get-Process|Get-NetAdapter|Get-NetIPAddress|Get-NetTCPConnection|Get-ChildItem|Write-Host|Format-Table|Format-List|Select-Object|Sort-Object|Where-Object|ForEach-Object|Invoke-Command|Start-Service|Stop-Service|Disable-ADAccount|Unlock-ADAccount|Clear-DnsClientCache|Resolve-DnsName|Test-NetConnection|Test-ComputerSecureChannel|Remove-ScheduledTask|Enable-ScheduledTask|Disable-ScheduledTask)\b/g,
      '<span class="ps-cmdlet">$1</span>')
    .replace(/\$\w+/g, '<span class="ps-var">$&</span>')
    .replace(/'([^']*)'/g, '<span class="ps-string">\'$1\'</span>')
    .replace(/"([^"]*)"/g, '<span class="ps-string">"$1"</span>')
    .replace(/\b(if|else|foreach|where|switch|return|try|catch)\b/g, '<span class="ps-keyword">$1</span>');
}

export function applyHighlighting() {
  document.querySelectorAll('.ps-code').forEach(el => {
    if (!el.dataset.highlighted) {
      el.innerHTML = highlightPowerShell(el.innerHTML);
      el.dataset.highlighted = '1';
    }
  });
}

// ─── Footer event count ───────────────────────────────────────────────────────
export function renderSidebarFooter(el, totalEvents) {
  if (el) el.textContent = `${totalEvents} events across 6 sources`;
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
