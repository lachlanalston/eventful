/**
 * Eventful — app.js
 * Main application controller: state management, routing, event wiring
 */

import '../css/main.css';
import '../css/components.css';
import '../css/animations.css';

import { allEvents } from '../../data/events/index.js';
import { bundles }   from '../../data/bundles.js';
import { initSearch, search, getEventById, isNumericQuery } from './search.js';
import {
  renderSkeletons, renderResults, renderEmpty, renderNoResults,
  renderResultCount, renderFilters, renderRecentSearches,
  renderBundleNav, renderBundleCard,
  setupKeyboardNav, applyHighlighting, renderSidebarFooter
} from './ui.js';
import { initBundles, getBundleById, getBundleEvents } from './bundles.js';

// ─── State ────────────────────────────────────────────────────────────────────
const DEFAULT_FILTERS = { severity: 'All', channel: 'All', skill_level: 'All' };

let state = {
  query: '',
  filters: { ...DEFAULT_FILTERS },
  expanded_id: null,
  active_bundle: null,
  recent_searches: [],
  checked_steps: {}
};

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const $searchInput    = document.getElementById('search-input');
const $resultCount    = document.getElementById('result-count');
const $resultsContainer = document.getElementById('results-container');
const $filtersContainer = document.getElementById('filters-container');
const $recentContainer  = document.getElementById('recent-searches');
const $bundleNavContainer = document.getElementById('bundle-nav');
const $bundleViewContainer = document.getElementById('bundle-view');
const $sidebarFooter  = document.getElementById('sidebar-footer');
const $filterDrawerToggle = document.getElementById('filter-drawer-toggle');
const $sidebar        = document.getElementById('sidebar');

// ─── LocalStorage persistence ─────────────────────────────────────────────────
function loadFromStorage() {
  try {
    const saved = localStorage.getItem('eventful_state');
    if (saved) {
      const parsed = JSON.parse(saved);
      state.recent_searches = parsed.recent_searches || [];
      state.checked_steps   = parsed.checked_steps || {};
    }
  } catch { /* ignore */ }
}

function saveToStorage() {
  try {
    localStorage.setItem('eventful_state', JSON.stringify({
      recent_searches: state.recent_searches,
      checked_steps:   state.checked_steps
    }));
  } catch { /* ignore */ }
}

// ─── URL hash routing ─────────────────────────────────────────────────────────
function parseHash() {
  const hash = location.hash.slice(1); // strip #
  if (!hash) return {};
  const params = {};
  hash.split('&').forEach(part => {
    const [k, v] = part.split('=');
    if (k && v !== undefined) params[k] = decodeURIComponent(v);
  });
  return params;
}

function buildHash(s) {
  const parts = [];
  if (s.query)         parts.push(`search=${encodeURIComponent(s.query)}`);
  if (s.expanded_id)   parts.push(`id=${s.expanded_id}`);
  if (s.active_bundle) parts.push(`bundle=${s.active_bundle}`);
  return parts.length ? '#' + parts.join('&') : '#';
}

function applyRouteFromHash() {
  const params = parseHash();

  if (params.bundle) {
    state.active_bundle = params.bundle;
    state.query = '';
    state.expanded_id = null;
  } else if (params.id) {
    state.expanded_id = parseInt(params.id, 10);
    state.active_bundle = null;
    // Also set query so ID search mode shows result
    state.query = String(params.id);
    if ($searchInput) $searchInput.value = state.query;
  } else if (params.search) {
    state.query = params.search;
    state.active_bundle = null;
    if ($searchInput) $searchInput.value = state.query;
  }
}

function pushHash() {
  const newHash = buildHash(state);
  if (location.hash !== newHash) {
    history.replaceState(null, '', newHash || location.pathname);
  }
}

// ─── State mutations ──────────────────────────────────────────────────────────
function setState(patch) {
  Object.assign(state, patch);
  pushHash();
  render();
  saveToStorage();
}

function setQuery(q) {
  const trimmed = q.trim();
  // Add to recent searches (text only, not numeric IDs)
  if (trimmed && !isNumericQuery(trimmed) && trimmed.length > 1) {
    const without = state.recent_searches.filter(s => s !== trimmed);
    state.recent_searches = [trimmed, ...without].slice(0, 5);
  }
  setState({ query: q, expanded_id: null, active_bundle: null });
}

function setExpanded(id) {
  setState({ expanded_id: state.expanded_id === id ? null : id });
}

function setBundle(bundleId) {
  setState({
    active_bundle: state.active_bundle === bundleId ? null : bundleId,
    query: '',
    expanded_id: null
  });
  if ($searchInput) $searchInput.value = '';
}

function setFilters(filters) {
  setState({ filters, expanded_id: null });
}

function removeRecentSearch(query) {
  setState({ recent_searches: state.recent_searches.filter(s => s !== query) });
}

function toggleStep(eventId, stepIndex, checked) {
  const key = `${eventId}-${stepIndex}`;
  const steps = { ...state.checked_steps };
  if (checked) {
    steps[key] = true;
  } else {
    delete steps[key];
  }
  state.checked_steps = steps;
  saveToStorage();
}

function navigateToEvent(id) {
  // If in a bundle view, exit bundle first
  setState({ active_bundle: null, query: String(id), expanded_id: id });
  if ($searchInput) $searchInput.value = String(id);
  // Scroll to expanded event
  requestAnimationFrame(() => {
    const row = document.querySelector(`.result-row[data-id="${id}"]`);
    if (row) row.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

// ─── Render ───────────────────────────────────────────────────────────────────
function render() {
  // Sidebar always renders
  renderFilters($filtersContainer, state.filters, setFilters);
  renderRecentSearches($recentContainer, state.recent_searches, {
    onSelect: q => {
      if ($searchInput) $searchInput.value = q;
      setQuery(q);
    },
    onRemove: removeRecentSearch
  });
  renderBundleNav($bundleNavContainer, bundles, {
    activeBundle: state.active_bundle,
    onSelect: setBundle
  });
  renderSidebarFooter($sidebarFooter, allEvents.length);

  // Main area: bundle view OR search results
  if (state.active_bundle) {
    $resultsContainer.style.display = 'none';
    $bundleViewContainer.style.display = 'block';
    $resultCount.textContent = '';

    const bundle = getBundleById(state.active_bundle);
    if (bundle) {
      renderBundleCard($bundleViewContainer, bundle, allEvents, {
        onEventClick: navigateToEvent
      });
    }
  } else {
    $resultsContainer.style.display = 'block';
    $bundleViewContainer.style.display = 'none';

    const { results, mode, query } = search(state.query, state.filters);

    renderResultCount($resultCount, {
      results,
      total: allEvents.length,
      query,
      mode
    });

    if (!state.query && !results.length) {
      renderEmpty($resultsContainer, {
        onSuggestionClick: q => {
          if ($searchInput) $searchInput.value = q;
          setQuery(q);
        }
      });
    } else if (state.query && !results.length) {
      renderNoResults($resultsContainer, state.query);
    } else {
      renderResults($resultsContainer, results, {
        expandedId: state.expanded_id,
        checkedSteps: state.checked_steps,
        onToggle: (id, willExpand) => {
          setState({ expanded_id: willExpand ? id : null });
          if (willExpand) {
            requestAnimationFrame(() => {
              const row = document.querySelector(`.result-row[data-id="${id}"]`);
              if (row) row.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
          }
        },
        onRelatedClick: navigateToEvent
      });

      // Auto-expand if ID mode
      if (mode === 'id' && results.length === 1 && !state.expanded_id) {
        setState({ expanded_id: results[0].id });
      }
    }

    // Apply PS syntax highlighting after render
    requestAnimationFrame(applyHighlighting);
  }
}

// ─── Search input wiring ──────────────────────────────────────────────────────
let debounceTimer = null;

function onSearchInput(e) {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    setQuery(e.target.value);
  }, 120);
}

// ─── Step checkbox wiring ─────────────────────────────────────────────────────
function onStepChange(e) {
  const { eventId, step, checked } = e.detail;
  toggleStep(eventId, step, checked);
}

// ─── Mobile drawer ────────────────────────────────────────────────────────────
function setupMobileDrawer() {
  if (!$filterDrawerToggle || !$sidebar) return;
  $filterDrawerToggle.addEventListener('click', () => {
    $sidebar.classList.toggle('drawer-open');
    $filterDrawerToggle.setAttribute(
      'aria-expanded',
      $sidebar.classList.contains('drawer-open') ? 'true' : 'false'
    );
  });
  // Close drawer when clicking outside
  document.addEventListener('click', e => {
    if ($sidebar.classList.contains('drawer-open') &&
        !$sidebar.contains(e.target) &&
        e.target !== $filterDrawerToggle) {
      $sidebar.classList.remove('drawer-open');
    }
  });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
function init() {
  loadFromStorage();
  initSearch(allEvents);
  initBundles(bundles, allEvents);

  // Show skeletons while page settles
  if ($resultsContainer) renderSkeletons($resultsContainer, 8);

  // Apply hash route
  applyRouteFromHash();

  // Wire up search
  if ($searchInput) {
    $searchInput.addEventListener('input', onSearchInput);
    $searchInput.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        $searchInput.value = '';
        setQuery('');
      }
    });
    $searchInput.focus();
  }

  // Wire up step checkboxes via event delegation
  document.addEventListener('step-change', onStepChange);

  // Hash navigation
  window.addEventListener('hashchange', () => {
    applyRouteFromHash();
    render();
  });

  // Mobile drawer
  setupMobileDrawer();

  // Keyboard shortcuts
  setupKeyboardNav($searchInput, () => [], navigateToEvent);

  // Initial render
  render();
}

document.addEventListener('DOMContentLoaded', init);
