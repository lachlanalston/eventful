/**
 * Bundle view logic for Eventful
 * Handles rendering investigation bundles and their associated events
 */

import { renderBundleCard, renderBundleNav, renderResults } from './ui.js';

let _bundles = [];
let _allEvents = [];

export function initBundles(bundles, allEvents) {
  _bundles = bundles;
  _allEvents = allEvents;
}

export function getBundles() {
  return _bundles;
}

export function getBundleById(id) {
  return _bundles.find(b => b.id === id) || null;
}

export function getBundleEvents(bundleId) {
  const bundle = getBundleById(bundleId);
  if (!bundle) return [];
  return _allEvents.filter(e => bundle.event_ids.includes(e.id));
}

export function renderBundleView(container, bundleId, state, callbacks) {
  const bundle = getBundleById(bundleId);
  if (!bundle) {
    container.innerHTML = '<p class="error-msg">Bundle not found.</p>';
    return;
  }

  renderBundleCard(container, bundle, _allEvents, {
    onEventClick: callbacks.onEventClick
  });
}

export function updateBundleNavActive(navContainer, activeBundleId) {
  navContainer.querySelectorAll('.bundle-nav-btn').forEach(btn => {
    btn.closest('.bundle-nav-item')?.classList.toggle('active', btn.dataset.bundle === activeBundleId);
  });
}
