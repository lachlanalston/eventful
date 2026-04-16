/**
 * Search engine for Eventful
 * Uses Fuse.js for fuzzy text search, exact match for numeric IDs
 */

import Fuse from 'fuse.js';

let fuse = null;
let allEvents = [];

export function initSearch(events) {
  allEvents = events;

  fuse = new Fuse(events, {
    keys: [
      { name: 'symptoms', weight: 0.4 },
      { name: 'tags',     weight: 0.3 },
      { name: 'title',    weight: 0.2 },
      { name: 'description', weight: 0.1 }
    ],
    threshold: 0.4,
    includeScore: true,
    minMatchCharLength: 2,
    shouldSort: true,
    ignoreLocation: true
  });
}

export function isNumericQuery(q) {
  return /^\d+$/.test(q.trim());
}

/**
 * Returns { results: Event[], mode: 'id' | 'symptom' | 'empty' }
 */
export function search(query, filters) {
  const q = query.trim();

  let results = allEvents;

  if (q) {
    if (isNumericQuery(q)) {
      // ID mode — exact match
      const id = parseInt(q, 10);
      results = allEvents.filter(e => e.id === id);
    } else {
      // Symptom mode — fuzzy search
      if (!fuse) return { results: [], mode: 'empty' };
      const fuseResults = fuse.search(q);
      results = fuseResults.map(r => r.item);
    }
  }

  // Apply filters
  results = applyFilters(results, filters);

  const mode = q ? (isNumericQuery(q) ? 'id' : 'symptom') : 'browse';
  return { results, mode, query: q };
}

export function applyFilters(events, filters) {
  return events.filter(e => {
    if (filters.severity && filters.severity !== 'All' && e.severity !== filters.severity) return false;
    if (filters.channel && filters.channel !== 'All' && e.channel !== filters.channel) return false;
    if (filters.skill_level && filters.skill_level !== 'All' && e.skill_level !== filters.skill_level) return false;
    return true;
  });
}

export function getEventById(id) {
  return allEvents.find(e => e.id === id) || null;
}

export function getAllEvents() {
  return allEvents;
}
