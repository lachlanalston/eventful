/* ── Eventful — parser.js ────────────────────────────────────────────────────
   Parses Windows Event Viewer XML exports into structured event objects.
   Supports both single-log exports and filtered custom-view exports.
──────────────────────────────────────────────────────────────────────────── */

/**
 * @typedef {Object} ParsedEvent
 * @property {number} id
 * @property {string} provider
 * @property {string} channel
 * @property {number} levelNum
 * @property {string} severity  - 'Critical'|'Error'|'Warning'|'Info'|'Verbose'
 * @property {Date}   timestamp
 * @property {string} computer
 * @property {string} message
 * @property {number} recordId
 * @property {Object} data      - key/value pairs from EventData
 */

const NS = 'http://schemas.microsoft.com/win/2004/08/events/event';

/**
 * Parse a Windows Event Viewer XML string.
 * Returns events sorted oldest → newest.
 * @param {string} xmlString
 * @returns {ParsedEvent[]}
 */
export function parseEventXML(xmlString) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlString, 'text/xml');

  const parseError = doc.querySelector('parsererror');
  if (parseError) {
    throw new Error(`Invalid XML: ${parseError.textContent.substring(0, 120)}`);
  }

  // Events can be directly under <Events> or under any root element
  const nodes = doc.querySelectorAll('Event');
  if (nodes.length === 0) {
    throw new Error('No <Event> elements found. Make sure you exported in XML format from Event Viewer.');
  }

  const events = [];
  for (const node of nodes) {
    try {
      const ev = parseEventNode(node);
      if (!isNaN(ev.id) && ev.id > 0 && ev.timestamp instanceof Date && !isNaN(ev.timestamp)) {
        events.push(ev);
      }
    } catch (_) {
      // Skip malformed individual events
    }
  }

  if (events.length === 0) {
    throw new Error('No valid events could be parsed. Check that the XML is a Windows Event Viewer export.');
  }

  return events.sort((a, b) => a.timestamp - b.timestamp);
}

/** @param {Element} node */
function parseEventNode(node) {
  // Try namespace-aware query first, fall back to plain querySelector
  const sys = node.querySelector('System');

  const id = parseInt(getText(sys, 'EventID'), 10);
  const levelNum = parseInt(getText(sys, 'Level'), 10);

  const providerEl = sys?.querySelector('Provider');
  const provider = providerEl?.getAttribute('Name') || providerEl?.getAttribute('EventSourceName') || '';

  const channel = getText(sys, 'Channel');
  const computer = getText(sys, 'Computer');
  const recordId = parseInt(getText(sys, 'EventRecordID'), 10);

  const timeCreated = sys?.querySelector('TimeCreated');
  const timeStr = timeCreated?.getAttribute('SystemTime') || timeCreated?.textContent || '';
  const timestamp = new Date(timeStr);

  // Get severity — prefer RenderingInfo Level text (pre-rendered, more reliable)
  const renderingInfo = node.querySelector('RenderingInfo');
  const renderedLevel = renderingInfo?.querySelector('Level')?.textContent?.trim();
  const severity = levelToSeverity(levelNum, renderedLevel);

  // Build message
  const message = extractMessage(node, renderingInfo);

  // Extract key/value data pairs
  const data = extractEventData(node);

  return {
    id,
    provider,
    channel,
    levelNum,
    severity,
    timestamp,
    computer,
    message,
    recordId: isNaN(recordId) ? 0 : recordId,
    data,
  };
}

/** Get text content of a direct child element */
function getText(parent, tag) {
  return parent?.querySelector(tag)?.textContent?.trim() || '';
}

/** Extract human-readable message, preferring RenderingInfo */
function extractMessage(node, renderingInfo) {
  // Best case: Windows pre-rendered the message for us
  const rendered = renderingInfo?.querySelector('Message')?.textContent?.trim();
  if (rendered) return rendered.substring(0, 800);

  // Fall back: build from EventData key-value pairs
  const eventData = node.querySelector('EventData');
  if (eventData) {
    const parts = [];
    for (const data of eventData.querySelectorAll('Data')) {
      const name = data.getAttribute('Name');
      const val = data.textContent.trim();
      if (val && val !== '-') {
        parts.push(name ? `${name}: ${val}` : val);
      }
    }
    if (parts.length) return parts.join(' | ').substring(0, 800);
  }

  // Last resort: UserData
  const userData = node.querySelector('UserData');
  if (userData) return userData.textContent.trim().substring(0, 800);

  return '';
}

/** Extract EventData fields as an object */
function extractEventData(node) {
  const data = {};
  const eventData = node.querySelector('EventData');
  if (!eventData) return data;
  for (const el of eventData.querySelectorAll('Data')) {
    const name = el.getAttribute('Name');
    const val = el.textContent.trim();
    if (name && val) data[name] = val;
  }
  return data;
}

/** Map numeric Level + optional text to severity string */
function levelToSeverity(level, text) {
  if (text) {
    const t = text.toLowerCase();
    if (t.includes('critical'))    return 'Critical';
    if (t.includes('error'))       return 'Error';
    if (t.includes('warning'))     return 'Warning';
    if (t.includes('information')) return 'Info';
    if (t.includes('verbose'))     return 'Verbose';
    if (t.includes('audit'))       return text.includes('Failure') ? 'Error' : 'Info';
  }
  switch (level) {
    case 1: return 'Critical';
    case 2: return 'Error';
    case 3: return 'Warning';
    case 4: return 'Info';
    case 5: return 'Verbose';
    case 0: return 'Info'; // LogAlways
    default: return 'Info';
  }
}

/** Group consecutive identical events into clusters */
export function clusterEvents(events) {
  const clusters = [];
  let i = 0;
  while (i < events.length) {
    const current = events[i];
    let count = 1;
    while (
      i + count < events.length &&
      events[i + count].id === current.id &&
      events[i + count].provider === current.provider &&
      events[i + count].timestamp - current.timestamp < 60_000 * 5 // within 5 min
    ) {
      count++;
    }
    clusters.push({ event: current, count, isCluster: count > 1 });
    i += count;
  }
  return clusters;
}
