# Eventful

Windows Event ID lookup and learning tool for MSP technicians.

Eventful is a fast, searchable reference for Windows Event IDs — built for the technician who needs to know what Event 4740 means at 11pm during an incident, not tomorrow morning after reading a Microsoft doc. It includes plain-English descriptions, common causes, step-by-step investigation checklists, ready-to-run PowerShell snippets, and pre-built investigation bundles for common incident types.

**Live site:** 

---

## Features

- **Instant search** — type a symptom or Event ID and results appear in real time
- **Fuzzy matching** — finds results even with typos or imprecise descriptions
- **60+ events** across Security, System, Application, RDS, and Network logs
- **10 investigation bundles** — pre-built checklists for common incidents (account lockout, BSOD, RDP drops, etc.)
- **PowerShell snippets** — every event has a copy-ready PS script
- **Deep links** — share a specific event or bundle via URL hash
- **Zero dependencies at runtime** — pure HTML/CSS/JS, no framework, no build step

---

## Deploy to GitHub Pages

1. Fork or clone this repository
2. In your GitHub repository settings, go to **Pages**
3. Set source to **Deploy from branch**, select `main`, folder `/` (root)
4. Save — GitHub Pages will serve the site from `index.html`

No build step. No CI/CD pipeline needed. It just works.

> **Note:** All routing is hash-based (`#id=4625`, `#bundle=rdp-disconnecting`) so there are no 404 errors from GitHub Pages' lack of server-side routing.

---

## How to Add a New Event

### 1. Choose the right data file

| Channel | File |
|---|---|
| Security | `data/events/security.js` |
| System | `data/events/system.js` |
| Application | `data/events/application.js` |
| RDS | `data/events/rds.js` |
| Network (DNS/DHCP/WiFi) | `data/events/network.js` |

### 2. Add the event object to the array

Copy this schema and fill in every field — no placeholders, no empty arrays:

```js
{
  id: 4625,                          // Event ID number
  source: 'Microsoft-Windows-Security-Auditing',
  channel: 'Security',               // Security | System | Application | RDS | Network
  severity: 'Warning',               // Critical | Error | Warning | Info | Verbose
  skill_level: 'Fundamental',        // Fundamental | Intermediate | Advanced
  title: 'Failed Logon',
  short_desc: 'One-line summary shown in collapsed result row.',
  description: 'Plain English paragraph explaining what this event means and what causes it.',
  why_it_happens: 'The underlying Windows mechanism — what subsystem generates this and why.',
  what_good_looks_like: 'What is normal vs what warrants investigation.',
  common_mistakes: [
    'Specific mistake junior techs make when investigating this event',
    'Another common mistake',
  ],
  causes: [
    'First cause',
    'Second cause',
  ],
  steps: [
    'First step in the investigation',
    'Second step',
  ],
  symptoms: [
    'how a junior would describe this problem',
    'user cant log in',
    'account locked out',
  ],
  tags: ['authentication', 'lockout', 'security'],
  powershell: `# Event Title Investigation
# Eventful

$computer  = $env:COMPUTERNAME  # Replace with remote hostname if needed
$startTime = (Get-Date).AddHours(-24)

Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`,
  related_ids: [4624, 4740],         // Other event IDs to link to
  ms_docs: 'https://learn.microsoft.com/...'  // or null
}
```

### 3. No other changes needed

The event index (`data/events/index.js`) re-exports all arrays into `allEvents` automatically. The search engine and UI pick up the new event on the next page load.

---

## How to Add a New Investigation Bundle

Edit `data/bundles.js` and add a new object to the `bundles` array:

```js
{
  id: 'printer-issues',              // URL slug — used in #bundle=<id>
  title: 'Printer Not Working',
  icon: '🖨️',
  description: 'One-line description shown in the sidebar nav.',
  brief: 'Paragraph explaining what you are looking for and why. Written for a junior tech who needs context, not just steps.',
  start_here: 'Paragraph — where to begin. What is the first event to look at and why.',
  escalate_if: [
    'Specific condition that means escalate — be precise',
    'Another escalation trigger with concrete indicator',
  ],
  event_ids: [7000, 7031, 7036],     // Event IDs in this bundle
  composite_powershell: `# Bundle Title Investigation
# Eventful

$computer  = $env:COMPUTERNAME
$startTime = (Get-Date).AddHours(-24)

# Query all relevant events in one script
Get-WinEvent -ComputerName $computer -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    Id           = @(7000, 7031, 7036)
    StartTime    = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List`
}
```

The bundle will automatically appear in the sidebar navigation and be accessible via `#bundle=printer-issues`.

---

## How to Update an Existing Event

1. Open the relevant file in `data/events/`
2. Find the event object by its `id` field
3. Edit the fields you want to change
4. Save — no rebuild needed

The site reads data directly from the JS module files on every load.

---

## Project Structure

```
eventful/
├── index.html              # Single HTML entry point
├── assets/
│   ├── css/
│   │   ├── main.css        # Variables, layout, typography
│   │   ├── components.css  # UI components (cards, badges, filters)
│   │   └── animations.css  # Transitions and keyframes
│   └── js/
│       ├── app.js          # State management, routing, boot
│       ├── search.js       # Fuse.js search engine
│       ├── ui.js           # DOM rendering functions
│       ├── bundles.js      # Bundle view logic
│       └── clipboard.js    # Copy to clipboard utilities
├── data/
│   ├── events/
│   │   ├── security.js     # Security log events (4xxx)
│   │   ├── system.js       # System log events (41, 55, 6xxx, 7xxx)
│   │   ├── application.js  # Application log events (1000, 1002, 1026)
│   │   ├── rds.js          # RDS/Terminal Services events
│   │   ├── network.js      # DNS, DHCP, WiFi, TCP events
│   │   └── index.js        # Re-exports allEvents array
│   └── bundles.js          # Investigation bundle definitions
└── README.md
```

---

## Technology

- **HTML5 + CSS3 + Vanilla JS (ES modules)** — no framework, no build step
- **Fuse.js** — fuzzy search loaded from CDN
- **JetBrains Mono + Syne** — fonts from Google Fonts
- **Hash-based routing** — works on GitHub Pages without server config
- **localStorage** — persists recent searches and step checkboxes
