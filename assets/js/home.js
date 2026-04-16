import { initTheme, toggleTheme } from './theme.js';

initTheme();

const input         = document.querySelector('.search-input');
const form          = document.querySelector('.search-form');
const severityInput = document.getElementById('severity-input');
let selectedSeverity = '';

// Theme toggle
document.querySelectorAll('.theme-btn').forEach(btn => {
  btn.addEventListener('click', toggleTheme);
});

// Severity filter toggle
document.querySelectorAll('.sev-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const sev = btn.dataset.severity;
    if (selectedSeverity === sev) {
      selectedSeverity = '';
      btn.classList.remove('active');
    } else {
      selectedSeverity = sev;
      document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    }
    severityInput.value = selectedSeverity;
  });
});

// Don't submit if search is empty; strip empty severity param
form.addEventListener('submit', e => {
  const q = input.value.trim();
  if (!q) { e.preventDefault(); return; }
  if (!selectedSeverity) severityInput.disabled = true;
});
