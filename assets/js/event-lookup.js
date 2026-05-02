import { initTheme, toggleTheme } from './theme.js';

initTheme();

document.querySelectorAll('.theme-btn').forEach(btn => {
  btn.addEventListener('click', toggleTheme);
});
