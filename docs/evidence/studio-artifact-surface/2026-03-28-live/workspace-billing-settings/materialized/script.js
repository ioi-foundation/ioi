const chips = Array.from(document.querySelectorAll('[data-focus]'));
const panels = Array.from(document.querySelectorAll('[data-panel]'));
function activate(index) {
  chips.forEach((chip) => chip.classList.toggle('is-active', chip.dataset.focus === String(index)));
  panels.forEach((panel) => panel.classList.toggle('is-active', panel.dataset.panel === String(index)));
}
chips.forEach((chip) => chip.addEventListener('click', () => activate(chip.dataset.focus)));
activate(0);
