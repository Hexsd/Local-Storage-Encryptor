document.addEventListener('DOMContentLoaded', async () => {
  await loadSites();
  await loadStats();
  await loadSettings();
  await loadLogs();
  setupEventListeners();
  setInterval(async () => {
    await loadSites();
    await loadStats();
    await loadLogs();
  }, 5000);
});

async function loadSites() {
  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  const sitesList = document.getElementById('sites-list');
  sitesList.innerHTML = '';

  if (monitoredSites.length === 0) {
    sitesList.innerHTML = '<p style="text-align:center; opacity:0.6; padding:16px;">Нет отслеживаемых сайтов</p>';
    return;
  }

  monitoredSites.forEach(site => {
    const riskBadge = getRiskBadge(site.risk || 'low');
    const row = document.createElement('div');
    row.className = 'site-row';
    row.dataset.site = site.url;
    row.innerHTML = `
      <span>${site.url}</span>
      <span class="site-actions">
        <span class="badge ${riskBadge.class}">${riskBadge.text}</span>
        <button class="danger remove-site-btn">Удалить</button>
      </span>`;
    sitesList.appendChild(row);
  });
}

async function loadStats() {
  const { stats = {} } = await chrome.storage.local.get('stats');
  document.getElementById('threats-today').textContent = stats.threatsToday || 0;
  document.getElementById('threats-month').textContent = stats.threatsMonth || 0;
  document.getElementById('sites-monitored').textContent = stats.sitesCount || 0;
  
  const index = stats.securityIndex || 100;
  document.getElementById('security-score').textContent = `${index} / 100`;
  document.getElementById('security-bar').style.width = `${index}%`;

  let riskText = 'низкий', riskColor = '#8ef0a9';
  if (index < 40) { riskText = 'критический'; riskColor = '#f08e8e'; }
  else if (index < 70) { riskText = 'высокий'; riskColor = '#f0d88e'; }
  else if (index < 90) { riskText = 'средний'; riskColor = '#f0c88e'; }
  
  const riskDesc = document.getElementById('risk-desc');
  riskDesc.textContent = `Уровень риска: ${riskText}.`;
  riskDesc.style.color = riskColor;
}

async function loadSettings() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  document.getElementById('mode-select').value = settings.mode || 'hybrid';
  document.getElementById('notifications').checked = settings.notifications !== false;
  document.getElementById('logging').checked = settings.logging !== false;
}

async function loadLogs() {
  const { logs = [] } = await chrome.storage.local.get('logs');
  const logsList = document.getElementById('logs-list');
  
  if (logs.length === 0) {
    logsList.innerHTML = '<p style="text-align:center; opacity:0.6; font-size:13px;">Логи пока пусты</p>';
    return;
  }

  logsList.innerHTML = '';
  logs.slice().reverse().slice(0, 50).forEach(log => {
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    const typeClass = log.type === 'error' ? 'error' : log.type === 'warn' ? 'warn' : 'info';
    entry.innerHTML = `
      <div class="log-message">
        <span class="log-type ${typeClass}">${log.type.toUpperCase()}</span>
        ${log.message}
      </div>
      <div class="log-details">
        <span class="log-time">${new Date(log.timestamp).toLocaleString('ru-RU')}</span>
        <span class="log-url">${log.url || 'background'}</span>
      </div>
    `;
    logsList.appendChild(entry);
  });
}

function setupEventListeners() {
  document.getElementById('add-site-btn').onclick = addSite;
  document.getElementById('sites-list').onclick = async (e) => {
    if (e.target.classList.contains('remove-site-btn')) {
      removeSite(e.target.closest('.site-row').dataset.site);
    }
  };
  document.getElementById('save-settings-btn').onclick = saveSettings;
  document.getElementById('clear-logs-btn').onclick = clearLogs;
}

async function addSite() {
  const input = document.getElementById('site-input');
  const url = input.value.trim();
  if (!url || !url.startsWith('http')) {
    alert('Введите полный URL (https://...)');
    return;
  }
  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  if (!monitoredSites.some(site => site.url === url)) {
    monitoredSites.push({ url, risk: 'low', added: Date.now() });
    await chrome.storage.sync.set({ monitoredSites });
  }
  input.value = '';
  await loadSites();
}

async function removeSite(url) {
  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  const filtered = monitoredSites.filter(site => site.url !== url);
  await chrome.storage.sync.set({ monitoredSites: filtered });
  await loadSites();
}

async function saveSettings() {
  const settings = {
    mode: document.getElementById('mode-select').value,
    notifications: document.getElementById('notifications').checked,
    logging: document.getElementById('logging').checked,
    autoEncrypt: true
  };
  await chrome.storage.sync.set({ settings });
  const btn = document.getElementById('save-settings-btn');
  const original = btn.textContent;
  btn.textContent = 'Сохранено ✓';
  btn.style.background = '#2ea043';
  setTimeout(() => {
    btn.textContent = original;
    btn.style.background = '#6c5ce7';
  }, 1500);
}

async function clearLogs() {
  if (confirm('Очистить журнал?')) {
    await chrome.storage.local.set({ logs: [] });
    await loadLogs();
  }
}

function getRiskBadge(risk) {
  const badges = {
    low: { class: 'badge-ok', text: 'низкий' },
    medium: { class: 'badge-warn', text: 'средний' },
    high: { class: 'badge-risk', text: 'высокий' }
  };
  return badges[risk] || badges.low;
}
