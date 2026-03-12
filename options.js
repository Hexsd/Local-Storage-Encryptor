const FEEDBACK_TIMEOUT_MS = 2600;
const VISIBLE_LOGS_LIMIT = 50;
const ALLOWED_LOG_TYPES = new Set(['error', 'warn', 'info', 'system', 'auto_encrypt']);

const dom = {};
let feedbackTimer = null;
let saveButtonTimer = null;

document.addEventListener('DOMContentLoaded', init);

async function init() {
  cacheDom();
  bindEvents();
  bindStorageTriggers();

  await initialLoad();
}

function cacheDom() {
  dom.siteInput = document.getElementById('site-input');
  dom.siteFeedback = document.getElementById('site-feedback');
  dom.addSiteBtn = document.getElementById('add-site-btn');
  dom.sitesList = document.getElementById('sites-list');

  dom.threatsToday = document.getElementById('threats-today');
  dom.threatsMonth = document.getElementById('threats-month');
  dom.sitesMonitored = document.getElementById('sites-monitored');

  dom.securityScore = document.getElementById('security-score');
  dom.securityProgress = document.querySelector('.progress');
  dom.securityBar = document.getElementById('security-bar');
  dom.riskDesc = document.getElementById('risk-desc');

  dom.modeSelect = document.getElementById('mode-select');
  dom.notifications = document.getElementById('notifications');
  dom.logging = document.getElementById('logging');
  dom.settingsForm = document.getElementById('settings-form');
  dom.saveSettingsBtn = document.getElementById('save-settings-btn');
  dom.saveSettingsBtn.dataset.baseLabel = dom.saveSettingsBtn.textContent;

  dom.logsList = document.getElementById('logs-list');
  dom.clearLogsBtn = document.getElementById('clear-logs-btn');

  dom.protectionToggle = document.getElementById('protection-toggle');
  dom.protectionState = document.getElementById('protection-state');
}

function bindEvents() {
  dom.addSiteBtn.addEventListener('click', addSite);
  dom.siteInput.addEventListener('keydown', onSiteInputKeyDown);
  dom.siteInput.addEventListener('input', onSiteInputChanged);

  dom.sitesList.addEventListener('click', onSitesListClick);

  dom.settingsForm.addEventListener('submit', saveSettings);
  dom.clearLogsBtn.addEventListener('click', clearLogs);
  dom.protectionToggle.addEventListener('click', toggleProtection);
}

function bindStorageTriggers() {
  chrome.storage.onChanged.addListener(onStorageChanged);
  window.addEventListener('beforeunload', unbindStorageTriggers, { once: true });
}

function unbindStorageTriggers() {
  if (chrome.storage.onChanged.hasListener(onStorageChanged)) {
    chrome.storage.onChanged.removeListener(onStorageChanged);
  }
}

function onStorageChanged(changes, areaName) {
  void refreshByStorageChange(changes, areaName);
}

async function refreshByStorageChange(changes, areaName) {
  try {
    if (areaName === 'sync' && changes.monitoredSites) {
      await Promise.all([loadSites(), loadStats()]);
      return;
    }

    if (areaName === 'sync' && changes.settings) {
      await Promise.all([loadSettings(), loadLogs()]);
      return;
    }

    if (areaName === 'local' && changes.logs) {
      await loadLogs();
    }

    if (areaName === 'local' && changes.stats) {
      await loadStats();
    }
  } catch (error) {
    console.error('Ошибка обновления по storage-триггеру:', error);
  }
}

async function initialLoad() {
  try {
    await Promise.all([loadSites(), loadStats(), loadSettings(), loadLogs()]);
  } catch (error) {
    console.error('Ошибка начальной загрузки данных options:', error);
    showSiteFeedback('Не удалось загрузить данные страницы.', 'error');
  }
}

function onSiteInputKeyDown(event) {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  addSite();
}

function onSiteInputChanged() {
  dom.siteInput.classList.remove('is-invalid');
  if (dom.siteFeedback.classList.contains('is-error')) {
    clearSiteFeedback();
  }
}

function onSitesListClick(event) {
  const removeBtn = event.target.closest('.remove-site-btn');
  if (!removeBtn) return;

  const siteRow = removeBtn.closest('.site-row');
  if (!siteRow?.dataset.site) return;

  removeSite(siteRow.dataset.site);
}

async function loadSites() {
  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  const safeSites = monitoredSites.filter((site) => site && typeof site.url === 'string' && site.url.trim());
  dom.sitesList.replaceChildren();

  if (safeSites.length === 0) {
    appendEmptyState(dom.sitesList, 'Нет отслеживаемых сайтов');
    return;
  }

  safeSites.forEach((site) => {
    dom.sitesList.appendChild(createSiteRow(site));
  });
}

function createSiteRow(site) {
  const riskBadge = getRiskBadge(site.risk || 'low');
  const score = getNumericScore(site.score);
  const aiDanger = normalizeAiDanger(site.aiDanger);

  const row = document.createElement('div');
  row.className = 'site-row';
  row.dataset.site = site.url;

  const info = document.createElement('div');
  info.className = 'site-info';

  const siteUrl = document.createElement('span');
  siteUrl.className = 'site-url';
  siteUrl.textContent = site.url;

  const meta = document.createElement('div');
  meta.className = 'site-meta';

  const heuristicMeta = document.createElement('span');
  heuristicMeta.className = 'site-meta-item';
  heuristicMeta.textContent = Number.isFinite(score)
    ? `Эвристика: ${riskBadge.text} (${score}/100)`
    : `Эвристика: ${riskBadge.text} (нет данных)`;
  meta.appendChild(heuristicMeta);

  if (aiDanger) {
    const aiMeta = document.createElement('span');
    aiMeta.className = 'site-meta-item site-meta-ai';
    aiMeta.textContent = `ИИ: ${aiDanger}`;
    meta.appendChild(aiMeta);
  }

  const actions = document.createElement('span');
  actions.className = 'site-actions';

  const badge = document.createElement('span');
  badge.className = `badge ${riskBadge.className}`;
  badge.textContent = `Риск: ${riskBadge.text}`;

  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'danger remove-site-btn';
  removeBtn.textContent = 'Удалить';

  info.append(siteUrl, meta);
  actions.append(badge, removeBtn);
  row.append(info, actions);

  return row;
}

async function loadStats() {
  const [{ stats = {} }, { monitoredSites = [] }] = await Promise.all([
    chrome.storage.local.get('stats'),
    chrome.storage.sync.get('monitoredSites')
  ]);
  const safeSites = monitoredSites.filter((site) => site && typeof site.url === 'string' && site.url.trim());

  dom.threatsToday.textContent = String(toPositiveInteger(stats.threatsToday));
  dom.threatsMonth.textContent = String(toPositiveInteger(stats.threatsMonth));

  const sitesCount = safeSites.length;
  dom.sitesMonitored.textContent = String(sitesCount);

  const indexSource = sitesCount === 0 ? 100 : stats.securityIndex ?? 100;
  const index = clamp(toPositiveInteger(indexSource), 0, 100);
  dom.securityScore.textContent = `${index} / 100`;
  dom.securityBar.style.width = `${index}%`;
  dom.securityProgress.setAttribute('aria-valuenow', String(index));

  const risk = getRiskByIndex(index);
  dom.riskDesc.dataset.risk = risk.key;
  dom.riskDesc.textContent = `Уровень риска: ${risk.text}.`;
}

async function loadSettings() {
  const { settings = {} } = await chrome.storage.sync.get('settings');

  dom.modeSelect.value = settings.mode === 'local' ? 'local' : 'hybrid';
  dom.notifications.checked = settings.notifications !== false;
  dom.logging.checked = settings.logging !== false;

  const protectionEnabled = settings.protectionEnabled !== false;
  updateProtectionUi(protectionEnabled);
}

function updateProtectionUi(enabled) {
  dom.protectionToggle.textContent = enabled ? 'Отключить защиту' : 'Включить защиту';
  dom.protectionToggle.classList.toggle('protection-on', enabled);
  dom.protectionToggle.classList.toggle('protection-off', !enabled);

  dom.protectionState.textContent = enabled ? 'Защита активна' : 'Защита отключена';
  dom.protectionState.classList.toggle('is-on', enabled);
  dom.protectionState.classList.toggle('is-off', !enabled);
}

async function toggleProtection() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  const currentlyEnabled = settings.protectionEnabled !== false;
  const nextState = !currentlyEnabled;

  settings.protectionEnabled = nextState;
  await chrome.storage.sync.set({ settings });

  updateProtectionUi(nextState);

  chrome.runtime.sendMessage({
    action: 'log_event',
    message: nextState ? 'Защита включена' : 'Защита отключена',
    type: 'system'
  });
}

async function loadLogs() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  const loggingEnabled = settings.logging !== false;

  if (!loggingEnabled) {
    dom.logsList.replaceChildren();
    dom.clearLogsBtn.disabled = true;
    appendEmptyState(dom.logsList, 'Логирование отключено в настройках.');
    return;
  }

  const { logs = [] } = await chrome.storage.local.get('logs');
  dom.logsList.replaceChildren();

  const recentLogs = logs.slice(-VISIBLE_LOGS_LIMIT).reverse();
  dom.clearLogsBtn.disabled = recentLogs.length === 0;

  if (recentLogs.length === 0) {
    appendEmptyState(dom.logsList, 'Логи пока пусты');
    return;
  }

  recentLogs.forEach((log) => {
    dom.logsList.appendChild(createLogEntry(log));
  });
}

function createLogEntry(log) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';

  const messageLine = document.createElement('div');
  messageLine.className = 'log-message';

  const type = normalizeLogType(log.type);
  const typeBadge = document.createElement('span');
  typeBadge.className = `log-type ${type}`;
  typeBadge.textContent = type.toUpperCase().replace('_', ' ');

  const messageText = document.createTextNode(String(log.message ?? 'Без сообщения'));
  messageLine.append(typeBadge, messageText);

  const details = document.createElement('div');
  details.className = 'log-details';

  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = formatTimestamp(log.timestamp);

  const url = document.createElement('span');
  url.className = 'log-url';
  url.textContent = log.url || 'background';

  details.append(time, url);
  entry.append(messageLine, details);

  return entry;
}

async function addSite() {
  const rawUrl = dom.siteInput.value.trim();
  const normalizedUrl = normalizeHttpUrl(rawUrl);

  if (!normalizedUrl) {
    dom.siteInput.classList.add('is-invalid');
    showSiteFeedback('Введите корректный URL вида https://example.com', 'error');
    return;
  }

  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  const safeSites = monitoredSites.filter((site) => site && typeof site.url === 'string' && site.url.trim());
  const exists = safeSites.some((site) => site.url === normalizedUrl);

  if (exists) {
    showSiteFeedback('Этот сайт уже есть в списке.', 'error');
    return;
  }

  safeSites.push({ url: normalizedUrl, risk: 'low', added: Date.now() });
  await chrome.storage.sync.set({ monitoredSites: safeSites });
  await syncStatsBySites(safeSites);

  dom.siteInput.value = '';
  dom.siteInput.classList.remove('is-invalid');
  showSiteFeedback('Сайт добавлен в мониторинг.', 'success');

  await Promise.all([loadSites(), loadStats()]);
}

async function removeSite(url) {
  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  const safeSites = monitoredSites.filter((site) => site && typeof site.url === 'string' && site.url.trim());
  const filtered = safeSites.filter((site) => site.url !== url);

  if (filtered.length === safeSites.length) return;

  await chrome.storage.sync.set({ monitoredSites: filtered });
  await syncStatsBySites(filtered);
  showSiteFeedback('Сайт удалён из списка.', 'success');

  await Promise.all([loadSites(), loadStats()]);
}

async function saveSettings(event) {
  event.preventDefault();

  const { settings = {} } = await chrome.storage.sync.get('settings');

  const newSettings = {
    ...settings,
    mode: dom.modeSelect.value,
    notifications: dom.notifications.checked,
    logging: dom.logging.checked,
    autoEncrypt: true
  };

  await chrome.storage.sync.set({ settings: newSettings });
  flashSaveButton();
}

function flashSaveButton() {
  const baseLabel = dom.saveSettingsBtn.dataset.baseLabel || 'Сохранить настройки';

  if (saveButtonTimer) {
    window.clearTimeout(saveButtonTimer);
    saveButtonTimer = null;
  }

  dom.saveSettingsBtn.textContent = 'Сохранено';
  dom.saveSettingsBtn.classList.add('is-saved');

  saveButtonTimer = window.setTimeout(() => {
    dom.saveSettingsBtn.textContent = baseLabel;
    dom.saveSettingsBtn.classList.remove('is-saved');
    saveButtonTimer = null;
  }, 1400);
}

async function clearLogs() {
  const shouldClear = window.confirm('Очистить все логи?');
  if (!shouldClear) return;

  await chrome.storage.local.set({ logs: [] });
  await loadLogs();
}

function getRiskBadge(risk) {
  const normalizedRisk = typeof risk === 'string' ? risk.toLowerCase() : 'low';

  switch (normalizedRisk) {
    case 'critical':
      return { className: 'badge-risk', text: 'Критический' };
    case 'high':
      return { className: 'badge-risk', text: 'Высокий' };
    case 'medium':
      return { className: 'badge-warn', text: 'Средний' };
    default:
      return { className: 'badge-ok', text: 'Низкий' };
  }
}

function getNumericScore(score) {
  const value = Number(score);
  if (!Number.isFinite(value)) return null;
  return clamp(Math.round(value), 0, 100);
}

function normalizeAiDanger(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';

  if (raw === 'high' || raw === 'высокий') return 'высокий';
  if (raw === 'medium' || raw === 'средний') return 'средний';
  if (raw === 'low' || raw === 'низкий') return 'низкий';
  if (raw === 'critical' || raw === 'критический') return 'критический';

  return raw;
}

function getRiskByIndex(index) {
  if (index < 40) {
    return { key: 'critical', text: 'критический' };
  }

  if (index < 70) {
    return { key: 'high', text: 'высокий' };
  }

  if (index < 90) {
    return { key: 'medium', text: 'средний' };
  }

  return { key: 'low', text: 'низкий' };
}

function normalizeLogType(type) {
  const normalized = String(type || 'info').toLowerCase().replace('-', '_');
  return ALLOWED_LOG_TYPES.has(normalized) ? normalized : 'info';
}

function formatTimestamp(timestamp) {
  const value = Number(timestamp);
  if (!Number.isFinite(value)) return '-';

  return new Date(value).toLocaleString('ru-RU');
}

function normalizeHttpUrl(value) {
  if (!value) return null;

  try {
    const parsed = new URL(value);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    const trimmedPath = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/$/, '');
    return `${parsed.origin}${trimmedPath}${parsed.search}`;
  } catch {
    return null;
  }
}

function appendEmptyState(container, text) {
  const empty = document.createElement('p');
  empty.className = 'empty-state';
  empty.textContent = text;
  container.appendChild(empty);
}

async function syncStatsBySites(sites) {
  const safeSites = Array.isArray(sites)
    ? sites.filter((site) => site && typeof site.url === 'string' && site.url.trim())
    : [];
  const sitesCount = safeSites.length;
  const { stats = {} } = await chrome.storage.local.get('stats');
  const nextStats = { ...stats, sitesCount };

  if (sitesCount === 0) {
    nextStats.securityIndex = 100;
  } else {
    const avgScore =
      safeSites.reduce((sum, site) => sum + getSiteScore(site), 0) / sitesCount;
    nextStats.securityIndex = Math.max(0, Math.round(100 - Math.min(avgScore, 100)));
  }

  await chrome.storage.local.set({ stats: nextStats });
}

function getSiteScore(site) {
  if (!site || typeof site !== 'object') return 0;

  const numericScore = Number(site.score);
  if (Number.isFinite(numericScore)) {
    return clamp(Math.round(numericScore), 0, 100);
  }

  switch (String(site.risk || '').toLowerCase()) {
    case 'critical':
      return 90;
    case 'high':
      return 70;
    case 'medium':
      return 40;
    default:
      return 0;
  }
}

function showSiteFeedback(text, type = 'info') {
  if (feedbackTimer) {
    window.clearTimeout(feedbackTimer);
    feedbackTimer = null;
  }

  dom.siteFeedback.textContent = text;
  dom.siteFeedback.className = `feedback is-visible ${feedbackClassByType(type)}`;

  feedbackTimer = window.setTimeout(() => {
    clearSiteFeedback();
  }, FEEDBACK_TIMEOUT_MS);
}

function clearSiteFeedback() {
  dom.siteFeedback.textContent = '';
  dom.siteFeedback.className = 'feedback';
}

function feedbackClassByType(type) {
  if (type === 'error') return 'is-error';
  if (type === 'success') return 'is-success';
  return '';
}

function toPositiveInteger(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  if (numeric < 0) return 0;
  return Math.round(numeric);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}
