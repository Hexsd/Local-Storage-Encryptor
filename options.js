const FEEDBACK_TIMEOUT_MS = 2600;
const VISIBLE_LOGS_LIMIT = 50;
const DEFAULT_LM_ENDPOINT = 'http://127.0.0.1:1234/v1/chat/completions';
const DEFAULT_LM_MODEL = 'qwen3-4b-2507';
const LOG_LEVELS = new Set(['info', 'success', 'warn', 'error']);
const LOG_CATEGORIES = new Set(['analysis', 'encryption', 'ai', 'settings', 'data', 'system']);
const LOG_CATEGORY_FILTERS = [
  { key: 'all', label: 'Все' },
  { key: 'encryption', label: 'Шифрование' },
  { key: 'analysis', label: 'Анализ' },
  { key: 'ai', label: 'AI' },
  { key: 'settings', label: 'Настройки' },
  { key: 'data', label: 'Данные' },
  { key: 'system', label: 'Система' }
];
const LOG_CATEGORY_META = {
  encryption: { label: 'Шифрование', tone: 'encryption' },
  analysis: { label: 'Анализ', tone: 'analysis' },
  ai: { label: 'AI', tone: 'ai' },
  settings: { label: 'Настройки', tone: 'settings' },
  data: { label: 'Данные', tone: 'data' },
  system: { label: 'Система', tone: 'system' }
};
const LOG_LEVEL_META = {
  info: { label: 'Информация', tone: 'info' },
  success: { label: 'Успех', tone: 'success' },
  warn: { label: 'Предупреждение', tone: 'warn' },
  error: { label: 'Ошибка', tone: 'error' }
};

const dom = {};
let feedbackTimer = null;
let saveButtonTimer = null;
const activeLogFilters = {
  category: 'all',
  level: 'all'
};

document.addEventListener('DOMContentLoaded', init);

async function init() {
  cacheDom();
  renderLogCategoryFilters();
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
  dom.statsChart = document.getElementById('stats-chart');
  dom.chartValueToday = document.getElementById('chart-value-today');
  dom.chartValueMonth = document.getElementById('chart-value-month');
  dom.chartValueSites = document.getElementById('chart-value-sites');
  dom.chartBarToday = document.getElementById('chart-bar-today');
  dom.chartBarMonth = document.getElementById('chart-bar-month');
  dom.chartBarSites = document.getElementById('chart-bar-sites');

  dom.securityScore = document.getElementById('security-score');
  dom.securityProgress = document.querySelector('.progress');
  dom.securityBar = document.getElementById('security-bar');
  dom.riskDesc = document.getElementById('risk-desc');

  dom.modeSelect = document.getElementById('mode-select');
  dom.fullAnalysisPolicy = document.getElementById('full-analysis-policy');
  dom.lmEndpoint = document.getElementById('lm-endpoint');
  dom.lmModel = document.getElementById('lm-model');
  dom.notifications = document.getElementById('notifications');
  dom.logging = document.getElementById('logging');
  dom.settingsForm = document.getElementById('settings-form');
  dom.saveSettingsBtn = document.getElementById('save-settings-btn');
  dom.testLmBtn = document.getElementById('test-lm-btn');
  dom.lmTestStatus = document.getElementById('lm-test-status');

  dom.logsList = document.getElementById('logs-list');
  dom.clearLogsBtn = document.getElementById('clear-logs-btn');
  dom.logCategoryFilters = document.getElementById('log-category-filters');
  dom.logLevelFilter = document.getElementById('log-level-filter');
  dom.logsSummary = document.getElementById('logs-summary');
  dom.logsCounter = document.getElementById('logs-counter');

  dom.protectionToggle = document.getElementById('protection-toggle');
  dom.protectionState = document.getElementById('protection-state');

  if (dom.saveSettingsBtn) {
    dom.saveSettingsBtn.dataset.baseLabel = dom.saveSettingsBtn.textContent;
  }
}

function bindEvents() {
  dom.addSiteBtn?.addEventListener('click', addSite);
  dom.siteInput?.addEventListener('keydown', onSiteInputKeyDown);
  dom.siteInput?.addEventListener('input', onSiteInputChanged);

  dom.sitesList?.addEventListener('click', onSitesListClick);

  dom.settingsForm?.addEventListener('submit', saveSettings);
  dom.testLmBtn?.addEventListener('click', testLmStudioConnection);
  dom.clearLogsBtn?.addEventListener('click', clearLogs);
  dom.protectionToggle?.addEventListener('click', toggleProtection);
  dom.logCategoryFilters?.addEventListener('click', onLogCategoryFilterClick);
  dom.logLevelFilter?.addEventListener('change', onLogLevelFilterChange);
}

function renderLogCategoryFilters() {
  if (!dom.logCategoryFilters) return;

  dom.logCategoryFilters.replaceChildren();

  LOG_CATEGORY_FILTERS.forEach((filter) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `log-filter-chip${filter.key === activeLogFilters.category ? ' is-active' : ''}`;
    button.dataset.category = filter.key;
    button.textContent = filter.label;
    dom.logCategoryFilters.appendChild(button);
  });

  if (dom.logLevelFilter) {
    dom.logLevelFilter.value = activeLogFilters.level;
  }
}

function onLogCategoryFilterClick(event) {
  const button = event.target.closest('[data-category]');
  if (!button?.dataset.category) return;

  activeLogFilters.category = button.dataset.category;
  renderLogCategoryFilters();
  void loadLogs();
}

function onLogLevelFilterChange() {
  activeLogFilters.level = dom.logLevelFilter?.value || 'all';
  void loadLogs();
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
  const threatsToday = getOperationCountForDisplay(stats, 'day');
  const threatsMonth = getOperationCountForDisplay(stats, 'month');
  const sitesCount = safeSites.length;

  dom.threatsToday.textContent = String(threatsToday);
  dom.threatsMonth.textContent = String(threatsMonth);
  dom.sitesMonitored.textContent = String(sitesCount);
  updateStatsChart([
    { value: threatsToday, valueNode: dom.chartValueToday, barNode: dom.chartBarToday },
    { value: threatsMonth, valueNode: dom.chartValueMonth, barNode: dom.chartBarMonth },
    { value: sitesCount, valueNode: dom.chartValueSites, barNode: dom.chartBarSites }
  ]);

  const indexSource = sitesCount === 0 ? 100 : stats.securityIndex ?? 100;
  const index = clamp(toPositiveInteger(indexSource), 0, 100);
  dom.securityScore.textContent = `${index} / 100`;
  dom.securityBar.style.width = `${index}%`;
  dom.securityProgress.setAttribute('aria-valuenow', String(index));

  const risk = getRiskByIndex(index);
  dom.riskDesc.dataset.risk = risk.key;
  dom.riskDesc.textContent = `Уровень риска: ${risk.text}.`;
}

function updateStatsChart(items) {
  if (!Array.isArray(items) || items.length === 0) return;

  const maxValue = items.reduce((currentMax, item) => Math.max(currentMax, Number(item?.value) || 0), 0);
  const safeMax = maxValue > 0 ? maxValue : 1;

  if (dom.statsChart) {
    dom.statsChart.dataset.empty = maxValue === 0 ? 'true' : 'false';
  }

  items.forEach(({ value, valueNode, barNode }) => {
    const numericValue = Math.max(0, Number(value) || 0);
    const normalizedHeight =
      numericValue === 0
        ? 8
        : Math.max(18, Math.round((numericValue / safeMax) * 100));

    if (valueNode) {
      valueNode.textContent = String(numericValue);
    }

    if (barNode) {
      barNode.style.height = `${normalizedHeight}%`;
      barNode.style.opacity = numericValue === 0 ? '0.35' : '1';
    }
  });
}

function getOperationCountForDisplay(stats, period) {
  const safeStats = stats && typeof stats === 'object' ? stats : {};

  if (period === 'month') {
    return safeStats.operationsLastMonth === getLocalMonthKey()
      ? toPositiveInteger(safeStats.operationsMonth)
      : 0;
  }

  return safeStats.operationsLastDate === getLocalDateKey()
    ? toPositiveInteger(safeStats.operationsToday)
    : 0;
}

function getLocalDateKey(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function getLocalMonthKey(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  return `${year}-${month}`;
}

async function loadSettings() {
  const { settings = {} } = await chrome.storage.sync.get('settings');

  dom.modeSelect.value = settings.mode === 'local' ? 'local' : 'hybrid';
  dom.fullAnalysisPolicy.value = settings.fullAnalysisPolicy === 'smart' ? 'smart' : 'always';
  dom.lmEndpoint.value = typeof settings.lmStudioEndpoint === 'string' && settings.lmStudioEndpoint.trim()
    ? settings.lmStudioEndpoint
    : DEFAULT_LM_ENDPOINT;
  if (dom.lmModel) {
    dom.lmModel.value = typeof settings.lmStudioModel === 'string' && settings.lmStudioModel.trim()
      ? settings.lmStudioModel
      : DEFAULT_LM_MODEL;
  }
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

  await sendLog({
    category: 'settings',
    level: 'info',
    event: 'protection_toggled',
    title: nextState ? 'Защита включена' : 'Защита отключена',
    message: nextState
      ? 'Мониторинг и автоматическая защита снова активны.'
      : 'Мониторинг временно остановлен пользователем.',
    source: 'options'
  });
}

async function loadLogs() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  const loggingEnabled = settings.logging !== false;

  if (!loggingEnabled) {
    dom.logsList.replaceChildren();
    dom.clearLogsBtn.disabled = true;
    updateLogsSummary(0, 0);
    appendEmptyState(dom.logsList, 'Логирование отключено в настройках.');
    return;
  }

  const { logs = [] } = await chrome.storage.local.get('logs');
  dom.logsList.replaceChildren();

  const normalizedLogs = Array.isArray(logs)
    ? logs
        .map((log) => normalizeStoredLog(log))
        .filter(Boolean)
        .sort((left, right) => right.timestamp - left.timestamp)
    : [];
  const filteredLogs = normalizedLogs.filter((log) => matchesLogFilters(log));
  const displayedLogs = filteredLogs.slice(0, VISIBLE_LOGS_LIMIT);

  dom.clearLogsBtn.disabled = normalizedLogs.length === 0;
  updateLogsSummary(displayedLogs.length, filteredLogs.length, normalizedLogs.length);

  if (normalizedLogs.length === 0) {
    appendEmptyState(dom.logsList, 'Журнал пока пуст.');
    return;
  }

  if (filteredLogs.length === 0) {
    appendEmptyState(dom.logsList, 'По текущим фильтрам событий не найдено.');
    return;
  }

  displayedLogs.forEach((log) => {
    dom.logsList.appendChild(createLogEntry(log));
  });
}

function createLogEntry(log) {
  const entry = document.createElement('div');
  entry.className = `log-entry tone-${log.level}`;

  const head = document.createElement('div');
  head.className = 'log-head';

  const badges = document.createElement('div');
  badges.className = 'log-badges';
  badges.append(
    createLogBadge(getLogCategoryMeta(log.category).label, `tone-${getLogCategoryMeta(log.category).tone}`),
    createLogBadge(getLogLevelMeta(log.level).label, `tone-${getLogLevelMeta(log.level).tone}`),
    createLogBadge(describeLogSource(log), 'tone-source')
  );

  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = formatTimestamp(log.timestamp);

  head.append(badges, time);

  const title = document.createElement('h3');
  title.className = 'log-title';
  title.textContent = log.title || 'Событие';

  const message = document.createElement('p');
  message.className = 'log-message';
  message.textContent = log.message || 'Без описания.';

  const meta = document.createElement('div');
  meta.className = 'log-details';

  const location = document.createElement('span');
  location.className = 'log-url';
  location.textContent = describeLogLocation(log);
  meta.appendChild(location);

  if (log.context && Object.keys(log.context).length > 0) {
    meta.appendChild(createLogContext(log.context));
  }

  entry.append(head, title, message, meta);

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
  await sendLog({
    category: 'settings',
    level: 'success',
    event: 'site_added',
    title: 'Сайт добавлен в мониторинг',
    message: 'Новый сайт будет участвовать в автоматическом анализе.',
    source: 'options',
    url: normalizedUrl
  });

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
  await sendLog({
    category: 'settings',
    level: 'info',
    event: 'site_removed',
    title: 'Сайт удалён из мониторинга',
    message: 'Сайт больше не будет автоматически отслеживаться.',
    source: 'options',
    url
  });
  showSiteFeedback('Сайт удалён из списка.', 'success');

  await Promise.all([loadSites(), loadStats()]);
}

async function saveSettings(event) {
  event.preventDefault();

  const { settings = {} } = await chrome.storage.sync.get('settings');
  const lmEndpoint = dom.lmEndpoint.value.trim() || DEFAULT_LM_ENDPOINT;
  const lmModel = getLmModelValue();

  const newSettings = {
    ...settings,
    mode: dom.modeSelect.value,
    fullAnalysisPolicy: dom.fullAnalysisPolicy.value === 'smart' ? 'smart' : 'always',
    lmStudioEndpoint: lmEndpoint,
    lmStudioModel: lmModel,
    notifications: dom.notifications.checked,
    logging: dom.logging.checked,
    autoEncrypt: true
  };

  await chrome.storage.sync.set({ settings: newSettings });
  await sendLog({
    category: 'settings',
    level: 'success',
    event: 'settings_saved',
    title: 'Настройки сохранены',
    message: 'Параметры анализа и уведомлений обновлены.',
    source: 'options',
    context: {
      mode: newSettings.mode,
      policy: newSettings.fullAnalysisPolicy,
      logging: newSettings.logging,
      notifications: newSettings.notifications
    }
  });
  flashSaveButton();
  showLmTestStatus('Настройки LM Studio сохранены.', 'success');
}

async function testLmStudioConnection() {
  const endpoint = dom.lmEndpoint.value.trim() || DEFAULT_LM_ENDPOINT;
  const model = getLmModelValue();

  setButtonBusy(dom.testLmBtn, true, 'Проверяем...');
  showLmTestStatus('Проверяем подключение к LM Studio...', 'info');

  try {
    const response = await sendRuntimeMessage({
      action: 'test_lm_studio',
      endpoint,
      model
    });

    if (!response?.success || !response?.data?.ok) {
      throw new Error(response?.error || 'Нет ответа от service worker');
    }

    const result = response.data;
    await sendLog({
      category: 'ai',
      level: 'success',
      event: 'lm_connection_test_success',
      title: 'Проверка LM Studio успешна',
      message: 'Тестовый запрос к LM Studio завершился успешно.',
      source: 'options',
      context: {
        model: result.model,
        verdict: normalizeAiDanger(result.danger) || result.danger
      }
    });
    showLmTestStatus(
      `LM Studio отвечает. Модель: ${result.model}. Вердикт: ${normalizeAiDanger(result.danger) || result.danger}.`,
      'success'
    );
  } catch (error) {
    await sendLog({
      category: 'ai',
      level: 'error',
      event: 'lm_connection_test_failed',
      title: 'Проверка LM Studio завершилась ошибкой',
      message: error.message,
      source: 'options'
    });
    showLmTestStatus(`Ошибка LM Studio: ${error.message}`, 'error');
  } finally {
    setButtonBusy(dom.testLmBtn, false);
  }
}

function flashSaveButton() {
  if (!dom.saveSettingsBtn) return;
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

function createLogBadge(text, toneClass) {
  const badge = document.createElement('span');
  badge.className = `log-badge ${toneClass}`;
  badge.textContent = text;
  return badge;
}

function createLogContext(context) {
  const container = document.createElement('div');
  container.className = 'log-context';

  Object.entries(context).forEach(([key, value]) => {
    const item = document.createElement('span');
    item.className = 'log-context-item';
    item.textContent = `${getContextLabel(key)}: ${formatContextValue(key, value)}`;
    container.appendChild(item);
  });

  return container;
}

function updateLogsSummary(displayedCount, filteredCount, totalCount = filteredCount) {
  if (dom.logsCounter) {
    dom.logsCounter.textContent = String(displayedCount);
  }

  if (!dom.logsSummary) return;

  if (totalCount === 0) {
    dom.logsSummary.textContent = 'Журнал пуст.';
    return;
  }

  if (filteredCount === 0) {
    dom.logsSummary.textContent = 'По текущим фильтрам событий нет.';
    return;
  }

  if (filteredCount === totalCount && displayedCount === filteredCount) {
    dom.logsSummary.textContent = `Показаны все события: ${totalCount}.`;
    return;
  }

  if (filteredCount !== totalCount && displayedCount === filteredCount) {
    dom.logsSummary.textContent = `Показано ${filteredCount} из ${totalCount} событий после фильтрации.`;
    return;
  }

  if (filteredCount !== totalCount) {
    dom.logsSummary.textContent = `Показано ${displayedCount} из ${filteredCount} отфильтрованных событий. Всего в журнале ${totalCount}.`;
    return;
  }

  dom.logsSummary.textContent = `Показано ${displayedCount} из ${totalCount} событий.`;
}

function matchesLogFilters(log) {
  if (activeLogFilters.category !== 'all' && log.category !== activeLogFilters.category) {
    return false;
  }

  if (activeLogFilters.level !== 'all' && log.level !== activeLogFilters.level) {
    return false;
  }

  return true;
}

function normalizeStoredLog(log) {
  if (!log || typeof log !== 'object') return null;

  const type = normalizeLegacyLogType(log.type || log.level || 'info');
  const level = normalizeLogLevel(log.level || type);
  const category = normalizeLogCategory(log.category || inferLogCategory(type, log.message || log.title));
  const event = normalizeLogEvent(log.event || type);
  const title = String(log.title || inferLogTitle(category, level, event, log.message || '')).trim();
  const message = String(log.message || title || 'Без описания').trim();
  const url = String(log.url || 'background').trim() || 'background';

  return {
    id: String(log.id || `${Number(log.timestamp) || Date.now()}-${event || 'log'}`),
    timestamp: Number(log.timestamp) || Date.now(),
    level,
    category,
    event,
    title,
    message,
    url,
    source: normalizeLogSource(log.source, url),
    context: normalizeLogContext(log.context)
  };
}

function normalizeLegacyLogType(type) {
  return String(type || 'info').trim().toLowerCase().replace(/-/g, '_');
}

function normalizeLogLevel(value) {
  const normalized = normalizeLegacyLogType(value);
  if (LOG_LEVELS.has(normalized)) return normalized;
  if (normalized === 'warning') return 'warn';
  if (normalized === 'auto_encrypt' || normalized === 'auto_encrypt_ai' || normalized === 'manual_encrypt' || normalized === 'manual_decrypt' || normalized === 'export') {
    return 'success';
  }
  return normalized === 'error' ? 'error' : normalized === 'warn' ? 'warn' : 'info';
}

function normalizeLogCategory(value) {
  const normalized = normalizeLegacyLogType(value);
  return LOG_CATEGORIES.has(normalized) ? normalized : 'system';
}

function normalizeLogEvent(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function normalizeLogSource(value, url = 'background') {
  const normalized = normalizeLegacyLogType(value);
  if (normalized === 'background' || normalized === 'site' || normalized === 'popup' || normalized === 'options' || normalized === 'extension') {
    return normalized;
  }

  if (!url || url === 'background') return 'background';
  if (!String(url).startsWith('chrome-extension://')) return 'site';
  if (String(url).endsWith('/popup.html')) return 'popup';
  if (String(url).endsWith('/options.html')) return 'options';
  return 'extension';
}

function normalizeLogContext(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;

  const entries = Object.entries(value).filter(([, nested]) => nested !== undefined && nested !== null);
  if (entries.length === 0) return null;

  return Object.fromEntries(
    entries.map(([key, nested]) => [String(key), typeof nested === 'string' ? nested : String(nested)])
  );
}

function inferLogCategory(type, message = '') {
  const normalizedType = normalizeLegacyLogType(type);
  const text = String(message || '').toLowerCase();

  if (
    normalizedType === 'auto_encrypt' ||
    normalizedType === 'auto_encrypt_ai' ||
    normalizedType === 'manual_encrypt' ||
    normalizedType === 'manual_decrypt' ||
    text.includes('шифр') ||
    text.includes('дешиф')
  ) {
    return 'encryption';
  }

  if (normalizedType === 'request' || normalizedType === 'lm_response' || normalizedType === 'lm_verdict' || text.includes('lm studio')) {
    return 'ai';
  }

  if (normalizedType === 'export' || text.includes('экспорт')) {
    return 'data';
  }

  if (text.includes('настро') || text.includes('защит')) {
    return 'settings';
  }

  if (text.includes('анализ') || text.includes('risk') || text.includes('score')) {
    return 'analysis';
  }

  return 'system';
}

function inferLogTitle(category, level, event, message = '') {
  const eventTitles = {
    extension_installed: 'Расширение установлено',
    heuristic_analysis_saved: 'Эвристический анализ сохранён',
    auto_encrypt_confirmed: 'Подтверждено авто-шифрование',
    hybrid_analysis_requested: 'Запущен гибридный анализ',
    lm_request_started: 'Запрос к LM Studio отправлен',
    lm_verdict_received: 'Получен AI-вердикт',
    lm_request_failed: 'Ошибка LM Studio'
  };

  if (eventTitles[event]) return eventTitles[event];

  const byCategory = {
    encryption: { error: 'Ошибка шифрования', warn: 'Событие шифрования', success: 'Шифрование выполнено', info: 'Событие шифрования' },
    analysis: { error: 'Ошибка анализа', warn: 'Анализ требует внимания', success: 'Анализ завершён', info: 'Событие анализа' },
    ai: { error: 'Ошибка AI-анализа', warn: 'AI требует внимания', success: 'AI-событие', info: 'AI-событие' },
    settings: { error: 'Ошибка настроек', warn: 'Настройки изменены', success: 'Настройки обновлены', info: 'Событие настроек' },
    data: { error: 'Ошибка данных', warn: 'Операция с данными', success: 'Данные обработаны', info: 'Событие данных' },
    system: { error: 'Системная ошибка', warn: 'Системное предупреждение', success: 'Системное событие', info: 'Системное событие' }
  };

  return byCategory[category]?.[level] || String(message || 'Событие');
}

function getLogCategoryMeta(category) {
  return LOG_CATEGORY_META[category] || LOG_CATEGORY_META.system;
}

function getLogLevelMeta(level) {
  return LOG_LEVEL_META[level] || LOG_LEVEL_META.info;
}

function describeLogSource(log) {
  switch (log.source) {
    case 'popup':
      return 'Popup';
    case 'options':
      return 'Настройки';
    case 'site':
      return 'Сайт';
    case 'extension':
      return 'Расширение';
    default:
      return 'Service Worker';
  }
}

function describeLogLocation(log) {
  const url = String(log.url || '').trim();
  if (!url || url === 'background') return 'Источник: service worker';

  if (url.startsWith('chrome-extension://')) {
    if (url.endsWith('/popup.html')) return 'Источник: popup расширения';
    if (url.endsWith('/options.html')) return 'Источник: страница настроек';
    return 'Источник: внутренняя страница расширения';
  }

  try {
    const parsed = new URL(url);
    return `Сайт: ${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  } catch {
    return `Источник: ${url}`;
  }
}

function getContextLabel(key) {
  const labels = {
    count: 'Количество',
    skipped: 'Пропущено',
    mode: 'Режим',
    policy: 'Политика',
    logging: 'Логи',
    notifications: 'Уведомления',
    model: 'Модель',
    verdict: 'Вердикт',
    risk: 'Риск',
    score: 'Счёт',
    triggers: 'Триггеры',
    trigger: 'Причина',
    endpoint: 'API',
    reason: 'Причина',
    key: 'Ключ',
    size: 'Размер',
    site: 'Сайт',
    danger: 'Опасность',
    aiDanger: 'Вердикт AI',
    sender: 'Источник'
  };

  return labels[key] || key;
}

function formatContextValue(key, value) {
  if (key === 'logging' || key === 'notifications') {
    return String(value) === 'true' ? 'вкл' : 'выкл';
  }

  if (key === 'risk' || key === 'danger' || key === 'aiDanger' || key === 'verdict') {
    return normalizeAiDanger(value) || String(value);
  }

  return String(value);
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

function showLmTestStatus(text, type = 'info') {
  if (!dom.lmTestStatus) return;
  dom.lmTestStatus.textContent = text;
  dom.lmTestStatus.className = `feedback is-visible ${feedbackClassByType(type)}`;
}

function feedbackClassByType(type) {
  if (type === 'error') return 'is-error';
  if (type === 'success') return 'is-success';
  return '';
}

function setButtonBusy(button, isBusy, busyText = '') {
  if (!button) return;

  if (isBusy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
    return;
  }

  button.textContent = button.dataset.originalText || button.textContent;
  button.disabled = false;
}

function getLmModelValue() {
  return dom.lmModel?.value?.trim() || DEFAULT_LM_MODEL;
}

function normalizeRuntimeMessageError(error) {
  const message = String(error?.message || error || '').trim();

  if (message.includes('The message port closed before a response was received')) {
    return 'Service worker расширения закрыл соединение до ответа. Перезагрузите расширение и повторите проверку.';
  }

  if (message.includes('Receiving end does not exist')) {
    return 'Фоновый обработчик расширения недоступен. Перезагрузите расширение и повторите попытку.';
  }

  return message || 'Неизвестная ошибка обмена сообщениями расширения.';
}

function sendRuntimeMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(normalizeRuntimeMessageError(chrome.runtime.lastError)));
        return;
      }

      resolve(response);
    });
  });
}

async function sendLog(entry) {
  try {
    await sendRuntimeMessage({ action: 'log_event', ...entry });
  } catch (error) {
    console.error('Не удалось записать событие журнала:', error);
  }
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
