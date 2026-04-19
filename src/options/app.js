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
  dom.whitelistInput = document.getElementById('whitelist-input');
  dom.whitelistFeedback = document.getElementById('whitelist-feedback');
  dom.addWhitelistBtn = document.getElementById('add-whitelist-btn');
  dom.whitelistList = document.getElementById('whitelist-list');

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
  dom.addWhitelistBtn?.addEventListener('click', addWhitelistSite);
  dom.whitelistInput?.addEventListener('keydown', onWhitelistInputKeyDown);
  dom.whitelistInput?.addEventListener('input', onWhitelistInputChanged);

  dom.sitesList?.addEventListener('click', onSitesListClick);
  dom.whitelistList?.addEventListener('click', onWhitelistListClick);

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
    if (areaName === 'sync' && (changes.monitoredSites || changes.whitelistedSites)) {
      await Promise.all([loadSiteCollections(), loadStats()]);
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
    await Promise.all([loadSiteCollections(), loadStats(), loadSettings(), loadLogs()]);
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

function onWhitelistInputKeyDown(event) {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  addWhitelistSite();
}

function onWhitelistInputChanged() {
  dom.whitelistInput.classList.remove('is-invalid');
  if (dom.whitelistFeedback.classList.contains('is-error')) {
    clearWhitelistFeedback();
  }
}

function onSitesListClick(event) {
  const actionButton = event.target.closest('[data-site-action]');
  if (!actionButton) return;

  const siteRow = actionButton.closest('.site-row');
  if (!siteRow?.dataset.site) return;

  if (actionButton.dataset.siteAction === 'whitelist') {
    void moveSiteToWhitelist(siteRow.dataset.site);
    return;
  }

  if (actionButton.dataset.siteAction === 'remove') {
    void removeSite(siteRow.dataset.site);
  }
}

function onWhitelistListClick(event) {
  const actionButton = event.target.closest('[data-whitelist-action]');
  if (!actionButton) return;

  const siteRow = actionButton.closest('.site-row');
  if (!siteRow?.dataset.site) return;

  if (actionButton.dataset.whitelistAction === 'monitor') {
    void moveWhitelistToMonitoring(siteRow.dataset.site);
    return;
  }

  if (actionButton.dataset.whitelistAction === 'remove') {
    void removeWhitelistedSite(siteRow.dataset.site);
  }
}
