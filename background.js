chrome.runtime.onInstalled.addListener(() => {
  logEvent('LocalStorage Encryptor установлен', 'system');
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    if (request.action === 'show_notification') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/128.png',
        title: 'LocalStorage Encryptor',
        message: request.message || 'Обнаружен потенциальный риск!'
      });
    }

    if (request.action === 'page_analyzed') {
      handlePageAnalysis(request).catch(e => logEvent(`Анализ страницы: ${e.message}`, 'error'));
    }

    if (request.action === 'log_event') {
      logEvent(request.message, request.type);
    }
  } catch (e) {
    logEvent(`Background ошибка: ${e.message}`, 'error');
  }
});

async function logEvent(message, type = 'info') {
  try {
    const { logs = [] } = await chrome.storage.local.get('logs');
    logs.push({
      timestamp: Date.now(),
      message,
      type,
      url: 'background'
    });

    if (logs.length > 500) logs.splice(0, logs.length - 500);
    await chrome.storage.local.set({ logs });
  } catch (e) {
    console.error('Критическая ошибка логирования:', e);
  }
}

async function handlePageAnalysis(data) {
  const { url, risk, score, issues } = data;
  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  const existingIndex = monitoredSites.findIndex(site => site.url === url);

  if (existingIndex === -1) {
    monitoredSites.push({ url, risk, score, issues: issues || [], added: Date.now() });
  } else {
    monitoredSites[existingIndex] = { ...monitoredSites[existingIndex], risk, score, issues: issues || [] };
  }

  await chrome.storage.sync.set({ monitoredSites });
  await updateStats(risk);
}

async function updateStats(currentRisk) {
  const today = new Date().toISOString().split('T')[0];
  const { stats = {} } = await chrome.storage.local.get('stats');

  if (stats.lastDate !== today) {
    stats.threatsToday = 0;
    stats.lastDate = today;
  }

  if (currentRisk !== 'low') {
    stats.threatsToday = (stats.threatsToday || 0) + 1;
    stats.threatsMonth = (stats.threatsMonth || 0) + 1;
  }

  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  stats.sitesCount = monitoredSites.length;

  if (monitoredSites.length > 0) {
    const avgScore = monitoredSites.reduce((sum, site) => sum + (site.score || 0), 0) / monitoredSites.length;
    stats.securityIndex = Math.max(0, Math.round(100 - Math.min(avgScore, 100)));
  } else {
    stats.securityIndex = 100;
  }

  await chrome.storage.local.set({ stats });
}
