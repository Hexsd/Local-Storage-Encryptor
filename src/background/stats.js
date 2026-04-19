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

function sanitizeStatsEntries(value) {
  if (!Array.isArray(value)) return [];

  return Array.from(
    new Set(
      value
        .map((item) => String(item || '').trim())
        .filter(Boolean)
    )
  );
}

function normalizeOperationType(value) {
  const operation = String(value || '').trim().toLowerCase();

  switch (operation) {
    case 'popup_encrypt':
    case 'popup_decrypt':
    case 'popup_export':
    case 'popup_options':
    case 'auto_encrypt':
    case 'auto_encrypt_ai':
      return operation;
    default:
      return '';
  }
}

async function recordOperation(operationType, sourceUrl = '') {
  const normalizedOperation = normalizeOperationType(operationType);
  if (!normalizedOperation) return;

  const now = new Date();
  const today = getLocalDateKey(now);
  const currentMonth = getLocalMonthKey(now);
  const { [STATS_STORAGE_KEY]: statsValue = {} } = await chrome.storage.local.get(STATS_STORAGE_KEY);
  const stats = statsValue && typeof statsValue === 'object' ? { ...statsValue } : {};

  if (stats.operationsLastDate !== today) {
    stats.operationsToday = 0;
    stats.operationsLastDate = today;
  }

  if (stats.operationsLastMonth !== currentMonth) {
    stats.operationsMonth = 0;
    stats.operationsLastMonth = currentMonth;
  }

  stats.operationsToday = Math.max(0, Math.round(Number(stats.operationsToday) || 0)) + 1;
  stats.operationsMonth = Math.max(0, Math.round(Number(stats.operationsMonth) || 0)) + 1;

  await chrome.storage.local.set({ [STATS_STORAGE_KEY]: stats });
  await debugTrace('stats.operation.recorded', {
    operation: normalizedOperation,
    sourceUrl: String(sourceUrl || ''),
    operationsToday: stats.operationsToday,
    operationsMonth: stats.operationsMonth
  });
}

async function updateStats(currentRisk, monitoredSites, currentUrl = '') {
  const now = new Date();
  const today = getLocalDateKey(now);
  const currentMonth = getLocalMonthKey(now);
  const { [STATS_STORAGE_KEY]: statsValue = {} } = await chrome.storage.local.get(STATS_STORAGE_KEY);
  const stats = statsValue && typeof statsValue === 'object' ? { ...statsValue } : {};
  const safeUrl = String(currentUrl || '').trim();

  if (stats.lastDate !== today) {
    stats.threatsToday = 0;
    stats.threatsTodayEntries = [];
    stats.lastDate = today;
  }

  if (stats.lastMonth !== currentMonth) {
    stats.threatsMonth = 0;
    stats.threatsMonthEntries = [];
    stats.lastMonth = currentMonth;
  }

  const todayEntries = sanitizeStatsEntries(stats.threatsTodayEntries);
  const monthEntries = sanitizeStatsEntries(stats.threatsMonthEntries);

  if (normalizeRisk(currentRisk) !== 'low' && safeUrl) {
    if (!todayEntries.includes(safeUrl)) {
      todayEntries.push(safeUrl);
    }

    const monthEntry = `${today}|${safeUrl}`;
    if (!monthEntries.includes(monthEntry)) {
      monthEntries.push(monthEntry);
    }
  }

  stats.threatsTodayEntries = todayEntries;
  stats.threatsMonthEntries = monthEntries;
  stats.threatsToday = todayEntries.length;
  stats.threatsMonth = monthEntries.length;

  const safeSites = Array.isArray(monitoredSites) ? monitoredSites : await getMonitoredSites();
  stats.sitesCount = safeSites.length;

  if (safeSites.length > 0) {
    const avgScore = safeSites.reduce((sum, site) => sum + getSiteScore(site), 0) / safeSites.length;
    stats.securityIndex = Math.max(0, Math.round(100 - Math.min(avgScore, 100)));
  } else {
    stats.securityIndex = 100;
  }

  await chrome.storage.local.set({ [STATS_STORAGE_KEY]: stats });
}

function getSiteScore(site) {
  const numericScore = normalizeScore(site?.score);
  if (numericScore !== null) {
    return numericScore;
  }

  switch (normalizeRisk(site?.risk)) {
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
