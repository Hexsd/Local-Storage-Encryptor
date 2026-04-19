async function loadStats() {
  const [{ stats = {} }, { monitoredSites: safeSites }] = await Promise.all([
    chrome.storage.local.get('stats'),
    getSiteCollections()
  ]);
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
