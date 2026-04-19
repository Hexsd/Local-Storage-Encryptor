async function loadSiteCollections() {
  const { monitoredSites, whitelistedSites } = await getSiteCollections();
  renderMonitoredSites(monitoredSites);
  renderWhitelistedSites(whitelistedSites);
}

function renderMonitoredSites(safeSites) {
  dom.sitesList.replaceChildren();

  if (safeSites.length === 0) {
    appendEmptyState(dom.sitesList, 'Нет отслеживаемых сайтов');
    return;
  }

  safeSites.forEach((site) => {
    dom.sitesList.appendChild(createSiteRow(site));
  });
}

function renderWhitelistedSites(safeSites) {
  dom.whitelistList.replaceChildren();

  if (safeSites.length === 0) {
    appendEmptyState(dom.whitelistList, 'Белый список пуст');
    return;
  }

  safeSites.forEach((site) => {
    dom.whitelistList.appendChild(createWhitelistRow(site));
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

  const whitelistBtn = document.createElement('button');
  whitelistBtn.type = 'button';
  whitelistBtn.className = 'site-action-btn';
  whitelistBtn.dataset.siteAction = 'whitelist';
  whitelistBtn.textContent = 'В белый список';

  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'danger remove-site-btn';
  removeBtn.dataset.siteAction = 'remove';
  removeBtn.textContent = 'Удалить';

  info.append(siteUrl, meta);
  actions.append(badge, whitelistBtn, removeBtn);
  row.append(info, actions);

  return row;
}

function createWhitelistRow(site) {
  const row = document.createElement('div');
  row.className = 'site-row site-row-whitelist';
  row.dataset.site = site.url;

  const info = document.createElement('div');
  info.className = 'site-info';

  const siteUrl = document.createElement('span');
  siteUrl.className = 'site-url';
  siteUrl.textContent = site.url;

  const meta = document.createElement('div');
  meta.className = 'site-meta';

  const statusMeta = document.createElement('span');
  statusMeta.className = 'site-meta-item';
  statusMeta.textContent = 'Анализ отключён';
  meta.appendChild(statusMeta);

  const addedMeta = document.createElement('span');
  addedMeta.className = 'site-meta-item';
  addedMeta.textContent = `Добавлен: ${formatSiteDate(site.added)}`;
  meta.appendChild(addedMeta);

  const actions = document.createElement('span');
  actions.className = 'site-actions';

  const badge = document.createElement('span');
  badge.className = 'badge badge-neutral';
  badge.textContent = 'Без анализа';

  const monitorBtn = document.createElement('button');
  monitorBtn.type = 'button';
  monitorBtn.className = 'site-action-btn';
  monitorBtn.dataset.whitelistAction = 'monitor';
  monitorBtn.textContent = 'В мониторинг';

  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'danger';
  removeBtn.dataset.whitelistAction = 'remove';
  removeBtn.textContent = 'Удалить';

  info.append(siteUrl, meta);
  actions.append(badge, monitorBtn, removeBtn);
  row.append(info, actions);

  return row;
}
