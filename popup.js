const popup = {};
let activeTab = null;
let pageStatus = null;
let globalProtectionEnabled = true;

document.addEventListener('DOMContentLoaded', initPopup);

async function initPopup() {
  for (const id of ['site', 'power', 'shield', 'status-title', 'status-text', 'blocked', 'findings', 'finding-list', 'scan', 'trust', 'options']) {
    popup[id] = document.getElementById(id);
  }
  popup.power.addEventListener('click', toggleGlobalProtection);
  popup.scan.addEventListener('click', scanCurrentPage);
  popup.trust.addEventListener('click', toggleSiteTrust);
  popup.options.addEventListener('click', () => chrome.runtime.openOptionsPage());
  await refreshPopup();
}

async function refreshPopup() {
  const [[tab], sync, local] = await Promise.all([
    chrome.tabs.query({ active: true, currentWindow: true }),
    chrome.storage.sync.get(['settings', 'whitelistedSites']),
    chrome.storage.local.get('securityStats')
  ]);
  activeTab = tab || null;
  const enabled = sync.settings?.protectionEnabled !== false;
  globalProtectionEnabled = enabled;
  const trusted = isPopupSiteTrusted(activeTab?.url, sync.whitelistedSites);
  popup.power.setAttribute('aria-pressed', String(enabled));
  popup.site.textContent = popupHostname(activeTab?.url);
  popup.blocked.textContent = String(Number(local.securityStats?.totalBlocked) || 0);
  popup.trust.textContent = trusted ? 'Не доверять сайту' : 'Доверять сайту';
  popup.trust.disabled = !popupOrigin(activeTab?.url);

  try {
    pageStatus = await sendToTab({ action: 'get_security_status' });
    if (!pageStatus?.success) throw new Error('status unavailable');
    renderPageState(enabled, trusted, pageStatus.data);
  } catch {
    renderUnavailable(enabled);
  }
}

function renderPageState(enabled, trusted, data) {
  const findings = Array.isArray(data.findings) ? data.findings : [];
  popup.findings.textContent = String(findings.length);
  popup['finding-list'].hidden = findings.length === 0;
  popup['finding-list'].replaceChildren(...findings.slice(0, 4).map((finding) => {
    const row = document.createElement('p'); row.textContent = finding.text; return row;
  }));
  const hero = popup.shield.parentElement;
  hero.className = 'hero';
  if (!enabled) {
    hero.classList.add('is-off'); popup.shield.textContent = '—'; popup['status-title'].textContent = 'Защита выключена'; popup['status-text'].textContent = 'Включите щит, чтобы блокировать угрозы';
  } else if (trusted) {
    hero.classList.add('is-off'); popup.shield.textContent = '○'; popup['status-title'].textContent = 'Сайт доверенный'; popup['status-text'].textContent = 'Блокировка для него приостановлена';
  } else if (findings.some((item) => item.level === 'high' || item.level === 'critical')) {
    hero.classList.add('is-alert'); popup.shield.textContent = '!'; popup['status-title'].textContent = 'Требуется внимание'; popup['status-text'].textContent = 'Опасная отправка будет остановлена';
  } else {
    popup.shield.textContent = '✓'; popup['status-title'].textContent = 'Защита активна'; popup['status-text'].textContent = 'Утечки блокируются до отправки';
  }
}

function renderUnavailable(enabled) {
  popup.findings.textContent = '—'; popup['finding-list'].hidden = true; popup.scan.disabled = true;
  popup.shield.parentElement.className = `hero${enabled ? '' : ' is-off'}`;
  popup.shield.textContent = enabled ? '✓' : '—';
  popup['status-title'].textContent = enabled ? 'Защита активна' : 'Защита выключена';
  popup['status-text'].textContent = 'Эта системная страница недоступна для проверки';
}

async function scanCurrentPage() {
  popup.scan.disabled = true; popup.scan.textContent = 'Проверяем…';
  try {
    const response = await sendToTab({ action: 'scan_page' });
    if (response?.success) renderPageState(globalProtectionEnabled, response.data.trusted, response.data);
  } finally {
    popup.scan.disabled = false; popup.scan.textContent = 'Проверить страницу';
  }
}

async function toggleGlobalProtection() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  settings.protectionEnabled = settings.protectionEnabled === false;
  await chrome.storage.sync.set({ settings });
  await refreshPopup();
}

async function toggleSiteTrust() {
  const origin = popupOrigin(activeTab?.url);
  if (!origin) return;
  const { whitelistedSites = [] } = await chrome.storage.sync.get('whitelistedSites');
  const list = Array.isArray(whitelistedSites) ? whitelistedSites : [];
  const trusted = isPopupSiteTrusted(origin, list);
  const next = trusted
    ? list.filter((item) => popupOrigin(typeof item === 'object' ? item.url : item) !== origin)
    : [...list, { url: origin, added: Date.now() }];
  await chrome.storage.sync.set({ whitelistedSites: next });
  await refreshPopup();
}

function sendToTab(message) {
  if (!activeTab?.id) return Promise.reject(new Error('Нет активной вкладки'));
  return chrome.tabs.sendMessage(activeTab.id, message);
}

function popupOrigin(value) {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.origin.toLowerCase() : ''; } catch { return ''; }
}

function popupHostname(value) {
  try { return new URL(value).hostname || 'Текущая вкладка'; } catch { return 'Текущая вкладка'; }
}

function isPopupSiteTrusted(url, list) {
  const origin = popupOrigin(url);
  return Boolean(origin) && Array.isArray(list) && list.some((item) => popupOrigin(typeof item === 'object' ? item.url : item) === origin);
}
