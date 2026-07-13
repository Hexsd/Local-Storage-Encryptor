const DEFAULT_ENDPOINT = 'http://127.0.0.1:1234/v1/chat/completions';
const DEFAULT_MODEL = 'qwen/qwen3-4b-thinking-2507';
const ui = {};
let saveTimer = null;

document.addEventListener('DOMContentLoaded', initOptions);

async function initOptions() {
  for (const id of ['save-state','total-blocked','blocked-leaks','blocked-forms','protection-enabled','protection-mode','block-forms','protect-links','notifications','logging','trusted-destinations','analysis-mode','lm-endpoint','lm-model','test-lm','lm-status','trusted-sites','events','clear-data']) ui[id] = document.getElementById(id);
  await loadOptions();
  for (const element of document.querySelectorAll('input,select,textarea')) element.addEventListener('change', saveOptions);
  ui['trusted-destinations'].addEventListener('input', debounceSaveOptions);
  ui['test-lm'].addEventListener('click', testLocalAi);
  ui['clear-data'].addEventListener('click', clearSecurityData);
  ui['trusted-sites'].addEventListener('click', removeTrustedSite);
  chrome.storage.onChanged.addListener(() => void renderSecurityData());
}

async function loadOptions() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  ui['protection-enabled'].checked = settings.protectionEnabled !== false;
  ui['protection-mode'].value = ['strict','balanced','monitor'].includes(settings.protectionMode) ? settings.protectionMode : 'balanced';
  ui['block-forms'].checked = settings.blockDangerousForms !== false;
  ui['protect-links'].checked = settings.protectExternalLinks !== false;
  ui.notifications.checked = settings.notifications !== false;
  ui.logging.checked = settings.logging !== false;
  ui['trusted-destinations'].value = Array.isArray(settings.trustedDestinations) ? settings.trustedDestinations.join('\n') : '';
  ui['analysis-mode'].value = settings.mode === 'hybrid' ? 'hybrid' : 'local';
  ui['lm-endpoint'].value = settings.lmStudioEndpoint || DEFAULT_ENDPOINT;
  ui['lm-model'].value = settings.lmStudioModel || DEFAULT_MODEL;
  await renderSecurityData();
}

async function saveOptions() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  const trustedDestinations = ui['trusted-destinations'].value.split(/\r?\n|,/).map((item) => item.trim().toLowerCase()).filter(isSafeDestination).slice(0, 64);
  await chrome.storage.sync.set({ settings: {
    ...settings,
    protectionEnabled: ui['protection-enabled'].checked,
    protectionMode: ui['protection-mode'].value,
    blockDangerousForms: ui['block-forms'].checked,
    protectExternalLinks: ui['protect-links'].checked,
    notifications: ui.notifications.checked,
    logging: ui.logging.checked,
    trustedDestinations,
    mode: ui['analysis-mode'].value === 'hybrid' ? 'hybrid' : 'local',
    fullAnalysisPolicy: 'smart',
    lmStudioEndpoint: normalizeLoopbackEndpoint(ui['lm-endpoint'].value),
    lmStudioModel: ui['lm-model'].value.trim().slice(0, 120) || DEFAULT_MODEL
  }});
  ui['trusted-destinations'].value = trustedDestinations.join('\n');
  flashSaved();
}

function debounceSaveOptions() { clearTimeout(saveTimer); saveTimer = setTimeout(saveOptions, 450); }
function flashSaved() { ui['save-state'].textContent = 'Сохранено'; clearTimeout(saveTimer); saveTimer = setTimeout(() => { ui['save-state'].textContent = 'Все изменения сохраняются локально'; }, 1300); }

async function renderSecurityData() {
  const [{ securityStats = {} }, { whitelistedSites = [] }] = await Promise.all([chrome.storage.local.get('securityStats'), chrome.storage.sync.get('whitelistedSites')]);
  ui['total-blocked'].textContent = String(Number(securityStats.totalBlocked) || 0);
  ui['blocked-leaks'].textContent = String(Number(securityStats.blockedLeaks) || 0);
  ui['blocked-forms'].textContent = String(Number(securityStats.blockedForms) || 0);
  renderTrustedSites(Array.isArray(whitelistedSites) ? whitelistedSites : []);
  renderEvents(Array.isArray(securityStats.events) ? securityStats.events.slice(-20).reverse() : []);
}

function renderTrustedSites(sites) {
  ui['trusted-sites'].replaceChildren();
  if (!sites.length) return ui['trusted-sites'].append(emptyNode('Нет доверенных сайтов'));
  for (const item of sites) {
    const url = typeof item === 'object' ? item.url : item;
    const row = document.createElement('div'); row.className = 'site';
    const label = document.createElement('span'); label.textContent = url;
    const button = document.createElement('button'); button.type = 'button'; button.dataset.url = url; button.textContent = 'Удалить';
    row.append(label, button); ui['trusted-sites'].append(row);
  }
}

function renderEvents(events) {
  ui.events.replaceChildren();
  if (!events.length) return ui.events.append(emptyNode('Срабатываний пока нет'));
  for (const item of events) {
    const row = document.createElement('div'); row.className = 'event';
    const body = document.createElement('div'); const title = document.createElement('strong'); const meta = document.createElement('span');
    title.textContent = item.event === 'dangerous_form_blocked' ? 'Опасная форма' : 'Утечка токена'; meta.textContent = [safeHost(item.site), safeHost(item.destination)].filter(Boolean).join(' → ');
    const time = document.createElement('time'); time.dateTime = new Date(item.timestamp).toISOString(); time.textContent = formatTime(item.timestamp);
    body.append(title, meta); row.append(body, time); ui.events.append(row);
  }
}

async function removeTrustedSite(event) {
  const url = event.target?.dataset?.url; if (!url) return;
  const { whitelistedSites = [] } = await chrome.storage.sync.get('whitelistedSites');
  await chrome.storage.sync.set({ whitelistedSites: whitelistedSites.filter((item) => (typeof item === 'object' ? item.url : item) !== url) });
  await renderSecurityData();
}

async function clearSecurityData() {
  if (!confirm('Очистить локальный журнал и статистику блокировок?')) return;
  await chrome.storage.local.set({ securityStats: {}, logs: [] });
  await renderSecurityData();
}

async function testLocalAi() {
  ui['test-lm'].disabled = true; ui['lm-status'].textContent = 'Проверяем…';
  try {
    const response = await chrome.runtime.sendMessage({ action: 'test_lm_studio', endpoint: normalizeLoopbackEndpoint(ui['lm-endpoint'].value), model: ui['lm-model'].value.trim() });
    ui['lm-status'].textContent = response?.success ? 'Соединение установлено' : (response?.error || 'Нет ответа');
  } catch (error) { ui['lm-status'].textContent = error.message; }
  finally { ui['test-lm'].disabled = false; }
}

function isSafeDestination(value) { return /^(?:[a-z0-9-]+\.)*[a-z0-9-]+(?::\d+)?$/i.test(value) && value.length <= 253; }
function normalizeLoopbackEndpoint(value) { try { const url = new URL(value); return ['localhost','127.0.0.1','[::1]'].includes(url.hostname) && ['http:','https:'].includes(url.protocol) ? url.href : DEFAULT_ENDPOINT; } catch { return DEFAULT_ENDPOINT; } }
function safeHost(value) { try { return new URL(value).hostname; } catch { return ''; } }
function formatTime(value) { const date = new Date(Number(value)); return Number.isNaN(date.getTime()) ? '' : date.toLocaleString('ru-RU', { day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit' }); }
function emptyNode(text) { const node = document.createElement('p'); node.className = 'empty'; node.textContent = text; return node; }
