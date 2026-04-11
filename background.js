const DEFAULT_LM_STUDIO_ENDPOINT = 'http://127.0.0.1:1234/v1/chat/completions';
const DEFAULT_LM_STUDIO_MODEL = 'qwen3-4b-2507';
const DEFAULT_LM_STUDIO_TIMEOUT_MS = 15000;
const LOGS_STORAGE_KEY = 'logs';
const STATS_STORAGE_KEY = 'stats';
const SETTINGS_STORAGE_KEY = 'settings';
const MONITORED_SITES_STORAGE_KEY = 'monitoredSites';
const WHITELISTED_SITES_STORAGE_KEY = 'whitelistedSites';
const SITE_DETAILS_PREFIX = 'siteDetails:';
const MAX_LOGS = 500;
const LOG_SCHEMA_VERSION = 2;
const LOG_TITLE_MAX_LENGTH = 96;
const LOG_MESSAGE_MAX_LENGTH = 320;
const LOG_CONTEXT_MAX_KEYS = 8;
const LOG_CONTEXT_VALUE_MAX_LENGTH = 120;
const LOG_LEVELS = new Set(['info', 'success', 'warn', 'error']);
const LOG_CATEGORIES = new Set(['analysis', 'encryption', 'ai', 'settings', 'data', 'system']);
const LOG_SOURCES = new Set(['background', 'site', 'popup', 'options', 'extension']);
const MAX_SYNC_ISSUES = 5;
const MAX_SYNC_ISSUE_LENGTH = 160;
const MAX_SYNC_REASON_LENGTH = 400;
const MAX_SYNC_RECOMMENDATION_LENGTH = 240;
const MAX_PROMPT_ISSUES = 6;
const MAX_PROMPT_JSON_LENGTH = 3200;
const DEBUG_STORAGE_KEY = 'debugTrace';
const MAX_DEBUG_ENTRIES = 200;
const DEBUG_MODE = true;

chrome.runtime.onInstalled.addListener(() => {
  void logEvent({
    category: 'system',
    level: 'success',
    event: 'extension_installed',
    title: 'Расширение установлено',
    message: 'Local Storage Encryptor установлен и готов к работе.'
  });
  void debugTrace('lifecycle.installed');
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const action = request?.action;
  void debugTrace('runtime.message.received', {
    action,
    senderUrl: getSenderUrl(sender)
  });

  if (action === 'page_analyzed_full' || action === 'test_lm_studio') {
    void handleAsyncMessage(request, sender, sendResponse);
    return true;
  }

  switch (action) {
    case 'show_notification':
      void showNotification(request?.message);
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'page_analyzed':
      void handlePageAnalysis(request).catch((error) =>
        logEvent(
          {
            category: 'analysis',
            level: 'error',
            event: 'page_analysis_failed',
            title: 'Не удалось сохранить анализ страницы',
            message: error.message,
            context: {
              sender: getSenderSource(sender)
            }
          },
          null,
          getSenderUrl(sender),
          getSenderSource(sender)
        )
      );
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'log_event':
      void logEvent(request, request?.type, getSenderUrl(sender), getSenderSource(sender));
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'record_operation':
      void recordOperation(request?.operation, getSenderUrl(sender));
      safeSendResponse(sendResponse, { success: true });
      break;
    default:
      break;
  }

  return false;
});

async function handleAsyncMessage(request, sender, sendResponse) {
  void debugTrace('runtime.message.async.start', {
    action: request?.action,
    senderUrl: getSenderUrl(sender)
  });

  try {
    const data =
      request?.action === 'test_lm_studio'
        ? await handleLmStudioTest(request, sender)
        : await handleFullPageAnalysis(request, sender);

    safeSendResponse(sendResponse, { success: true, data });

    void debugTrace('runtime.message.async.success', {
      action: request?.action,
      senderUrl: getSenderUrl(sender),
      url: data?.url,
      aiDanger: data?.aiDanger
    });
  } catch (error) {
    const errorMessage = error?.message || String(error);
    safeSendResponse(sendResponse, { success: false, error: errorMessage });

    void debugTrace('runtime.message.async.error', {
      action: request?.action,
      senderUrl: getSenderUrl(sender),
      error: errorMessage
    });
    void logEvent(
      {
        category: 'analysis',
        level: 'error',
        event: 'full_analysis_failed',
        title: 'Ошибка полного анализа',
        message: errorMessage
      },
      null,
      getSenderUrl(sender),
      getSenderSource(sender)
    );
  }
}

function safeSendResponse(sendResponse, payload) {
  try {
    sendResponse(payload);
    void debugTrace('runtime.message.response.sent', {
      success: Boolean(payload?.success),
      error: payload?.error || ''
    });
  } catch {
    void debugTrace('runtime.message.response.failed');
  }
}

function getSenderUrl(sender) {
  return sender?.url || sender?.tab?.url || 'background';
}

function getSenderSource(sender) {
  return inferLogSourceFromUrl(getSenderUrl(sender));
}

async function getStoredSettings() {
  try {
    const { [SETTINGS_STORAGE_KEY]: settings = {} } = await chrome.storage.sync.get(SETTINGS_STORAGE_KEY);
    return settings && typeof settings === 'object' ? settings : {};
  } catch {
    return {};
  }
}

async function getExtensionSettings() {
  const settings = await getStoredSettings();

  return {
    notifications: settings.notifications !== false,
    logging: settings.logging !== false,
    mode: settings.mode === 'local' ? 'local' : 'hybrid',
    lmStudioEndpoint: normalizeEndpoint(settings.lmStudioEndpoint),
    lmStudioModel: normalizeModel(settings.lmStudioModel),
    lmStudioTimeoutMs: normalizeTimeout(settings.lmStudioTimeoutMs)
  };
}

function normalizeEndpoint(value) {
  const endpoint = String(value || DEFAULT_LM_STUDIO_ENDPOINT).trim();

  try {
    const parsed = new URL(endpoint);
    return parsed.toString();
  } catch {
    return DEFAULT_LM_STUDIO_ENDPOINT;
  }
}

function normalizeModel(value) {
  const model = String(value || DEFAULT_LM_STUDIO_MODEL).trim();
  return model || DEFAULT_LM_STUDIO_MODEL;
}

function normalizeTimeout(value) {
  const timeout = Number(value);
  if (!Number.isFinite(timeout) || timeout < 1000) {
    return DEFAULT_LM_STUDIO_TIMEOUT_MS;
  }
  return Math.round(timeout);
}

async function showNotification(message) {
  const { notifications } = await getExtensionSettings();
  if (!notifications) return;

  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/128.png',
    title: 'Local Storage Encryptor',
    message: String(message || 'Potential risk detected')
  });
}

async function debugTrace(event, payload = null) {
  if (!DEBUG_MODE) return;

  const entry = {
    timestamp: Date.now(),
    event: String(event || 'debug'),
    payload: sanitizeDebugPayload(payload)
  };

  try {
    console.log('[LSE debug]', entry.event, entry.payload || '');
  } catch {
  }

  try {
    const { [DEBUG_STORAGE_KEY]: debugEntries = [] } = await chrome.storage.local.get(DEBUG_STORAGE_KEY);
    const nextEntries = Array.isArray(debugEntries) ? debugEntries.slice(-MAX_DEBUG_ENTRIES + 1) : [];
    nextEntries.push(entry);
    await chrome.storage.local.set({ [DEBUG_STORAGE_KEY]: nextEntries });
  } catch (error) {
    try {
      console.warn('[LSE debug] failed to persist trace', error);
    } catch {
    }
  }
}

function sanitizeDebugPayload(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth >= 3) return '[max-depth]';

  if (typeof value === 'string') {
    return truncateText(value, 800);
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.slice(0, 10).map((item) => sanitizeDebugPayload(item, depth + 1));
  }

  if (typeof value === 'object') {
    const result = {};
    for (const [key, nestedValue] of Object.entries(value).slice(0, 20)) {
      result[key] = sanitizeDebugPayload(nestedValue, depth + 1);
    }
    return result;
  }

  return String(value);
}

async function logEvent(input, type = 'info', url = 'background', source = '') {
  try {
    const { logging } = await getExtensionSettings();
    if (!logging) return;

    const { [LOGS_STORAGE_KEY]: logs = [] } = await chrome.storage.local.get(LOGS_STORAGE_KEY);
    const nextLogs = Array.isArray(logs) ? logs.slice(-MAX_LOGS + 1) : [];

    nextLogs.push(buildLogEntry(input, type, url, source));

    await chrome.storage.local.set({ [LOGS_STORAGE_KEY]: nextLogs });
  } catch (error) {
    console.error('Logging failure:', error);
  }
}

function normalizeLogType(type) {
  const normalized = String(type || 'info').trim().toLowerCase();
  return normalized || 'info';
}

function buildLogEntry(input, legacyType = 'info', fallbackUrl = 'background', sourceHint = '') {
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    const rawType = normalizeLogType(input.type || legacyType);
    const level = normalizeLogLevel(input.level || rawType);
    const url = normalizeLogUrl(input.url || fallbackUrl);
    const category = normalizeLogCategory(input.category || inferLogCategory(rawType, input.message));
    const event = normalizeLogEvent(input.event || rawType);
    const title = truncateText(
      input.title || inferLogTitle(category, level, event, input.message),
      LOG_TITLE_MAX_LENGTH
    );
    const message = truncateText(
      input.message || inferLogMessage(category, event, title),
      LOG_MESSAGE_MAX_LENGTH
    );

    return {
      id: createLogId(),
      version: LOG_SCHEMA_VERSION,
      timestamp: normalizeLogTimestamp(input.timestamp),
      level,
      category,
      event,
      title: title || 'Событие',
      message,
      url,
      source: normalizeLogSource(input.source || sourceHint, url),
      context: sanitizeLogContext(input.context)
    };
  }

  const message = truncateText(String(input || ''), LOG_MESSAGE_MAX_LENGTH);
  const rawType = normalizeLogType(legacyType);
  const category = normalizeLogCategory(inferLogCategory(rawType, message));
  const level = normalizeLogLevel(rawType);
  const event = normalizeLogEvent(rawType);
  const title = truncateText(inferLogTitle(category, level, event, message), LOG_TITLE_MAX_LENGTH);
  const url = normalizeLogUrl(fallbackUrl);

  return {
    id: createLogId(),
    version: LOG_SCHEMA_VERSION,
    timestamp: Date.now(),
    level,
    category,
    event,
    title: title || 'Событие',
    message,
    url,
    source: normalizeLogSource(sourceHint, url),
    context: null
  };
}

function createLogId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeLogLevel(value) {
  const normalized = String(value || 'info').trim().toLowerCase();
  if (LOG_LEVELS.has(normalized)) return normalized;
  if (normalized === 'warning') return 'warn';
  if (normalized === 'system') return 'info';
  if (
    normalized === 'auto_encrypt' ||
    normalized === 'auto_encrypt_ai' ||
    normalized === 'manual_encrypt' ||
    normalized === 'manual_decrypt'
  ) {
    return 'success';
  }
  return normalized === 'warn' ? 'warn' : 'info';
}

function normalizeLogCategory(value) {
  const normalized = String(value || 'system').trim().toLowerCase();
  return LOG_CATEGORIES.has(normalized) ? normalized : 'system';
}

function normalizeLogEvent(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function normalizeLogTimestamp(value) {
  const timestamp = Number(value);
  return Number.isFinite(timestamp) && timestamp > 0 ? timestamp : Date.now();
}

function normalizeLogUrl(value) {
  const url = String(value || '').trim();
  return url || 'background';
}

function normalizeLogSource(value, url = 'background') {
  const normalized = String(value || '').trim().toLowerCase();
  if (LOG_SOURCES.has(normalized)) return normalized;
  return inferLogSourceFromUrl(url);
}

function inferLogSourceFromUrl(url) {
  const sourceUrl = String(url || '').trim();
  if (!sourceUrl || sourceUrl === 'background') return 'background';
  if (!sourceUrl.startsWith('chrome-extension://')) return 'site';
  if (sourceUrl.endsWith('/popup.html')) return 'popup';
  if (sourceUrl.endsWith('/options.html')) return 'options';
  return 'extension';
}

function inferLogCategory(type, message = '') {
  const normalizedType = normalizeLogType(type);
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

  if (
    normalizedType === 'request' ||
    normalizedType === 'lm_response' ||
    normalizedType === 'lm_verdict' ||
    text.includes('lm studio') ||
    text.includes('ai')
  ) {
    return 'ai';
  }

  if (normalizedType === 'export' || text.includes('экспорт')) {
    return 'data';
  }

  if (text.includes('настро') || text.includes('защит')) {
    return 'settings';
  }

  if (text.includes('анализ') || text.includes('risk=') || text.includes('score=')) {
    return 'analysis';
  }

  return 'system';
}

function inferLogTitle(category, level, event, message = '') {
  const eventMap = {
    extension_installed: 'Расширение установлено',
    page_analysis_failed: 'Ошибка сохранения анализа',
    full_analysis_failed: 'Ошибка полного анализа',
    heuristic_analysis_saved: 'Эвристический анализ сохранён',
    hybrid_analysis_requested: 'Запущен гибридный анализ',
    lm_request_started: 'Запрос к LM Studio отправлен',
    lm_request_failed: 'Ошибка LM Studio',
    lm_response_received: 'Получен ответ LM Studio',
    lm_verdict_received: 'Получен AI-вердикт',
    auto_encrypt_confirmed: 'Подтверждено авто-шифрование'
  };

  if (eventMap[event]) return eventMap[event];

  const categoryTitles = {
    analysis: {
      error: 'Ошибка анализа',
      warn: 'Предупреждение анализа',
      success: 'Анализ завершён',
      info: 'Событие анализа'
    },
    encryption: {
      error: 'Ошибка шифрования',
      warn: 'Шифрование требует внимания',
      success: 'Шифрование выполнено',
      info: 'Событие шифрования'
    },
    ai: {
      error: 'Ошибка AI-анализа',
      warn: 'AI-анализ требует внимания',
      success: 'AI-ответ получен',
      info: 'AI-событие'
    },
    settings: {
      error: 'Ошибка настроек',
      warn: 'Изменение настроек',
      success: 'Настройки обновлены',
      info: 'Событие настроек'
    },
    data: {
      error: 'Ошибка данных',
      warn: 'Операция с данными',
      success: 'Данные обработаны',
      info: 'Событие данных'
    },
    system: {
      error: 'Системная ошибка',
      warn: 'Системное предупреждение',
      success: 'Системное событие',
      info: 'Системное событие'
    }
  };

  const byCategory = categoryTitles[category] || categoryTitles.system;
  const title = byCategory[level] || byCategory.info;

  return title || truncateText(String(message || 'Событие'), LOG_TITLE_MAX_LENGTH);
}

function inferLogMessage(category, event, title) {
  if (title) return String(title);

  if (event) {
    return `${category}: ${event}`;
  }

  return 'Событие без описания';
}

function sanitizeLogContext(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;

  const entries = Object.entries(value).slice(0, LOG_CONTEXT_MAX_KEYS);
  const sanitized = {};

  for (const [key, nestedValue] of entries) {
    const safeKey = String(key || '').trim();
    if (!safeKey) continue;

    if (typeof nestedValue === 'number' && Number.isFinite(nestedValue)) {
      sanitized[safeKey] = nestedValue;
      continue;
    }

    if (typeof nestedValue === 'boolean') {
      sanitized[safeKey] = nestedValue;
      continue;
    }

    if (typeof nestedValue === 'string') {
      sanitized[safeKey] = truncateText(nestedValue, LOG_CONTEXT_VALUE_MAX_LENGTH);
      continue;
    }

    if (nestedValue !== null && nestedValue !== undefined) {
      sanitized[safeKey] = truncateText(String(nestedValue), LOG_CONTEXT_VALUE_MAX_LENGTH);
    }
  }

  return Object.keys(sanitized).length > 0 ? sanitized : null;
}

function normalizeRisk(value) {
  const risk = String(value || 'low').trim().toLowerCase();

  if (risk === 'critical') return 'critical';
  if (risk === 'high') return 'high';
  if (risk === 'medium') return 'medium';
  return 'low';
}

function normalizeAiDanger(value) {
  const normalized = String(value || '').trim().toLowerCase();

  if (normalized === 'critical' || normalized === 'критический') return 'critical';
  if (normalized === 'high' || normalized === 'высокий') return 'high';
  if (normalized === 'medium' || normalized === 'средний') return 'medium';
  if (normalized === 'low' || normalized === 'низкий') return 'low';
  return '';
}

function normalizeScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  return clamp(Math.round(score), 0, 100);
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function sanitizeIssues(value, maxItems = MAX_SYNC_ISSUES, maxLength = MAX_SYNC_ISSUE_LENGTH) {
  if (!Array.isArray(value)) return [];

  return value
    .map((item) => truncateText(item, maxLength))
    .filter(Boolean)
    .slice(0, maxItems);
}

function truncateText(value, maxLength) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.length <= maxLength) return text;
  if (maxLength <= 3) return text.slice(0, maxLength);
  return `${text.slice(0, maxLength - 3)}...`;
}

function getSiteDetailsStorageKey(url) {
  return `${SITE_DETAILS_PREFIX}${encodeURIComponent(url)}`;
}

function normalizeSiteUrl(value) {
  if (!value) return '';

  try {
    const parsed = new URL(String(value).trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return '';
    }
    return parsed.origin.toLowerCase();
  } catch {
    return '';
  }
}

function isSameSiteUrl(left, right) {
  const leftKey = normalizeSiteUrl(left);
  const rightKey = normalizeSiteUrl(right);
  return Boolean(leftKey) && leftKey === rightKey;
}

function getBaseSiteRecord(record) {
  if (!record || typeof record !== 'object') return null;

  const url = normalizeSiteUrl(record.url);
  if (!url) return null;

  return {
    url,
    risk: normalizeRisk(record.risk),
    score: normalizeScore(record.score),
    issues: sanitizeIssues(record.issues),
    aiDanger: normalizeAiDanger(record.aiDanger),
    aiReason: truncateText(record.aiReason, MAX_SYNC_REASON_LENGTH),
    aiRecommendation: truncateText(record.aiRecommendation, MAX_SYNC_RECOMMENDATION_LENGTH),
    added: Number.isFinite(Number(record.added)) ? Number(record.added) : Date.now(),
    updatedAt: Number.isFinite(Number(record.updatedAt)) ? Number(record.updatedAt) : Date.now()
  };
}

function getBaseWhitelistRecord(record) {
  const source = record && typeof record === 'object' ? record : { url: record };
  const url = normalizeSiteUrl(source?.url);
  if (!url) return null;

  return {
    url,
    added: Number.isFinite(Number(source.added)) ? Number(source.added) : Date.now()
  };
}

function mergeSiteRecord(existingRecord, patchRecord) {
  const base = getBaseSiteRecord(existingRecord) || { url: patchRecord.url, added: patchRecord.added };

  return {
    ...base,
    ...patchRecord,
    added: Number.isFinite(Number(base.added)) ? Number(base.added) : patchRecord.added,
    updatedAt: Date.now()
  };
}

async function getMonitoredSites() {
  const { [MONITORED_SITES_STORAGE_KEY]: monitoredSites = [] } =
    await chrome.storage.sync.get(MONITORED_SITES_STORAGE_KEY);

  if (!Array.isArray(monitoredSites)) return [];

  return monitoredSites
    .map((site) => getBaseSiteRecord(site))
    .filter(Boolean);
}

async function getWhitelistedSites() {
  const { [WHITELISTED_SITES_STORAGE_KEY]: whitelistedSites = [] } =
    await chrome.storage.sync.get(WHITELISTED_SITES_STORAGE_KEY);

  if (!Array.isArray(whitelistedSites)) return [];

  return whitelistedSites
    .map((site) => getBaseWhitelistRecord(site))
    .filter((site, index, collection) => collection.findIndex((item) => isSameSiteUrl(item.url, site.url)) === index);
}

async function isSiteWhitelisted(url) {
  const whitelistedSites = await getWhitelistedSites();
  return whitelistedSites.some((site) => isSameSiteUrl(site.url, url));
}

async function saveMonitoredSites(sites) {
  await debugTrace('storage.sync.save.start', {
    sitesCount: Array.isArray(sites) ? sites.length : null
  });
  await chrome.storage.sync.set({ [MONITORED_SITES_STORAGE_KEY]: sites });
  await debugTrace('storage.sync.save.success', {
    sitesCount: Array.isArray(sites) ? sites.length : null
  });
  return sites;
}

async function saveMonitoredSiteSummary(summary) {
  const sites = await getMonitoredSites();
  const existingIndex = sites.findIndex((site) => site.url === summary.url);
  const merged =
    existingIndex === -1
      ? summary
      : mergeSiteRecord(sites[existingIndex], summary);

  const nextSites = existingIndex === -1 ? [...sites, merged] : sites.map((site, index) => (
    index === existingIndex ? merged : site
  ));

  try {
    return await saveMonitoredSites(nextSites);
  } catch (error) {
    await debugTrace('storage.sync.save.error', {
      url: summary.url,
      error: error?.message || String(error)
    });
    const compactSites = nextSites.map((site) => ({
      url: site.url,
      risk: site.risk,
      score: site.score,
      aiDanger: site.aiDanger,
      added: site.added,
      updatedAt: site.updatedAt
    }));

    await logEvent({
      category: 'system',
      level: 'warn',
      event: 'sync_storage_compacted',
      title: 'Sync-хранилище переполнено',
      message: 'Список отслеживаемых сайтов сохранён в сокращённом виде.',
      context: {
        reason: error.message
      }
    });
    return saveMonitoredSites(compactSites);
  }
}

async function saveSiteDetails(url, payload) {
  const storageKey = getSiteDetailsStorageKey(url);
  const detailsRecord = {
    updatedAt: Date.now(),
    ...payload
  };

  await debugTrace('storage.local.details.save.start', {
    url,
    storageKey,
    issuesCount: Array.isArray(payload?.issues) ? payload.issues.length : 0
  });
  await chrome.storage.local.set({ [storageKey]: detailsRecord });
  await debugTrace('storage.local.details.save.success', {
    url,
    storageKey
  });
}

function buildSiteSummary(data, extra = {}) {
  const url = String(data?.url || '').trim();
  if (!url) {
    throw new Error('Missing analyzed page URL');
  }

  return getBaseSiteRecord({
    url,
    risk: data?.risk,
    score: data?.score,
    issues: data?.issues,
    aiDanger: extra.aiDanger,
    aiReason: extra.aiReason,
    aiRecommendation: extra.aiRecommendation,
    added: extra.added
  });
}

async function persistAnalysisResult(data, extra = {}) {
  const summary = buildSiteSummary(data, extra);
  await debugTrace('analysis.persist.start', {
    url: summary.url,
    source: extra.source || 'heuristic',
    risk: summary.risk,
    score: summary.score
  });

  const tasks = [
    saveMonitoredSiteSummary(summary),
    saveSiteDetails(summary.url, {
      risk: summary.risk,
      score: summary.score,
      issues: Array.isArray(data?.issues) ? data.issues : [],
      details: data?.details || null,
      aiDanger: normalizeAiDanger(extra.aiDanger),
      aiReason: String(extra.aiReason || ''),
      aiRecommendation: String(extra.aiRecommendation || ''),
      source: extra.source || 'heuristic'
    })
  ];

  const [syncResult, localResult] = await Promise.allSettled(tasks);
  await debugTrace('analysis.persist.done', {
    url: summary.url,
    syncStatus: syncResult.status,
    localStatus: localResult.status
  });

  if (syncResult.status === 'rejected') {
    await logEvent(
      {
        category: 'system',
        level: 'error',
        event: 'monitored_site_summary_save_failed',
        title: 'Не удалось сохранить карточку сайта',
        message: 'Сводная информация по сайту не была записана в sync-хранилище.',
        context: {
          reason: syncResult.reason?.message || String(syncResult.reason || ''),
          site: summary.url
        }
      },
      null,
      summary.url
    );
  }

  if (localResult.status === 'rejected') {
    await logEvent(
      {
        category: 'system',
        level: 'error',
        event: 'local_analysis_details_save_failed',
        title: 'Не удалось сохранить детали анализа',
        message: 'Подробные данные локального анализа не были записаны.',
        context: {
          reason: localResult.reason?.message || String(localResult.reason || ''),
          site: summary.url
        }
      },
      null,
      summary.url
    );
  }

  const syncedSites = syncResult.status === 'fulfilled' ? syncResult.value : null;
  await updateStats(summary.risk, syncedSites, summary.url);

  return summary;
}

async function handlePageAnalysis(data) {
  if (await isSiteWhitelisted(data?.url)) {
    await debugTrace('analysis.heuristic.skipped_whitelist', {
      url: String(data?.url || '')
    });
    return;
  }

  const summary = await persistAnalysisResult(data, { source: 'heuristic' });
  await debugTrace('analysis.heuristic.stored', {
    url: summary.url,
    risk: summary.risk,
    score: summary.score
  });
  await logEvent(
    {
      category: 'analysis',
      level: 'success',
      event: 'heuristic_analysis_saved',
      title: 'Эвристический анализ сохранён',
      message: `Сайт ${summary.url} обновлён в журнале мониторинга.`,
      context: {
        risk: summary.risk,
        score: summary.score ?? 'n/a'
      }
    },
    null,
    summary.url
  );

  if (data?.encryptedByAI && Number(data?.encryptedCount) > 0) {
    await logEvent(
      {
        category: 'encryption',
        level: 'success',
        event: 'auto_encrypt_confirmed',
        title: 'Подтверждено авто-шифрование',
        message: `После AI-анализа зашифровано ${data.encryptedCount} записей.`,
        context: {
          count: Number(data.encryptedCount) || 0,
          trigger: 'ai'
        }
      },
      null,
      summary.url
    );
  }
}

async function handleFullPageAnalysis(data) {
  const settings = await getExtensionSettings();
  const url = String(data?.url || '').trim();

  if (!url) {
    throw new Error('Missing analyzed page URL');
  }

  if (await isSiteWhitelisted(url)) {
    await debugTrace('analysis.full.skipped_whitelist', { url });
    return buildFullResponse(data, {
      aiDanger: 'low',
      aiReason: 'Site is whitelisted',
      aiRecommendation: ''
    });
  }

  await persistAnalysisResult(data, { source: 'heuristic' });
  await debugTrace('analysis.full.requested', {
    url,
    mode: settings.mode,
    endpoint: settings.lmStudioEndpoint,
    model: settings.lmStudioModel
  });
  await logEvent(
    {
      category: 'ai',
      level: 'info',
      event: 'hybrid_analysis_requested',
      title: 'Запущен гибридный анализ',
      message: 'Локальный результат передан в LM Studio для дополнительной оценки.',
      context: {
        mode: settings.mode,
        risk: normalizeRisk(data?.risk),
        score: normalizeScore(data?.score) ?? 'n/a'
      }
    },
    null,
    url
  );

  if (settings.mode === 'local') {
    await debugTrace('analysis.full.local_mode', { url });
    return buildFullResponse(data, {
      aiDanger: 'low',
      aiReason: '',
      aiRecommendation: ''
    });
  }

  let aiAssessment = null;
  try {
    aiAssessment = await askLmStudioAboutSite(data, settings);
    await debugTrace('analysis.full.lm.success', {
      url,
      aiDanger: aiAssessment?.danger || ''
    });
    await logEvent(
      {
        category: 'ai',
        level: 'success',
        event: 'lm_verdict_received',
        title: 'Получен AI-вердикт',
        message: 'LM Studio вернул итоговую оценку поведения страницы.',
        context: {
          danger: aiAssessment.danger
        }
      },
      null,
      url
    );
  } catch (error) {
    await debugTrace('analysis.full.lm.error', {
      url,
      error: error?.message || String(error)
    });
    await logEvent(
      {
        category: 'ai',
        level: 'error',
        event: 'lm_request_failed',
        title: 'Ошибка запроса к LM Studio',
        message: error.message
      },
      null,
      url
    );
  }

  const aiDanger = aiAssessment?.danger || 'low';
  const aiReason = aiAssessment?.reason || '';
  const aiRecommendation = aiAssessment?.recommendation || '';

  await persistAnalysisResult(data, {
    source: aiAssessment ? 'lm_studio' : 'heuristic_fallback',
    aiDanger,
    aiReason,
    aiRecommendation
  });

  return buildFullResponse(data, {
    aiDanger,
    aiReason,
    aiRecommendation
  });
}

function buildFullResponse(data, extra) {
  return {
    url: String(data?.url || ''),
    risk: normalizeRisk(data?.risk),
    score: normalizeScore(data?.score),
    issues: Array.isArray(data?.issues) ? data.issues : [],
    details: data?.details || null,
    aiDanger: normalizeAiDanger(extra?.aiDanger) || 'low',
    aiReason: String(extra?.aiReason || ''),
    aiRecommendation: String(extra?.aiRecommendation || '')
  };
}

function buildPromptDetailsSummary(details) {
  if (!details || typeof details !== 'object') return '';

  const summary = {
    version: details.version || null,
    observationMs: details.observationMs || null,
    probeReady: Boolean(details.probeReady),
    probeErrors: Number(details.probeErrors) || 0,
    components: details.components || null,
    metrics: {
      storage: details.metrics?.storage
        ? {
            localWrites: details.metrics.storage.localWrites,
            localReads: details.metrics.storage.localReads,
            sensitiveKeyWrites: details.metrics.storage.sensitiveKeyWrites,
            highEntropyWrites: details.metrics.storage.highEntropyWrites,
            largeValueWrites: details.metrics.storage.largeValueWrites,
            sensitiveHighEntropyWrites: details.metrics.storage.sensitiveHighEntropyWrites,
            writeBurst1s: details.metrics.storage.writeBurst1s
          }
        : null,
      network: details.metrics?.network
        ? {
            totalRequests: details.metrics.network.totalRequests,
            crossOriginRequests: details.metrics.network.crossOriginRequests,
            requestsAfterStorageEvent: details.metrics.network.requestsAfterStorageEvent,
            requestsAfterSensitiveWrite: details.metrics.network.requestsAfterSensitiveWrite,
            encodedPayloadRequests: details.metrics.network.encodedPayloadRequests,
            unrelatedRequests: details.metrics.network.unrelatedRequests,
            apiRequests: details.metrics.network.apiRequests,
            unrelatedApiRequests: details.metrics.network.unrelatedApiRequests,
            mutatingRequests: details.metrics.network.mutatingRequests,
            mutatingAfterSensitiveWrite: details.metrics.network.mutatingAfterSensitiveWrite,
            uniqueHosts: details.metrics.network.uniqueHosts,
            unrelatedHosts: details.metrics.network.unrelatedHosts
          }
        : null,
      activity: details.metrics?.activity
        ? {
            fastTimeoutRegistrations: details.metrics.activity.fastTimeoutRegistrations,
            fastIntervalRegistrations: details.metrics.activity.fastIntervalRegistrations,
            beforeUnloadListeners: details.metrics.activity.beforeUnloadListeners,
            unloadListeners: details.metrics.activity.unloadListeners,
            hiddenStorageOps: details.metrics.activity.hiddenStorageOps,
            hiddenNetworkRequests: details.metrics.activity.hiddenNetworkRequests,
            mutationRatePerSec: details.metrics.activity.mutationRatePerSec
          }
        : null
    },
    hotKeys: Array.isArray(details.hotKeys) ? details.hotKeys.slice(0, 4) : [],
    hotDomains: Array.isArray(details.hotDomains) ? details.hotDomains.slice(0, 4) : []
  };

  const serialized = JSON.stringify(summary);
  if (serialized.length <= MAX_PROMPT_JSON_LENGTH) {
    return serialized;
  }

  return `${serialized.slice(0, MAX_PROMPT_JSON_LENGTH)}...`;
}

function buildLmStudioPrompt(data) {
  const issues = sanitizeIssues(data?.issues, MAX_PROMPT_ISSUES, 220);
  const detailsSummary = buildPromptDetailsSummary(data?.details);

  return [
    'You are a web security analyst.',
    'Assess whether the site behavior looks malicious, suspicious, or normal.',
    'Always include exactly one line in the answer: Danger: high, Danger: medium, or Danger: low.',
    '',
    `URL: ${String(data?.url || '')}`,
    `Heuristic risk: ${normalizeRisk(data?.risk)}`,
    `Heuristic score: ${normalizeScore(data?.score) ?? 'n/a'}`,
    `Top issues: ${issues.length > 0 ? issues.join('; ') : 'none'}`,
    `Behavior summary: ${detailsSummary || 'none'}`,
    '',
    'After the danger line, give a short reason in plain text.'
  ].join('\n');
}

function extractLmText(payload) {
  const choice = payload?.choices?.[0];
  if (!choice || typeof choice !== 'object') return '';

  const directMessage = choice.message?.content;
  if (typeof directMessage === 'string') return directMessage.trim();

  if (Array.isArray(directMessage)) {
    return directMessage
      .map((item) => {
        if (typeof item === 'string') return item;
        if (typeof item?.text === 'string') return item.text;
        if (typeof item?.content === 'string') return item.content;
        return '';
      })
      .join('')
      .trim();
  }

  if (typeof choice.text === 'string') return choice.text.trim();
  return '';
}

function parseDangerLevel(text) {
  const lower = String(text || '').toLowerCase();

  if (
    lower.includes('danger: high') ||
    lower.includes('risk: high') ||
    lower.includes('уровень опасности: high') ||
    lower.includes('опасность: high') ||
    lower.includes('высокий риск')
  ) {
    return 'high';
  }

  if (
    lower.includes('danger: medium') ||
    lower.includes('risk: medium') ||
    lower.includes('уровень опасности: medium') ||
    lower.includes('опасность: medium') ||
    lower.includes('средний риск')
  ) {
    return 'medium';
  }

  return 'low';
}

async function askLmStudioAboutSite(data, settings) {
  const endpoint = normalizeEndpoint(settings?.lmStudioEndpoint);
  const model = normalizeModel(settings?.lmStudioModel);
  const timeoutMs = normalizeTimeout(settings?.lmStudioTimeoutMs);
  const prompt = buildLmStudioPrompt(data);
  const requestBody = {
    model,
    temperature: 0.2,
    messages: [
      {
        role: 'system',
        content:
          'You analyze browser security signals. Always include one line formatted exactly as Danger: high|medium|low.'
      },
      {
        role: 'user',
        content: prompt
      }
    ]
  };

  await logEvent(
    {
      category: 'ai',
      level: 'info',
      event: 'lm_request_started',
      title: 'Запрос к LM Studio отправлен',
      message: 'Расширение отправило сводку сигналов страницы на AI-анализ.',
      context: {
        endpoint,
        model
      }
    },
    null,
    String(data?.url || 'background')
  );
  await debugTrace('lm.request.start', {
    url: data?.url,
    endpoint,
    model,
    timeoutMs,
    promptPreview: prompt.slice(0, 500)
  });

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

  let response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody),
      signal: abortController.signal
    });
    await debugTrace('lm.request.fetch_resolved', {
      url: data?.url,
      ok: response.ok,
      status: response.status,
      statusText: response.statusText
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      await debugTrace('lm.request.abort', {
        url: data?.url,
        timeoutMs
      });
      throw new Error(`LM Studio did not answer within ${timeoutMs}ms`);
    }

    await debugTrace('lm.request.fetch_error', {
      url: data?.url,
      name: error?.name || '',
      message: error?.message || String(error),
      stack: error?.stack || ''
    });
    throw new Error(`LM Studio network error: ${error.message}`);
  } finally {
    clearTimeout(timeoutId);
  }

  const rawText = await response.text().catch(() => '');
  await debugTrace('lm.request.response_text', {
    url: data?.url,
    status: response.status,
    bodyPreview: rawText.slice(0, 500)
  });

  if (!response.ok) {
    throw new Error(`LM Studio HTTP ${response.status}${rawText ? `: ${rawText.slice(0, 300)}` : ''}`);
  }

  let payload;
  try {
    payload = rawText ? JSON.parse(rawText) : {};
  } catch {
    throw new Error(`LM Studio returned non-JSON response: ${rawText.slice(0, 300)}`);
  }

  const text = extractLmText(payload);
  if (!text) {
    throw new Error(`LM Studio returned an empty completion: ${rawText.slice(0, 300)}`);
  }

  await debugTrace('lm.request.parsed', {
    url: data?.url,
    danger: parseDangerLevel(text),
    textPreview: text.slice(0, 400)
  });
  await logEvent(
    {
      category: 'ai',
      level: 'info',
      event: 'lm_response_received',
      title: 'Получен ответ LM Studio',
      message: truncateText(text, 400)
    },
    null,
    String(data?.url || 'background')
  );

  return {
    danger: parseDangerLevel(text),
    reason: truncateText(text, 400),
    recommendation: ''
  };
}

async function handleLmStudioTest(request, sender) {
  const settings = await getExtensionSettings();
  const endpoint = normalizeEndpoint(request?.endpoint || settings.lmStudioEndpoint);
  const model = normalizeModel(request?.model || settings.lmStudioModel);
  const timeoutMs = normalizeTimeout(request?.timeoutMs || settings.lmStudioTimeoutMs);

  await debugTrace('lm.test.start', {
    endpoint,
    model,
    timeoutMs,
    senderUrl: getSenderUrl(sender)
  });

  const result = await askLmStudioAboutSite(
    {
      url: 'chrome-extension://lm-test',
      risk: 'medium',
      score: 50,
      issues: ['Manual connectivity test from options page'],
      details: {
        version: 'lm-test',
        observationMs: 0,
        probeReady: true,
        probeErrors: 0,
        components: null,
        metrics: null,
        hotKeys: [],
        hotDomains: []
      }
    },
    {
      lmStudioEndpoint: endpoint,
      lmStudioModel: model,
      lmStudioTimeoutMs: timeoutMs
    }
  );

  await debugTrace('lm.test.success', {
    endpoint,
    model,
    danger: result?.danger || ''
  });

  return {
    ok: true,
    endpoint,
    model,
    timeoutMs,
    danger: result?.danger || 'low',
    reason: result?.reason || ''
  };
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

self.addEventListener('unhandledrejection', (event) => {
  void debugTrace('worker.unhandledrejection', {
    reason: event?.reason?.message || String(event?.reason || '')
  });
});

self.addEventListener('error', (event) => {
  void debugTrace('worker.error', {
    message: event?.message || '',
    filename: event?.filename || '',
    lineno: event?.lineno || 0,
    colno: event?.colno || 0
  });
});
