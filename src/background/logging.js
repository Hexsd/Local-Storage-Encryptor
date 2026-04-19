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
