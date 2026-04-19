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

function formatSiteDate(timestamp) {
  const value = Number(timestamp);
  if (!Number.isFinite(value)) return 'только что';

  return new Date(value).toLocaleDateString('ru-RU');
}
