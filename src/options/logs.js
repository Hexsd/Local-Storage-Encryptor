async function loadLogs() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  const loggingEnabled = settings.logging !== false;

  if (!loggingEnabled) {
    dom.logsList.replaceChildren();
    dom.clearLogsBtn.disabled = true;
    updateLogsSummary(0, 0);
    appendEmptyState(dom.logsList, 'Логирование отключено в настройках.');
    return;
  }

  const { logs = [] } = await chrome.storage.local.get('logs');
  dom.logsList.replaceChildren();

  const normalizedLogs = Array.isArray(logs)
    ? logs
        .map((log) => normalizeStoredLog(log))
        .filter(Boolean)
        .sort((left, right) => right.timestamp - left.timestamp)
    : [];
  const filteredLogs = normalizedLogs.filter((log) => matchesLogFilters(log));
  const displayedLogs = filteredLogs.slice(0, VISIBLE_LOGS_LIMIT);

  dom.clearLogsBtn.disabled = normalizedLogs.length === 0;
  updateLogsSummary(displayedLogs.length, filteredLogs.length, normalizedLogs.length);

  if (normalizedLogs.length === 0) {
    appendEmptyState(dom.logsList, 'Журнал пока пуст.');
    return;
  }

  if (filteredLogs.length === 0) {
    appendEmptyState(dom.logsList, 'По текущим фильтрам событий не найдено.');
    return;
  }

  displayedLogs.forEach((log) => {
    dom.logsList.appendChild(createLogEntry(log));
  });
}

function createLogEntry(log) {
  const entry = document.createElement('div');
  entry.className = `log-entry tone-${log.level}`;

  const head = document.createElement('div');
  head.className = 'log-head';

  const badges = document.createElement('div');
  badges.className = 'log-badges';
  badges.append(
    createLogBadge(getLogCategoryMeta(log.category).label, `tone-${getLogCategoryMeta(log.category).tone}`),
    createLogBadge(getLogLevelMeta(log.level).label, `tone-${getLogLevelMeta(log.level).tone}`),
    createLogBadge(describeLogSource(log), 'tone-source')
  );

  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = formatTimestamp(log.timestamp);

  head.append(badges, time);

  const title = document.createElement('h3');
  title.className = 'log-title';
  title.textContent = log.title || 'Событие';

  const message = document.createElement('p');
  message.className = 'log-message';
  message.textContent = log.message || 'Без описания.';

  const meta = document.createElement('div');
  meta.className = 'log-details';

  const location = document.createElement('span');
  location.className = 'log-url';
  location.textContent = describeLogLocation(log);
  meta.appendChild(location);

  if (log.context && Object.keys(log.context).length > 0) {
    meta.appendChild(createLogContext(log.context));
  }

  entry.append(head, title, message, meta);

  return entry;
}
