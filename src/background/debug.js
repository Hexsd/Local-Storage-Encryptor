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
