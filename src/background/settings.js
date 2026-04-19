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
  if (!Number.isFinite(timeout) || timeout < MIN_LM_STUDIO_TIMEOUT_MS) {
    return DEFAULT_LM_STUDIO_TIMEOUT_MS;
  }
  return Math.min(Math.max(Math.round(timeout), MIN_LM_STUDIO_TIMEOUT_MS), MAX_LM_STUDIO_TIMEOUT_MS);
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
