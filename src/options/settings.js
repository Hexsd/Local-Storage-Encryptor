async function loadSettings() {
  const { settings = {} } = await chrome.storage.sync.get('settings');

  dom.modeSelect.value = settings.mode === 'local' ? 'local' : 'hybrid';
  dom.fullAnalysisPolicy.value = settings.fullAnalysisPolicy === 'smart' ? 'smart' : 'always';
  dom.lmEndpoint.value = typeof settings.lmStudioEndpoint === 'string' && settings.lmStudioEndpoint.trim()
    ? settings.lmStudioEndpoint
    : DEFAULT_LM_ENDPOINT;
  if (dom.lmModel) {
    dom.lmModel.value = typeof settings.lmStudioModel === 'string' && settings.lmStudioModel.trim()
      ? settings.lmStudioModel
      : DEFAULT_LM_MODEL;
  }
  dom.notifications.checked = settings.notifications !== false;
  dom.logging.checked = settings.logging !== false;

  const protectionEnabled = settings.protectionEnabled !== false;
  updateProtectionUi(protectionEnabled);
}

function updateProtectionUi(enabled) {
  dom.protectionToggle.textContent = enabled ? 'Отключить защиту' : 'Включить защиту';
  dom.protectionToggle.classList.toggle('protection-on', enabled);
  dom.protectionToggle.classList.toggle('protection-off', !enabled);

  dom.protectionState.textContent = enabled ? 'Защита активна' : 'Защита отключена';
  dom.protectionState.classList.toggle('is-on', enabled);
  dom.protectionState.classList.toggle('is-off', !enabled);
}

async function toggleProtection() {
  const { settings = {} } = await chrome.storage.sync.get('settings');
  const currentlyEnabled = settings.protectionEnabled !== false;
  const nextState = !currentlyEnabled;

  settings.protectionEnabled = nextState;
  await chrome.storage.sync.set({ settings });

  updateProtectionUi(nextState);

  await sendLog({
    category: 'settings',
    level: 'info',
    event: 'protection_toggled',
    title: nextState ? 'Защита включена' : 'Защита отключена',
    message: nextState
      ? 'Мониторинг и автоматическая защита снова активны.'
      : 'Мониторинг временно остановлен пользователем.',
    source: 'options'
  });
}
