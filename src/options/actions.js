async function addSite() {
  const rawUrl = dom.siteInput.value.trim();
  const normalizedUrl = normalizeSiteUrl(rawUrl);

  if (!normalizedUrl) {
    dom.siteInput.classList.add('is-invalid');
    showSiteFeedback('Введите корректный URL, например example.com, http://example.com или file:///C:/site.html', 'error');
    return;
  }

  const { monitoredSites, whitelistedSites } = await getSiteCollections();
  const exists = hasSiteUrl(monitoredSites, normalizedUrl);

  if (exists) {
    showSiteFeedback('Этот сайт уже есть в списке.', 'error');
    return;
  }

  if (hasSiteUrl(whitelistedSites, normalizedUrl)) {
    showSiteFeedback('Этот сайт уже находится в белом списке.', 'error');
    return;
  }

  const nextMonitoredSites = [...monitoredSites, { url: normalizedUrl, risk: 'low', added: Date.now() }];
  await chrome.storage.sync.set({ monitoredSites: nextMonitoredSites });
  await syncStatsBySites(nextMonitoredSites);
  await sendLog({
    category: 'settings',
    level: 'success',
    event: 'site_added',
    title: 'Сайт добавлен в мониторинг',
    message: 'Новый сайт будет участвовать в автоматическом анализе.',
    source: 'options',
    url: normalizedUrl
  });

  dom.siteInput.value = '';
  dom.siteInput.classList.remove('is-invalid');
  showSiteFeedback('Сайт добавлен в мониторинг.', 'success');

  await Promise.all([loadSiteCollections(), loadStats()]);
}

async function removeSite(url) {
  const { monitoredSites, whitelistedSites } = await getSiteCollections();
  const filtered = monitoredSites.filter((site) => !isSameSiteUrl(site.url, url));

  if (filtered.length === monitoredSites.length) return;

  await chrome.storage.sync.set({ monitoredSites: filtered, whitelistedSites });
  await syncStatsBySites(filtered);
  await sendLog({
    category: 'settings',
    level: 'info',
    event: 'site_removed',
    title: 'Сайт удалён из мониторинга',
    message: 'Сайт больше не будет автоматически отслеживаться.',
    source: 'options',
    url
  });
  showSiteFeedback('Сайт удалён из списка.', 'success');

  await Promise.all([loadSiteCollections(), loadStats()]);
}

async function addWhitelistSite() {
  const rawUrl = dom.whitelistInput.value.trim();
  const normalizedUrl = normalizeSiteUrl(rawUrl);

  if (!normalizedUrl) {
    dom.whitelistInput.classList.add('is-invalid');
    showWhitelistFeedback('Введите корректный URL, например example.com, http://example.com или file:///C:/site.html', 'error');
    return;
  }

  const { monitoredSites, whitelistedSites } = await getSiteCollections();

  if (hasSiteUrl(whitelistedSites, normalizedUrl)) {
    showWhitelistFeedback('Этот сайт уже есть в белом списке.', 'error');
    return;
  }

  if (hasSiteUrl(monitoredSites, normalizedUrl)) {
    showWhitelistFeedback('Этот сайт уже отслеживается. Перенесите его кнопкой из списка мониторинга.', 'error');
    return;
  }

  const nextWhitelistedSites = [...whitelistedSites, { url: normalizedUrl, added: Date.now() }];
  await chrome.storage.sync.set({ monitoredSites, whitelistedSites: nextWhitelistedSites });
  await sendLog({
    category: 'settings',
    level: 'success',
    event: 'site_whitelisted',
    title: 'Сайт добавлен в белый список',
    message: 'Этот сайт исключён из анализа и мониторинга.',
    source: 'options',
    url: normalizedUrl
  });

  dom.whitelistInput.value = '';
  dom.whitelistInput.classList.remove('is-invalid');
  showWhitelistFeedback('Сайт добавлен в белый список.', 'success');

  await Promise.all([loadSiteCollections(), loadStats()]);
}

async function removeWhitelistedSite(url) {
  const { monitoredSites, whitelistedSites } = await getSiteCollections();
  const filtered = whitelistedSites.filter((site) => !isSameSiteUrl(site.url, url));

  if (filtered.length === whitelistedSites.length) return;

  await chrome.storage.sync.set({ monitoredSites, whitelistedSites: filtered });
  await sendLog({
    category: 'settings',
    level: 'info',
    event: 'site_removed_from_whitelist',
    title: 'Сайт удалён из белого списка',
    message: 'Сайт снова можно добавить в мониторинг при необходимости.',
    source: 'options',
    url
  });
  showWhitelistFeedback('Сайт удалён из белого списка.', 'success');

  await Promise.all([loadSiteCollections(), loadStats()]);
}

async function moveSiteToWhitelist(url) {
  const { monitoredSites, whitelistedSites } = await getSiteCollections();
  const siteToMove = monitoredSites.find((site) => isSameSiteUrl(site.url, url));
  if (!siteToMove) return;

  const nextMonitoredSites = monitoredSites.filter((site) => !isSameSiteUrl(site.url, url));
  const nextWhitelistedSites = hasSiteUrl(whitelistedSites, siteToMove.url)
    ? whitelistedSites
    : [...whitelistedSites, { url: siteToMove.url, added: Date.now() }];

  await chrome.storage.sync.set({
    monitoredSites: nextMonitoredSites,
    whitelistedSites: nextWhitelistedSites
  });
  await syncStatsBySites(nextMonitoredSites);
  await sendLog({
    category: 'settings',
    level: 'info',
    event: 'site_moved_to_whitelist',
    title: 'Сайт перенесён в белый список',
    message: 'Сайт исключён из автоматического анализа.',
    source: 'options',
    url: siteToMove.url
  });
  showSiteFeedback('Сайт перенесён в белый список.', 'success');

  await Promise.all([loadSiteCollections(), loadStats()]);
}

async function moveWhitelistToMonitoring(url) {
  const { monitoredSites, whitelistedSites } = await getSiteCollections();
  const siteToMove = whitelistedSites.find((site) => isSameSiteUrl(site.url, url));
  if (!siteToMove) return;

  const nextWhitelistedSites = whitelistedSites.filter((site) => !isSameSiteUrl(site.url, url));
  const nextMonitoredSites = hasSiteUrl(monitoredSites, siteToMove.url)
    ? monitoredSites
    : [...monitoredSites, { url: siteToMove.url, risk: 'low', added: Date.now() }];

  await chrome.storage.sync.set({
    monitoredSites: nextMonitoredSites,
    whitelistedSites: nextWhitelistedSites
  });
  await syncStatsBySites(nextMonitoredSites);
  await sendLog({
    category: 'settings',
    level: 'success',
    event: 'site_moved_to_monitoring',
    title: 'Сайт возвращён в мониторинг',
    message: 'Сайт снова будет участвовать в автоматическом анализе.',
    source: 'options',
    url: siteToMove.url
  });
  showWhitelistFeedback('Сайт возвращён в мониторинг.', 'success');

  await Promise.all([loadSiteCollections(), loadStats()]);
}

async function saveSettings(event) {
  event.preventDefault();

  const { settings = {} } = await chrome.storage.sync.get('settings');
  const lmEndpoint = dom.lmEndpoint.value.trim() || DEFAULT_LM_ENDPOINT;
  const lmModel = getLmModelValue();

  const newSettings = {
    ...settings,
    mode: dom.modeSelect.value,
    fullAnalysisPolicy: dom.fullAnalysisPolicy.value === 'smart' ? 'smart' : 'always',
    lmStudioEndpoint: lmEndpoint,
    lmStudioModel: lmModel,
    notifications: dom.notifications.checked,
    logging: dom.logging.checked,
    autoEncrypt: true
  };

  await chrome.storage.sync.set({ settings: newSettings });
  await sendLog({
    category: 'settings',
    level: 'success',
    event: 'settings_saved',
    title: 'Настройки сохранены',
    message: 'Параметры анализа и уведомлений обновлены.',
    source: 'options',
    context: {
      mode: newSettings.mode,
      policy: newSettings.fullAnalysisPolicy,
      logging: newSettings.logging,
      notifications: newSettings.notifications
    }
  });
  flashSaveButton();
  showLmTestStatus('Настройки LM Studio сохранены.', 'success');
}

async function testLmStudioConnection() {
  const endpoint = dom.lmEndpoint.value.trim() || DEFAULT_LM_ENDPOINT;
  const model = getLmModelValue();

  setButtonBusy(dom.testLmBtn, true, 'Проверяем...');
  showLmTestStatus('Проверяем подключение к LM Studio...', 'info');

  try {
    const response = await sendRuntimeMessage({
      action: 'test_lm_studio',
      endpoint,
      model
    });

    if (!response?.success || !response?.data?.ok) {
      throw new Error(response?.error || 'Нет ответа от service worker');
    }

    const result = response.data;
    await sendLog({
      category: 'ai',
      level: 'success',
      event: 'lm_connection_test_success',
      title: 'Проверка LM Studio успешна',
      message: 'Тестовый запрос к LM Studio завершился успешно.',
      source: 'options',
      context: {
        model: result.model,
        verdict: normalizeAiDanger(result.danger) || result.danger
      }
    });
    showLmTestStatus(
      `LM Studio отвечает. Модель: ${result.model}. Вердикт: ${normalizeAiDanger(result.danger) || result.danger}.`,
      'success'
    );
  } catch (error) {
    await sendLog({
      category: 'ai',
      level: 'error',
      event: 'lm_connection_test_failed',
      title: 'Проверка LM Studio завершилась ошибкой',
      message: error.message,
      source: 'options'
    });
    showLmTestStatus(`Ошибка LM Studio: ${error.message}`, 'error');
  } finally {
    setButtonBusy(dom.testLmBtn, false);
  }
}

function flashSaveButton() {
  if (!dom.saveSettingsBtn) return;
  const baseLabel = dom.saveSettingsBtn.dataset.baseLabel || 'Сохранить настройки';

  if (saveButtonTimer) {
    window.clearTimeout(saveButtonTimer);
    saveButtonTimer = null;
  }

  dom.saveSettingsBtn.textContent = 'Сохранено';
  dom.saveSettingsBtn.classList.add('is-saved');

  saveButtonTimer = window.setTimeout(() => {
    dom.saveSettingsBtn.textContent = baseLabel;
    dom.saveSettingsBtn.classList.remove('is-saved');
    saveButtonTimer = null;
  }, 1400);
}

async function clearLogs() {
  const shouldClear = window.confirm('Очистить все логи?');
  if (!shouldClear) return;

  await chrome.storage.local.set({ logs: [] });
  await loadLogs();
}
