const LM_STUDIO_ENDPOINT = 'http://127.0.0.1:1234/v1/chat/completions';
const LM_STUDIO_MODEL = 'gpt-4o-mini';
const LM_STUDIO_TIMEOUT_MS = 15000;

async function getExtensionSettings() {
  try {
    const { settings = {} } = await chrome.storage.sync.get('settings');
    return {
      notifications: settings.notifications !== false,
      logging: settings.logging !== false,
      mode: settings.mode || 'hybrid'
    };
  } catch {
    return {
      notifications: true,
      logging: true,
      mode: 'hybrid'
    };
  }
}

async function showNotification(message) {
  const { notifications } = await getExtensionSettings();
  if (!notifications) return;

  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/128.png',
    title: 'Local Storage Encryptor',
    message: message || 'Обнаружен потенциальный риск!'
  });
}

chrome.runtime.onInstalled.addListener(() => {
  void logEvent('Расширение установлено', 'system');
});


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    if (request.action === 'show_notification') {
      void showNotification(request.message);
    }

    if (request.action === 'page_analyzed') {
      handlePageAnalysis(request)
        .catch(e => void logEvent(`Анализ страницы: ${e.message}`, 'error'));
    }

    if (request.action === 'page_analyzed_full') {
      handleFullPageAnalysis(request, sender, sendResponse);
      return true;
    }

    if (request.action === 'log_event') {
      void logEvent(request.message, request.type);
    }
  } catch (e) {
    void logEvent(`Background ошибка: ${e.message}`, 'error');
  }
});

async function logEvent(message, type = 'info') {
  try {
    const { logging } = await getExtensionSettings();
    if (!logging) return;

    const { logs = [] } = await chrome.storage.local.get('logs');
    logs.push({
      timestamp: Date.now(),
      message,
      type,
      url: 'background'
    });
    if (logs.length > 500) logs.splice(0, logs.length - 500);
    await chrome.storage.local.set({ logs });
  } catch (e) {
    console.error('Критическая ошибка логирования:', e);
  }
}

function extractLmText(payload) {
  const direct = payload?.choices?.[0]?.message?.content;
  if (typeof direct === 'string') return direct;
  if (Array.isArray(direct)) {
    return direct
      .map(item => (typeof item?.text === 'string' ? item.text : ''))
      .join('')
      .trim();
  }
  return '';
}

function parseDangerLevel(text) {
  const lower = String(text || '').toLowerCase();

  if (
    lower.includes('уровень опасности: high') ||
    lower.includes('опасность: high') ||
    lower.includes('danger: high') ||
    lower.includes('risk: high') ||
    lower.includes('высокий риск') ||
    lower.includes('очень опасн')
  ) {
    return 'высокий';
  }

  if (
    lower.includes('уровень опасности: medium') ||
    lower.includes('опасность: medium') ||
    lower.includes('danger: medium') ||
    lower.includes('risk: medium') ||
    lower.includes('средний риск')
  ) {
    return 'средний';
  }

  if (
    lower.includes('уровень опасности: low') ||
    lower.includes('опасность: low') ||
    lower.includes('danger: low') ||
    lower.includes('risk: low') ||
    lower.includes('низкий риск')
  ) {
    return 'низкий';
  }

  return 'низкий';
}

async function askLmStudioAboutSite(data) {
  const { url, risk, score, issues, details } = data;

  const prompt = `
Ты – эксперт по информационной безопасности.
Определи уровень опасности сайта и кратко объясни.

Тебе даны:
- URL: ${url}
- Риск по эвристике: ${risk}
- Суммарный балл риска: ${score}
- Проблемы: ${(issues || []).join('; ')}
- Доп. детали: ${JSON.stringify(details || {})}

Ответь СВОБОДНЫМ текстом, но обязательно явно укажи строку вида:
"Уровень опасности: high" или "Уровень опасности: medium" или "Уровень опасности: low".
После этого можешь кратко объяснить, почему.
`;

  await logEvent(
    `LM Studio запрос: endpoint=${LM_STUDIO_ENDPOINT}, model=${LM_STUDIO_MODEL}, url=${url}, риск=${risk}, счет=${score}`,
    'request'
  );

  const body = {
    model: LM_STUDIO_MODEL,
    messages: [
      {
        role: 'system',
        content:
          'Ты помощник по безопасности веб-сайтов. Всегда явно пиши строку "Уровень опасности: high|medium|low".'
      },
      { role: 'user', content: prompt }
    ],
    temperature: 0.3
  };

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), LM_STUDIO_TIMEOUT_MS);

  let response;
  try {
    response = await fetch(LM_STUDIO_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: abortController.signal
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error(`LM Studio не ответил за ${LM_STUDIO_TIMEOUT_MS}мс`);
    }
    throw new Error(`Ошибка сети LM Studio: ${error.message}`);
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    const errorBody = (await response.text().catch(() => '')).slice(0, 300);
    throw new Error(`LM Studio HTTP ${response.status}${errorBody ? `: ${errorBody}` : ''}`);
  }

  let dataResp;
  try {
    dataResp = await response.json();
  } catch {
    throw new Error('LM Studio вернул не-JSON ответ');
  }

  const text = extractLmText(dataResp);
  if (!text.trim()) {
    throw new Error('LM Studio вернул пустой ответ');
  }

  await logEvent(
    `Ответ LM Studio для ${url}: ${text.slice(0, 400)}`,
    'lm_response'
  );

  const danger = parseDangerLevel(text);

  const reason = text.slice(0, 400);

  await logEvent(
    `LM Studio: уровень опасности - ${danger}`,
    'lm_parsed'
  );

  return {
    danger,
    reason,
    recommendation: ''
  };
}

async function handlePageAnalysis(data) {
  const { url, risk, score, issues, details, encryptedByAI, encryptedCount } = data;

  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  const existingIndex = monitoredSites.findIndex(site => site.url === url);

  let siteInfo = {
    url,
    risk,
    score,
    issues: issues || [],
    details: details || null,
    added: existingIndex === -1 ? Date.now() : (monitoredSites[existingIndex].added || Date.now())
  };

  if (existingIndex === -1) {
    monitoredSites.push(siteInfo);
    await logEvent(`Добавлен новый сайт в мониторинг: ${url}`, 'info');
  } else {
    monitoredSites[existingIndex] = { ...monitoredSites[existingIndex], ...siteInfo };
    await logEvent(`Обновлены данные сайта: ${url}`, 'info');
  }
  await chrome.storage.sync.set({ monitoredSites });

  await updateStats(risk);

  if (encryptedByAI && encryptedCount > 0) {
    await logEvent(
      `Подтверждено авто-шифрование по вердикту ИИ: ${encryptedCount} записей для ${url}`,
      'auto_encrypt_ai'
    );
  }
}

async function handleFullPageAnalysis(data, sender, sendResponse) {
  const { url, risk, score, issues, details } = data;

  try {
    await logEvent(
      `Полный анализ: url=${url}, угроза - ${risk}, счет - ${score}`,
      'info'
    );

    const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
    const existingIndex = monitoredSites.findIndex(site => site.url === url);

    let siteInfo = {
      url,
      risk,
      score,
      issues: issues || [],
      details: details || null,
      added: existingIndex === -1 ? Date.now() : (monitoredSites[existingIndex].added || Date.now())
    };

    if (existingIndex === -1) {
      monitoredSites.push(siteInfo);
      await logEvent(`добавлен новый сайт ${url}`, 'info');
    } else {
      monitoredSites[existingIndex] = { ...monitoredSites[existingIndex], ...siteInfo };
      await logEvent(`обновлён сайт ${url}`, 'info');
    }
    await chrome.storage.sync.set({ monitoredSites });
    await updateStats(risk);

    const { settings = {} } = await chrome.storage.sync.get('settings');
    const mode = settings.mode || 'hybrid';

    if (mode === 'local') {
      await logEvent(`Локальный режим анализа для ${url}`, 'info');
      sendResponse({
        success: true,
        data: {
          url,
          risk,
          score,
          issues: issues || [],
          details: details || null,
          aiDanger: 'низкий',
          aiReason: '',
          aiRecommendation: ''
        }
      });
      return;
    }

    await logEvent(`Полный анализ для ${url}`, 'info');

    let aiAssessment = null;
    try {
      aiAssessment = await askLmStudioAboutSite(data);
    } catch (e) {
      await logEvent(`Ошибка полного анализа для ${url}: ${e.message}`, 'error');
    }

    let aiDanger = 'низкий';
    let aiReason = '';
    let aiRecommendation = '';

    if (aiAssessment) {
      aiDanger = aiAssessment.danger || 'низкий';
      aiReason = aiAssessment.reason || '';
      aiRecommendation = aiAssessment.recommendation || '';

      await logEvent(
        `Полный анализ: Вердикт ИИ для ${url}: уровень опасности - ${aiDanger}`,
        'lm_verdict'
      );

      const { monitoredSites: sitesAfterAI = [] } = await chrome.storage.sync.get('monitoredSites');
      const idx = sitesAfterAI.findIndex(site => site.url === url);
      const target = idx === -1
        ? { url, added: Date.now() }
        : sitesAfterAI[idx];

      const updatedSite = {
        ...target,
        risk,
        score,
        issues: issues || [],
        details: details || null,
        aiDanger,
        aiReason,
        aiRecommendation
      };

      if (idx === -1) {
        sitesAfterAI.push(updatedSite);
      } else {
        sitesAfterAI[idx] = updatedSite;
      }

      await chrome.storage.sync.set({ monitoredSites: sitesAfterAI });
    }

    sendResponse({
      success: true,
      data: {
        url,
        risk,
        score,
        issues: issues || [],
        details: details || null,
        aiDanger,
        aiReason,
        aiRecommendation
      }
    });
  } catch (e) {
    await logEvent(`Полный анализ: ошибка обработки для ${url}: ${e.message}`, 'error');
    sendResponse({ success: false, error: e.message });
  }
}

async function updateStats(currentRisk) {
  const today = new Date().toISOString().split('T')[0];
  const { stats = {} } = await chrome.storage.local.get('stats');

  if (stats.lastDate !== today) {
    stats.threatsToday = 0;
    stats.lastDate = today;
  }

  if (currentRisk !== 'low') {
    stats.threatsToday = (stats.threatsToday || 0) + 1;
    stats.threatsMonth = (stats.threatsMonth || 0) + 1;
  }

  const { monitoredSites = [] } = await chrome.storage.sync.get('monitoredSites');
  stats.sitesCount = monitoredSites.length;

  if (monitoredSites.length > 0) {
    const avgScore = monitoredSites.reduce((sum, site) => sum + (site.score || 0), 0) / monitoredSites.length;
    stats.securityIndex = Math.max(0, Math.round(100 - Math.min(avgScore, 100)));
  } else {
    stats.securityIndex = 100;
  }

  await chrome.storage.local.set({ stats });
}
