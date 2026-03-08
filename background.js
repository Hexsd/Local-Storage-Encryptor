const std = 'http://127.0.0.1:1234/v1/chat/completions';
const model = 'gpt-4o-mini';

chrome.runtime.onInstalled.addListener(() => {
  logEvent('Расширение установлено', 'system');
});


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    if (request.action === 'show_notification') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/128.png',
        title: 'Local Storage Encryptor',
        message: request.message || 'Обнаружен потенциальный риск!'
      });
    }

    if (request.action === 'page_analyzed') {
      handlePageAnalysis(request)
        .catch(e => logEvent(`Анализ страницы: ${e.message}`, 'error'));
    }

    if (request.action === 'page_analyzed_full') {
      handleFullPageAnalysis(request, sender, sendResponse);
      return true;
    }

    if (request.action === 'log_event') {
      logEvent(request.message, request.type);
    }
  } catch (e) {
    logEvent(`Background ошибка: ${e.message}`, 'error');
  }
});

async function logEvent(message, type = 'info') {
  try {
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
    `Отправка запроса в LM Studio для ${url}: угроза=${risk}, счет=${score}`,
    'request'
  );

  const body = {
    model: model,
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

  const response = await fetch(std, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    throw new Error(`LM Studio HTTP ${response.status}`);
  }

  const dataResp = await response.json();
  const text = dataResp.choices?.[0]?.message?.content || '';

  await logEvent(
    `Ответ LM Studio для ${url}: ${text.slice(0, 400)}`,
    'lm_response'
  );

  const lower = text.toLowerCase();
  let danger = 'низкий';

  if (lower.includes('уровень опасности: high') || lower.includes('опасность: high')) {
    danger = 'высокий';
  } else if (lower.includes('уровень опасности: medium') || lower.includes('опасность: medium')) {
    danger = 'средний';
  } else if (lower.includes('уровень опасности: low') || lower.includes('опасность: low')) {
    danger = 'низкий';
  } else if (lower.includes('высокий риск') || lower.includes('очень опасн')) {
    danger = 'высокий';
  } else if (lower.includes('средний риск')) {
    danger = 'средний';
  } else if (lower.includes('низкий риск')) {
    danger = 'низкий';
  }

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
          aiDanger: 'low',
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
