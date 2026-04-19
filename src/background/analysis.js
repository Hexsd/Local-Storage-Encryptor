async function handlePageAnalysis(data) {
  const normalizedData = normalizeAnalyzedData(data);

  if (await isSiteWhitelisted(normalizedData.url)) {
    await debugTrace('analysis.heuristic.skipped_whitelist', {
      url: normalizedData.url
    });
    return;
  }

  const summary = await persistAnalysisResult(normalizedData, { source: 'heuristic' });
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
  const normalizedData = normalizeAnalyzedData(data);
  const { url } = normalizedData;

  if (await isSiteWhitelisted(url)) {
    await debugTrace('analysis.full.skipped_whitelist', { url });
    return buildFullResponse(normalizedData, {
      aiDanger: 'low',
      aiReason: 'Site is whitelisted',
      aiRecommendation: ''
    });
  }

  await persistAnalysisResult(normalizedData, { source: 'heuristic' });
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
        risk: normalizeRisk(normalizedData?.risk),
        score: normalizeScore(normalizedData?.score) ?? 'n/a'
      }
    },
    null,
    url
  );

  if (settings.mode === 'local') {
    await debugTrace('analysis.full.local_mode', { url });
    return buildFullResponse(normalizedData, {
      aiDanger: 'low',
      aiReason: '',
      aiRecommendation: ''
    });
  }

  let aiAssessment = null;
  try {
    aiAssessment = await askLmStudioAboutSite(normalizedData, settings);
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

  await persistAnalysisResult(normalizedData, {
    source: aiAssessment ? 'lm_studio' : 'heuristic_fallback',
    aiDanger,
    aiReason,
    aiRecommendation
  });

  return buildFullResponse(normalizedData, {
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
