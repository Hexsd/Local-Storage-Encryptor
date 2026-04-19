async function askLmStudioAboutSite(data, settings) {
  const endpoint = normalizeEndpoint(settings?.lmStudioEndpoint);
  const model = normalizeModel(settings?.lmStudioModel);
  const timeoutMs = normalizeTimeout(settings?.lmStudioTimeoutMs);
  const prompt = buildLmStudioPrompt(data);
  const requestBody = {
    model,
    temperature: 0,
    top_p: 0.1,
    max_tokens: LM_STUDIO_ANALYSIS_MAX_TOKENS,
    stream: false,
    messages: [
      {
        role: 'system',
        content:
          '/no_think. You classify browser security telemetry. Output one compact JSON object only. No markdown. No explanation outside JSON.'
      },
      {
        role: 'user',
        content: prompt
      }
    ]
  };

  await logEvent(
    {
      category: 'ai',
      level: 'info',
      event: 'lm_request_started',
      title: 'Запрос к LM Studio отправлен',
      message: 'Расширение отправило сводку сигналов страницы на AI-анализ.',
      context: {
        endpoint,
        model
      }
    },
    null,
    String(data?.url || 'background')
  );
  await debugTrace('lm.request.start', {
    url: data?.url,
    endpoint,
    model,
    timeoutMs,
    promptPreview: prompt.slice(0, 500)
  });

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

  let response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody),
      signal: abortController.signal
    });
    await debugTrace('lm.request.fetch_resolved', {
      url: data?.url,
      ok: response.ok,
      status: response.status,
      statusText: response.statusText
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      await debugTrace('lm.request.abort', {
        url: data?.url,
        timeoutMs
      });
      throw new Error(`LM Studio did not answer within ${timeoutMs}ms`);
    }

    await debugTrace('lm.request.fetch_error', {
      url: data?.url,
      name: error?.name || '',
      message: error?.message || String(error),
      stack: error?.stack || ''
    });
    throw new Error(`LM Studio network error: ${error.message}`);
  } finally {
    clearTimeout(timeoutId);
  }

  const rawText = await response.text().catch(() => '');
  await debugTrace('lm.request.response_text', {
    url: data?.url,
    status: response.status,
    bodyPreview: rawText.slice(0, 500)
  });

  if (!response.ok) {
    throw new Error(`LM Studio HTTP ${response.status}${rawText ? `: ${rawText.slice(0, 300)}` : ''}`);
  }

  let payload;
  try {
    payload = rawText ? JSON.parse(rawText) : {};
  } catch {
    throw new Error(`LM Studio returned non-JSON response: ${rawText.slice(0, 300)}`);
  }

  const text = extractLmText(payload);
  if (!text) {
    throw new Error(`LM Studio returned an empty completion: ${rawText.slice(0, 300)}`);
  }
  const assessment = parseLmAssessment(text);

  await debugTrace('lm.request.parsed', {
    url: data?.url,
    danger: assessment.danger,
    textPreview: text.slice(0, 400)
  });
  await logEvent(
    {
      category: 'ai',
      level: 'info',
      event: 'lm_response_received',
      title: 'Получен ответ LM Studio',
      message: truncateText(assessment.reason || text, 180)
    },
    null,
    String(data?.url || 'background')
  );

  return {
    danger: assessment.danger,
    reason: assessment.reason,
    recommendation: ''
  };
}

async function handleLmStudioTest(request, sender) {
  const settings = await getExtensionSettings();
  const endpoint = normalizeEndpoint(request?.endpoint || settings.lmStudioEndpoint);
  const model = normalizeModel(request?.model || settings.lmStudioModel);
  const timeoutMs = Math.min(
    normalizeTimeout(request?.timeoutMs || settings.lmStudioTimeoutMs),
    LM_STUDIO_TEST_TIMEOUT_MS
  );

  await debugTrace('lm.test.start', {
    endpoint,
    model,
    timeoutMs,
    senderUrl: getSenderUrl(sender)
  });

  const requestBody = {
    model,
    temperature: 0,
    top_p: 0.1,
    max_tokens: LM_STUDIO_TEST_MAX_TOKENS,
    stream: false,
    messages: [
      {
        role: 'system',
        content: '/no_think. Reply with exactly OK.'
      },
      {
        role: 'user',
        content: 'OK'
      }
    ]
  };

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);
  let response;

  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody),
      signal: abortController.signal
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error(`LM Studio did not answer within ${timeoutMs}ms`);
    }
    throw new Error(`LM Studio network error: ${error.message}`);
  } finally {
    clearTimeout(timeoutId);
  }

  const rawText = await response.text().catch(() => '');
  if (!response.ok) {
    throw new Error(`LM Studio HTTP ${response.status}${rawText ? `: ${rawText.slice(0, 200)}` : ''}`);
  }

  let payload;
  try {
    payload = rawText ? JSON.parse(rawText) : {};
  } catch {
    throw new Error(`LM Studio returned non-JSON response: ${rawText.slice(0, 200)}`);
  }

  const text = extractLmText(payload) || 'OK';

  await debugTrace('lm.test.success', {
    endpoint,
    model,
    responsePreview: text.slice(0, 40)
  });

  return {
    ok: true,
    endpoint,
    model,
    timeoutMs,
    danger: 'low',
    reason: truncateText(text, 40)
  };
}
