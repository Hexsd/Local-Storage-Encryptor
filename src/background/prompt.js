function buildPromptDetailsSummary(details) {
  if (!details || typeof details !== 'object') return '';

  const summary = {
    version: details.version || null,
    observationMs: details.observationMs || null,
    probeReady: Boolean(details.probeReady),
    probeErrors: Number(details.probeErrors) || 0,
    components: details.components || null,
    metrics: {
      storage: details.metrics?.storage
        ? {
            localWrites: details.metrics.storage.localWrites,
            localReads: details.metrics.storage.localReads,
            sensitiveKeyWrites: details.metrics.storage.sensitiveKeyWrites,
            highEntropyWrites: details.metrics.storage.highEntropyWrites,
            largeValueWrites: details.metrics.storage.largeValueWrites,
            sensitiveHighEntropyWrites: details.metrics.storage.sensitiveHighEntropyWrites,
            writeBurst1s: details.metrics.storage.writeBurst1s
          }
        : null,
      network: details.metrics?.network
        ? {
            totalRequests: details.metrics.network.totalRequests,
            crossOriginRequests: details.metrics.network.crossOriginRequests,
            requestsAfterStorageEvent: details.metrics.network.requestsAfterStorageEvent,
            requestsAfterSensitiveWrite: details.metrics.network.requestsAfterSensitiveWrite,
            encodedPayloadRequests: details.metrics.network.encodedPayloadRequests,
            unrelatedRequests: details.metrics.network.unrelatedRequests,
            apiRequests: details.metrics.network.apiRequests,
            unrelatedApiRequests: details.metrics.network.unrelatedApiRequests,
            mutatingRequests: details.metrics.network.mutatingRequests,
            mutatingAfterSensitiveWrite: details.metrics.network.mutatingAfterSensitiveWrite,
            uniqueHosts: details.metrics.network.uniqueHosts,
            unrelatedHosts: details.metrics.network.unrelatedHosts
          }
        : null,
      activity: details.metrics?.activity
        ? {
            fastTimeoutRegistrations: details.metrics.activity.fastTimeoutRegistrations,
            fastIntervalRegistrations: details.metrics.activity.fastIntervalRegistrations,
            beforeUnloadListeners: details.metrics.activity.beforeUnloadListeners,
            unloadListeners: details.metrics.activity.unloadListeners,
            hiddenStorageOps: details.metrics.activity.hiddenStorageOps,
            hiddenNetworkRequests: details.metrics.activity.hiddenNetworkRequests,
            mutationRatePerSec: details.metrics.activity.mutationRatePerSec
          }
        : null
    },
    hotKeys: Array.isArray(details.hotKeys) ? details.hotKeys.slice(0, 4) : [],
    hotDomains: Array.isArray(details.hotDomains) ? details.hotDomains.slice(0, 4) : []
  };

  const serialized = JSON.stringify(summary);
  if (serialized.length <= MAX_PROMPT_JSON_LENGTH) {
    return serialized;
  }

  return `${serialized.slice(0, MAX_PROMPT_JSON_LENGTH)}...`;
}

function buildLmStudioPrompt(data) {
  const issues = sanitizeIssues(data?.issues, MAX_PROMPT_ISSUES, 120);
  const detailsSummary = buildPromptDetailsSummary(data?.details);

  return [
    '/no_think',
    'Classify browser security telemetry. Reply with JSON only:',
    '{"danger":"high|medium|low","reason":"short reason up to 12 words"}',
    `URL: ${String(data?.url || '')}`,
    `Risk: ${normalizeRisk(data?.risk)} Score: ${normalizeScore(data?.score) ?? 'n/a'}`,
    `Issues: ${issues.length > 0 ? issues.join('; ') : 'none'}`,
    `Signals: ${detailsSummary || 'none'}`
  ].join('\n');
}

function extractLmText(payload) {
  const choice = payload?.choices?.[0];
  if (!choice || typeof choice !== 'object') return '';

  const directMessage = choice.message?.content;
  if (typeof directMessage === 'string') return directMessage.trim();

  if (Array.isArray(directMessage)) {
    return directMessage
      .map((item) => {
        if (typeof item === 'string') return item;
        if (typeof item?.text === 'string') return item.text;
        if (typeof item?.content === 'string') return item.content;
        return '';
      })
      .join('')
      .trim();
  }

  if (typeof choice.text === 'string') return choice.text.trim();
  return '';
}

function parseDangerLevel(text) {
  const lower = String(text || '').toLowerCase();

  if (lower.trim() === 'high') return 'high';
  if (lower.trim() === 'medium') return 'medium';
  if (lower.trim() === 'low') return 'low';

  if (
    lower.includes('danger: high') ||
    lower.includes('risk: high') ||
    lower.includes('уровень опасности: high') ||
    lower.includes('опасность: high') ||
    lower.includes('высокий риск')
  ) {
    return 'high';
  }

  if (
    lower.includes('danger: medium') ||
    lower.includes('risk: medium') ||
    lower.includes('уровень опасности: medium') ||
    lower.includes('опасность: medium') ||
    lower.includes('средний риск')
  ) {
    return 'medium';
  }

  return 'low';
}

function parseLmAssessment(text) {
  const raw = String(text || '').trim();
  const jsonText = raw.match(/\{[\s\S]*\}/)?.[0] || '';

  if (jsonText) {
    try {
      const parsed = JSON.parse(jsonText);
      const danger = parseDangerLevel(String(parsed?.danger || parsed?.risk || ''));
      const reason = truncateText(parsed?.reason || parsed?.summary || raw, 160);
      return { danger, reason };
    } catch {
    }
  }

  return {
    danger: parseDangerLevel(raw),
    reason: truncateText(raw, 160)
  };
}
