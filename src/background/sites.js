function getSiteDetailsStorageKey(url) {
  return `${SITE_DETAILS_PREFIX}${encodeURIComponent(url)}`;
}

function normalizeSiteUrl(value) {
  if (!value) return '';

  try {
    const parsed = new URL(toSiteUrlCandidate(value));
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.origin.toLowerCase();
    }
    if (isTrackablePageUrl(parsed)) {
      return normalizeFullPageUrl(parsed);
    }
    return '';
  } catch {
    return '';
  }
}

function normalizeFullPageUrl(parsed) {
  parsed.hash = '';
  return parsed.href;
}

function isTrackablePageUrl(parsed) {
  const blockedProtocols = new Set(['javascript:', 'data:', 'blob:', 'mailto:', 'tel:']);
  return Boolean(parsed?.protocol) && !blockedProtocols.has(parsed.protocol);
}

function toSiteUrlCandidate(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (/^\/[a-z]:[\\/]/i.test(raw)) {
    return `file://${raw.replace(/\\/g, '/')}`;
  }
  if (/^[a-z]:[\\/]/i.test(raw)) {
    return `file:///${raw.replace(/\\/g, '/')}`;
  }
  if (raw.startsWith('\\\\')) {
    return `file:${raw.replace(/\\/g, '/')}`;
  }
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(raw) || /^file:/i.test(raw)) return raw;
  return `http://${raw}`;
}

function getAnalyzedSiteUrl(data) {
  const normalized = normalizeSiteUrl(data?.url);
  if (!normalized) {
    throw new Error('Missing analyzed page URL');
  }
  return normalized;
}

function normalizeAnalyzedData(data) {
  const url = getAnalyzedSiteUrl(data);

  return {
    ...data,
    url
  };
}

function isSameSiteUrl(left, right) {
  const leftKey = normalizeSiteUrl(left);
  const rightKey = normalizeSiteUrl(right);
  return Boolean(leftKey) && leftKey === rightKey;
}

function getBaseSiteRecord(record) {
  if (!record || typeof record !== 'object') return null;

  const url = normalizeSiteUrl(record.url);
  if (!url) return null;

  return {
    url,
    risk: normalizeRisk(record.risk),
    score: normalizeScore(record.score),
    issues: sanitizeIssues(record.issues),
    aiDanger: normalizeAiDanger(record.aiDanger),
    aiReason: truncateText(record.aiReason, MAX_SYNC_REASON_LENGTH),
    aiRecommendation: truncateText(record.aiRecommendation, MAX_SYNC_RECOMMENDATION_LENGTH),
    added: Number.isFinite(Number(record.added)) ? Number(record.added) : Date.now(),
    updatedAt: Number.isFinite(Number(record.updatedAt)) ? Number(record.updatedAt) : Date.now()
  };
}

function getBaseWhitelistRecord(record) {
  const source = record && typeof record === 'object' ? record : { url: record };
  const url = normalizeSiteUrl(source?.url);
  if (!url) return null;

  return {
    url,
    added: Number.isFinite(Number(source.added)) ? Number(source.added) : Date.now()
  };
}

function mergeSiteRecord(existingRecord, patchRecord) {
  const base = getBaseSiteRecord(existingRecord) || { url: patchRecord.url, added: patchRecord.added };

  return {
    ...base,
    ...patchRecord,
    added: Number.isFinite(Number(base.added)) ? Number(base.added) : patchRecord.added,
    updatedAt: Date.now()
  };
}

async function getMonitoredSites() {
  const { [MONITORED_SITES_STORAGE_KEY]: monitoredSites = [] } =
    await chrome.storage.sync.get(MONITORED_SITES_STORAGE_KEY);

  if (!Array.isArray(monitoredSites)) return [];

  return monitoredSites
    .map((site) => getBaseSiteRecord(site))
    .filter(Boolean);
}

async function getWhitelistedSites() {
  const { [WHITELISTED_SITES_STORAGE_KEY]: whitelistedSites = [] } =
    await chrome.storage.sync.get(WHITELISTED_SITES_STORAGE_KEY);

  if (!Array.isArray(whitelistedSites)) return [];

  return whitelistedSites
    .map((site) => getBaseWhitelistRecord(site))
    .filter((site, index, collection) => collection.findIndex((item) => isSameSiteUrl(item.url, site.url)) === index);
}

async function isSiteWhitelisted(url) {
  const whitelistedSites = await getWhitelistedSites();
  return whitelistedSites.some((site) => isSameSiteUrl(site.url, url));
}

async function saveMonitoredSites(sites) {
  await debugTrace('storage.sync.save.start', {
    sitesCount: Array.isArray(sites) ? sites.length : null
  });
  await chrome.storage.sync.set({ [MONITORED_SITES_STORAGE_KEY]: sites });
  await debugTrace('storage.sync.save.success', {
    sitesCount: Array.isArray(sites) ? sites.length : null
  });
  return sites;
}

async function saveMonitoredSiteSummary(summary) {
  const sites = await getMonitoredSites();
  const existingIndex = sites.findIndex((site) => site.url === summary.url);
  const merged =
    existingIndex === -1
      ? summary
      : mergeSiteRecord(sites[existingIndex], summary);

  const nextSites = existingIndex === -1 ? [...sites, merged] : sites.map((site, index) => (
    index === existingIndex ? merged : site
  ));

  try {
    return await saveMonitoredSites(nextSites);
  } catch (error) {
    await debugTrace('storage.sync.save.error', {
      url: summary.url,
      error: error?.message || String(error)
    });
    const compactSites = nextSites.map((site) => ({
      url: site.url,
      risk: site.risk,
      score: site.score,
      aiDanger: site.aiDanger,
      added: site.added,
      updatedAt: site.updatedAt
    }));

    await logEvent({
      category: 'system',
      level: 'warn',
      event: 'sync_storage_compacted',
      title: 'Sync-хранилище переполнено',
      message: 'Список отслеживаемых сайтов сохранён в сокращённом виде.',
      context: {
        reason: error.message
      }
    });
    return saveMonitoredSites(compactSites);
  }
}

async function saveSiteDetails(url, payload) {
  const storageKey = getSiteDetailsStorageKey(url);
  const detailsRecord = {
    updatedAt: Date.now(),
    ...payload
  };

  await debugTrace('storage.local.details.save.start', {
    url,
    storageKey,
    issuesCount: Array.isArray(payload?.issues) ? payload.issues.length : 0
  });
  await chrome.storage.local.set({ [storageKey]: detailsRecord });
  await debugTrace('storage.local.details.save.success', {
    url,
    storageKey
  });
}

function buildSiteSummary(data, extra = {}) {
  const normalizedData = normalizeAnalyzedData(data);

  const summary = getBaseSiteRecord({
    url: normalizedData.url,
    risk: normalizedData.risk,
    score: normalizedData.score,
    issues: normalizedData.issues,
    aiDanger: extra.aiDanger,
    aiReason: extra.aiReason,
    aiRecommendation: extra.aiRecommendation,
    added: extra.added
  });

  if (!summary) {
    throw new Error('Missing analyzed page URL');
  }

  return summary;
}

async function persistAnalysisResult(data, extra = {}) {
  const summary = buildSiteSummary(data, extra);
  await debugTrace('analysis.persist.start', {
    url: summary.url,
    source: extra.source || 'heuristic',
    risk: summary.risk,
    score: summary.score
  });

  const tasks = [
    saveMonitoredSiteSummary(summary),
    saveSiteDetails(summary.url, {
      risk: summary.risk,
      score: summary.score,
      issues: Array.isArray(data?.issues) ? data.issues : [],
      details: data?.details || null,
      aiDanger: normalizeAiDanger(extra.aiDanger),
      aiReason: String(extra.aiReason || ''),
      aiRecommendation: String(extra.aiRecommendation || ''),
      source: extra.source || 'heuristic'
    })
  ];

  const [syncResult, localResult] = await Promise.allSettled(tasks);
  await debugTrace('analysis.persist.done', {
    url: summary.url,
    syncStatus: syncResult.status,
    localStatus: localResult.status
  });

  if (syncResult.status === 'rejected') {
    await logEvent(
      {
        category: 'system',
        level: 'error',
        event: 'monitored_site_summary_save_failed',
        title: 'Не удалось сохранить карточку сайта',
        message: 'Сводная информация по сайту не была записана в sync-хранилище.',
        context: {
          reason: syncResult.reason?.message || String(syncResult.reason || ''),
          site: summary.url
        }
      },
      null,
      summary.url
    );
  }

  if (localResult.status === 'rejected') {
    await logEvent(
      {
        category: 'system',
        level: 'error',
        event: 'local_analysis_details_save_failed',
        title: 'Не удалось сохранить детали анализа',
        message: 'Подробные данные локального анализа не были записаны.',
        context: {
          reason: localResult.reason?.message || String(localResult.reason || ''),
          site: summary.url
        }
      },
      null,
      summary.url
    );
  }

  const syncedSites = syncResult.status === 'fulfilled' ? syncResult.value : null;
  await updateStats(summary.risk, syncedSites, summary.url);

  return summary;
}
