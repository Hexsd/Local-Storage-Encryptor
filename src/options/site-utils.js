function normalizeSiteUrl(value) {
  if (!value) return null;

  try {
    const parsed = new URL(toSiteUrlCandidate(value));

    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.origin.toLowerCase();
    }

    if (isTrackablePageUrl(parsed)) {
      return normalizeFullPageUrl(parsed);
    }

    return null;
  } catch {
    return null;
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

function getSiteMatchKey(value) {
  return normalizeSiteUrl(value) || String(value || '').trim().toLowerCase();
}

function isSameSiteUrl(left, right) {
  return getSiteMatchKey(left) !== '' && getSiteMatchKey(left) === getSiteMatchKey(right);
}

function hasSiteUrl(sites, url) {
  return Array.isArray(sites) && sites.some((site) => isSameSiteUrl(site?.url, url));
}

function normalizeStoredSiteItem(item, listType) {
  const source = item && typeof item === 'object' && !Array.isArray(item) ? item : { url: item };
  const url = normalizeSiteUrl(source.url);
  if (!url) return null;

  const added = Number.isFinite(Number(source.added)) ? Number(source.added) : Date.now();

  if (listType === 'whitelist') {
    return { url, added };
  }

  const normalized = {
    ...source,
    url,
    added
  };

  if (!normalized.risk || typeof normalized.risk !== 'string') {
    normalized.risk = 'low';
  }

  if (normalized.aiDanger) {
    normalized.aiDanger = normalizeAiDanger(normalized.aiDanger);
  }

  return normalized;
}

function sanitizeSiteList(items, listType) {
  if (!Array.isArray(items)) return [];

  return items.reduce((result, item) => {
    const normalized = normalizeStoredSiteItem(item, listType);
    if (!normalized || hasSiteUrl(result, normalized.url)) {
      return result;
    }

    result.push(normalized);
    return result;
  }, []);
}

async function getSiteCollections() {
  const { monitoredSites = [], whitelistedSites = [] } = await chrome.storage.sync.get([
    'monitoredSites',
    'whitelistedSites'
  ]);
  const safeWhitelistedSites = sanitizeSiteList(whitelistedSites, 'whitelist');
  const whitelistKeys = new Set(safeWhitelistedSites.map((site) => getSiteMatchKey(site.url)));
  const safeMonitoredSites = sanitizeSiteList(monitoredSites, 'monitored')
    .filter((site) => !whitelistKeys.has(getSiteMatchKey(site.url)));

  return {
    monitoredSites: safeMonitoredSites,
    whitelistedSites: safeWhitelistedSites
  };
}

function appendEmptyState(container, text) {
  const empty = document.createElement('p');
  empty.className = 'empty-state';
  empty.textContent = text;
  container.appendChild(empty);
}

async function syncStatsBySites(sites) {
  const safeSites = Array.isArray(sites)
    ? sites.filter((site) => site && typeof site.url === 'string' && site.url.trim())
    : [];
  const sitesCount = safeSites.length;
  const { stats = {} } = await chrome.storage.local.get('stats');
  const nextStats = { ...stats, sitesCount };

  if (sitesCount === 0) {
    nextStats.securityIndex = 100;
  } else {
    const avgScore =
      safeSites.reduce((sum, site) => sum + getSiteScore(site), 0) / sitesCount;
    nextStats.securityIndex = Math.max(0, Math.round(100 - Math.min(avgScore, 100)));
  }

  await chrome.storage.local.set({ stats: nextStats });
}

function getSiteScore(site) {
  if (!site || typeof site !== 'object') return 0;

  const numericScore = Number(site.score);
  if (Number.isFinite(numericScore)) {
    return clamp(Math.round(numericScore), 0, 100);
  }

  switch (String(site.risk || '').toLowerCase()) {
    case 'critical':
      return 90;
    case 'high':
      return 70;
    case 'medium':
      return 40;
    default:
      return 0;
  }
}
