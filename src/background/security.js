const securityEventRateLimits = new Map();

async function recordSecurityEvent(request, sender) {
  const event = request?.event === 'dangerous_form_blocked' ? 'dangerous_form_blocked' : 'storage_leak_blocked';
  const senderUrl = getSenderUrl(sender);
  const site = normalizeSiteUrl(senderUrl) || senderUrl;
  const destination = sanitizeSecurityDestination(request?.destination);
  const timestamp = Date.now();
  const rateKey = `${sender?.tab?.id ?? 'extension'}:${event}:${destination}`;
  const previousTimestamp = securityEventRateLimits.get(rateKey) || 0;
  if (timestamp - previousTimestamp < 1500) return;
  securityEventRateLimits.set(rateKey, timestamp);
  if (securityEventRateLimits.size > 300) {
    for (const [key, value] of securityEventRateLimits) {
      if (timestamp - value > 60000) securityEventRateLimits.delete(key);
    }
  }
  const { [SECURITY_STATS_STORAGE_KEY]: stored = {} } = await chrome.storage.local.get(SECURITY_STATS_STORAGE_KEY);
  const bySite = stored.bySite && typeof stored.bySite === 'object' ? { ...stored.bySite } : {};
  const events = Array.isArray(stored.events) ? stored.events.slice(-MAX_SECURITY_EVENTS + 1) : [];

  bySite[site] = (Number(bySite[site]) || 0) + 1;
  events.push({ event, site, destination, timestamp });
  const next = {
    totalBlocked: (Number(stored.totalBlocked) || 0) + 1,
    blockedLeaks: (Number(stored.blockedLeaks) || 0) + (event === 'storage_leak_blocked' ? 1 : 0),
    blockedForms: (Number(stored.blockedForms) || 0) + (event === 'dangerous_form_blocked' ? 1 : 0),
    lastBlockedAt: timestamp,
    bySite,
    events
  };
  await chrome.storage.local.set({ [SECURITY_STATS_STORAGE_KEY]: next });

  await logEvent({
    category: 'security',
    level: 'warn',
    event,
    title: event === 'storage_leak_blocked' ? 'Утечка секрета заблокирована' : 'Опасная форма остановлена',
    message: destination ? `Передача на ${destination} остановлена до отправки.` : 'Опасная передача остановлена до отправки.',
    url: site,
    context: { destination }
  });

  if (event === 'storage_leak_blocked') {
    await showNotification(destination ? `Заблокирована утечка данных на ${destination}` : 'Заблокирована утечка данных');
  }
}

async function getSecuritySummary() {
  const { [SECURITY_STATS_STORAGE_KEY]: stored = {} } = await chrome.storage.local.get(SECURITY_STATS_STORAGE_KEY);
  return {
    totalBlocked: Number(stored.totalBlocked) || 0,
    blockedLeaks: Number(stored.blockedLeaks) || 0,
    blockedForms: Number(stored.blockedForms) || 0,
    lastBlockedAt: Number(stored.lastBlockedAt) || 0
  };
}

function sanitizeSecurityDestination(value) {
  try {
    const parsed = new URL(String(value || ''));
    return parsed.origin.slice(0, 160);
  } catch {
    return '';
  }
}
