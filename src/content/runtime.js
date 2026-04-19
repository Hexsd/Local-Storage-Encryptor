async function isProtectionEnabled() {
    const { settings = {} } = await chrome.storage.sync.get('settings');
    return settings.protectionEnabled !== false;
}

async function isSiteWhitelisted(url = getCurrentPageUrl()) {
    const { whitelistedSites = [] } = await chrome.storage.sync.get('whitelistedSites');
    if (!Array.isArray(whitelistedSites)) return false;

    return whitelistedSites.some((site) => {
        const siteUrl =
            site && typeof site === 'object' && !Array.isArray(site)
                ? site.url
                : site;
        return isSameSiteUrl(siteUrl, url);
    });
}

function startRuntimeMonitoring() {
    if (runtimeMonitoringStarted) return;
    runtimeMonitoringStarted = true;
    resetRuntimeSignalWindow();
    setupRuntimeMonitoring();
    registerDynamicAnalysisTriggers();
}

async function bootstrapRuntimeMonitoring() {
    if (!isRuntimeMessageAvailable()) return;
    if (await isSiteWhitelisted()) return;
    startRuntimeMonitoring();
}

function isRuntimeMessageAvailable() {
    return Boolean(chrome?.runtime?.id && chrome.runtime?.sendMessage);
}

function isIgnorableRuntimeError(error) {
    const message = String(error?.message || error || '');
    return (
        message.includes('Extension context invalidated') ||
        message.includes('Receiving end does not exist') ||
        message.includes('The message port closed before a response was received')
    );
}

async function sendRuntimeMessageQuietly(payload) {
    if (!isRuntimeMessageAvailable()) return null;

    try {
        return await chrome.runtime.sendMessage(payload);
    } catch (error) {
        if (isIgnorableRuntimeError(error)) {
            return null;
        }
        throw error;
    }
}

async function logToExtension(entry, type = 'info') {
    if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        await sendRuntimeMessageQuietly({ action: 'log_event', ...entry });
        return;
    }

    await sendRuntimeMessageQuietly({ action: 'log_event', message: entry, type });
}

async function recordOperation(operation) {
    await sendRuntimeMessageQuietly({ action: 'record_operation', operation });
}
