const ENCRYPTION_KEY_STORAGE = 'encryptionPassphrase';
const slt = new TextEncoder().encode('}vsosh{');
const ins = 100000;
let cryptoKeyPromise = null;
let cryptoKeyPassphrase = null;

const SENSITIVE_KEY_PATTERN = /(token|auth|session|jwt|bearer|secret|pass|credential|sid|csrf|xsrf|refresh|access)/i;
const LARGE_VALUE_THRESHOLD = 2048;
const MIN_OBSERVATION_MS = 3000;
const CORRELATION_WINDOW_MS = 2500;
const ANALYSIS_DEBOUNCE_MS = 1500;
const ANALYSIS_MIN_INTERVAL_MS = 12000;
const FORCE_REPORT_INTERVAL_MS = 90000;
const FULL_ANALYSIS_MIN_INTERVAL_MS = 45000;
const SIGNIFICANT_SCORE_DELTA = 8;
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const API_HOST_PATTERN = /(^|[.-])(api|graphql|gateway|backend|service|rest)\b/i;
const API_PATH_PATTERN = /(?:^|\/)(api|graphql|rest|rpc|jsonrpc|v\d+)(?:\/|$)/i;
const COMMON_SECOND_LEVEL_DOMAINS = new Set([
    'co.uk',
    'org.uk',
    'gov.uk',
    'ac.uk',
    'com.au',
    'net.au',
    'org.au',
    'co.jp',
    'co.kr',
    'com.br',
    'com.mx',
    'com.tr',
    'com.cn',
    'com.tw',
    'co.in',
    'net.in',
    'org.in',
    'co.id'
]);
const PAGE_HOSTNAME = String(window.location.hostname || '').toLowerCase();
const PAGE_BASE_DOMAIN = getBaseDomain(PAGE_HOSTNAME);

const runtimeSignals = createRuntimeSignals();
const analysisState = createAnalysisState();
let runtimeMonitoringStarted = false;

function createRuntimeSignals() {
    return {
        startedAt: Date.now(),
        probeReady: false,
        storage: {
            localReads: 0,
            localWrites: 0,
            localRemoves: 0,
            localClears: 0,
            sessionReads: 0,
            sessionWrites: 0,
            sessionRemoves: 0,
            sessionClears: 0,
            sensitiveKeyWrites: 0,
            highEntropyWrites: 0,
            largeValueWrites: 0,
            encodedLikeWrites: 0,
            sensitiveHighEntropyWrites: 0,
            keyStats: Object.create(null),
            lastStorageEventAt: 0,
            lastSensitiveWriteAt: 0,
            writeTimestamps: [],
            storageEventTimestamps: []
        },
        network: {
            fetchRequests: 0,
            xhrRequests: 0,
            beaconRequests: 0,
            websocketConnections: 0,
            crossOriginRequests: 0,
            requestsAfterStorageEvent: 0,
            requestsAfterSensitiveWrite: 0,
            encodedPayloadRequests: 0,
            totalBodyBytes: 0,
            sameSiteRequests: 0,
            unrelatedRequests: 0,
            apiRequests: 0,
            unrelatedApiRequests: 0,
            mutatingRequests: 0,
            mutatingAfterStorageEvent: 0,
            mutatingAfterSensitiveWrite: 0,
            requestsWithoutUrl: 0,
            hostStats: Object.create(null),
            requestTimestamps: []
        },
        activity: {
            fastTimeoutRegistrations: 0,
            fastIntervalRegistrations: 0,
            beforeUnloadListeners: 0,
            unloadListeners: 0,
            pagehideListeners: 0,
            visibilityListeners: 0,
            storageListeners: 0,
            historyWrites: 0,
            mutationBatches: 0,
            addedNodes: 0,
            removedNodes: 0,
            attributeMutations: 0,
            hiddenStorageOps: 0,
            hiddenNetworkRequests: 0,
            hiddenMutationBursts: 0
        },
        probeErrors: 0
    };
}

function createAnalysisState() {
    return {
        timerId: null,
        inFlight: false,
        pending: false,
        pendingReasons: new Set(),
        lastRunAt: 0,
        lastReportedAt: 0,
        lastReportedScore: null,
        lastReportedRisk: null,
        lastFullRunAt: 0,
        protectionDisabledLogged: false
    };
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

function getCurrentPageUrl() {
    return normalizeSiteUrl(window.location.href) || window.location.href;
}

function isSameSiteUrl(left, right) {
    const leftKey = normalizeSiteUrl(left);
    const rightKey = normalizeSiteUrl(right);
    return Boolean(leftKey) && leftKey === rightKey;
}

function setupRuntimeMonitoring() {
    window.addEventListener('message', handleProbeMessage, false);
    startDomMutationObserver();
    injectPageProbe();
}

function injectPageProbe() {
    try {
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('src/content/page-probe.js');
        script.async = false;
        script.onload = () => script.remove();
        script.onerror = () => {
            runtimeSignals.probeErrors += 1;
        };
        (document.head || document.documentElement).appendChild(script);
    } catch {
        runtimeSignals.probeErrors += 1;
    }
}

function startDomMutationObserver() {
    const root = document.documentElement;
    if (!root || !window.MutationObserver) return;

    const observer = new MutationObserver((mutations) => {
        runtimeSignals.activity.mutationBatches += mutations.length;

        for (const mutation of mutations) {
            if (mutation.type === 'childList') {
                runtimeSignals.activity.addedNodes += mutation.addedNodes.length;
                runtimeSignals.activity.removedNodes += mutation.removedNodes.length;
            } else if (mutation.type === 'attributes') {
                runtimeSignals.activity.attributeMutations += 1;
            }
        }

        if (document.hidden) {
            runtimeSignals.activity.hiddenMutationBursts += mutations.length;
        }
    });

    observer.observe(root, {
        subtree: true,
        childList: true,
        attributes: true
    });
}

function handleProbeMessage(event) {
    if (event.source !== window || !event.data || event.data.source !== 'lse_probe') return;

    const { type, payload = {}, ts } = event.data;
    const timestamp = Number(ts) || Date.now();

    switch (type) {
        case 'probe_ready':
            runtimeSignals.probeReady = true;
            scheduleAnalysis('probe_ready');
            break;
        case 'probe_error':
            runtimeSignals.probeErrors += 1;
            break;
        case 'storage':
            applyStorageSignal(payload, timestamp);
            maybeScheduleAnalysisFromSignals('storage');
            break;
        case 'network_fetch':
        case 'network_xhr':
        case 'network_beacon':
        case 'network_ws':
            applyNetworkSignal(type, payload, timestamp);
            maybeScheduleAnalysisFromSignals('network');
            break;
        case 'timer':
            applyTimerSignal(payload);
            break;
        case 'listener':
            applyListenerSignal(payload);
            break;
        case 'history':
            runtimeSignals.activity.historyWrites += 1;
            scheduleAnalysis('history', { force: true });
            break;
        default:
            break;
    }
}

function applyStorageSignal(payload, timestamp) {
    const area = payload.area === 'session' ? 'session' : 'local';
    const op = payload.op;
    const key = payload.key === undefined || payload.key === null ? '' : String(payload.key);
    const keyBucket = op === 'clear' ? null : getKeyBucket(key, area);

    if (op === 'getItem') {
        if (area === 'local') runtimeSignals.storage.localReads += 1;
        else runtimeSignals.storage.sessionReads += 1;
        if (keyBucket) keyBucket.reads += 1;
    }

    if (op === 'setItem') {
        if (area === 'local') runtimeSignals.storage.localWrites += 1;
        else runtimeSignals.storage.sessionWrites += 1;

        if (keyBucket) {
            keyBucket.writes += 1;
            keyBucket.lastValueLength = Number(payload.valueLength) || 0;
            keyBucket.lastEntropy = Number(payload.entropy) || 0;
            keyBucket.encodedLike = Boolean(payload.encodedLike);

            if (keyBucket.sensitive) {
                runtimeSignals.storage.sensitiveKeyWrites += 1;
                runtimeSignals.storage.lastSensitiveWriteAt = timestamp;
                if (keyBucket.lastEntropy >= 4.3 && keyBucket.lastValueLength >= 64) {
                    runtimeSignals.storage.sensitiveHighEntropyWrites += 1;
                }
            }
            if (keyBucket.lastValueLength >= LARGE_VALUE_THRESHOLD) runtimeSignals.storage.largeValueWrites += 1;
            if (keyBucket.lastEntropy >= 4.3 && keyBucket.lastValueLength >= 64) runtimeSignals.storage.highEntropyWrites += 1;
            if (keyBucket.encodedLike) runtimeSignals.storage.encodedLikeWrites += 1;
        }

        runtimeSignals.storage.writeTimestamps.push(timestamp);
        trimOldTimestamps(runtimeSignals.storage.writeTimestamps, timestamp, 12000);
    }

    if (op === 'removeItem') {
        if (area === 'local') runtimeSignals.storage.localRemoves += 1;
        else runtimeSignals.storage.sessionRemoves += 1;
        if (keyBucket) keyBucket.removes += 1;
    }

    if (op === 'clear') {
        if (area === 'local') runtimeSignals.storage.localClears += 1;
        else runtimeSignals.storage.sessionClears += 1;
    }

    runtimeSignals.storage.lastStorageEventAt = timestamp;
    runtimeSignals.storage.storageEventTimestamps.push(timestamp);
    trimOldTimestamps(runtimeSignals.storage.storageEventTimestamps, timestamp, 12000);

    if (document.hidden) runtimeSignals.activity.hiddenStorageOps += 1;
}

function getBaseDomain(hostname) {
    if (!hostname) return '';

    const safeHost = String(hostname || '').toLowerCase();
    if (!safeHost) return '';

    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(safeHost) || safeHost.includes(':')) {
        return safeHost;
    }

    const parts = safeHost.split('.').filter(Boolean);
    if (parts.length <= 2) return safeHost;

    const tail2 = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (COMMON_SECOND_LEVEL_DOMAINS.has(tail2) && parts.length >= 3) {
        return `${parts[parts.length - 3]}.${tail2}`;
    }

    return tail2;
}

function isApiLikeTarget(hostname, pathname) {
    const host = String(hostname || '').toLowerCase();
    const path = String(pathname || '');
    return API_HOST_PATTERN.test(host) || API_PATH_PATTERN.test(path);
}

function classifyNetworkTarget(rawUrl) {
    if (!rawUrl) return null;

    try {
        const parsed = new URL(String(rawUrl), window.location.href);
        const hostname = String(parsed.hostname || '').toLowerCase();
        const baseDomain = getBaseDomain(hostname);
        const isSameSiteFamily = hostname === PAGE_HOSTNAME || (baseDomain && baseDomain === PAGE_BASE_DOMAIN);
        const apiLike = isApiLikeTarget(hostname, parsed.pathname);

        return {
            hostname,
            pathname: parsed.pathname || '/',
            baseDomain,
            isSameSiteFamily,
            apiLike,
            unrelatedApi: apiLike && !isSameSiteFamily
        };
    } catch {
        return null;
    }
}
