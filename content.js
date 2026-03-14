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
setupRuntimeMonitoring();

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

function setupRuntimeMonitoring() {
    window.addEventListener('message', handleProbeMessage, false);
    startDomMutationObserver();
    injectPageProbe();
}

function injectPageProbe() {
    try {
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('page-probe.js');
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

    // Keep IP addresses as-is to avoid false "related domain" matches.
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

function getOrCreateHostBucket(hostname) {
    const safeHost = hostname || '[unknown]';
    if (!runtimeSignals.network.hostStats[safeHost]) {
        runtimeSignals.network.hostStats[safeHost] = {
            requests: 0,
            crossOriginRequests: 0,
            unrelatedRequests: 0,
            apiRequests: 0,
            unrelatedApiRequests: 0,
            mutatingRequests: 0
        };
    }
    return runtimeSignals.network.hostStats[safeHost];
}

function applyNetworkSignal(type, payload, timestamp) {
    if (type === 'network_fetch') runtimeSignals.network.fetchRequests += 1;
    if (type === 'network_xhr') runtimeSignals.network.xhrRequests += 1;
    if (type === 'network_beacon') runtimeSignals.network.beaconRequests += 1;
    if (type === 'network_ws') runtimeSignals.network.websocketConnections += 1;

    const crossOrigin = Boolean(payload.crossOrigin);
    if (crossOrigin) runtimeSignals.network.crossOriginRequests += 1;

    const bodyBytes = Number(payload.bodyBytes) || 0;
    runtimeSignals.network.totalBodyBytes += Math.max(0, bodyBytes);

    if (Boolean(payload.encodedPayload)) {
        runtimeSignals.network.encodedPayloadRequests += 1;
    }

    const method = String(payload.method || 'GET').toUpperCase();
    const isMutatingMethod = MUTATING_METHODS.has(method);
    if (isMutatingMethod) {
        runtimeSignals.network.mutatingRequests += 1;
    }

    const target = classifyNetworkTarget(payload.url);
    if (target) {
        const hostBucket = getOrCreateHostBucket(target.hostname);
        hostBucket.requests += 1;

        if (crossOrigin) hostBucket.crossOriginRequests += 1;
        if (target.isSameSiteFamily) {
            runtimeSignals.network.sameSiteRequests += 1;
        } else {
            runtimeSignals.network.unrelatedRequests += 1;
            hostBucket.unrelatedRequests += 1;
        }

        if (target.apiLike) {
            runtimeSignals.network.apiRequests += 1;
            hostBucket.apiRequests += 1;
        }

        if (target.unrelatedApi) {
            runtimeSignals.network.unrelatedApiRequests += 1;
            hostBucket.unrelatedApiRequests += 1;
        }

        if (isMutatingMethod) {
            hostBucket.mutatingRequests += 1;
        }
    } else {
        runtimeSignals.network.requestsWithoutUrl += 1;
    }

    const lastStorageAt = runtimeSignals.storage.lastStorageEventAt || 0;
    if (lastStorageAt > 0 && timestamp - lastStorageAt <= CORRELATION_WINDOW_MS) {
        runtimeSignals.network.requestsAfterStorageEvent += 1;
        if (isMutatingMethod) runtimeSignals.network.mutatingAfterStorageEvent += 1;
    }

    const lastSensitiveWriteAt = runtimeSignals.storage.lastSensitiveWriteAt || 0;
    if (lastSensitiveWriteAt > 0 && timestamp - lastSensitiveWriteAt <= CORRELATION_WINDOW_MS) {
        runtimeSignals.network.requestsAfterSensitiveWrite += 1;
        if (isMutatingMethod) runtimeSignals.network.mutatingAfterSensitiveWrite += 1;
    }

    runtimeSignals.network.requestTimestamps.push(timestamp);
    trimOldTimestamps(runtimeSignals.network.requestTimestamps, timestamp, 12000);

    if (document.hidden) runtimeSignals.activity.hiddenNetworkRequests += 1;
}

function applyTimerSignal(payload) {
    const kind = String(payload.kind || '');
    const delay = Number(payload.delay) || 0;

    if (kind === 'timeout' && delay > 0 && delay <= 600) {
        runtimeSignals.activity.fastTimeoutRegistrations += 1;
    }

    if (kind === 'interval' && delay > 0 && delay <= 1500) {
        runtimeSignals.activity.fastIntervalRegistrations += 1;
    }
}

function applyListenerSignal(payload) {
    const eventName = String(payload.event || '').toLowerCase();

    if (eventName === 'beforeunload') runtimeSignals.activity.beforeUnloadListeners += 1;
    if (eventName === 'unload') runtimeSignals.activity.unloadListeners += 1;
    if (eventName === 'pagehide') runtimeSignals.activity.pagehideListeners += 1;
    if (eventName === 'visibilitychange') runtimeSignals.activity.visibilityListeners += 1;
    if (eventName === 'storage') runtimeSignals.activity.storageListeners += 1;
}

function maybeScheduleAnalysisFromSignals(source) {
    const storageOps = runtimeSignals.storage;
    const networkOps = runtimeSignals.network;
    const writeBurst1s = maxEventsInWindow(storageOps.writeTimestamps, 1000);
    const networkBurst1s = maxEventsInWindow(networkOps.requestTimestamps, 1000);

    const suspiciousBridge =
        networkOps.requestsAfterSensitiveWrite >= 2 ||
        networkOps.mutatingAfterSensitiveWrite >= 1 ||
        networkOps.mutatingAfterStorageEvent >= 2 ||
        networkOps.unrelatedApiRequests >= 2;

    if (suspiciousBridge) {
        scheduleAnalysis(`signal:${source}:suspicious`, { force: true });
        return;
    }

    if (source === 'storage') {
        if (writeBurst1s >= 4 || storageOps.sensitiveHighEntropyWrites >= 1) {
            scheduleAnalysis('signal:storage');
        }
        return;
    }

    if (source === 'network') {
        if (networkBurst1s >= 7 || networkOps.unrelatedRequests >= 4 || networkOps.apiRequests >= 5) {
            scheduleAnalysis('signal:network');
        }
    }
}

function scheduleAnalysis(reason, options = {}) {
    const { force = false } = options;
    analysisState.pendingReasons.add(reason || 'runtime');

    if (analysisState.inFlight) {
        analysisState.pending = true;
        return;
    }

    if (analysisState.timerId) {
        window.clearTimeout(analysisState.timerId);
        analysisState.timerId = null;
    }

    const now = Date.now();
    const sinceLastRun = now - analysisState.lastRunAt;
    const cooldownMs = force ? 0 : Math.max(0, ANALYSIS_MIN_INTERVAL_MS - sinceLastRun);
    const delay = force ? Math.max(250, Math.min(900, cooldownMs)) : Math.max(ANALYSIS_DEBOUNCE_MS, cooldownMs);

    analysisState.timerId = window.setTimeout(() => {
        analysisState.timerId = null;
        void runAnalysisCycle();
    }, delay);
}

function getKeyBucket(key, area) {
    const safeKey = key || '[empty]';
    if (!runtimeSignals.storage.keyStats[safeKey]) {
        runtimeSignals.storage.keyStats[safeKey] = {
            area,
            reads: 0,
            writes: 0,
            removes: 0,
            lastValueLength: 0,
            lastEntropy: 0,
            encodedLike: false,
            sensitive: SENSITIVE_KEY_PATTERN.test(safeKey)
        };
    }
    return runtimeSignals.storage.keyStats[safeKey];
}

function trimOldTimestamps(list, now, windowMs) {
    while (list.length > 0 && now - list[0] > windowMs) {
        list.shift();
    }
}

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function estimateEntropy(input) {
    const text = input === undefined || input === null ? '' : String(input);
    if (text.length < 16) return 0;

    const sample = text.length > 2048 ? text.slice(0, 2048) : text;
    const counts = Object.create(null);
    for (const ch of sample) {
        counts[ch] = (counts[ch] || 0) + 1;
    }

    let entropy = 0;
    const len = sample.length;
    for (const count of Object.values(counts)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function maxEventsInWindow(timestamps, windowMs) {
    if (!timestamps.length) return 0;

    let left = 0;
    let best = 0;
    for (let right = 0; right < timestamps.length; right++) {
        while (timestamps[right] - timestamps[left] > windowMs) {
            left += 1;
        }
        best = Math.max(best, right - left + 1);
    }
    return best;
}

function collectStorageSnapshot(storageObj, area) {
    const snapshot = {
        area,
        keyCount: 0,
        totalBytes: 0,
        sensitiveKeys: 0,
        largeValues: 0,
        highEntropyValues: 0
    };

    try {
        for (let i = 0; i < storageObj.length; i++) {
            const key = storageObj.key(i);
            if (key === null) continue;

            const value = storageObj.getItem(key) || '';
            const valueLength = value.length;

            snapshot.keyCount += 1;
            snapshot.totalBytes += valueLength;

            if (SENSITIVE_KEY_PATTERN.test(key)) snapshot.sensitiveKeys += 1;
            if (valueLength >= LARGE_VALUE_THRESHOLD) snapshot.largeValues += 1;
            if (valueLength >= 64 && estimateEntropy(value) >= 4.3) {
                snapshot.highEntropyValues += 1;
            }
        }
    } catch {
        runtimeSignals.probeErrors += 1;
    }

    return snapshot;
}

async function waitForObservationWindow(minMs) {
    const elapsed = Date.now() - runtimeSignals.startedAt;
    if (elapsed >= minMs) return;

    await new Promise(resolve => setTimeout(resolve, minMs - elapsed));
}

async function isProtectionEnabled() {
    const { settings = {} } = await chrome.storage.sync.get('settings');
    return settings.protectionEnabled !== false;
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

async function logToExtension(message, type = 'info') {
    await sendRuntimeMessageQuietly({ action: 'log_event', message, type });
}

async function recordOperation(operation) {
    await sendRuntimeMessageQuietly({ action: 'record_operation', operation });
}

async function getEncryptionPassphrase() {
    const stored = await chrome.storage.local.get(ENCRYPTION_KEY_STORAGE);
    const passphrase = stored?.[ENCRYPTION_KEY_STORAGE];

    if (typeof passphrase !== 'string' || passphrase.length === 0) {
        throw new Error('Ключ шифрования не задан. Добавьте его в popup расширения.');
    }

    return passphrase;
}

async function getCryptoKey() {
    const passphrase = await getEncryptionPassphrase();

    if (!cryptoKeyPromise || cryptoKeyPassphrase !== passphrase) {
        const passwordBuffer = new TextEncoder().encode(passphrase);
        const baseKey = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        cryptoKeyPromise = crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: slt,
                iterations: ins,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
        cryptoKeyPassphrase = passphrase;
    }
    return cryptoKeyPromise;
}

function uint8ToBinaryString(uint8) {
    return String.fromCharCode(...uint8);
}

function binaryStringToUint8(binary) {
    return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

async function encryptValue(value) {
    const key = await getCryptoKey();
    const data = new TextEncoder().encode(String(value || ''));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
    );
    const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.byteLength);
    return btoa(uint8ToBinaryString(combined));
}

async function decryptValue(encryptedBase64) {
    const key = await getCryptoKey();
    const combined = binaryStringToUint8(atob(encryptedBase64));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        await logToExtension(`Расшифровка: ${e.message}`, 'error');
        throw e;
    }
}

async function analyze() {
    await waitForObservationWindow(MIN_OBSERVATION_MS);

    const localSnapshot = collectStorageSnapshot(localStorage, 'local');
    const sessionSnapshot = collectStorageSnapshot(sessionStorage, 'session');

    const storageOps = runtimeSignals.storage;
    const networkOps = runtimeSignals.network;
    const activityOps = runtimeSignals.activity;

    const observationMs = Date.now() - runtimeSignals.startedAt;
    const observationSec = Math.max(1, observationMs / 1000);

    const writes = storageOps.localWrites + storageOps.sessionWrites;
    const reads = storageOps.localReads + storageOps.sessionReads;
    const removes = storageOps.localRemoves + storageOps.sessionRemoves;
    const clears = storageOps.localClears + storageOps.sessionClears;
    const destructiveOps = removes + clears * 3;

    const totalRequests =
        networkOps.fetchRequests +
        networkOps.xhrRequests +
        networkOps.beaconRequests +
        networkOps.websocketConnections;

    const keyStatsEntries = Object.entries(storageOps.keyStats);
    const keyStatsValues = keyStatsEntries.map(([, value]) => value);
    const churnedKeys = keyStatsValues.filter(k => k.writes >= 3).length;
    const rotatingKeys = keyStatsValues.filter(k => k.writes >= 3 && k.removes >= 1).length;
    const sensitiveTouchedKeys = keyStatsValues.filter(k => k.sensitive).length;
    const sensitiveHighEntropyKeys = keyStatsValues.filter(
        (k) => k.sensitive && k.lastEntropy >= 4.3 && k.lastValueLength >= 64
    ).length;

    const writeBurst1s = maxEventsInWindow(storageOps.writeTimestamps, 1000);
    const networkBurst1s = maxEventsInWindow(networkOps.requestTimestamps, 1000);
    const writeReadRatio = writes / Math.max(1, reads);

    const hostStatsEntries = Object.entries(networkOps.hostStats);
    const uniqueHosts = hostStatsEntries.length;
    const unrelatedHosts = hostStatsEntries.filter(([, value]) => value.unrelatedRequests > 0).length;
    const apiHosts = hostStatsEntries.filter(([, value]) => value.apiRequests > 0).length;
    const unrelatedApiHosts = hostStatsEntries.filter(([, value]) => value.unrelatedApiRequests > 0).length;
    const unrelatedRatio = totalRequests > 0 ? networkOps.unrelatedRequests / totalRequests : 0;

    const mutationVolume =
        activityOps.mutationBatches +
        activityOps.addedNodes +
        activityOps.removedNodes +
        activityOps.attributeMutations;

    const mutationRatePerSec = mutationVolume / observationSec;

    const storageParts = {
        writeIntensity: Math.min(12, Math.round(writes * 1.1)),
        readIntensity: Math.min(5, Math.round(reads * 0.3)),
        sensitiveUsage: Math.min(9, storageOps.sensitiveKeyWrites * 2 + localSnapshot.sensitiveKeys),
        destructiveOps: Math.min(8, destructiveOps * 2),
        payloadRisk: Math.min(
            8,
            storageOps.largeValueWrites * 2 +
            storageOps.highEntropyWrites * 2 +
            storageOps.encodedLikeWrites +
            localSnapshot.largeValues +
            sessionSnapshot.largeValues
        ),
        burstRisk: Math.min(6, Math.max(0, writeBurst1s - 2) * 2),
        churnRisk: Math.min(5, churnedKeys * 2),
        keyRotationRisk: Math.min(5, rotatingKeys * 2),
        sensitiveEntropyRisk: Math.min(6, storageOps.sensitiveHighEntropyWrites * 2 + sensitiveHighEntropyKeys),
        writeDominanceRisk: Math.min(4, writeReadRatio >= 3 ? Math.round(writeReadRatio) : 0),
        footprintRisk: Math.min(4, Math.round((localSnapshot.keyCount + sessionSnapshot.keyCount) / 8))
    };

    const networkParts = {
        requestIntensity: Math.min(6, Math.round(totalRequests * 0.7)),
        crossOriginRisk: Math.min(5, Math.round(networkOps.crossOriginRequests * 1.2)),
        domainDiversityRisk: Math.min(6, Math.max(0, uniqueHosts - 2) + unrelatedHosts),
        unrelatedDomainRisk: Math.min(7, Math.round(networkOps.unrelatedRequests * 1.3) + unrelatedHosts),
        apiSurfaceRisk: Math.min(6, apiHosts + Math.round(networkOps.apiRequests * 0.7)),
        unrelatedApiRisk: Math.min(7, unrelatedApiHosts * 2 + networkOps.unrelatedApiRequests * 2),
        storageCorrelationRisk: Math.min(
            8,
            networkOps.requestsAfterStorageEvent +
            networkOps.requestsAfterSensitiveWrite * 2
        ),
        mutatingCorrelationRisk: Math.min(
            6,
            networkOps.mutatingAfterStorageEvent * 2 +
            networkOps.mutatingAfterSensitiveWrite * 2
        ),
        outboundDataRisk: Math.min(4, Math.round(networkOps.totalBodyBytes / 8192)),
        encodedPayloadRisk: Math.min(4, networkOps.encodedPayloadRequests * 2),
        beaconAndWsRisk: Math.min(5, networkOps.beaconRequests * 2 + networkOps.websocketConnections * 2)
    };

    const activityParts = {
        fastTimers: Math.min(6, activityOps.fastTimeoutRegistrations + activityOps.fastIntervalRegistrations),
        lifecycleHooks: Math.min(
            5,
            activityOps.beforeUnloadListeners * 3 +
            activityOps.unloadListeners * 2 +
            activityOps.pagehideListeners * 2
        ),
        hiddenActivity: Math.min(
            6,
            activityOps.hiddenStorageOps * 2 +
            activityOps.hiddenNetworkRequests * 2 +
            Math.round(activityOps.hiddenMutationBursts / 10)
        ),
        domVolatility: Math.min(4, Math.round(mutationRatePerSec / 25)),
        historyRewrites: Math.min(3, activityOps.historyWrites * 2),
        visibilityHooks: Math.min(2, activityOps.visibilityListeners)
    };

    const storageScore = clamp(Object.values(storageParts).reduce((sum, n) => sum + n, 0), 0, 45);
    const networkScore = clamp(Object.values(networkParts).reduce((sum, n) => sum + n, 0), 0, 35);
    const activityScore = clamp(Object.values(activityParts).reduce((sum, n) => sum + n, 0), 0, 20);

    const totalScore = clamp(storageScore + networkScore + activityScore, 0, 100);

    let risk = 'low';
    if (totalScore >= 70) risk = 'high';
    else if (totalScore >= 35) risk = 'medium';

    const issues = [];

    if (storageScore >= 22) {
        issues.push(
            `Интенсивная работа с хранилищем: ${writes} записей, ${reads} чтений, ${destructiveOps} деструктивных операций.`
        );
    }

    if (storageOps.sensitiveKeyWrites > 0 || localSnapshot.sensitiveKeys > 0) {
        issues.push(
            `Работа с чувствительными ключами: записей=${storageOps.sensitiveKeyWrites}, ключей в localStorage=${localSnapshot.sensitiveKeys}.`
        );
    }

    if (storageOps.sensitiveHighEntropyWrites > 0 || sensitiveHighEntropyKeys > 0) {
        issues.push(
            `Чувствительные ключи с высокоэнтропийными значениями: runtime=${storageOps.sensitiveHighEntropyWrites}, snapshot=${sensitiveHighEntropyKeys}.`
        );
    }

    if (writeBurst1s >= 4) {
        issues.push(`Всплеск записи в storage: до ${writeBurst1s} операций/сек.`);
    }

    if (networkScore >= 16) {
        issues.push(
            `Сетевая активность после storage-событий: ${networkOps.requestsAfterStorageEvent} запросов, после чувствительных записей=${networkOps.requestsAfterSensitiveWrite}.`
        );
    }

    if (networkOps.unrelatedRequests > 0 || unrelatedHosts > 0) {
        issues.push(
            `Внешние домены вне зоны сайта: запросов=${networkOps.unrelatedRequests}, уникальных доменов=${unrelatedHosts}, доля=${Math.round(unrelatedRatio * 100)}%.`
        );
    }

    if (networkOps.unrelatedApiRequests > 0) {
        issues.push(
            `Обращения к API внешних доменов: запросов=${networkOps.unrelatedApiRequests}, доменов=${unrelatedApiHosts}.`
        );
    }

    if (networkOps.encodedPayloadRequests > 0 || storageOps.encodedLikeWrites > 0) {
        issues.push(
            `Обнаружены похожие на закодированные данные полезные нагрузки: storage=${storageOps.encodedLikeWrites}, network=${networkOps.encodedPayloadRequests}.`
        );
    }

    if (activityScore >= 10) {
        issues.push(
            `Высокая автоматизированная активность страницы: таймеры=${activityOps.fastTimeoutRegistrations + activityOps.fastIntervalRegistrations}, hidden-операции=${activityOps.hiddenStorageOps + activityOps.hiddenNetworkRequests}.`
        );
    }

    if (clears > 0) {
        issues.push(`Были вызовы полной очистки storage: ${clears}.`);
    }

    const topChurnKeys = keyStatsEntries
        .filter(([, value]) => value.writes > 0)
        .sort((a, b) => b[1].writes - a[1].writes)
        .slice(0, 5)
        .map(([key, value]) => ({
            key,
            area: value.area,
            writes: value.writes,
            reads: value.reads,
            sensitive: value.sensitive,
            lastValueLength: value.lastValueLength,
            lastEntropy: Number(value.lastEntropy || 0)
        }));

    const topDomains = hostStatsEntries
        .sort((a, b) => b[1].requests - a[1].requests)
        .slice(0, 8)
        .map(([host, value]) => ({
            host,
            requests: value.requests,
            crossOriginRequests: value.crossOriginRequests,
            unrelatedRequests: value.unrelatedRequests,
            apiRequests: value.apiRequests,
            unrelatedApiRequests: value.unrelatedApiRequests,
            mutatingRequests: value.mutatingRequests
        }));

    return {
        score: totalScore,
        risk,
        issues: issues.slice(0, 8),
        details: {
            version: 'behavioral-v3',
            observationMs,
            probeReady: runtimeSignals.probeReady,
            probeErrors: runtimeSignals.probeErrors,
            pageContext: {
                host: PAGE_HOSTNAME,
                baseDomain: PAGE_BASE_DOMAIN
            },
            components: {
                storage: { score: storageScore, parts: storageParts },
                network: { score: networkScore, parts: networkParts },
                activity: { score: activityScore, parts: activityParts }
            },
            metrics: {
                storage: {
                    localReads: storageOps.localReads,
                    localWrites: storageOps.localWrites,
                    localRemoves: storageOps.localRemoves,
                    localClears: storageOps.localClears,
                    sessionReads: storageOps.sessionReads,
                    sessionWrites: storageOps.sessionWrites,
                    sessionRemoves: storageOps.sessionRemoves,
                    sessionClears: storageOps.sessionClears,
                    sensitiveKeyWrites: storageOps.sensitiveKeyWrites,
                    highEntropyWrites: storageOps.highEntropyWrites,
                    largeValueWrites: storageOps.largeValueWrites,
                    encodedLikeWrites: storageOps.encodedLikeWrites,
                    sensitiveHighEntropyWrites: storageOps.sensitiveHighEntropyWrites,
                    keyCountTouched: keyStatsValues.length,
                    sensitiveTouchedKeys,
                    sensitiveHighEntropyKeys,
                    churnedKeys,
                    rotatingKeys,
                    writeReadRatio: Number(writeReadRatio.toFixed(2)),
                    writeBurst1s
                },
                network: {
                    totalRequests,
                    fetchRequests: networkOps.fetchRequests,
                    xhrRequests: networkOps.xhrRequests,
                    beaconRequests: networkOps.beaconRequests,
                    websocketConnections: networkOps.websocketConnections,
                    crossOriginRequests: networkOps.crossOriginRequests,
                    requestsAfterStorageEvent: networkOps.requestsAfterStorageEvent,
                    requestsAfterSensitiveWrite: networkOps.requestsAfterSensitiveWrite,
                    encodedPayloadRequests: networkOps.encodedPayloadRequests,
                    totalBodyBytes: networkOps.totalBodyBytes,
                    sameSiteRequests: networkOps.sameSiteRequests,
                    unrelatedRequests: networkOps.unrelatedRequests,
                    apiRequests: networkOps.apiRequests,
                    unrelatedApiRequests: networkOps.unrelatedApiRequests,
                    mutatingRequests: networkOps.mutatingRequests,
                    mutatingAfterStorageEvent: networkOps.mutatingAfterStorageEvent,
                    mutatingAfterSensitiveWrite: networkOps.mutatingAfterSensitiveWrite,
                    requestsWithoutUrl: networkOps.requestsWithoutUrl,
                    uniqueHosts,
                    unrelatedHosts,
                    apiHosts,
                    unrelatedApiHosts,
                    unrelatedRatio: Number(unrelatedRatio.toFixed(3)),
                    networkBurst1s
                },
                activity: {
                    fastTimeoutRegistrations: activityOps.fastTimeoutRegistrations,
                    fastIntervalRegistrations: activityOps.fastIntervalRegistrations,
                    beforeUnloadListeners: activityOps.beforeUnloadListeners,
                    unloadListeners: activityOps.unloadListeners,
                    pagehideListeners: activityOps.pagehideListeners,
                    visibilityListeners: activityOps.visibilityListeners,
                    storageListeners: activityOps.storageListeners,
                    historyWrites: activityOps.historyWrites,
                    mutationBatches: activityOps.mutationBatches,
                    addedNodes: activityOps.addedNodes,
                    removedNodes: activityOps.removedNodes,
                    attributeMutations: activityOps.attributeMutations,
                    hiddenStorageOps: activityOps.hiddenStorageOps,
                    hiddenNetworkRequests: activityOps.hiddenNetworkRequests,
                    hiddenMutationBursts: activityOps.hiddenMutationBursts,
                    mutationRatePerSec: Number(mutationRatePerSec.toFixed(2))
                },
                storageSnapshot: {
                    local: localSnapshot,
                    session: sessionSnapshot
                }
            },
            hotKeys: topChurnKeys,
            hotDomains: topDomains
        }
    };
}

async function safeEncryptAll() {
    if (!(await isProtectionEnabled())) {
        await logToExtension('Авто-шифрование пропущено: защита отключена', 'info');
        return { count: 0, skipped: 0, disabled: true };
    }

    await getCryptoKey();

    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && !key.startsWith('encrypted_')) keys.push(key);
    }

    let count = 0;
    let skipped = 0;
    for (const key of keys) {
        try {
            const value = localStorage.getItem(key);
            if (value === null) continue;
            const encrypted = await encryptValue(value);
            localStorage.setItem('encrypted_' + key, encrypted);
            localStorage.removeItem(key);
            count++;
        } catch (e) {
            skipped++;
            await logToExtension(`Шифрование "${key}": ${e.message}`, 'error');
        }
    }
    return { count, skipped };
}

async function safeDecryptAll() {
    await getCryptoKey();

    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key?.startsWith('encrypted_')) keys.push(key);
    }

    let count = 0;
    for (const key of keys) {
        try {
            const encrypted = localStorage.getItem(key);
            const decrypted = await decryptValue(encrypted);
            localStorage.setItem(key.replace('encrypted_', ''), decrypted);
            localStorage.removeItem(key);
            count++;
        } catch (e) {
            await logToExtension(`Дешифрование "${key}": ${e.message}`, 'error');
        }
    }
    return { count };
}

async function safeExport() {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if (key?.startsWith('encrypted_')) {
            try {
                data[key.replace('encrypted_', '')] = await decryptValue(value);
            } catch {
                data[key] = '[Ошибка дешифрования]';
            }
        } else {
            data[key] = value;
        }
    }
    return Object.entries(data)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        try {
            if (request.action === 'encrypt') {
                const res = await safeEncryptAll();
                await logToExtension(
                    `Ручное шифрование по кнопке: количество полей - ${res.count}, пропущенных - ${res.skipped}`,
                    'manual_encrypt'
                );
                sendResponse({ success: true, ...res });
            } else if (request.action === 'decrypt') {
                const res = await safeDecryptAll();
                await logToExtension(
                    `Ручная расшифровка по кнопке: количество полей - ${res.count}`,
                    'manual_decrypt'
                );
                sendResponse({ success: true, ...res });
            } else if (request.action === 'export') {
                const data = await safeExport();
                await logToExtension(
                    `Экспорт данных localStorage (${window.location.origin}), длина - ${data.length}`,
                    'export'
                );
                sendResponse({ success: true, data });
            }
        } catch (e) {
            await logToExtension(`Ошибка: ${e.message}`, 'error');
            sendResponse({ success: false, error: e.message });
        }
    })();
    return true;
});

function requestFullAnalysis(analysis) {
    return new Promise((resolve, reject) => {
        if (!isRuntimeMessageAvailable()) {
            reject(new Error('Контекст расширения недоступен'));
            return;
        }

        try {
            chrome.runtime.sendMessage(
                {
                    action: 'page_analyzed_full',
                    url: window.location.origin,
                    ...analysis
                },
                (response) => {
                    if (chrome.runtime.lastError) {
                        const runtimeError = new Error(chrome.runtime.lastError.message);
                        if (isIgnorableRuntimeError(runtimeError)) {
                            reject(new Error('Контекст расширения был перезагружен'));
                            return;
                        }
                        reject(runtimeError);
                        return;
                    }
                    if (!response || !response.success) {
                        reject(new Error(response?.error || 'Нет ответа от background'));
                        return;
                    }
                    resolve(response.data);
                }
            );
        } catch (e) {
            reject(e);
        }
    });
}

function riskToRank(risk) {
    if (risk === 'high') return 3;
    if (risk === 'medium') return 2;
    return 1;
}

function shouldReportAnalysis(analysis, reasons, now) {
    if (analysisState.lastReportedScore === null || analysisState.lastReportedRisk === null) {
        return true;
    }

    const hasPriorityReason = reasons.some((reason) =>
        reason === 'load' ||
        reason === 'pageshow' ||
        reason === 'popstate' ||
        reason === 'hashchange' ||
        reason.includes('history') ||
        reason.includes('suspicious')
    );
    if (hasPriorityReason) return true;

    const scoreDelta = Math.abs((analysisState.lastReportedScore || 0) - analysis.score);
    if (scoreDelta >= SIGNIFICANT_SCORE_DELTA) return true;

    if (riskToRank(analysis.risk) !== riskToRank(analysisState.lastReportedRisk)) {
        return true;
    }

    return now - analysisState.lastReportedAt >= FORCE_REPORT_INTERVAL_MS;
}

function shouldRunFullAnalysis(mode, analysis, reasons, now, policy) {
    if (mode === 'local') return false;
    if (policy === 'always') return true;
    if (analysis.risk === 'high') return true;

    const sinceLastFull = now - analysisState.lastFullRunAt;
    if (analysisState.lastFullRunAt === 0) {
        return analysis.score >= 35;
    }

    if (sinceLastFull < FULL_ANALYSIS_MIN_INTERVAL_MS) {
        return false;
    }

    if (analysis.score >= 55) return true;

    return reasons.some((reason) =>
        reason === 'load' ||
        reason === 'pageshow' ||
        reason.includes('history') ||
        reason.includes('suspicious')
    );
}

function resetRuntimeSignalWindow() {
    const next = createRuntimeSignals();
    runtimeSignals.startedAt = Date.now();
    runtimeSignals.storage = next.storage;
    runtimeSignals.network = next.network;
    runtimeSignals.activity = next.activity;
}

async function runAnalysisCycle() {
    if (!isRuntimeMessageAvailable()) return;
    if (analysisState.inFlight) {
        analysisState.pending = true;
        return;
    }

    analysisState.inFlight = true;
    const reasons = Array.from(analysisState.pendingReasons);
    analysisState.pendingReasons.clear();
    analysisState.lastRunAt = Date.now();

    try {
        if (!(await isProtectionEnabled())) {
            if (!analysisState.protectionDisabledLogged) {
                await logToExtension(`Защита отключена, анализ пропущен для ${window.location.origin}`, 'info');
                analysisState.protectionDisabledLogged = true;
            }
            return;
        }
        analysisState.protectionDisabledLogged = false;

        const analysis = await analyze();
        const now = Date.now();
        const shouldReport = shouldReportAnalysis(analysis, reasons, now);

        if (!shouldReport) {
            return;
        }

        await logToExtension(
            `Анализ ${window.location.origin}: угроза=${analysis.risk}, счет=${analysis.score}, триггеры=${reasons.join(',') || 'scheduled'}`,
            'info'
        );

        const { settings = {} } = await chrome.storage.sync.get('settings');
        const mode = settings.mode || 'hybrid';
        const autoEncrypt = settings.autoEncrypt !== false;
        const fullAnalysisPolicy = settings.fullAnalysisPolicy || 'always';

        if (mode === 'local') {
            await sendRuntimeMessageQuietly({
                action: 'page_analyzed',
                url: window.location.origin,
                ...analysis
            });

            if (analysis.risk === 'high' && autoEncrypt) {
                await sendRuntimeMessageQuietly({
                    action: 'log_event',
                    message: 'Локальный режим анализа, запускаю авто-шифрование',
                    type: 'auto_encrypt'
                });
                const result = await safeEncryptAll();
                if (result.count > 0) {
                    await recordOperation('auto_encrypt');
                    await sendRuntimeMessageQuietly({
                        action: 'show_notification',
                        message: `Зашифровано ${result.count} записей`
                    });
                    await logToExtension(
                        `Auto-шифрование (локальный анализ): ${result.count} записей`,
                        'auto_encrypt'
                    );
                }
            }
        } else {
            const runFull = shouldRunFullAnalysis(mode, analysis, reasons, now, fullAnalysisPolicy);
            if (!runFull) {
                await sendRuntimeMessageQuietly({
                    action: 'page_analyzed',
                    url: window.location.origin,
                    ...analysis
                });
            } else {
                await logToExtension(
                    `Полный режим анализа: отправляю запрос на полный анализ (локальный risk=${analysis.risk})`,
                    'info'
                );
                const full = await requestFullAnalysis(analysis);
                analysisState.lastFullRunAt = now;

                await logToExtension(
                    `Ответ полного анализа: угроза - ${full.aiDanger}`,
                    'info'
                );

                if (autoEncrypt && full.aiDanger === 'высокий') {
                    const result = await safeEncryptAll();
                    if (result.count > 0) {
                        await recordOperation('auto_encrypt_ai');
                        await sendRuntimeMessageQuietly({
                            action: 'show_notification',
                            message: `Сайт признан опасным. Зашифровано ${result.count} записей (Полный анализ)`
                        });
                        await logToExtension(
                            `Полный анализ: зашифровано ${result.count} записей`,
                            'auto_encrypt_ai'
                        );
                    }
                }
            }
        }

        analysisState.lastReportedAt = now;
        analysisState.lastReportedRisk = analysis.risk;
        analysisState.lastReportedScore = analysis.score;
    } catch (e) {
        await logToExtension(`Ошибка анализа: ${e.message}`, 'error');
    } finally {
        resetRuntimeSignalWindow();
        analysisState.inFlight = false;
        if (analysisState.pending) {
            analysisState.pending = false;
            scheduleAnalysis('pending', { force: true });
        }
    }
}

function registerDynamicAnalysisTriggers() {
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        scheduleAnalysis('startup', { force: true });
    }

    window.addEventListener(
        'load',
        () => {
            scheduleAnalysis('load', { force: true });
        },
        { once: true }
    );

    window.addEventListener('popstate', () => {
        scheduleAnalysis('popstate', { force: true });
    });

    window.addEventListener('hashchange', () => {
        scheduleAnalysis('hashchange', { force: true });
    });

    window.addEventListener('pageshow', () => {
        scheduleAnalysis('pageshow');
    });

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            scheduleAnalysis('visible');
        }
    });
}

if (chrome.runtime?.sendMessage) {
    registerDynamicAnalysisTriggers();
}
