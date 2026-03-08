const pwd = 'vsosh{fake_flag}';
const slt = new TextEncoder().encode('}vsosh{');
const ins = 100000;
let cryptoKeyPromise = null;

const SENSITIVE_KEY_PATTERN = /(token|auth|session|jwt|bearer|secret|pass|credential|sid|csrf|xsrf|refresh|access)/i;
const LARGE_VALUE_THRESHOLD = 2048;
const MIN_OBSERVATION_MS = 3000;
const CORRELATION_WINDOW_MS = 2500;

const runtimeSignals = createRuntimeSignals();
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
            keyStats: Object.create(null),
            lastStorageEventAt: 0,
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
            encodedPayloadRequests: 0,
            totalBodyBytes: 0,
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
            break;
        case 'probe_error':
            runtimeSignals.probeErrors += 1;
            break;
        case 'storage':
            applyStorageSignal(payload, timestamp);
            break;
        case 'network_fetch':
        case 'network_xhr':
        case 'network_beacon':
        case 'network_ws':
            applyNetworkSignal(type, payload, timestamp);
            break;
        case 'timer':
            applyTimerSignal(payload);
            break;
        case 'listener':
            applyListenerSignal(payload);
            break;
        case 'history':
            runtimeSignals.activity.historyWrites += 1;
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

            if (keyBucket.sensitive) runtimeSignals.storage.sensitiveKeyWrites += 1;
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

    const lastStorageAt = runtimeSignals.storage.lastStorageEventAt || 0;
    if (lastStorageAt > 0 && timestamp - lastStorageAt <= CORRELATION_WINDOW_MS) {
        runtimeSignals.network.requestsAfterStorageEvent += 1;
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

async function logToExtension(message, type = 'info') {
    if (chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ action: 'log_event', message, type }).catch(() => {});
    }
}

async function getCryptoKey() {
    if (!cryptoKeyPromise) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(pwd);
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
    const sensitiveTouchedKeys = keyStatsValues.filter(k => k.sensitive).length;

    const writeBurst1s = maxEventsInWindow(storageOps.writeTimestamps, 1000);
    const networkBurst1s = maxEventsInWindow(networkOps.requestTimestamps, 1000);

    const mutationVolume =
        activityOps.mutationBatches +
        activityOps.addedNodes +
        activityOps.removedNodes +
        activityOps.attributeMutations;

    const mutationRatePerSec = mutationVolume / observationSec;

    const storageParts = {
        writeIntensity: Math.min(14, Math.round(writes * 1.2)),
        readIntensity: Math.min(6, Math.round(reads * 0.35)),
        sensitiveUsage: Math.min(10, storageOps.sensitiveKeyWrites * 2 + localSnapshot.sensitiveKeys),
        destructiveOps: Math.min(8, destructiveOps * 2),
        payloadRisk: Math.min(
            9,
            storageOps.largeValueWrites * 2 +
            storageOps.highEntropyWrites * 2 +
            storageOps.encodedLikeWrites +
            localSnapshot.largeValues +
            sessionSnapshot.largeValues
        ),
        burstRisk: Math.min(7, Math.max(0, writeBurst1s - 2) * 2),
        churnRisk: Math.min(7, churnedKeys * 2),
        footprintRisk: Math.min(5, Math.round((localSnapshot.keyCount + sessionSnapshot.keyCount) / 6))
    };

    const networkParts = {
        requestIntensity: Math.min(8, Math.round(totalRequests * 0.8)),
        crossOriginRisk: Math.min(10, networkOps.crossOriginRequests * 2),
        storageCorrelationRisk: Math.min(10, networkOps.requestsAfterStorageEvent * 2),
        outboundDataRisk: Math.min(4, Math.round(networkOps.totalBodyBytes / 8192)),
        encodedPayloadRisk: Math.min(5, networkOps.encodedPayloadRequests * 2),
        beaconAndWsRisk: Math.min(6, networkOps.beaconRequests * 2 + networkOps.websocketConnections * 3)
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

    if (writeBurst1s >= 4) {
        issues.push(`Всплеск записи в storage: до ${writeBurst1s} операций/сек.`);
    }

    if (networkScore >= 16) {
        issues.push(
            `Сетевая активность после storage-событий: ${networkOps.requestsAfterStorageEvent} запросов, cross-origin=${networkOps.crossOriginRequests}.`
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
            lastValueLength: value.lastValueLength
        }));

    return {
        score: totalScore,
        risk,
        issues: issues.slice(0, 8),
        details: {
            version: 'behavioral-v2',
            observationMs,
            probeReady: runtimeSignals.probeReady,
            probeErrors: runtimeSignals.probeErrors,
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
                    keyCountTouched: keyStatsValues.length,
                    sensitiveTouchedKeys,
                    churnedKeys,
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
                    encodedPayloadRequests: networkOps.encodedPayloadRequests,
                    totalBodyBytes: networkOps.totalBodyBytes,
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
            hotKeys: topChurnKeys
        }
    };
}

async function safeEncryptAll() {
    if (!(await isProtectionEnabled())) {
        await logToExtension('Авто-шифрование пропущено: защита отключена', 'info');
        return { count: 0, skipped: 0, disabled: true };
    }

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
        try {
            chrome.runtime.sendMessage(
                {
                    action: 'page_analyzed_full',
                    url: window.location.origin,
                    ...analysis
                },
                (response) => {
                    if (chrome.runtime.lastError) {
                        reject(new Error(chrome.runtime.lastError.message));
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

if (chrome.runtime?.sendMessage) {
    window.addEventListener('load', async () => {
        try {
            if (!(await isProtectionEnabled())) {
                await logToExtension(`Защита отключена, анализ пропущен для ${window.location.origin}`, 'info');
                return;
            }

            await logToExtension(`Старт локального анализа для ${window.location.origin}`, 'info');
            const analysis = await analyze();
            await logToExtension(
                `Результат локального анализа ${window.location.origin}: угроза - ${analysis.risk}, счет - ${analysis.score}`,
                'info'
            );

            const { settings = {} } = await chrome.storage.sync.get('settings');
            const mode = settings.mode || 'hybrid';
            const autoEncrypt = settings.autoEncrypt !== false;

            if (analysis.risk !== 'high' || !autoEncrypt) {
                chrome.runtime.sendMessage({
                    action: 'page_analyzed',
                    url: window.location.origin,
                    ...analysis
                });
                await logToExtension(
                    `Авто-шифрование не запущено (risk=${analysis.risk}, autoEncrypt=${autoEncrypt})`,
                    'info'
                );
                return;
            }

            if (mode === 'local') {
                chrome.runtime.sendMessage({
                    action: 'page_analyzed',
                    url: window.location.origin,
                    ...analysis
                });
                await logToExtension(
                    'Локальный режим анализа, запускаю авто-шифрование',
                    'auto_encrypt'
                );
                const result = await safeEncryptAll();
                if (result.count > 0) {
                    chrome.runtime.sendMessage({
                        action: 'show_notification',
                        message: `Зашифровано ${result.count} записей`
                    });
                    await logToExtension(
                        `Auto-шифрование (локальный анализ): ${result.count} записей`,
                        'auto_encrypt'
                    );
                }
                return;
            }

            await logToExtension(
                'Полный режим анализа: отправляю запрос на полный анализ',
                'info'
            );
            const full = await requestFullAnalysis(analysis);
            await logToExtension(
                `Ответ полного анализа: угроза - ${full.aiDanger}`,
                'info'
            );

            if (full.aiDanger === 'высокий') {
                const result = await safeEncryptAll();
                if (result.count > 0) {
                    chrome.runtime.sendMessage({
                        action: 'page_analyzed',
                        url: window.location.origin,
                        ...analysis,
                        encryptedByAI: true,
                        encryptedCount: result.count
                    });
                    chrome.runtime.sendMessage({
                        action: 'show_notification',
                        message: `Сайт признан опасным. Зашифровано ${result.count} записей (Полный анализ)`
                    });
                    await logToExtension(
                        `Полный анализ: зашифровано ${result.count} записей`,
                        'auto_encrypt_ai'
                    );
                }
            } else {
                await logToExtension(
                    `Вердикт ИИ не высок (${full.aiDanger}), авто-шифрование не выполняется`,
                    'info'
                );
            }
        } catch (e) {
            await logToExtension(`Ошибка анализа: ${e.message}`, 'error');
        }
    }, { once: true });
}
