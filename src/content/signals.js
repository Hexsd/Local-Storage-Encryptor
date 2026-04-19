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
