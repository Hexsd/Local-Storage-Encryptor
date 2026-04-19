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
