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
                    url: getCurrentPageUrl(),
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
        if (await isSiteWhitelisted()) {
            return;
        }

        if (!(await isProtectionEnabled())) {
            if (!analysisState.protectionDisabledLogged) {
                await logToExtension({
                    category: 'settings',
                    level: 'warn',
                    event: 'analysis_skipped_protection_disabled',
                    title: 'Анализ пропущен',
                    message: 'Защита отключена, поэтому проверка страницы не выполнялась.',
                    url: getCurrentPageUrl()
                });
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

        await logToExtension({
            category: 'analysis',
            level: 'info',
            event: 'local_analysis_completed',
            title: 'Локальный анализ завершён',
            message: 'Страница проверена по локальным эвристикам.',
            url: getCurrentPageUrl(),
            context: {
                risk: analysis.risk,
                score: analysis.score,
                triggers: reasons.join(',') || 'scheduled'
            }
        });

        const { settings = {} } = await chrome.storage.sync.get('settings');
        const mode = settings.mode || 'hybrid';
        const autoEncrypt = settings.autoEncrypt !== false;
        const fullAnalysisPolicy = settings.fullAnalysisPolicy || 'always';

        if (mode === 'local') {
            await sendRuntimeMessageQuietly({
                action: 'page_analyzed',
                url: getCurrentPageUrl(),
                ...analysis
            });

            if (analysis.risk === 'high' && autoEncrypt) {
                await logToExtension({
                    category: 'encryption',
                    level: 'info',
                    event: 'auto_encrypt_started',
                    title: 'Запущено авто-шифрование',
                    message: 'Локальный анализ обнаружил высокий риск, запускаем автоматическое шифрование.',
                    url: getCurrentPageUrl(),
                    context: {
                        risk: analysis.risk,
                        score: analysis.score,
                        mode: 'local'
                    }
                });
                const result = await safeEncryptAll();
                if (result.count > 0) {
                    await recordOperation('auto_encrypt');
                    await sendRuntimeMessageQuietly({
                        action: 'show_notification',
                        message: `Зашифровано ${result.count} записей`
                    });
                    await logToExtension({
                        category: 'encryption',
                        level: 'success',
                        event: 'auto_encrypt_completed',
                        title: 'Авто-шифрование выполнено',
                        message: `После локального анализа зашифровано ${result.count} записей.`,
                        url: getCurrentPageUrl(),
                        context: {
                            count: result.count,
                            skipped: result.skipped,
                            mode: 'local'
                        }
                    });
                }
            }
        } else {
            const runFull = shouldRunFullAnalysis(mode, analysis, reasons, now, fullAnalysisPolicy);
            if (!runFull) {
                await sendRuntimeMessageQuietly({
                    action: 'page_analyzed',
                    url: getCurrentPageUrl(),
                    ...analysis
                });
            } else {
                await logToExtension({
                    category: 'ai',
                    level: 'info',
                    event: 'full_analysis_requested',
                    title: 'Запрошен полный анализ',
                    message: 'Локальная оценка требует дополнительной проверки в LM Studio.',
                    url: getCurrentPageUrl(),
                    context: {
                        risk: analysis.risk,
                        score: analysis.score,
                        policy: fullAnalysisPolicy
                    }
                });
                const full = await requestFullAnalysis(analysis);
                analysisState.lastFullRunAt = now;

                await logToExtension({
                    category: 'ai',
                    level: 'info',
                    event: 'full_analysis_received',
                    title: 'Получен результат полного анализа',
                    message: 'LM Studio вернул итоговую оценку страницы.',
                    url: getCurrentPageUrl(),
                    context: {
                        aiDanger: full.aiDanger,
                        risk: full.risk,
                        score: full.score
                    }
                });

                if (autoEncrypt && (full.aiDanger === 'high' || full.aiDanger === 'высокий')) {
                    const result = await safeEncryptAll();
                    if (result.count > 0) {
                        await recordOperation('auto_encrypt_ai');
                        await sendRuntimeMessageQuietly({
                            action: 'show_notification',
                            message: `Сайт признан опасным. Зашифровано ${result.count} записей (Полный анализ)`
                        });
                        await logToExtension({
                            category: 'encryption',
                            level: 'success',
                            event: 'ai_auto_encrypt_completed',
                            title: 'AI-автошифрование выполнено',
                            message: `После полного анализа зашифровано ${result.count} записей.`,
                            url: getCurrentPageUrl(),
                            context: {
                                count: result.count,
                                skipped: result.skipped,
                                trigger: 'ai'
                            }
                        });
                    }
                }
            }
        }

        analysisState.lastReportedAt = now;
        analysisState.lastReportedRisk = analysis.risk;
        analysisState.lastReportedScore = analysis.score;
    } catch (e) {
        await logToExtension({
            category: 'analysis',
            level: 'error',
            event: 'analysis_failed',
            title: 'Ошибка анализа страницы',
            message: e.message,
            url: getCurrentPageUrl()
        });
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
    void bootstrapRuntimeMonitoring();
}

if (chrome.storage?.onChanged) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== 'sync' || !changes.whitelistedSites) return;
        void bootstrapRuntimeMonitoring();
    });
}
