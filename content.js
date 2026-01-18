const pwd = 'vsosh{fake_flag}';
const slt = new TextEncoder().encode('}vsosh{');
const ins = 100000;
let cryptoKeyPromise = null;

// Проверка состояния защиты
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

function analyzePageForXSS() {
    let score = 0;
    const issues = [];

    const inlineScripts = document.querySelectorAll('script:not([src])');
    const inlineCount = inlineScripts.length;
    if (inlineCount > 5) {
        score += 25;
        issues.push(`Много подозрительных скриптов: ${inlineCount}`);
    } else if (inlineCount > 0) {
        score += 15;
    }

    const dangerousEvents = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onchange'];
    let eventCount = 0;
    dangerousEvents.forEach(attr => {
        eventCount += document.querySelectorAll(`[${attr}]`).length;
    });
    if (eventCount > 10) {
        score += 30;
        issues.push(`Много обработчиков событий: ${eventCount}`);
    } else if (eventCount > 3) {
        score += 10;
    }

    const scripts = document.querySelectorAll('script');
    const dangerousPatterns = [/eval\s*\(/gi, /innerHTML\s*=/gi, /document\.write/gi];
    let dangerousCount = 0;
    scripts.forEach(script => {
        const code = (script.textContent || '').toLowerCase();
        dangerousPatterns.forEach(pattern => {
            const matches = code.match(pattern);
            if (matches) dangerousCount += matches.length;
        });
    });
    if (dangerousCount > 3) {
        score += 30;
        issues.push(`Опасные функции: ${dangerousCount}`);
    } else if (dangerousCount > 0) {
        score += 15;
    }

    const forms = Array.from(document.forms);
    for (const form of forms) {
        const action = (form.action || '').toLowerCase();
        if (action.includes('javascript:') || action.includes('vbscript:')) {
            score += 30;
            issues.push('JS в action формы');
        }
        if (!form.action || form.action === '#') {
            score += 10;
        }
    }

    const externalScripts = document.querySelectorAll('script[src]');
    const badDomains = ['.xyz', '.tk', 'pastebin', 'rawgit'];
    let suspiciousScripts = 0;
    let httpScripts = 0;
    externalScripts.forEach(script => {
        const src = script.src.toLowerCase();
        if (window.location.protocol === 'https:' && src.startsWith('http:')) {
            httpScripts++;
            score += 15;
        }
        if (badDomains.some(domain => src.includes(domain))) {
            score += 30;
            suspiciousScripts++;
        }
    });
    if (suspiciousScripts > 0) issues.push(`Подозрительные скрипты: ${suspiciousScripts}`);
    if (httpScripts > 0) issues.push(`HTTP на HTTPS странице: ${httpScripts}`);

    const iframes = document.querySelectorAll('iframe:not([sandbox])');
    if (iframes.length > 3) {
        score += 30;
        issues.push(`Много iframe без sandbox: ${iframes.length}`);
    } else if (iframes.length > 0) {
        score += 10;
    }

    let risk = 'low';
    if (score >= 70) risk = 'high';
    else if (score >= 35) risk = 'medium';

    return {
        score: Math.min(score, 100),
        risk,
        issues: issues.slice(0, 5),
        details: {
            inlineCount,
            eventCount,
            dangerousCount,
            suspiciousScripts,
            iframes: iframes.length
        }
    };
}

async function safeEncryptAll() {
    // Проверяем защиту
    if (!(await isProtectionEnabled())) {
        await logToExtension('Авто-шифрование пропущено: защита отключена', 'info');
        return { count: 0, skipped: 0, disabled: true };
    }

    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && !key.startsWith('encrypted_')) keys.push(key);
    }

    let count = 0, skipped = 0;
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

// ====== ОБМЕН С POPUP ======
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
            // Проверяем, включена ли защита
            if (!(await isProtectionEnabled())) {
                await logToExtension(`Защита отключена, анализ пропущен для ${window.location.origin}`, 'info');
                return;
            }

            await logToExtension(`Старт локального анализа для ${window.location.origin}`, 'info');
            const analysis = analyzePageForXSS();
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
                    `Локальный режим анализа, запускаю авто-шифрование`,
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
                `Полный режим анализа: отправляю запрос на полный анализ`,
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
