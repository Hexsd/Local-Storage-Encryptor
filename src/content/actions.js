async function safeEncryptAll() {
    if (!(await isProtectionEnabled())) {
        await logToExtension({
            category: 'encryption',
            level: 'warn',
            event: 'auto_encrypt_skipped',
            title: 'Авто-шифрование пропущено',
            message: 'Защита отключена, поэтому автоматическое шифрование не запускалось.',
            url: getCurrentPageUrl()
        });
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
            await logToExtension({
                category: 'encryption',
                level: 'error',
                event: 'encrypt_key_failed',
                title: 'Ошибка шифрования записи',
                message: `Не удалось зашифровать ключ "${key}".`,
                url: getCurrentPageUrl(),
                context: {
                    key,
                    reason: e.message
                }
            });
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
            await logToExtension({
                category: 'encryption',
                level: 'error',
                event: 'decrypt_key_failed',
                title: 'Ошибка расшифровки записи',
                message: `Не удалось расшифровать ключ "${key}".`,
                url: getCurrentPageUrl(),
                context: {
                    key,
                    reason: e.message
                }
            });
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
                await logToExtension({
                    category: 'encryption',
                    level: 'success',
                    event: 'manual_encrypt_completed',
                    title: 'Ручное шифрование завершено',
                    message: `Зашифровано ${res.count} записей, пропущено ${res.skipped}.`,
                    url: getCurrentPageUrl(),
                    context: {
                        count: res.count,
                        skipped: res.skipped
                    }
                });
                sendResponse({ success: true, ...res });
            } else if (request.action === 'decrypt') {
                const res = await safeDecryptAll();
                await logToExtension({
                    category: 'encryption',
                    level: 'success',
                    event: 'manual_decrypt_completed',
                    title: 'Ручная расшифровка завершена',
                    message: `Расшифровано ${res.count} записей.`,
                    url: getCurrentPageUrl(),
                    context: {
                        count: res.count
                    }
                });
                sendResponse({ success: true, ...res });
            } else if (request.action === 'export') {
                const data = await safeExport();
                await logToExtension({
                    category: 'data',
                    level: 'success',
                    event: 'export_completed',
                    title: 'Экспорт localStorage подготовлен',
                    message: 'Данные собраны и готовы к сохранению в файл.',
                    url: getCurrentPageUrl(),
                    context: {
                        size: data.length
                    }
                });
                sendResponse({ success: true, data });
            }
        } catch (e) {
            await logToExtension({
                category: 'system',
                level: 'error',
                event: 'content_action_failed',
                title: 'Ошибка действия на странице',
                message: e.message,
                url: getCurrentPageUrl()
            });
            sendResponse({ success: false, error: e.message });
        }
    })();
    return true;
});
