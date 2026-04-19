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
        await logToExtension({
            category: 'encryption',
            level: 'error',
            event: 'decrypt_value_failed',
            title: 'Не удалось расшифровать значение',
            message: e.message,
            url: getCurrentPageUrl()
        });
        throw e;
    }
}
