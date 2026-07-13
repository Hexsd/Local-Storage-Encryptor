(() => {
    'use strict';

    if (window.__localSentinelProbe) return;
    Object.defineProperty(window, '__localSentinelProbe', { value: true });

    const SOURCE = 'local_sentinel_probe';
    const POLICY_SOURCE = 'local_sentinel_guard';
    const SENSITIVE_KEY = /(access|refresh|id)[_-]?token|auth|authorization|bearer|session|jwt|secret|credential|password|passwd|csrf|xsrf|sid/i;
    const TRACKED_EVENTS = new Set(['beforeunload', 'unload', 'pagehide', 'visibilitychange', 'storage']);
    const secrets = new Set();
    const MAX_SECRETS = 64;
    const MIN_SECRET_LENGTH = 12;
    let policy = { enabled: true, mode: 'balanced', blockDangerousForms: true, trustedDestinations: [] };

    function emit(type, payload = {}) {
        try {
            window.postMessage({ source: SOURCE, type, payload, ts: Date.now() }, '*');
        } catch {
        }
    }

    function baseDomain(hostname) {
        const host = String(hostname || '').toLowerCase();
        if (!host || host === 'localhost' || /^\d+(?:\.\d+){3}$/.test(host) || host.includes(':')) return host;
        const parts = host.split('.').filter(Boolean);
        const compound = new Set(['co.uk', 'org.uk', 'com.au', 'co.jp', 'com.br', 'com.tr', 'co.in']);
        if (parts.length > 2 && compound.has(parts.slice(-2).join('.'))) return parts.slice(-3).join('.');
        return parts.slice(-2).join('.');
    }

    function toUrl(value) {
        try {
            const raw = typeof value === 'string' ? value : value?.url;
            return raw ? new URL(raw, location.href) : null;
        } catch {
            return null;
        }
    }

    function isUnrelated(url) {
        return Boolean(url?.hostname) && baseDomain(url.hostname) !== baseDomain(location.hostname);
    }

    function isTrusted(url) {
        if (!url) return false;
        return policy.trustedDestinations.some((entry) => {
            try {
                const trusted = new URL(entry.includes('://') ? entry : `https://${entry}`);
                return trusted.hostname === url.hostname || url.hostname.endsWith(`.${trusted.hostname}`);
            } catch {
                return false;
            }
        });
    }

    function rememberSecret(value) {
        const text = String(value ?? '');
        if (text.length < MIN_SECRET_LENGTH || text.length > 8192) return;
        secrets.add(text);
        while (secrets.size > MAX_SECRETS) secrets.delete(secrets.values().next().value);
    }

    function inspectStructuredValue(value, depth = 0) {
        if (!value || typeof value !== 'object' || depth > 3) return;
        for (const [key, nested] of Object.entries(value).slice(0, 80)) {
            if (SENSITIVE_KEY.test(key) && (typeof nested === 'string' || typeof nested === 'number')) {
                rememberSecret(nested);
            } else if (nested && typeof nested === 'object') {
                inspectStructuredValue(nested, depth + 1);
            }
        }
    }

    function inspectStorageValue(key, value) {
        const text = String(value ?? '');
        if (SENSITIVE_KEY.test(String(key || ''))) rememberSecret(text);
        if (text.length > 1 && text.length <= 32768 && (text[0] === '{' || text[0] === '[')) {
            try { inspectStructuredValue(JSON.parse(text)); } catch { }
        }
    }

    function bodyText(body) {
        try {
            if (body == null) return '';
            if (typeof body === 'string') return body;
            if (body instanceof URLSearchParams) return body.toString();
            if (body instanceof FormData) {
                const parts = [];
                body.forEach((value, key) => {
                    if (typeof value === 'string') parts.push(`${key}=${value}`);
                });
                return parts.join('&');
            }
            if (body instanceof ArrayBuffer) return new TextDecoder().decode(body.slice(0, 65536));
            if (ArrayBuffer.isView(body)) return new TextDecoder().decode(body.buffer.slice(0, 65536));
        } catch { }
        return '';
    }

    function containsSecret(text) {
        const haystack = String(text || '');
        if (!haystack) return false;
        for (const secret of secrets) {
            if (haystack.includes(secret) || haystack.includes(encodeURIComponent(secret))) return true;
        }
        return false;
    }

    function shouldBlock(target, body) {
        if (!policy.enabled || policy.mode === 'monitor') return null;
        const url = toUrl(target);
        const external = policy.mode === 'strict' ? url?.origin !== location.origin : isUnrelated(url);
        if (!url || !external || isTrusted(url)) return null;
        const combined = `${url.href}\n${bodyText(body)}`;
        if (!containsSecret(combined)) return null;
        return { url, reason: 'sensitive_storage_value' };
    }

    function blocked(kind, result) {
        emit('request_blocked', {
            kind,
            destination: result.url.origin,
            reason: result.reason
        });
    }

    function storageArea(instance) {
        return instance === window.sessionStorage ? 'session' : 'local';
    }

    function wrapStorage() {
        if (!window.Storage?.prototype) return;
        const proto = window.Storage.prototype;
        const getItem = proto.getItem;
        const setItem = proto.setItem;
        const removeItem = proto.removeItem;
        const clear = proto.clear;

        proto.getItem = function (key) {
            const value = getItem.call(this, key);
            inspectStorageValue(key, value);
            emit('storage', { area: storageArea(this), op: 'getItem', key: String(key ?? '') });
            return value;
        };
        proto.setItem = function (key, value) {
            inspectStorageValue(key, value);
            emit('storage', {
                area: storageArea(this), op: 'setItem', key: String(key ?? ''),
                valueLength: String(value ?? '').length, sensitive: SENSITIVE_KEY.test(String(key ?? ''))
            });
            return setItem.call(this, key, value);
        };
        proto.removeItem = function (key) {
            emit('storage', { area: storageArea(this), op: 'removeItem', key: String(key ?? '') });
            return removeItem.call(this, key);
        };
        proto.clear = function () {
            secrets.clear();
            emit('storage', { area: storageArea(this), op: 'clear' });
            return clear.call(this);
        };

        for (const storage of [window.localStorage, window.sessionStorage]) {
            try {
                for (let i = 0; i < storage.length; i += 1) {
                    const key = storage.key(i);
                    inspectStorageValue(key, getItem.call(storage, key));
                }
            } catch { }
        }
    }

    function wrapFetch() {
        if (typeof window.fetch !== 'function') return;
        const original = window.fetch;
        window.fetch = function (input, init = {}) {
            const result = shouldBlock(input, init?.body);
            if (result) {
                blocked('fetch', result);
                return Promise.reject(new TypeError('Local Sentinel blocked a possible credential leak'));
            }
            const url = toUrl(input);
            emit('network_fetch', { url: url?.href || '', method: String(init?.method || 'GET').toUpperCase(), bodyBytes: bodyText(init?.body).length, crossOrigin: url?.origin !== location.origin });
            return original.apply(this, arguments);
        };
    }

    function wrapXhr() {
        if (!window.XMLHttpRequest?.prototype) return;
        const proto = window.XMLHttpRequest.prototype;
        const open = proto.open;
        const send = proto.send;
        const meta = new WeakMap();
        proto.open = function (method, url) {
            meta.set(this, { method: String(method || 'GET').toUpperCase(), url: toUrl(url) });
            return open.apply(this, arguments);
        };
        proto.send = function (body) {
            const item = meta.get(this) || {};
            const result = shouldBlock(item.url?.href, body);
            if (result) {
                blocked('xhr', result);
                throw new DOMException('Local Sentinel blocked a possible credential leak', 'SecurityError');
            }
            emit('network_xhr', { url: item.url?.href || '', method: item.method || 'GET', bodyBytes: bodyText(body).length, crossOrigin: item.url?.origin !== location.origin });
            return send.apply(this, arguments);
        };
    }

    function wrapBeacon() {
        if (typeof navigator.sendBeacon !== 'function') return;
        const original = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function (url, data) {
            const result = shouldBlock(url, data);
            if (result) { blocked('beacon', result); return false; }
            const parsed = toUrl(url);
            emit('network_beacon', { url: parsed?.href || '', method: 'BEACON', bodyBytes: bodyText(data).length, crossOrigin: parsed?.origin !== location.origin });
            return original(url, data);
        };
    }

    function wrapWebSocket() {
        if (typeof window.WebSocket !== 'function' || typeof Proxy !== 'function') return;
        const Original = window.WebSocket;
        window.WebSocket = new Proxy(Original, {
            construct(target, args) {
                const result = shouldBlock(args[0], null);
                if (result) { blocked('websocket', result); throw new DOMException('Blocked by Local Sentinel', 'SecurityError'); }
                const socket = Reflect.construct(target, args);
                const originalSend = socket.send;
                socket.send = function (data) {
                    const sendResult = shouldBlock(socket.url, data);
                    if (sendResult) { blocked('websocket', sendResult); throw new DOMException('Blocked by Local Sentinel', 'SecurityError'); }
                    return originalSend.apply(this, arguments);
                };
                const parsed = toUrl(args[0]);
                emit('network_ws', { url: parsed?.href || '', method: 'WS', bodyBytes: 0, crossOrigin: parsed?.origin !== location.origin });
                return socket;
            }
        });
    }

    function wrapSignals() {
        for (const [name, original] of [['pushState', history.pushState], ['replaceState', history.replaceState]]) {
            if (typeof original !== 'function') continue;
            history[name] = function () { emit('history', { method: name }); return original.apply(this, arguments); };
        }
        const originalAdd = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function (type) {
            if (TRACKED_EVENTS.has(String(type || '').toLowerCase())) emit('listener', { event: String(type).toLowerCase() });
            return originalAdd.apply(this, arguments);
        };
    }

    function wrapProgrammaticForms() {
        if (!window.HTMLFormElement?.prototype?.submit) return;
        const original = window.HTMLFormElement.prototype.submit;
        window.HTMLFormElement.prototype.submit = function () {
            if (policy.enabled && policy.blockDangerousForms && policy.mode !== 'monitor') {
                const sensitive = this.querySelector('input[type="password"],input[autocomplete="cc-number"],input[autocomplete="cc-csc"]');
                const action = toUrl(this.action || location.href);
                const external = action && isUnrelated(action) && !isTrusted(action);
                const insecure = location.protocol !== 'https:' || action?.protocol !== 'https:';
                if (sensitive && (external || insecure)) {
                    emit('form_blocked', { destination: action?.origin || '', reason: insecure ? 'insecure_credential_form' : 'cross_site_credential_form' });
                    throw new DOMException('Local Sentinel blocked a dangerous programmatic form submission', 'SecurityError');
                }
            }
            return original.apply(this, arguments);
        };
    }

    window.addEventListener('message', (event) => {
        if (event.source !== window || event.data?.source !== POLICY_SOURCE || event.data?.type !== 'policy') return;
        const next = event.data.payload || {};
        policy = {
            enabled: next.enabled !== false,
            mode: ['strict', 'balanced', 'monitor'].includes(next.mode) ? next.mode : 'balanced',
            blockDangerousForms: next.blockDangerousForms !== false,
            trustedDestinations: Array.isArray(next.trustedDestinations) ? next.trustedDestinations.slice(0, 64).map(String) : []
        };
    });

    try {
        wrapStorage(); wrapFetch(); wrapXhr(); wrapBeacon(); wrapWebSocket(); wrapSignals(); wrapProgrammaticForms();
        emit('probe_ready', { href: location.href, secretsTracked: secrets.size });
    } catch (error) {
        emit('probe_error', { message: String(error?.message || error) });
    }
})();
