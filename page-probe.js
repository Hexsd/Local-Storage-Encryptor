(() => {
    if (window.__lseProbeInstalled) return;

    Object.defineProperty(window, '__lseProbeInstalled', {
        value: true,
        configurable: false,
        writable: false
    });

    const SOURCE = 'lse_probe';
    const TRACKED_EVENTS = new Set(['beforeunload', 'unload', 'pagehide', 'visibilitychange', 'storage']);

    function emit(type, payload = {}) {
        try {
            window.postMessage({ source: SOURCE, type, payload, ts: Date.now() }, '*');
        } catch {
            // ignore
        }
    }

    function toAbsoluteUrl(value) {
        try {
            if (!value) return '';
            return new URL(String(value), window.location.href).href;
        } catch {
            return '';
        }
    }

    function isCrossOrigin(url) {
        if (!url) return false;
        try {
            return new URL(url).origin !== window.location.origin;
        } catch {
            return false;
        }
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

        return Number(entropy.toFixed(3));
    }

    function isEncodedLike(input) {
        const text = typeof input === 'string' ? input : input === undefined || input === null ? '' : String(input);
        if (text.length < 48) return false;

        const normalized = text.replace(/[\r\n\s]/g, '');
        if (normalized.length < 48) return false;

        return /^(?:[A-Za-z0-9+/_-]{16,}={0,2})$/.test(normalized);
    }

    function getBodyBytes(body) {
        try {
            if (body == null) return 0;
            if (typeof body === 'string') return body.length;
            if (body instanceof URLSearchParams) return body.toString().length;
            if (body instanceof Blob) return body.size || 0;
            if (body instanceof ArrayBuffer) return body.byteLength || 0;
            if (ArrayBuffer.isView(body)) return body.byteLength || 0;
            if (body instanceof FormData) {
                let total = 0;
                body.forEach((value, key) => {
                    total += String(key).length;
                    total += typeof value === 'string' ? value.length : String(value).length;
                });
                return total;
            }
            return 0;
        } catch {
            return 0;
        }
    }

    function bodyLooksEncoded(body) {
        try {
            if (typeof body === 'string') return isEncodedLike(body);
            if (body instanceof URLSearchParams) return isEncodedLike(body.toString());
            return false;
        } catch {
            return false;
        }
    }

    function safeMethod(value, fallback) {
        return typeof value === 'string' && value ? value.toUpperCase() : fallback;
    }

    function wrapStorage() {
        if (!window.Storage || !window.Storage.prototype) return;

        const proto = window.Storage.prototype;
        const originalGetItem = proto.getItem;
        const originalSetItem = proto.setItem;
        const originalRemoveItem = proto.removeItem;
        const originalClear = proto.clear;

        proto.getItem = function getItemPatched(key) {
            const area = this === window.sessionStorage ? 'session' : 'local';
            emit('storage', {
                area,
                op: 'getItem',
                key: key === undefined || key === null ? '' : String(key)
            });
            return originalGetItem.call(this, key);
        };

        proto.setItem = function setItemPatched(key, value) {
            const area = this === window.sessionStorage ? 'session' : 'local';
            const text = value === undefined || value === null ? '' : String(value);
            emit('storage', {
                area,
                op: 'setItem',
                key: key === undefined || key === null ? '' : String(key),
                valueLength: text.length,
                entropy: estimateEntropy(text),
                encodedLike: isEncodedLike(text)
            });
            return originalSetItem.call(this, key, value);
        };

        proto.removeItem = function removeItemPatched(key) {
            const area = this === window.sessionStorage ? 'session' : 'local';
            emit('storage', {
                area,
                op: 'removeItem',
                key: key === undefined || key === null ? '' : String(key)
            });
            return originalRemoveItem.call(this, key);
        };

        proto.clear = function clearPatched() {
            const area = this === window.sessionStorage ? 'session' : 'local';
            emit('storage', { area, op: 'clear' });
            return originalClear.call(this);
        };
    }

    function wrapFetch() {
        if (typeof window.fetch !== 'function') return;

        const originalFetch = window.fetch;
        window.fetch = function fetchPatched(input, init = {}) {
            const requestUrl = typeof input === 'string' ? input : input?.url;
            const url = toAbsoluteUrl(requestUrl);
            const body = init?.body;

            emit('network_fetch', {
                url,
                method: safeMethod(init?.method, 'GET'),
                bodyBytes: getBodyBytes(body),
                encodedPayload: bodyLooksEncoded(body),
                crossOrigin: isCrossOrigin(url)
            });

            return originalFetch.apply(this, arguments);
        };
    }

    function wrapXHR() {
        if (!window.XMLHttpRequest || !window.XMLHttpRequest.prototype) return;

        const proto = window.XMLHttpRequest.prototype;
        const originalOpen = proto.open;
        const originalSend = proto.send;
        const metaMap = new WeakMap();

        proto.open = function openPatched(method, url) {
            metaMap.set(this, {
                method: safeMethod(method, 'GET'),
                url: toAbsoluteUrl(url)
            });
            return originalOpen.apply(this, arguments);
        };

        proto.send = function sendPatched(body) {
            const meta = metaMap.get(this) || { method: 'GET', url: '' };
            emit('network_xhr', {
                url: meta.url,
                method: meta.method,
                bodyBytes: getBodyBytes(body),
                encodedPayload: bodyLooksEncoded(body),
                crossOrigin: isCrossOrigin(meta.url)
            });
            return originalSend.apply(this, arguments);
        };
    }

    function wrapBeacon() {
        if (typeof navigator.sendBeacon !== 'function') return;

        const originalSendBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function sendBeaconPatched(url, data) {
            const absoluteUrl = toAbsoluteUrl(url);
            emit('network_beacon', {
                url: absoluteUrl,
                method: 'BEACON',
                bodyBytes: getBodyBytes(data),
                encodedPayload: bodyLooksEncoded(data),
                crossOrigin: isCrossOrigin(absoluteUrl)
            });

            return originalSendBeacon(url, data);
        };
    }

    function wrapWebSocket() {
        if (!window.WebSocket || typeof window.WebSocket !== 'function') return;

        const OriginalWebSocket = window.WebSocket;

        if (typeof Proxy === 'function') {
            window.WebSocket = new Proxy(OriginalWebSocket, {
                construct(target, args) {
                    const rawUrl = args[0];
                    const url = toAbsoluteUrl(rawUrl);
                    emit('network_ws', {
                        url,
                        method: 'WS',
                        bodyBytes: 0,
                        encodedPayload: false,
                        crossOrigin: isCrossOrigin(url)
                    });
                    return Reflect.construct(target, args);
                }
            });
            return;
        }

        function PatchedWebSocket(url, protocols) {
            const absoluteUrl = toAbsoluteUrl(url);
            emit('network_ws', {
                url: absoluteUrl,
                method: 'WS',
                bodyBytes: 0,
                encodedPayload: false,
                crossOrigin: isCrossOrigin(absoluteUrl)
            });

            if (protocols === undefined) return new OriginalWebSocket(url);
            return new OriginalWebSocket(url, protocols);
        }

        PatchedWebSocket.prototype = OriginalWebSocket.prototype;
        PatchedWebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
        PatchedWebSocket.OPEN = OriginalWebSocket.OPEN;
        PatchedWebSocket.CLOSING = OriginalWebSocket.CLOSING;
        PatchedWebSocket.CLOSED = OriginalWebSocket.CLOSED;

        window.WebSocket = PatchedWebSocket;
    }

    function wrapTimers() {
        if (typeof window.setTimeout === 'function') {
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = function setTimeoutPatched(handler, delay) {
                emit('timer', {
                    kind: 'timeout',
                    delay: Number(delay) || 0
                });
                return originalSetTimeout.apply(this, arguments);
            };
        }

        if (typeof window.setInterval === 'function') {
            const originalSetInterval = window.setInterval;
            window.setInterval = function setIntervalPatched(handler, delay) {
                emit('timer', {
                    kind: 'interval',
                    delay: Number(delay) || 0
                });
                return originalSetInterval.apply(this, arguments);
            };
        }
    }

    function wrapAddEventListener(target, targetName) {
        if (!target || typeof target.addEventListener !== 'function') return;

        const originalAddEventListener = target.addEventListener.bind(target);
        target.addEventListener = function addEventListenerPatched(type) {
            const normalized = String(type || '').toLowerCase();
            if (TRACKED_EVENTS.has(normalized)) {
                emit('listener', { event: normalized, target: targetName });
            }
            return originalAddEventListener.apply(this, arguments);
        };
    }

    function wrapHistory() {
        const methods = ['pushState', 'replaceState'];
        for (const method of methods) {
            if (typeof history[method] !== 'function') continue;

            const original = history[method].bind(history);
            history[method] = function historyPatched() {
                emit('history', { method });
                return original.apply(this, arguments);
            };
        }
    }

    try {
        wrapStorage();
        wrapFetch();
        wrapXHR();
        wrapBeacon();
        wrapWebSocket();
        wrapTimers();
        wrapAddEventListener(window, 'window');
        wrapAddEventListener(document, 'document');
        wrapHistory();
        emit('probe_ready', { href: window.location.href });
    } catch (error) {
        emit('probe_error', { message: String(error?.message || error) });
    }
})();
