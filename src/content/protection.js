const SENTINEL_POLICY_SOURCE = 'local_sentinel_guard';
const SENTINEL_PROBE_SOURCE = 'local_sentinel_probe';
const SENTINEL_SENSITIVE_KEY = /(access|refresh|id)[_-]?token|auth|session|jwt|secret|credential|password|passwd|csrf|xsrf|sid/i;
const SENTINEL_CARD_FIELD = /card|cc-?num|pan|cvv|cvc/i;

const sentinelState = {
    enabled: true,
    trusted: false,
    mode: 'balanced',
    blockDangerousForms: true,
    protectExternalLinks: true,
    blockedRequests: 0,
    blockedForms: 0,
    securedLinks: 0,
    findings: [],
    lastEvent: null
};

const sentinelAllowedForms = new WeakSet();
let sentinelScanTimer = null;

function sentinelBaseDomain(hostname) {
    const host = String(hostname || '').toLowerCase();
    if (!host || host === 'localhost' || /^\d+(?:\.\d+){3}$/.test(host) || host.includes(':')) return host;
    const parts = host.split('.').filter(Boolean);
    const compound = new Set(['co.uk', 'org.uk', 'com.au', 'co.jp', 'com.br', 'com.tr', 'co.in']);
    if (parts.length > 2 && compound.has(parts.slice(-2).join('.'))) return parts.slice(-3).join('.');
    return parts.slice(-2).join('.');
}

function sentinelSameSite(left, right) {
    return sentinelBaseDomain(left) === sentinelBaseDomain(right);
}

async function loadSentinelPolicy() {
    const stored = await chrome.storage.sync.get(['settings', 'whitelistedSites']);
    const settings = stored.settings || {};
    const current = normalizeSiteUrl(location.href);
    const trusted = Array.isArray(stored.whitelistedSites) && stored.whitelistedSites.some((item) => {
        const value = item && typeof item === 'object' ? item.url : item;
        return isSameSiteUrl(value, current);
    });

    sentinelState.enabled = settings.protectionEnabled !== false;
    sentinelState.trusted = trusted;
    sentinelState.mode = ['strict', 'balanced', 'monitor'].includes(settings.protectionMode)
        ? settings.protectionMode
        : 'balanced';
    sentinelState.blockDangerousForms = settings.blockDangerousForms !== false;
    sentinelState.protectExternalLinks = settings.protectExternalLinks !== false;

    window.postMessage({
        source: SENTINEL_POLICY_SOURCE,
        type: 'policy',
        payload: {
            enabled: sentinelState.enabled && !trusted,
            mode: sentinelState.mode,
            blockDangerousForms: sentinelState.blockDangerousForms,
            trustedDestinations: Array.isArray(settings.trustedDestinations) ? settings.trustedDestinations : []
        }
    }, '*');
}

function isSensitiveForm(form) {
    return Boolean(form.querySelector(
        'input[type="password"], input[autocomplete="current-password"], input[autocomplete="new-password"], input[autocomplete="cc-number"], input[autocomplete="cc-csc"]'
    )) || Array.from(form.elements || []).some((element) => SENTINEL_CARD_FIELD.test(`${element.name || ''} ${element.id || ''}`));
}

function assessForm(form) {
    if (!isSensitiveForm(form)) return null;
    let action;
    try { action = new URL(form.action || location.href, location.href); } catch { return { level: 'high', reason: 'Некорректный адрес отправки формы' }; }

    if (location.protocol !== 'https:' || action.protocol !== 'https:') {
        return { level: 'critical', reason: 'Учётные данные отправляются без HTTPS', destination: action.origin };
    }
    if (!sentinelSameSite(action.hostname, location.hostname)) {
        return { level: 'high', reason: `Форма отправляет данные на другой сайт: ${action.hostname}`, destination: action.origin };
    }
    if (window.top !== window.self) {
        return { level: 'medium', reason: 'Форма с секретными данными встроена во фрейм', destination: action.origin };
    }
    return null;
}

function secureExternalLinks(root = document) {
    if (!sentinelState.enabled || !sentinelState.protectExternalLinks) return;
    let fixed = 0;
    for (const link of root.querySelectorAll?.('a[target="_blank"]') || []) {
        const rel = new Set(String(link.rel || '').split(/\s+/).filter(Boolean));
        if (!rel.has('noopener')) { rel.add('noopener'); fixed += 1; }
        rel.add('noreferrer');
        link.rel = Array.from(rel).join(' ');
    }
    sentinelState.securedLinks += fixed;
}

function scanPageSecurity() {
    const findings = [];
    let sensitiveStorageKeys = 0;
    for (const storage of [localStorage, sessionStorage]) {
        try {
            for (let index = 0; index < storage.length; index += 1) {
                if (SENTINEL_SENSITIVE_KEY.test(storage.key(index) || '')) sensitiveStorageKeys += 1;
            }
        } catch { }
    }
    if (sensitiveStorageKeys > 0) findings.push({ level: 'medium', code: 'sensitive_storage', text: `Секреты в Web Storage: ${sensitiveStorageKeys}` });
    if (location.protocol === 'http:') findings.push({ level: 'high', code: 'insecure_origin', text: 'Страница работает без HTTPS' });

    let dangerousForms = 0;
    for (const form of document.forms) {
        const assessment = assessForm(form);
        if (assessment) dangerousForms += 1;
    }
    if (dangerousForms > 0) findings.push({ level: 'high', code: 'dangerous_forms', text: `Опасные формы: ${dangerousForms}` });
    if (window.top !== window.self && document.querySelector('input[type="password"]')) {
        findings.push({ level: 'medium', code: 'framed_login', text: 'Поле пароля находится во фрейме' });
    }
    sentinelState.findings = findings;
    secureExternalLinks();
    return { findings, sensitiveStorageKeys, dangerousForms };
}

function showSentinelWarning(assessment, onContinue) {
    const old = document.getElementById('__local_sentinel_warning');
    if (old) old.remove();
    const host = document.createElement('div');
    host.id = '__local_sentinel_warning';
    host.style.cssText = 'position:fixed;inset:0;z-index:2147483647;display:grid;place-items:center;background:rgba(8,12,18,.64);font-family:system-ui,sans-serif';
    const shadow = host.attachShadow({ mode: 'closed' });
    shadow.innerHTML = `
        <style>
          .box{width:min(420px,calc(100vw - 32px));box-sizing:border-box;background:#fff;color:#1b1930;border:1px solid #e4e0f2;padding:22px;box-shadow:0 16px 50px #1b193044}
          .mark{width:34px;height:34px;display:grid;place-items:center;border:1px solid #f1cccc;background:#fff1f1;color:#b93535;font-weight:800}
          h2{font-size:18px;margin:14px 0 8px}p{font-size:14px;line-height:1.5;color:#696683;margin:0 0 18px}.actions{display:flex;gap:10px;justify-content:flex-end}
          button{border:1px solid #e4e0f2;padding:10px 14px;font:600 13px system-ui;cursor:pointer}.cancel{border-color:#7759ff;background:#7759ff;color:#fff}.continue{background:#fff;color:#696683}
        </style>
        <div class="box" role="alertdialog" aria-modal="true" aria-labelledby="sentinel-title">
          <div class="mark">!</div><h2 id="sentinel-title">Local Sentinel остановил отправку</h2>
          <p>${escapeSentinelText(assessment.reason)}. Продолжайте, только если доверяете странице и адресу назначения.</p>
          <div class="actions"><button class="continue">Всё равно отправить</button><button class="cancel" autofocus>Остаться на странице</button></div>
        </div>`;
    shadow.querySelector('.cancel').addEventListener('click', () => host.remove());
    shadow.querySelector('.continue').addEventListener('click', () => { host.remove(); onContinue(); });
    (document.documentElement || document).appendChild(host);
}

function escapeSentinelText(value) {
    return String(value || '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

async function recordSentinelBlock(kind, details) {
    sentinelState.lastEvent = { kind, destination: details.destination || '', timestamp: Date.now() };
    await sendRuntimeMessageQuietly({
        action: 'security_event',
        event: kind,
        url: getCurrentPageUrl(),
        destination: details.destination || '',
        reason: details.reason || ''
    });
}

function onSensitiveFormSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || sentinelAllowedForms.has(form)) return;
    if (!sentinelState.enabled || !sentinelState.blockDangerousForms || sentinelState.trusted || sentinelState.mode === 'monitor') return;
    const assessment = assessForm(form);
    if (!assessment) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    sentinelState.blockedForms += 1;
    runtimeSignals.protection.blockedForms += 1;
    void recordSentinelBlock('dangerous_form_blocked', assessment);
    showSentinelWarning(assessment, () => {
        sentinelAllowedForms.add(form);
        if (typeof form.requestSubmit === 'function') form.requestSubmit(event.submitter || undefined);
        else form.submit();
    });
}

function onSentinelProbeMessage(event) {
    if (event.source !== window || event.data?.source !== SENTINEL_PROBE_SOURCE || !['request_blocked', 'form_blocked'].includes(event.data?.type)) return;
    const payload = event.data.payload || {};
    if (event.data.type === 'form_blocked') {
        sentinelState.blockedForms += 1;
        void recordSentinelBlock('dangerous_form_blocked', payload);
    } else {
        sentinelState.blockedRequests += 1;
        void recordSentinelBlock('storage_leak_blocked', payload);
    }
}

function onSentinelRuntimeMessage(request, sender, sendResponse) {
    if (request?.action === 'get_security_status') {
        sendResponse({ success: true, data: { ...sentinelState, url: getCurrentPageUrl() } });
        return false;
    }
    if (request?.action === 'scan_page') {
        sendResponse({ success: true, data: { ...sentinelState, ...scanPageSecurity(), url: getCurrentPageUrl() } });
        return false;
    }
    return false;
}

function scheduleSentinelScan() {
    if (sentinelScanTimer) return;
    sentinelScanTimer = window.setTimeout(() => {
        sentinelScanTimer = null;
        scanPageSecurity();
    }, 500);
}

document.addEventListener('submit', onSensitiveFormSubmit, true);
window.addEventListener('message', onSentinelProbeMessage, false);
chrome.runtime.onMessage.addListener(onSentinelRuntimeMessage);
chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'sync' && (changes.settings || changes.whitelistedSites)) void loadSentinelPolicy();
});

const sentinelObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) secureExternalLinks(node);
        }
    }
    scheduleSentinelScan();
});

void loadSentinelPolicy();
if (document.documentElement) sentinelObserver.observe(document.documentElement, { subtree: true, childList: true });
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scanPageSecurity, { once: true });
else scanPageSecurity();
