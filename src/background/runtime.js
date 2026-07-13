chrome.runtime.onInstalled.addListener((details) => {
  void initializeExtension(details);
  void logEvent({
    category: 'system',
    level: 'success',
    event: 'extension_installed',
    title: 'Расширение установлено',
    message: 'Local Sentinel установлен и готов блокировать утечки.'
  });
  void debugTrace('lifecycle.installed');
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const action = request?.action;
  void debugTrace('runtime.message.received', {
    action,
    senderUrl: getSenderUrl(sender)
  });

  if (action === 'page_analyzed_full' || action === 'test_lm_studio') {
    void handleAsyncMessage(request, sender, sendResponse);
    return true;
  }

  switch (action) {
    case 'show_notification':
      void showNotification(request?.message);
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'page_analyzed':
      void handlePageAnalysis(request).catch((error) =>
        logEvent(
          {
            category: 'analysis',
            level: 'error',
            event: 'page_analysis_failed',
            title: 'Не удалось сохранить анализ страницы',
            message: error.message,
            context: {
              sender: getSenderSource(sender)
            }
          },
          null,
          getSenderUrl(sender),
          getSenderSource(sender)
        )
      );
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'log_event':
      void logEvent(request, request?.type, getSenderUrl(sender), getSenderSource(sender));
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'record_operation':
      void recordOperation(request?.operation, getSenderUrl(sender));
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'security_event':
      void recordSecurityEvent(request, sender);
      safeSendResponse(sendResponse, { success: true });
      break;
    case 'get_security_summary':
      void getSecuritySummary().then((data) => safeSendResponse(sendResponse, { success: true, data }));
      return true;
    default:
      break;
  }

  return false;
});

async function handleAsyncMessage(request, sender, sendResponse) {
  void debugTrace('runtime.message.async.start', {
    action: request?.action,
    senderUrl: getSenderUrl(sender)
  });

  try {
    const data =
      request?.action === 'test_lm_studio'
        ? await handleLmStudioTest(request, sender)
        : await handleFullPageAnalysis(request, sender);

    safeSendResponse(sendResponse, { success: true, data });

    void debugTrace('runtime.message.async.success', {
      action: request?.action,
      senderUrl: getSenderUrl(sender),
      url: data?.url,
      aiDanger: data?.aiDanger
    });
  } catch (error) {
    const errorMessage = error?.message || String(error);
    safeSendResponse(sendResponse, { success: false, error: errorMessage });

    void debugTrace('runtime.message.async.error', {
      action: request?.action,
      senderUrl: getSenderUrl(sender),
      error: errorMessage
    });
    void logEvent(
      {
        category: 'analysis',
        level: 'error',
        event: 'full_analysis_failed',
        title: 'Ошибка полного анализа',
        message: errorMessage
      },
      null,
      getSenderUrl(sender),
      getSenderSource(sender)
    );
  }
}

function safeSendResponse(sendResponse, payload) {
  try {
    sendResponse(payload);
    void debugTrace('runtime.message.response.sent', {
      success: Boolean(payload?.success),
      error: payload?.error || ''
    });
  } catch {
    void debugTrace('runtime.message.response.failed');
  }
}

function getSenderUrl(sender) {
  return sender?.url || sender?.tab?.url || 'background';
}

function getSenderSource(sender) {
  return inferLogSourceFromUrl(getSenderUrl(sender));
}

async function initializeExtension(details) {
  const { settings = {} } = await chrome.storage.sync.get(SETTINGS_STORAGE_KEY);
  await chrome.storage.sync.set({
    [SETTINGS_STORAGE_KEY]: {
      protectionEnabled: settings.protectionEnabled !== false,
      protectionMode: ['strict', 'balanced', 'monitor'].includes(settings.protectionMode) ? settings.protectionMode : 'balanced',
      blockDangerousForms: settings.blockDangerousForms !== false,
      protectExternalLinks: settings.protectExternalLinks !== false,
      notifications: settings.notifications !== false,
      logging: settings.logging !== false,
      mode: settings.mode === 'hybrid' ? 'hybrid' : 'local',
      fullAnalysisPolicy: settings.fullAnalysisPolicy === 'always' ? 'always' : 'smart',
      trustedDestinations: Array.isArray(settings.trustedDestinations) ? settings.trustedDestinations.slice(0, 64) : [],
      lmStudioEndpoint: settings.lmStudioEndpoint || DEFAULT_LM_STUDIO_ENDPOINT,
      lmStudioModel: settings.lmStudioModel || DEFAULT_LM_STUDIO_MODEL
    }
  });

  // Legacy versions stored a reusable encryption password in plaintext. It is no
  // longer needed by the preventive protection model and must not remain at rest.
  await chrome.storage.local.remove('encryptionPassphrase');
  await debugTrace('lifecycle.initialized', { reason: details?.reason || 'unknown' });
}
