function showSiteFeedback(text, type = 'info') {
  siteFeedbackTimer = showFeedbackMessage({
    node: dom.siteFeedback,
    timer: siteFeedbackTimer,
    text,
    type,
    onClear: () => {
      siteFeedbackTimer = null;
      clearSiteFeedback();
    }
  });
}

function clearSiteFeedback() {
  dom.siteFeedback.textContent = '';
  dom.siteFeedback.className = 'feedback';
}

function showWhitelistFeedback(text, type = 'info') {
  whitelistFeedbackTimer = showFeedbackMessage({
    node: dom.whitelistFeedback,
    timer: whitelistFeedbackTimer,
    text,
    type,
    onClear: () => {
      whitelistFeedbackTimer = null;
      clearWhitelistFeedback();
    }
  });
}

function clearWhitelistFeedback() {
  dom.whitelistFeedback.textContent = '';
  dom.whitelistFeedback.className = 'feedback';
}

function showFeedbackMessage({ node, timer, text, type = 'info', onClear }) {
  if (!node) return null;

  if (timer) {
    window.clearTimeout(timer);
  }

  node.textContent = text;
  node.className = `feedback is-visible ${feedbackClassByType(type)}`;

  return window.setTimeout(() => {
    onClear?.();
  }, FEEDBACK_TIMEOUT_MS);
}

function showLmTestStatus(text, type = 'info') {
  if (!dom.lmTestStatus) return;
  dom.lmTestStatus.textContent = text;
  dom.lmTestStatus.className = `feedback is-visible ${feedbackClassByType(type)}`;
}

function feedbackClassByType(type) {
  if (type === 'error') return 'is-error';
  if (type === 'success') return 'is-success';
  return '';
}

function setButtonBusy(button, isBusy, busyText = '') {
  if (!button) return;

  if (isBusy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
    return;
  }

  button.textContent = button.dataset.originalText || button.textContent;
  button.disabled = false;
}

function getLmModelValue() {
  return dom.lmModel?.value?.trim() || DEFAULT_LM_MODEL;
}

function normalizeRuntimeMessageError(error) {
  const message = String(error?.message || error || '').trim();

  if (message.includes('The message port closed before a response was received')) {
    return 'Service worker расширения закрыл соединение до ответа. Перезагрузите расширение и повторите проверку.';
  }

  if (message.includes('Receiving end does not exist')) {
    return 'Фоновый обработчик расширения недоступен. Перезагрузите расширение и повторите попытку.';
  }

  return message || 'Неизвестная ошибка обмена сообщениями расширения.';
}

function sendRuntimeMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(normalizeRuntimeMessageError(chrome.runtime.lastError)));
        return;
      }

      resolve(response);
    });
  });
}

async function sendLog(entry) {
  try {
    await sendRuntimeMessage({ action: 'log_event', ...entry });
  } catch (error) {
    console.error('Не удалось записать событие журнала:', error);
  }
}

function toPositiveInteger(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  if (numeric < 0) return 0;
  return Math.round(numeric);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}
