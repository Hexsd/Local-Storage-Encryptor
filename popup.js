const STATUS_TIMEOUT_MS = 3000;
const ENCRYPTION_KEY_STORAGE = 'encryptionPassphrase';

const dom = {};
let statusTimer = null;

document.addEventListener('DOMContentLoaded', init);

async function init() {
  cacheDom();
  bindEvents();
  await restoreSavedKeyState();
}

function cacheDom() {
  dom.encryptBtn = document.getElementById('encryptBtn');
  dom.decryptBtn = document.getElementById('decryptBtn');
  dom.exportBtn = document.getElementById('exportBtn');
  dom.optionsBtn = document.getElementById('optionsBtn');
  dom.encryptionKeyInput = document.getElementById('encryptionKeyInput');
  dom.saveKeyBtn = document.getElementById('saveKeyBtn');
  dom.keyStatus = document.getElementById('keyStatus');
  dom.status = document.getElementById('status');
}

function bindEvents() {
  dom.encryptBtn.addEventListener('click', () => {
    recordOperation('popup_encrypt');
    runTabAction({
      button: dom.encryptBtn,
      loadingText: 'Шифруем...',
      action: 'encrypt',
      onSuccess: (response) => `Зашифровано ${response.count} записей`,
      fallbackError: 'Ошибка шифрования'
    });
  });

  dom.decryptBtn.addEventListener('click', () => {
    recordOperation('popup_decrypt');
    runTabAction({
      button: dom.decryptBtn,
      loadingText: 'Расшифровываем...',
      action: 'decrypt',
      onSuccess: (response) => `Расшифровано ${response.count} записей`,
      fallbackError: 'Ошибка дешифрования'
    });
  });

  dom.exportBtn.addEventListener('click', () => {
    recordOperation('popup_export');
    exportData();
  });
  dom.optionsBtn.addEventListener('click', () => {
    recordOperation('popup_options');
    void sendLog({
      category: 'settings',
      level: 'info',
      event: 'options_opened',
      title: 'Открыта страница настроек',
      message: 'Пользователь перешёл из popup в настройки расширения.',
      source: 'popup'
    });
    chrome.runtime.openOptionsPage();
  });
  dom.saveKeyBtn.addEventListener('click', saveEncryptionKey);
  dom.encryptionKeyInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      saveEncryptionKey();
    }
  });
}

async function runTabAction({ button, loadingText, action, onSuccess, fallbackError }) {
  setButtonLoading(button, true, loadingText);

  try {
    const response = await sendMessageToActiveTab(action);

    if (response?.success) {
      showStatus(onSuccess(response), 'success');
      return;
    }

    await sendLog({
      category: 'encryption',
      level: 'error',
      event: `${action}_failed_popup`,
      title: 'Действие не выполнено',
      message: response?.error || fallbackError,
      source: 'popup'
    });
    showStatus(response?.error || fallbackError, 'error');
  } catch (error) {
    await sendLog({
      category: 'encryption',
      level: 'error',
      event: `${action}_runtime_failed`,
      title: 'Ошибка запуска действия',
      message: error.message,
      source: 'popup'
    });
    showStatus(`Ошибка: ${error.message}`, 'error');
  } finally {
    setButtonLoading(button, false);
  }
}

async function saveEncryptionKey() {
  const passphrase = dom.encryptionKeyInput.value.trim();
  if (!passphrase) {
    showStatus('Введите ключ шифрования', 'error');
    dom.encryptionKeyInput.focus();
    return;
  }

  setButtonLoading(dom.saveKeyBtn, true, 'Сохраняем...');
  try {
    await chrome.storage.local.set({ [ENCRYPTION_KEY_STORAGE]: passphrase });
    dom.encryptionKeyInput.value = '';
    dom.encryptionKeyInput.placeholder = 'Ключ сохранён';
    setKeyStatus(true);
    await sendLog({
      category: 'settings',
      level: 'success',
      event: 'encryption_key_saved',
      title: 'Ключ шифрования сохранён',
      message: 'Новый ключ сохранён локально и готов к использованию.',
      source: 'popup'
    });
    showStatus('Ключ шифрования сохранён', 'success');
  } catch (error) {
    await sendLog({
      category: 'settings',
      level: 'error',
      event: 'encryption_key_save_failed',
      title: 'Не удалось сохранить ключ шифрования',
      message: error.message,
      source: 'popup'
    });
    showStatus(`Ошибка сохранения ключа: ${error.message}`, 'error');
  } finally {
    setButtonLoading(dom.saveKeyBtn, false);
  }
}

async function restoreSavedKeyState() {
  try {
    const data = await chrome.storage.local.get(ENCRYPTION_KEY_STORAGE);
    setKeyStatus(Boolean(data?.[ENCRYPTION_KEY_STORAGE]));
  } catch {
    setKeyStatus(false);
  }
}

function setKeyStatus(hasKey) {
  if (!dom.keyStatus) return;

  dom.keyStatus.textContent = hasKey
    ? 'Ключ сохранён и готов к использованию.'
    : 'Ключ не задан.';
  dom.keyStatus.className = `key-status ${hasKey ? 'ready' : 'missing'}`;
}

async function exportData() {
  setButtonLoading(dom.exportBtn, true, 'Экспортируем...');

  let blobUrl = null;

  try {
    const response = await sendMessageToActiveTab('export');
    if (!response?.data) {
      throw new Error('Нет данных для экспорта');
    }

    const blob = new Blob([response.data], { type: 'text/plain' });
    blobUrl = URL.createObjectURL(blob);

    const date = new Date().toISOString().slice(0, 10);
    await chrome.downloads.download({
      url: blobUrl,
      filename: `localStorage_${date}.txt`,
      saveAs: true
    });

    showStatus('Файл сохранён', 'success');
  } catch (error) {
    await sendLog({
      category: 'data',
      level: 'error',
      event: 'export_failed',
      title: 'Не удалось экспортировать localStorage',
      message: error.message,
      source: 'popup'
    });
    showStatus(`Ошибка: ${error.message}`, 'error');
  } finally {
    if (blobUrl) {
      URL.revokeObjectURL(blobUrl);
    }

    setButtonLoading(dom.exportBtn, false);
  }
}

async function sendMessageToActiveTab(action) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    throw new Error('Нет активной вкладки');
  }

  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tab.id, { action }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      resolve(response);
    });
  });
}

function setButtonLoading(button, isLoading, loadingText = '') {
  if (!button) return;

  if (isLoading) {
    button.dataset.originalText = button.textContent;
    button.textContent = loadingText;
    button.disabled = true;
    return;
  }

  if (button.dataset.originalText) {
    button.textContent = button.dataset.originalText;
  }
  button.disabled = false;
}

function showStatus(message, type) {
  if (statusTimer) {
    window.clearTimeout(statusTimer);
    statusTimer = null;
  }

  dom.status.textContent = message;
  dom.status.className = `status is-visible ${type}`;

  statusTimer = window.setTimeout(() => {
    dom.status.className = 'status';
    dom.status.textContent = '';
    statusTimer = null;
  }, STATUS_TIMEOUT_MS);
}

function recordOperation(operation) {
  try {
    chrome.runtime.sendMessage({
      action: 'record_operation',
      operation
    });
  } catch {
  }
}

async function sendLog(entry) {
  try {
    await chrome.runtime.sendMessage({
      action: 'log_event',
      ...entry
    });
  } catch {
  }
}
