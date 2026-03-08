const STATUS_TIMEOUT_MS = 3000;

const dom = {};
let statusTimer = null;

document.addEventListener('DOMContentLoaded', init);

function init() {
  cacheDom();
  bindEvents();
}

function cacheDom() {
  dom.encryptBtn = document.getElementById('encryptBtn');
  dom.decryptBtn = document.getElementById('decryptBtn');
  dom.exportBtn = document.getElementById('exportBtn');
  dom.optionsBtn = document.getElementById('optionsBtn');
  dom.status = document.getElementById('status');
}

function bindEvents() {
  dom.encryptBtn.addEventListener('click', () => {
    runTabAction({
      button: dom.encryptBtn,
      loadingText: 'Шифруем...',
      action: 'encrypt',
      onSuccess: (response) => `Зашифровано ${response.count} записей`,
      fallbackError: 'Ошибка шифрования'
    });
  });

  dom.decryptBtn.addEventListener('click', () => {
    runTabAction({
      button: dom.decryptBtn,
      loadingText: 'Расшифровываем...',
      action: 'decrypt',
      onSuccess: (response) => `Расшифровано ${response.count} записей`,
      fallbackError: 'Ошибка дешифрования'
    });
  });

  dom.exportBtn.addEventListener('click', exportData);
  dom.optionsBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());
}

async function runTabAction({ button, loadingText, action, onSuccess, fallbackError }) {
  setButtonLoading(button, true, loadingText);

  try {
    const response = await sendMessageToActiveTab(action);

    if (response?.success) {
      showStatus(onSuccess(response), 'success');
      return;
    }

    showStatus(fallbackError, 'error');
  } catch (error) {
    showStatus(`Ошибка: ${error.message}`, 'error');
  } finally {
    setButtonLoading(button, false);
  }
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
