async function sendMessageToContent(action) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error('Нет активной вкладки');

  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tab.id, { action }, (response) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(response);
    });
  });
}

function showStatus(message, isSuccess) {
  const statusDiv = document.getElementById('status');
  statusDiv.textContent = message;
  statusDiv.className = isSuccess ? 'success' : 'error';
  statusDiv.style.display = 'block';
  setTimeout(() => statusDiv.style.display = 'none', 3000);
}

document.getElementById('encryptBtn').addEventListener('click', async () => {
  try {
    const response = await sendMessageToContent('encrypt');
    if (response?.success) showStatus(`Зашифровано ${response.count} записей`, true);
    else showStatus('Ошибка шифрования', false);
  } catch (e) { showStatus('Ошибка: ' + e.message, false); }
});

document.getElementById('decryptBtn').addEventListener('click', async () => {
  try {
    const response = await sendMessageToContent('decrypt');
    if (response?.success) showStatus(`Расшифровано ${response.count} записей`, true);
    else showStatus('Ошибка дешифрования', false);
  } catch (e) { showStatus('Ошибка: ' + e.message, false); }
});

document.getElementById('exportBtn').addEventListener('click', async () => {
  try {
    const response = await sendMessageToContent('export');
    if (response?.data) {
      const blob = new Blob([response.data], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const date = new Date().toISOString().split('T')[0];
      await chrome.downloads.download({
        url, filename: `localStorage_${date}.txt`, saveAs: true
      });
      showStatus('Файл сохранён', true);
    }
  } catch (e) { showStatus('Ошибка: ' + e.message, false); }
});

document.getElementById('optionsBtn').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
