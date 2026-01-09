function simpleEncrypt(text, key = 'SECRET_KEY') {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return btoa(result);
}

function simpleDecrypt(encoded, key = 'SECRET_KEY_2025') {
  const text = atob(encoded);
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return result;
}

function analyzePageForXSS() {
  let score = 0;
  const issues = [];

  // 1. Инлайновые скрипты (очень подозрительно)
  const inlineScripts = document.querySelectorAll('script:not([src])');
  if (inlineScripts.length > 0) {
    score += 25 * inlineScripts.length;
    issues.push(`Обнаружено инлайновых скриптов: ${inlineScripts.length} (высокий риск XSS)`);
  }

  // 2. Обработчики событий в атрибутах (on*)
  const eventHandlers = document.querySelectorAll('[onerror], [onclick], [onload], [onmouseover], [onfocus], [onblur], [onsubmit], [onchange]');
  if (eventHandlers.length > 3) {
    score += 15 * (eventHandlers.length - 3);
    issues.push(`Множество inline-обработчиков событий: ${eventHandlers.length}`);
  }

  // 3. Использование опасных функций в скриптах
  const allScripts = document.querySelectorAll('script');
  let dangerousFuncCount = 0;
  const dangerousFuncs = ['eval(', 'setTimeout(', 'setInterval(', 'Function(', 'innerHTML', 'outerHTML', 'document.write(', 'write('];

  allScripts.forEach(script => {
    const code = (script.textContent || '').toLowerCase();
    dangerousFuncs.forEach(func => {
      if (code.includes(func.toLowerCase())) {
        dangerousFuncCount++;
      }
    });
  });

  if (dangerousFuncCount > 0) {
    score += 30 * Math.min(dangerousFuncCount, 5); // Макс +150
    issues.push(`Опасные JS-функции (eval, innerHTML и др.): ${dangerousFuncCount} упоминаний`);
  }

  // 4. Формы с javascript: в action или подозрительные
  const forms = document.forms;
  for (const form of forms) {
    const action = (form.action || '').toLowerCase();
    if (action.includes('javascript:')) {
      score += 40;
      issues.push('Форма с javascript: в action — классическая XSS-вектора');
    }
    if (!form.action || form.action === '' || form.action === '#') {
      score += 10;
      issues.push('Форма без валидного action');
    }
  }

  // 5. Подозрительные внешние скрипты
  const externalScripts = document.querySelectorAll('script[src]');
  const suspiciousDomains = ['.ru/', '.cn/', '.xyz/', 'jquery.com', 'cdn.rawgit.com', 'pastebin.com'];
  for (const script of externalScripts) {
    const src = script.src.toLowerCase();
    if (suspiciousDomains.some(domain => src.includes(domain))) {
      score += 20;
      issues.push(`Подозрительный внешний скрипт: ${script.src}`);
    }
    if (window.location.protocol === 'https:' && src.startsWith('http:')) {
      score += 15;
      issues.push(`Скрипт по HTTP на HTTPS-странице: ${script.src}`);
    }
  }

  // 6. Использование document.cookie / document.domain
  const pageCode = document.documentElement.outerHTML.toLowerCase();
  if (pageCode.includes('document.cookie')) {
    score += 20;
    issues.push('Прямой доступ к document.cookie');
  }
  if (pageCode.includes('document.domain')) {
    score += 25;
    issues.push('Манипуляция document.domain — признак атаки');
  }

  // 7. iframe без sandbox
  const iframes = document.querySelectorAll('iframe:not([sandbox])');
  if (iframes.length > 0) {
    score += 10 * iframes.length;
    issues.push(`iframe без атрибута sandbox: ${iframes.length}`);
  }

  // Определяем уровень риска
  let risk = 'low';
  if (score >= 80) risk = 'high';
  else if (score >= 40) risk = 'medium';

  return { score, risk, issues: issues.slice(0, 10) };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    if (request.action === 'encrypt') {
      let count = 0;
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!key.startsWith('encrypted_')) {
          const value = localStorage.getItem(key);
          const encrypted = simpleEncrypt(value);
          localStorage.setItem('encrypted_' + key, encrypted);
          localStorage.removeItem(key);
          count++;
        }
      }
      sendResponse({ success: true, count });
    } else if (request.action === 'decrypt') {
      let count = 0;
      const keysToDecrypt = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key.startsWith('encrypted_')) keysToDecrypt.push(key);
      }
      keysToDecrypt.forEach(key => {
        const encrypted = localStorage.getItem(key);
        try {
          const decrypted = simpleDecrypt(encrypted);
          const originalKey = key.replace('encrypted_', '');
          localStorage.setItem(originalKey, decrypted);
          localStorage.removeItem(key);
          count++;
        } catch (e) {
          console.error('Ошибка дешифрования:', e);
        }
      });
      sendResponse({ success: true, count });
    } else if (request.action === 'export') {
      let exportData = 'Local Storage Data Export\n';
      exportData += '='.repeat(50) + '\n';
      exportData += `Дата экспорта: ${new Date().toLocaleString('ru-RU')}\n`;
      exportData += `URL: ${window.location.href}\n`;
      exportData += '='.repeat(50) + '\n\n';

      const tempStorage = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if (key.startsWith('encrypted_')) {
          try {
            const decrypted = simpleDecrypt(value);
            const originalKey = key.replace('encrypted_', '');
            tempStorage[originalKey] = decrypted;
          } catch (e) {
            tempStorage[key] = '[Ошибка дешифрования]';
          }
        } else {
          tempStorage[key] = value;
        }
      }

      Object.keys(tempStorage).forEach(key => {
        exportData += `Ключ: ${key}\n`;
        exportData += `Значение: ${tempStorage[key]}\n`;
        exportData += '-'.repeat(50) + '\n';
      });

      sendResponse({ success: true, data: exportData });
    }
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
  return true;
});

// Автоматический анализ и реакция при загрузке страницы
window.addEventListener('load', async () => {
  const url = window.location.origin;
  const analysis = analyzePageForXSS();

  // Отправляем результаты анализа в background
  chrome.runtime.sendMessage({
    action: 'page_analyzed',
    url: url,
    risk: analysis.risk,
    score: analysis.score,
    issues: analysis.issues
  });

  // Автоматическое шифрование при high risk
  const { settings = {} } = await chrome.storage.sync.get('settings');
  const loggingEnabled = settings.logging !== false;

  if (analysis.risk === 'high') {
    let count = 0;
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key.startsWith('encrypted_')) {
        const value = localStorage.getItem(key);
        const encrypted = simpleEncrypt(value);
        localStorage.setItem('encrypted_' + key, encrypted);
        localStorage.removeItem(key);
        count++;
      }
    }

    if (count > 0) {
      // Уведомление
      if (settings.notifications !== false) {
        chrome.runtime.sendMessage({
          action: 'show_notification',
          message: `Высокий риск на ${url}! Зашифровано ${count} записей localStorage.`
        });
      }

      // Запись в логи (только если включено логирование)
      if (loggingEnabled) {
        chrome.runtime.sendMessage({
          action: 'log_event',
          message: `Автоматическое шифрование: высокий риск XSS на ${url}. Зашифровано ${count} записей.`,
          type: 'auto_encrypt'
        });
      }
    }
  }
});