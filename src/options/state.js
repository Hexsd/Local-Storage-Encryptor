const FEEDBACK_TIMEOUT_MS = 2600;
const VISIBLE_LOGS_LIMIT = 50;
const DEFAULT_LM_ENDPOINT = 'http://127.0.0.1:1234/v1/chat/completions';
const DEFAULT_LM_MODEL = 'qwen3-4b-2507';
const LOG_LEVELS = new Set(['info', 'success', 'warn', 'error']);
const LOG_CATEGORIES = new Set(['analysis', 'encryption', 'ai', 'settings', 'data', 'system']);
const LOG_CATEGORY_FILTERS = [
  { key: 'all', label: 'Все' },
  { key: 'encryption', label: 'Шифрование' },
  { key: 'analysis', label: 'Анализ' },
  { key: 'ai', label: 'AI' },
  { key: 'settings', label: 'Настройки' },
  { key: 'data', label: 'Данные' },
  { key: 'system', label: 'Система' }
];
const LOG_CATEGORY_META = {
  encryption: { label: 'Шифрование', tone: 'encryption' },
  analysis: { label: 'Анализ', tone: 'analysis' },
  ai: { label: 'AI', tone: 'ai' },
  settings: { label: 'Настройки', tone: 'settings' },
  data: { label: 'Данные', tone: 'data' },
  system: { label: 'Система', tone: 'system' }
};
const LOG_LEVEL_META = {
  info: { label: 'Информация', tone: 'info' },
  success: { label: 'Успех', tone: 'success' },
  warn: { label: 'Предупреждение', tone: 'warn' },
  error: { label: 'Ошибка', tone: 'error' }
};

const dom = {};
let siteFeedbackTimer = null;
let whitelistFeedbackTimer = null;
let saveButtonTimer = null;
const activeLogFilters = {
  category: 'all',
  level: 'all'
};
