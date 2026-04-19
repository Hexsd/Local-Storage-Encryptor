self.addEventListener('unhandledrejection', (event) => {
  void debugTrace('worker.unhandledrejection', {
    reason: event?.reason?.message || String(event?.reason || '')
  });
});

self.addEventListener('error', (event) => {
  void debugTrace('worker.error', {
    message: event?.message || '',
    filename: event?.filename || '',
    lineno: event?.lineno || 0,
    colno: event?.colno || 0
  });
});
