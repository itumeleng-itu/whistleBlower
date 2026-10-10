import { formatKey, generateKey, isValidKey, normalizeKey } from './key.js';

// The session ID lives only in this variable: not in localStorage, cookies or
// sessionStorage. Closing or reloading the tab ends the session on this device.
let sessionId = null;
let expiryTimer = null;

const $ = (id) => document.getElementById(id);
const views = ['login', 'newkey', 'report', 'done'];

function show(view) {
  for (const v of views) $(`view-${v}`).hidden = v !== view;
  const loggedIn = sessionId !== null;
  $('logout').hidden = !loggedIn;
  $('session-badge').hidden = !loggedIn;
}

function showError(el, message) {
  el.textContent = message;
  el.hidden = !message;
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (sessionId) headers.Authorization = `Bearer ${sessionId}`;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body && JSON.stringify(body), cache: 'no-store' });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (res.status === 401) endSession();
  if (!res.ok) throw new Error(data?.error ?? `Request failed (${res.status})`);
  return data;
}

function endSession(message = 'Your session ended. Enter your key to start a new one.') {
  sessionId = null;
  clearTimeout(expiryTimer);
  $('report-form').reset();
  showError($('login-error'), message);
  show('login');
}

async function login(rawKey) {
  showError($('login-error'), '');
  if (!(await isValidKey(rawKey))) {
    showError($('login-error'), 'That key is not valid. Check for typos.');
    return;
  }
  // Key is valid locally. Clear it from the page and ask the server for a fresh,
  // random session ID. The key is NOT part of this request.
  $('key-input').value = '';
  try {
    const { sessionId: id, expiresAt } = await api('/api/session', { method: 'POST' });
    sessionId = id;
    $('session-badge').textContent = `session ${id.slice(0, 6)}…`;
    clearTimeout(expiryTimer);
    expiryTimer = setTimeout(() => endSession(), expiresAt - Date.now());
    show('report');
  } catch (err) {
    showError($('login-error'), err.message);
  }
}

$('login-form').addEventListener('submit', (e) => {
  e.preventDefault();
  login($('key-input').value);
});

$('key-input').addEventListener('input', (e) => {
  const n = normalizeKey(e.target.value).slice(0, 24);
  e.target.value = n ? formatKey(n) : '';
});

$('new-key').addEventListener('click', async () => {
  $('generated-key').textContent = await generateKey();
  $('saved-key').checked = false;
  $('use-key').disabled = true;
  show('newkey');
});

$('saved-key').addEventListener('change', (e) => {
  $('use-key').disabled = !e.target.checked;
});

$('use-key').addEventListener('click', () => {
  const key = $('generated-key').textContent;
  $('generated-key').textContent = '';
  login(key);
});

$('report-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  showError($('report-error'), '');
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  const body = Object.fromEntries(new FormData(form));
  try {
    const { reference } = await api('/api/reports', { method: 'POST', body });
    form.reset();
    $('reference').textContent = reference;
    show('done');
  } catch (err) {
    if (sessionId) showError($('report-error'), err.message);
  }
});

$('another').addEventListener('click', () => show('report'));

$('logout').addEventListener('click', async () => {
  try {
    await api('/api/session', { method: 'DELETE' });
  } catch {
    // Session is dropped locally regardless; the server expires it anyway.
  }
  endSession('');
});

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

show('login');
