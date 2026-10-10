import { formatCaseCode, generateCaseCode, isValidCaseCode, normalizeCaseCode } from './case-code.js';
import {
  CONTEXT, decryptText, deriveCaseSecrets, encryptText, importInvestigatorPublicKey, keyFingerprint, wrapCaseKey,
} from './crypto.js';
import { CATEGORY_LABELS, STATUS_LABELS, createApiClient, el } from './api.js';

// Held in memory only. Reloading or closing the tab forgets all of it.
let caseKey = null;
let pendingCode = null;
let investigatorKey = null;
let expiryTimer = null;

const $ = (id) => document.getElementById(id);
const api = createApiClient({ onUnauthorized: () => closeCase('Your session ended. Enter your case code to continue.') });

function show(view) {
  for (const section of document.querySelectorAll('main > section')) section.hidden = section.id !== `view-${view}`;
  $('logout').hidden = !api.loggedIn;
  window.scrollTo(0, 0);
}

function showError(id, message) {
  $(id).textContent = message;
  $(id).hidden = !message;
}

function closeCase(message = '') {
  api.clearSession();
  caseKey = null;
  clearTimeout(expiryTimer);
  $('case-thread').replaceChildren();
  $('case-report').replaceChildren();
  showError('login-error', message);
  show(message ? 'login' : 'home');
}

async function loadInvestigatorKey() {
  if (investigatorKey) return investigatorKey;
  const { investigatorPublicKey } = await api.request('/api/config');
  $('fingerprint').textContent = await keyFingerprint(investigatorPublicKey);
  investigatorKey = await importInvestigatorPublicKey(investigatorPublicKey);
  return investigatorKey;
}

// --- Making a report ------------------------------------------------------

for (const [value, label] of Object.entries(CATEGORY_LABELS)) {
  $('category').append(el('option', { value, text: label }));
}

$('start-report').addEventListener('click', () => {
  showError('report-error', '');
  show('report');
  loadInvestigatorKey().catch((err) => showError('report-error', err.message));
});

$('report-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  showError('report-error', '');
  if (!form.checkValidity()) return form.reportValidity();
  const button = form.querySelector('[type=submit]');
  button.disabled = true;
  try {
    const report = Object.fromEntries(new FormData(form));
    const code = await generateCaseCode();
    const { auth, rawKey, key } = await deriveCaseSecrets(code);
    await api.request('/api/cases', {
      method: 'POST',
      body: {
        auth,
        wrappedKey: await wrapCaseKey(await loadInvestigatorKey(), rawKey),
        report: await encryptText(key, JSON.stringify(report), CONTEXT.report),
      },
    });
    form.reset();
    pendingCode = code;
    $('case-code').textContent = code;
    $('saved-code').checked = false;
    $('code-continue').disabled = true;
    show('code');
  } catch (err) {
    showError('report-error', err.message);
  } finally {
    button.disabled = false;
  }
});

$('saved-code').addEventListener('change', (e) => {
  $('code-continue').disabled = !e.target.checked;
});

$('code-continue').addEventListener('click', () => {
  const code = pendingCode;
  pendingCode = null;
  $('case-code').textContent = '';
  openCase(code);
});

// --- Returning to a case --------------------------------------------------

$('open-case').addEventListener('click', () => {
  showError('login-error', '');
  show('login');
});

$('code-input').addEventListener('input', (e) => {
  const n = normalizeCaseCode(e.target.value).slice(0, 24);
  e.target.value = n ? formatCaseCode(n) : '';
});

$('login-form').addEventListener('submit', (e) => {
  e.preventDefault();
  openCase($('code-input').value);
});

async function openCase(code) {
  showError('login-error', '');
  if (!(await isValidCaseCode(code))) {
    showError('login-error', 'That case code is not valid. Check for typos.');
    show('login');
    return;
  }
  $('code-input').value = '';
  try {
    // Only the derived auth value is sent. The server replies with a fresh,
    // random session ID for this visit.
    const secrets = await deriveCaseSecrets(code);
    const { sessionId, expiresAt } = await api.request('/api/session', { method: 'POST', body: { auth: secrets.auth } });
    api.setSession(sessionId);
    caseKey = secrets.key;
    clearTimeout(expiryTimer);
    expiryTimer = setTimeout(() => closeCase('Your session timed out. Enter your case code to continue.'), expiresAt - Date.now());
    await renderCase();
    show('case');
  } catch (err) {
    showError('login-error', err.message);
    show('login');
  }
}

async function renderCase() {
  const c = await api.request('/api/case');
  const report = JSON.parse(await decryptText(caseKey, c.report, CONTEXT.report));

  $('case-status').textContent = STATUS_LABELS[c.status] ?? c.status;
  $('case-status').dataset.status = c.status;

  const rows = [
    ['Submitted', c.createdOn],
    ['Company', report.company],
    ['Category', CATEGORY_LABELS[report.category] ?? report.category],
    ['When', report.incidentDate],
    ['Where', report.location],
    ['What happened', report.description],
  ].filter(([, v]) => v);
  $('case-report').replaceChildren(...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]));

  const items = await Promise.all(c.messages.map(async (m) => {
    const text = await decryptText(caseKey, m.body, CONTEXT[m.sender]).catch(() => '[could not decrypt this message]');
    const who = m.sender === 'reporter' ? 'You' : 'Investigator';
    return el('li', { class: m.sender === 'reporter' ? 'mine' : 'theirs' }, el('div', { class: 'meta', text: `${who} · ${m.createdOn}` }), el('p', { text }));
  }));
  $('case-thread').replaceChildren(
    ...(items.length ? items : [el('li', { class: 'empty', text: 'No messages yet. Investigators may ask you questions here.' })]),
  );

  const closed = c.status === 'closed';
  $('reply-form').hidden = closed;
  if (closed) $('case-thread').append(el('li', { class: 'empty', text: 'This case is closed.' }));
}

$('reply-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('reply-error', '');
  const text = $('reply').value.trim();
  if (!text) return;
  try {
    await api.request('/api/case/messages', {
      method: 'POST',
      body: { message: await encryptText(caseKey, text, CONTEXT.reporter) },
    });
    $('reply').value = '';
    await renderCase();
  } catch (err) {
    if (api.loggedIn) showError('reply-error', err.message);
  }
});

$('refresh').addEventListener('click', () => renderCase().catch((err) => showError('reply-error', err.message)));

$('logout').addEventListener('click', async () => {
  await api.request('/api/session', { method: 'DELETE' }).catch(() => {});
  closeCase();
});

for (const button of document.querySelectorAll('[data-go]')) {
  button.addEventListener('click', () => show(button.dataset.go));
}

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

show('home');
