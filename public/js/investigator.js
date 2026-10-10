import {
  CONTEXT, decryptText, encryptText, importInvestigatorPrivateKey, keyFingerprint, unwrapCaseKey,
} from './crypto.js';
import { CATEGORY_LABELS, STATUS_LABELS, createApiClient, el } from './api.js';

// The private key and decrypted case keys are held in memory only.
let privateKey = null;
const caseKeys = new Map();
let currentCaseId = null;

const $ = (id) => document.getElementById(id);
const api = createApiClient({ onUnauthorized: () => logout('Your session expired. Please log in again.') });

function show(view) {
  for (const section of document.querySelectorAll('main > section')) section.hidden = section.id !== `view-${view}`;
  $('logout').hidden = !api.loggedIn;
}

function showError(id, message) {
  $(id).textContent = message;
  $(id).hidden = !message;
}

function logout(message = '') {
  api.clearSession();
  privateKey = null;
  caseKeys.clear();
  currentCaseId = null;
  $('case-list').replaceChildren();
  showError('login-error', message);
  show('login');
}

async function caseKey(c) {
  if (!caseKeys.has(c.id)) caseKeys.set(c.id, await unwrapCaseKey(privateKey, c.wrappedKey));
  return caseKeys.get(c.id);
}

async function decryptReport(c) {
  try {
    return JSON.parse(await decryptText(await caseKey(c), c.report, CONTEXT.report));
  } catch {
    return null;
  }
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('login-error', '');
  const file = $('key-file').files[0];
  if (!$('token').value || !file) return showError('login-error', 'Enter the token and choose your key file.');
  try {
    const jwk = JSON.parse(await file.text());
    privateKey = await importInvestigatorPrivateKey(jwk);
    const fingerprint = await keyFingerprint(jwk);
    const { investigatorPublicKey } = await api.request('/api/config');
    if ((await keyFingerprint(investigatorPublicKey)) !== fingerprint) {
      throw new Error('This private key does not match the public key the server gives to reporters.');
    }
    const { sessionId, expiresAt } = await api.request('/api/investigator/session', {
      method: 'POST',
      body: { token: $('token').value },
    });
    api.setSession(sessionId);
    setTimeout(() => api.loggedIn && logout('Your session expired. Please log in again.'), expiresAt - Date.now());
    $('token').value = '';
    $('key-file').value = '';
    $('fingerprint').textContent = fingerprint;
    await renderList();
  } catch (err) {
    privateKey = null;
    showError('login-error', err instanceof SyntaxError ? 'That key file is not valid JSON.' : err.message);
  }
});

async function renderList() {
  showError('list-error', '');
  const { cases } = await api.request('/api/investigator/cases');
  const items = await Promise.all(cases.map(async (c) => {
    const report = await decryptReport(c);
    const title = report ? report.company : '[could not decrypt]';
    const sub = report ? (CATEGORY_LABELS[report.category] ?? report.category) : '';
    const button = el('button', { class: 'case-row' },
      el('span', { class: 'case-id', text: `#${c.id}` }),
      el('span', { class: 'case-title' }, el('strong', { text: title }), el('small', { text: ` ${sub}` })),
      c.awaitingReply ? el('span', { class: 'pill', text: 'Reporter replied' }) : null,
      el('span', { class: 'status', 'data-status': c.status, text: STATUS_LABELS[c.status] ?? c.status }),
      el('small', { class: 'case-date', text: c.updatedOn }),
    );
    button.addEventListener('click', () => openCase(c.id));
    return el('li', {}, button);
  }));
  $('case-list').replaceChildren(...(items.length ? items : [el('li', { class: 'empty', text: 'No cases yet.' })]));
  show('list');
}

async function openCase(id) {
  currentCaseId = id;
  showError('case-error', '');
  try {
    await renderCase();
    show('case');
  } catch (err) {
    showError('list-error', err.message);
  }
}

async function renderCase() {
  const c = await api.request(`/api/investigator/cases/${currentCaseId}`);
  const key = await caseKey(c);
  const report = await decryptReport(c);

  $('case-title').textContent = `Case #${c.id}`;
  $('case-status-select').value = c.status;
  const rows = report
    ? [
        ['Submitted', c.createdOn],
        ['Company', report.company],
        ['Category', CATEGORY_LABELS[report.category] ?? report.category],
        ['When', report.incidentDate],
        ['Where', report.location],
        ['What happened', report.description],
      ].filter(([, v]) => v)
    : [['Report', '[could not decrypt]']];
  $('case-report').replaceChildren(...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]));

  const items = await Promise.all(c.messages.map(async (m) => {
    const text = await decryptText(key, m.body, CONTEXT[m.sender]).catch(() => '[could not decrypt this message]');
    const who = m.sender === 'reporter' ? 'Reporter' : 'Investigator';
    return el('li', { class: m.sender === 'investigator' ? 'mine' : 'theirs' },
      el('div', { class: 'meta', text: `${who} · ${m.createdOn}` }), el('p', { text }));
  }));
  $('case-thread').replaceChildren(...(items.length ? items : [el('li', { class: 'empty', text: 'No messages yet.' })]));
  $('reply-form').hidden = c.status === 'closed';
}

for (const [value, label] of Object.entries(STATUS_LABELS)) {
  $('case-status-select').append(el('option', { value, text: label }));
}

$('case-status-select').addEventListener('change', async (e) => {
  try {
    await api.request(`/api/investigator/cases/${currentCaseId}`, { method: 'PATCH', body: { status: e.target.value } });
    await renderCase();
  } catch (err) {
    showError('case-error', err.message);
  }
});

$('reply-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('case-error', '');
  const text = $('reply').value.trim();
  if (!text) return;
  try {
    const key = caseKeys.get(currentCaseId);
    await api.request(`/api/investigator/cases/${currentCaseId}/messages`, {
      method: 'POST',
      body: { message: await encryptText(key, text, CONTEXT.investigator) },
    });
    $('reply').value = '';
    await renderCase();
  } catch (err) {
    if (api.loggedIn) showError('case-error', err.message);
  }
});

$('back').addEventListener('click', () => renderList().catch((err) => showError('list-error', err.message)));
$('reload').addEventListener('click', () => renderList().catch((err) => showError('list-error', err.message)));
$('logout').addEventListener('click', async () => {
  await api.request('/api/session', { method: 'DELETE' }).catch(() => {});
  logout();
});

show('login');
