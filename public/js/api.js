// Small fetch wrapper. The session ID lives only in this closure: never in
// localStorage, cookies or sessionStorage, so a reload or closed tab ends it.
export function createApiClient({ onUnauthorized }) {
  let sessionId = null;

  return {
    get loggedIn() {
      return sessionId !== null;
    },
    setSession(id) {
      sessionId = id;
    },
    clearSession() {
      sessionId = null;
    },
    async request(path, { method = 'GET', body } = {}) {
      const headers = {};
      if (sessionId) headers.Authorization = `Bearer ${sessionId}`;
      if (body) headers['Content-Type'] = 'application/json';
      const res = await fetch(path, { method, headers, body: body && JSON.stringify(body), cache: 'no-store' });
      const data = res.status === 204 ? null : await res.json().catch(() => null);
      if (res.status === 401 && sessionId) {
        sessionId = null;
        onUnauthorized();
      }
      if (!res.ok) throw new Error(data?.error ?? `Request failed (${res.status})`);
      return data;
    },
  };
}

// Builds DOM nodes. Text is always set via textContent, never parsed as HTML.
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v);
  }
  node.append(...children.filter((c) => c != null));
  return node;
}

export const CATEGORY_LABELS = {
  'fraud': 'Fraud',
  'corruption-bribery': 'Corruption / bribery',
  'health-safety': 'Health & safety',
  'environmental': 'Environmental',
  'labour-violations': 'Labour violations',
  'harassment-discrimination': 'Harassment / discrimination',
  'data-privacy': 'Data privacy',
  'other': 'Other',
};

export const STATUS_LABELS = {
  'received': 'Received',
  'in-review': 'In review',
  'needs-info': 'Needs more information',
  'closed': 'Closed',
};
