// services/http.js — Drop-in HTTP client using Node.js native fetch
// Replaces axios entirely — zero external dependencies
// Node 18+ required (we are on Node 22)

/**
 * GET request
 */
async function get(url, options = {}) {
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'User-Agent': 'nu-pmc/1.0', ...options.headers },
    signal: options.timeout ? AbortSignal.timeout(options.timeout) : undefined,
  });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status}: ${res.statusText}`);
    err.status = res.status;
    throw err;
  }
  const contentType = res.headers.get('content-type') || '';
  if (options.responseType === 'arraybuffer') return { data: Buffer.from(await res.arrayBuffer()) };
  if (contentType.includes('application/json')) return { data: await res.json() };
  return { data: await res.text() };
}

/**
 * POST request
 */
async function post(url, data, options = {}) {
  let body, contentType;

  if (Buffer.isBuffer(data)) {
    body = data;
    // Caller must set Content-Type via options.headers
  } else if (typeof data === 'string') {
    // URL-encoded form data (Twilio style)
    body        = data;
    contentType = 'application/x-www-form-urlencoded';
  } else if (data instanceof FormData || data instanceof URLSearchParams) {  
    body = data;
  } else {
    body        = JSON.stringify(data);
    contentType = 'application/json';
  }

  const headers = {
    'User-Agent': 'nu-pmc/1.0',
    ...(contentType ? { 'Content-Type': contentType } : {}),
    ...options.headers,
  };

  // Basic auth support (Twilio uses this)
  if (options.auth) {
    const encoded = Buffer.from(`${options.auth.username}:${options.auth.password}`).toString('base64');
    headers['Authorization'] = `Basic ${encoded}`;
  }

  const res = await fetch(url, {
    method:  'POST',
    headers,
    body,
    // Default 30s timeout so a black-holed Matrix/Twilio/ICICI send fails fast
    // instead of hanging the request forever (and eventually exhausting the pool).
    signal: AbortSignal.timeout(options.timeout || 30000),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => res.statusText);
    const err     = new Error(`HTTP ${res.status}: ${errText}`);
    err.status    = res.status;
    let errData = errText;
    try { errData = JSON.parse(errText); } catch { /* not JSON */ }
    err.response  = { data: errData, status: res.status };
    throw err;
  }

  const ct = res.headers.get('content-type') || '';
  if (options.responseType === 'arraybuffer') return { data: Buffer.from(await res.arrayBuffer()) };
  if (ct.includes('application/json')) return { data: await res.json(), headers: Object.fromEntries(res.headers) };
  return { data: await res.text(), headers: Object.fromEntries(res.headers) };
}

/**
 * PUT request — used by Matrix C-S API for idempotent sends
 * (POST /send/{txnId} is the spec; reusing txnId returns the same event_id).
 * Mirrors POST's content-negotiation: string → form-urlencoded, FormData → as-is,
 * Buffer → raw bytes (use options.headers['Content-Type'] to specify),
 * else → JSON.
 */
async function put(url, data, options = {}) {
  let body, contentType;

  if (Buffer.isBuffer(data)) {
    body = data;
    // Caller must set Content-Type via options.headers
  } else if (typeof data === 'string') {
    body        = data;
    contentType = 'application/x-www-form-urlencoded';
  } else if (data instanceof FormData || data instanceof URLSearchParams) {  
    body = data;
  } else {
    body        = JSON.stringify(data);
    contentType = 'application/json';
  }

  const headers = {
    'User-Agent': 'nu-pmc/1.0',
    ...(contentType ? { 'Content-Type': contentType } : {}),
    ...options.headers,
  };

  const res = await fetch(url, {
    method:  'PUT',
    headers,
    body,
    // Default 30s timeout so a black-holed Matrix send fails fast instead of
    // hanging the request forever (and eventually exhausting the pool).
    signal: AbortSignal.timeout(options.timeout || 30000),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => res.statusText);
    const err     = new Error(`HTTP ${res.status}: ${errText}`);
    err.status    = res.status;
    let errData = errText;
    try { errData = JSON.parse(errText); } catch { /* not JSON */ }
    err.response  = { data: errData, status: res.status };
    throw err;
  }

  const ct = res.headers.get('content-type') || '';
  if (options.responseType === 'arraybuffer') return { data: Buffer.from(await res.arrayBuffer()) };
  if (ct.includes('application/json')) return { data: await res.json(), headers: Object.fromEntries(res.headers) };
  return { data: await res.text(), headers: Object.fromEntries(res.headers) };
}

module.exports = { get, post, put };
