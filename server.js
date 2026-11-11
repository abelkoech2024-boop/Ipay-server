'use strict';

/*
 * iPay payment API bridge
 *
 * Required environment variables:
 *   IPAY_ORG_ID       Organisation UUID from the iPay dashboard
 *   IPAY_JWT          JWT generated in iPay (keep it on the server)
 *
 * Optional:
 *   PORT              Defaults to 3000
 *   IPAY_BASE_URL     Defaults to https://api.ipay.tn
 *   IPAY_PRODUCT_CODE Defaults to SWITCH APITAL SAVINGS (must exist in iPay)
 *   APP_API_KEY       Protects the administrative proxy routes
 *   CORS_ORIGINS      Defaults to *; otherwise comma-separated origins
 *   PUBLIC_CHECKOUTS_PER_MINUTE Defaults to 10 per client IP
 *
 * The public checkout route accepts only customer name and amount. It injects
 * the configured product code, TND currency, and a server-generated unique
 * reference, and is rate limited. Never put IPAY_JWT or APP_API_KEY in a
 * browser bundle. APP_API_KEY remains required for administrative proxy
 * routes. The public webhook and receipt/SSE routes use transaction IDs as
 * capability URLs; treat those IDs as private.
 *
 * iPay's supplied documentation does not describe webhook signatures.
 * This server therefore cannot verify that an incoming webhook is genuine.
 * Confirm an iPay-supported signature or source-IP verification method
 * before relying on webhook events for production fulfilment.
 *
 * Webhook events and discovered receipts are held in memory only. A restart
 * loses them; use durable storage for production recovery and auditing.
 *
 * Runtime: Node.js 20+ (uses the built-in fetch API; no external packages).
 */

const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const ORG_ID = process.env.IPAY_ORG_ID || '';
const IPAY_JWT = process.env.IPAY_JWT || '';
const APP_API_KEY = process.env.APP_API_KEY || '';
const IPAY_BASE_URL = process.env.IPAY_BASE_URL || 'https://api.ipay.tn';
const IPAY_PRODUCT_CODE = (process.env.IPAY_PRODUCT_CODE || 'SWITCH APITAL SAVINGS').trim();
const PUBLIC_CHECKOUTS_PER_MINUTE = Math.max(
  1,
  Number.parseInt(process.env.PUBLIC_CHECKOUTS_PER_MINUTE || '10', 10) || 10
);
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const MAX_BODY_BYTES = 1024 * 1024;
const EVENT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CACHED_EVENTS = 5000;
const transactionEvents = new Map();
const eventStreams = new Map();
const publicCheckoutRateLimits = new Map();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, body) {
  if (res.headersSent) return;
  const data = Buffer.from(JSON.stringify(body));
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Length', data.length);
  res.end(data);
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  const wildcard = CORS_ORIGINS.includes('*');
  const allowed = !origin || wildcard || CORS_ORIGINS.includes(origin);

  if (!allowed) {
    sendJson(res, 403, { error: 'Origin is not allowed by CORS configuration' });
    return false;
  }

  if (wildcard) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Request-Id'
  );
  res.setHeader(
    'Access-Control-Expose-Headers',
    'Content-Disposition, X-Request-Id, X-Checkout-Reference'
  );
  res.setHeader('Access-Control-Max-Age', '600');
  return true;
}

function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAppKey(req, res) {
  if (!APP_API_KEY) {
    sendJson(res, 503, {
      error: 'Server is not configured',
      message: 'Set APP_API_KEY before using the protected API.'
    });
    return false;
  }

  const authorization = req.headers.authorization || '';
  const supplied = authorization.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length)
    : '';

  if (!supplied || !safeEqual(supplied, APP_API_KEY)) {
    sendJson(res, 401, { error: 'Unauthorized' });
    return false;
  }
  return true;
}

function requireIpayConfig(res) {
  if (!ORG_ID || !IPAY_JWT) {
    sendJson(res, 503, {
      error: 'iPay is not configured',
      message: 'Set IPAY_ORG_ID and IPAY_JWT on the server.'
    });
    return false;
  }
  return true;
}

function allowPublicCheckout(req) {
  const now = Date.now();
  if (publicCheckoutRateLimits.size > 10_000) {
    for (const [ip, entry] of publicCheckoutRateLimits) {
      if (now - entry.startedAt >= 60_000) publicCheckoutRateLimits.delete(ip);
    }
  }
  const forwardedFor = req.headers['x-forwarded-for'];
  const clientIp = (typeof forwardedFor === 'string' && forwardedFor.split(',')[0].trim())
    || req.socket.remoteAddress
    || 'unknown';
  const current = publicCheckoutRateLimits.get(clientIp);

  if (!current || now - current.startedAt >= 60_000) {
    publicCheckoutRateLimits.set(clientIp, { startedAt: now, count: 1 });
    return true;
  }
  if (current.count >= PUBLIC_CHECKOUTS_PER_MINUTE) return false;
  current.count += 1;
  return true;
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw new HttpError(413, 'Request body is too large');
    }
    chunks.push(chunk);
  }

  if (size === 0) return undefined;
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Request body must be valid JSON');
  }
}

function buildIpayUrl(path, query) {
  const base = new URL(IPAY_BASE_URL);
  const url = new URL(path, base);
  if (query) {
    for (const [key, value] of query.entries()) {
      url.searchParams.set(key, value);
    }
  }
  return url;
}

async function fetchIpay(path, options = {}) {
  if (!ORG_ID || !IPAY_JWT) {
    throw new Error('iPay server credentials are not configured');
  }

  const headers = {
    'X-Org-Id': ORG_ID,
    Authorization: `Bearer ${IPAY_JWT}`,
    Accept: '*/*'
  };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';

  return fetch(buildIpayUrl(path, options.query), {
    method: options.method || 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: AbortSignal.timeout(20_000)
  });
}

async function relayIpayResponse(res, response) {
  res.statusCode = response.status;
  res.setHeader(
    'Content-Type',
    response.headers.get('content-type') || 'application/octet-stream'
  );
  res.setHeader('Cache-Control', 'no-store');

  const disposition = response.headers.get('content-disposition');
  if (disposition) res.setHeader('Content-Disposition', disposition);
  const requestId = response.headers.get('x-request-id');
  if (requestId) res.setHeader('X-iPay-Request-Id', requestId);

  // Relay the provider's response status and body as received. This preserves
  // iPay's error payload for the calling frontend/backend.
  const data = Buffer.from(await response.arrayBuffer());
  res.setHeader('Content-Length', data.length);
  res.end(data);
}

function decodePathId(encoded) {
  let value;
  try {
    value = decodeURIComponent(encoded);
  } catch {
    throw new HttpError(400, 'Invalid path identifier');
  }
  if (!value || value.includes('/') || value.includes('\\')) {
    throw new HttpError(400, 'Invalid path identifier');
  }
  return encodeURIComponent(value);
}

function rememberEvent(transactionId, event) {
  const previous = transactionEvents.get(transactionId);
  const entry = {
    updatedAt: Date.now(),
    event,
    receipt: previous?.receipt || null
  };
  transactionEvents.set(transactionId, entry);

  const cutoff = Date.now() - EVENT_TTL_MS;
  for (const [id, cached] of transactionEvents) {
    if (cached.updatedAt < cutoff) transactionEvents.delete(id);
  }
  while (transactionEvents.size > MAX_CACHED_EVENTS) {
    transactionEvents.delete(transactionEvents.keys().next().value);
  }
  return entry;
}

function publish(transactionId, name, data) {
  const streams = eventStreams.get(transactionId);
  if (!streams) return;
  const message = `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of streams) {
    if (!res.write(message)) {
      // A slow client can reconnect and receive the latest cached event.
      res.end();
      streams.delete(res);
    }
  }
  if (streams.size === 0) eventStreams.delete(transactionId);
}

function receiptLookupPath(transactionId, customerId) {
  const query = new URLSearchParams();
  if (customerId) query.set('customer_id', customerId);
  const suffix = query.size ? `?${query.toString()}` : '';
  return `/api/admin/invoices${suffix}`;
}

async function findReceipt(transactionId) {
  const cached = transactionEvents.get(transactionId);
  if (cached?.receipt) return cached.receipt;

  const customerId = cached?.event?.data?.customer_id;
  const response = await fetchIpay(receiptLookupPath(transactionId, customerId));
  const text = await response.text();
  if (!response.ok) {
    const error = new Error(`iPay invoice lookup returned HTTP ${response.status}`);
    error.upstreamStatus = response.status;
    error.upstreamBody = text;
    throw error;
  }

  let invoices;
  try {
    invoices = JSON.parse(text);
  } catch {
    throw new Error('iPay returned an unreadable invoice list');
  }

  if (!Array.isArray(invoices)) return null;
  return invoices.find(
    (invoice) => String(invoice.transaction_id) === String(transactionId)
  ) || null;
}

async function attachReceipt(transactionId) {
  try {
    const receipt = await findReceipt(transactionId);
    if (!receipt) return;
    const entry = transactionEvents.get(transactionId) || {
      updatedAt: Date.now(),
      event: null,
      receipt: null
    };
    entry.updatedAt = Date.now();
    entry.receipt = receipt;
    transactionEvents.set(transactionId, entry);
    publish(transactionId, 'receipt', {
      transaction_id: transactionId,
      receipt,
      pdf_url: `/api/receipts/${encodeURIComponent(transactionId)}/pdf`
    });
  } catch (error) {
    // Don't fail the iPay webhook acknowledgement for an invoice lookup issue.
    console.error('Receipt lookup failed:', error.message);
  }
}

function streamEvents(req, res, transactionId) {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();
  res.write(': connected\n\n');

  const cached = transactionEvents.get(transactionId);
  if (cached?.event) {
    res.write(
      `event: payment\ndata: ${JSON.stringify({
        transaction_id: transactionId,
        ...cached.event
      })}\n\n`
    );
  }
  if (cached?.receipt) {
    res.write(
      `event: receipt\ndata: ${JSON.stringify({
        transaction_id: transactionId,
        receipt: cached.receipt,
        pdf_url: `/api/receipts/${encodeURIComponent(transactionId)}/pdf`
      })}\n\n`
    );
  }

  if (!eventStreams.has(transactionId)) eventStreams.set(transactionId, new Set());
  eventStreams.get(transactionId).add(res);

  const heartbeat = setInterval(() => {
    if (!res.writableEnded) res.write(': keep-alive\n\n');
  }, 20_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    const streams = eventStreams.get(transactionId);
    streams?.delete(res);
    if (streams?.size === 0) eventStreams.delete(transactionId);
  });
}

async function handleWebhook(req, res) {
  const event = await readJsonBody(req);
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new HttpError(400, 'Webhook body must be a JSON object');
  }

  const transactionId = event.data?.id;
  if (typeof transactionId === 'string' && transactionId) {
    rememberEvent(transactionId, event);
    publish(transactionId, 'payment', {
      transaction_id: transactionId,
      ...event
    });

    if (event.type === 'transaction.completed' || event.data?.status === 'paid') {
      // The payment event is acknowledged first. Invoice lookup then runs in
      // the background so an iPay API delay doesn't block the webhook response.
      setImmediate(() => void attachReceipt(transactionId));
    }
  } else {
    console.warn('Accepted iPay webhook without data.id; event cannot be streamed.');
  }

  // iPay's documentation says it does not retry failed webhook deliveries.
  sendJson(res, 200, { received: true });
}

async function handlePublicCheckout(req, res, requestId) {
  if (!requireIpayConfig(res)) return;
  if (!allowPublicCheckout(req)) {
    return sendJson(res, 429, {
      error: 'Too many checkout attempts',
      message: 'Please wait a minute before trying again.',
      request_id: requestId
    });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (error) {
    if (error instanceof HttpError) {
      return sendJson(res, error.status, { error: error.message, request_id: requestId });
    }
    return sendJson(res, 400, { error: 'Could not read request body', request_id: requestId });
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return sendJson(res, 400, { error: 'Request body must be a JSON object', request_id: requestId });
  }
  const customerName = typeof body.customer_name === 'string'
    ? body.customer_name.trim()
    : '';
  const amount = body.amount;
  if (customerName.length < 2 || customerName.length > 100) {
    return sendJson(res, 400, {
      error: 'customer_name must contain between 2 and 100 characters',
      request_id: requestId
    });
  }
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
    return sendJson(res, 400, {
      error: 'amount must be a number greater than zero',
      request_id: requestId
    });
  }

  const checkoutReference = `WEB-${crypto.randomUUID()}`;
  const ipayBody = {
    product_code: IPAY_PRODUCT_CODE,
    amount,
    currency: 'TND',
    customer_name: customerName,
    customer_external_id: checkoutReference
  };

  try {
    const response = await fetchIpay('/api/admin/transactions/create-oneshot', {
      method: 'POST',
      body: ipayBody
    });
    res.setHeader('X-Checkout-Reference', checkoutReference);
    return await relayIpayResponse(res, response);
  } catch (error) {
    console.error(`Public checkout failed (${requestId}):`, error.message);
    return sendJson(res, 502, {
      error: 'Could not reach iPay',
      message: error.message,
      request_id: requestId
    });
  }
}

function providerRoute(method, pathname, searchParams) {
  if (method === 'POST' && pathname === '/api/customers') {
    return { path: '/api/admin/customers', method: 'POST', hasBody: true };
  }
  let match = pathname.match(/^\/api\/customers\/([^/]+)$/);
  if (method === 'PUT' && match) {
    return {
      path: `/api/admin/customers/${decodePathId(match[1])}`,
      method: 'PUT',
      hasBody: true
    };
  }
  if (method === 'POST' && pathname === '/api/plans') {
    return { path: '/api/admin/plans', method: 'POST', hasBody: true };
  }
  if (method === 'PUT' && pathname === '/api/plans/update') {
    return { path: '/api/integration/plans/update', method: 'PUT', hasBody: true };
  }
  match = pathname.match(/^\/api\/plans\/([^/]+)\/archive$/);
  if (method === 'POST' && match) {
    return {
      path: `/api/admin/plans/${decodePathId(match[1])}/archive`,
      method: 'POST'
    };
  }
  if (method === 'POST' && pathname === '/api/subscriptions') {
    return { path: '/api/admin/subscriptions', method: 'POST', hasBody: true };
  }
  if (method === 'POST' && pathname === '/api/transactions/create-oneshot') {
    return {
      path: '/api/admin/transactions/create-oneshot',
      method: 'POST',
      hasBody: true
    };
  }
  if (method === 'GET' && pathname === '/api/invoices') {
    const query = new URLSearchParams();
    if (searchParams.has('customer_id')) {
      query.set('customer_id', searchParams.get('customer_id'));
    }
    return { path: '/api/admin/invoices', method: 'GET', query };
  }
  match = pathname.match(/^\/api\/invoices\/([^/]+)\/pdf$/);
  if (method === 'GET' && match) {
    return {
      path: `/api/admin/invoices/${decodePathId(match[1])}/pdf`,
      method: 'GET'
    };
  }
  match = pathname.match(/^\/api\/invoices\/([^/]+)$/);
  if (method === 'GET' && match) {
    return {
      path: `/api/admin/invoices/${decodePathId(match[1])}`,
      method: 'GET'
    };
  }
  if (method === 'GET' && pathname === '/api/webhooks/health') {
    const query = new URLSearchParams();
    if (searchParams.get('probe') === 'true') query.set('probe', 'true');
    return { path: '/api/admin/webhooks/health', method: 'GET', query };
  }
  return null;
}

async function handleReceiptRoute(res, transactionId, asPdf) {
  if (!ORG_ID || !IPAY_JWT) {
    return sendJson(res, 503, {
      error: 'iPay is not configured',
      message: 'Set IPAY_ORG_ID and IPAY_JWT on the server.'
    });
  }

  let receipt;
  try {
    receipt = await findReceipt(transactionId);
  } catch (error) {
    if (error.upstreamStatus) {
      res.statusCode = error.upstreamStatus;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      return res.end(error.upstreamBody);
    }
    return sendJson(res, 502, {
      error: 'Could not retrieve receipt from iPay',
      message: error.message
    });
  }

  if (!receipt) {
    return sendJson(res, 404, {
      error: 'Receipt not available yet',
      transaction_id: transactionId
    });
  }

  if (asPdf) {
    if (!receipt.id) {
      return sendJson(res, 502, { error: 'Invoice response did not include an id' });
    }
    try {
      const response = await fetchIpay(
        `/api/admin/invoices/${encodeURIComponent(receipt.id)}/pdf`
      );
      return await relayIpayResponse(res, response);
    } catch (error) {
      return sendJson(res, 502, {
        error: 'Could not download receipt PDF',
        message: error.message
      });
    }
  }

  const cached = transactionEvents.get(transactionId);
  if (cached) {
    cached.receipt = receipt;
    cached.updatedAt = Date.now();
  }
  return sendJson(res, 200, {
    receipt,
    pdf_url: `/api/receipts/${encodeURIComponent(transactionId)}/pdf`
  });
}

async function handleRequest(req, res) {
  const requestId = crypto.randomUUID();
  res.setHeader('X-Request-Id', requestId);

  if (!applyCors(req, res)) return;
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    return sendJson(res, 400, { error: 'Invalid request URL', request_id: requestId });
  }

  const pathname = url.pathname;
  if (req.method === 'GET' && pathname === '/health') {
    return sendJson(res, 200, {
      ok: true,
      service: 'ipay-payment-server',
      configured: {
        ipayOrgId: Boolean(ORG_ID),
        ipayJwt: Boolean(IPAY_JWT),
        appApiKey: Boolean(APP_API_KEY),
        productCode: Boolean(IPAY_PRODUCT_CODE),
        publicCheckout: Boolean(ORG_ID && IPAY_JWT && IPAY_PRODUCT_CODE)
      }
    });
  }

  if (req.method === 'POST' && pathname === '/api/webhooks/ipay') {
    try {
      return await handleWebhook(req, res);
    } catch (error) {
      if (error instanceof HttpError) {
        return sendJson(res, error.status, { error: error.message });
      }
      console.error('Webhook handling failed:', error.message);
      return sendJson(res, 500, { error: 'Webhook processing failed' });
    }
  }

  let match = pathname.match(/^\/api\/events\/([^/]+)$/);
  if (req.method === 'GET' && match) {
    try {
      return streamEvents(req, res, decodeURIComponent(match[1]));
    } catch {
      return sendJson(res, 400, { error: 'Invalid transaction identifier' });
    }
  }

  match = pathname.match(/^\/api\/receipts\/([^/]+)(\/pdf)?$/);
  if (req.method === 'GET' && match) {
    let transactionId;
    try {
      transactionId = decodeURIComponent(match[1]);
    } catch {
      return sendJson(res, 400, { error: 'Invalid transaction identifier' });
    }
    if (!transactionId || transactionId.includes('/') || transactionId.includes('\\')) {
      return sendJson(res, 400, { error: 'Invalid transaction identifier' });
    }
    return handleReceiptRoute(res, transactionId, Boolean(match[2]));
  }

  if (req.method === 'POST' && pathname === '/api/public/checkout') {
    return handlePublicCheckout(req, res, requestId);
  }

  const route = providerRoute(req.method, pathname, url.searchParams);
  if (!route) {
    return sendJson(res, 404, { error: 'Route not found', request_id: requestId });
  }
  if (!requireAppKey(req, res)) return;
  if (!requireIpayConfig(res)) return;

  let body;
  if (route.hasBody) {
    try {
      body = await readJsonBody(req);
      if (body === undefined) {
        return sendJson(res, 400, { error: 'A JSON request body is required' });
      }
    } catch (error) {
      if (error instanceof HttpError) {
        return sendJson(res, error.status, { error: error.message });
      }
      return sendJson(res, 400, { error: 'Could not read request body' });
    }
  }

  try {
    const response = await fetchIpay(route.path, {
      method: route.method,
      body,
      query: route.query
    });
    return await relayIpayResponse(res, response);
  } catch (error) {
    console.error(`iPay request failed (${requestId}):`, error.message);
    return sendJson(res, 502, {
      error: 'Could not reach iPay',
      message: error.message,
      request_id: requestId
    });
  }
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    console.error('Unhandled request error:', error.message);
    if (!res.headersSent) {
      sendJson(res, 500, { error: 'Internal server error' });
    } else {
      res.destroy();
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`iPay payment server listening on port ${PORT}`);
});
