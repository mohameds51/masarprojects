// api/paddle-webhook.js
//
// Receives Paddle Billing webhooks, verifies their signature, and forwards
// completed transactions to Meta's Conversions API (server-side) as a
// "Purchase" event. This is what makes conversion counting reliable for iOS
// traffic, where the browser pixel alone is frequently blocked (App Tracking
// Transparency) or delayed/dropped (Safari's Intelligent Tracking Prevention).
//
// ── Deduplication ──────────────────────────────────────────────────────────
// The event_id sent here is the Paddle transaction ID — the exact same ID
// the browser-side pixel uses as its eventID when firing Purchase right after
// checkout.completed (see index.html). Meta deduplicates any Pixel + CAPI
// event pair that shares an event_id, so a single real purchase is counted
// exactly once even when:
//   - both the browser pixel and this server call succeed (normal case)
//   - only this server call succeeds (iOS blocked the browser pixel)
//   - Paddle retries the webhook delivery (network hiccup, timeout, etc.)
//   - the customer reloads /access.html afterwards (nothing here re-fires)
//
// ── Required environment variables (set in Vercel → Project → Settings → Environment Variables) ──
//   PADDLE_WEBHOOK_SECRET   — from Paddle Dashboard → Developer Tools → Notifications
//                             (shown once you create a webhook destination pointing at
//                             this endpoint's live URL)
//   META_CAPI_ACCESS_TOKEN  — from Meta Events Manager → Data sources → your dataset
//                             → Settings → Conversions API → "Generate access token"
//
// ── One-time setup on Paddle's side ─────────────────────────────────────────
//   1. Deploy this file (just push to the repo — Vercel auto-detects /api/*.js).
//   2. In Paddle Dashboard → Developer Tools → Notifications, add a new
//      destination pointing to: https://masarprojects.net/api/paddle-webhook
//   3. Subscribe it to the "transaction.completed" event.
//   4. Copy the signing secret Paddle shows you into PADDLE_WEBHOOK_SECRET.
//   5. Generate the Meta access token and put it in META_CAPI_ACCESS_TOKEN.
//   6. Redeploy so the new environment variables take effect.
//
// ── Verifying it's actually working ─────────────────────────────────────────
//   - Vercel → Project → your deployment → Functions → paddle-webhook → Logs
//     will show a line per received webhook and the raw response from Meta.
//   - Meta Events Manager → Test Events will show incoming CAPI events live
//     if you trigger a real (or Paddle sandbox) transaction while it's open.
//   - Meta Events Manager → Diagnostics will start reporting an "Event Match
//     Quality" score for the Purchase event once real traffic comes through —
//     that's the number worth watching over the first few days.

const crypto = require('crypto');

const PIXEL_ID = '894972786659768';
const META_API_VERSION = 'v21.0';

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (err) {
    console.error('Failed to read webhook body:', err);
    res.status(400).send('Bad request');
    return;
  }

  const signatureHeader = req.headers['paddle-signature'];
  const webhookSecret = process.env.PADDLE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('PADDLE_WEBHOOK_SECRET is not set — refusing to process webhook.');
    res.status(500).send('Server not configured');
    return;
  }

  if (!verifyPaddleSignature(rawBody, signatureHeader, webhookSecret)) {
    console.error('Paddle webhook signature verification failed.');
    res.status(401).send('Invalid signature');
    return;
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (err) {
    console.error('Webhook body was not valid JSON:', err);
    res.status(400).send('Bad request');
    return;
  }

  // Always acknowledge quickly so Paddle doesn't retry unnecessarily; do the
  // Meta call and just log the outcome rather than making Paddle wait on it.
  res.status(200).send('OK');

  if (event.event_type !== 'transaction.completed') {
    return;
  }

  try {
    const result = await sendPurchaseToMeta(event.data);
    console.log('Meta CAPI response for transaction', event.data && event.data.id, ':', JSON.stringify(result));
  } catch (err) {
    console.error('Meta CAPI call failed for transaction', event.data && event.data.id, ':', err);
  }
};

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    var chunks = [];
    req.on('data', function (chunk) { chunks.push(chunk); });
    req.on('end', function () { resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}

function verifyPaddleSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader) return false;

  var parts = {};
  signatureHeader.split(';').forEach(function (part) {
    var kv = part.split('=');
    if (kv.length === 2) parts[kv[0].trim()] = kv[1].trim();
  });

  var ts = parts.ts;
  var h1 = parts.h1;
  if (!ts || !h1) return false;

  var signedPayload = ts + ':' + rawBody;
  var expected = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');

  var expectedBuf = Buffer.from(expected, 'utf8');
  var actualBuf = Buffer.from(h1, 'utf8');
  if (expectedBuf.length !== actualBuf.length) return false;

  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value.trim().toLowerCase()).digest('hex');
}

async function sendPurchaseToMeta(txn) {
  var accessToken = process.env.META_CAPI_ACCESS_TOKEN;
  if (!accessToken) {
    throw new Error('META_CAPI_ACCESS_TOKEN is not set.');
  }

  var custom = (txn && txn.custom_data) || {};
  var email = txn && txn.customer && txn.customer.email;

  // Paddle Billing reports totals in the smallest currency unit (e.g. halalas for SAR).
  // Fall back to the listed 99 SAR price if the field shape ever changes on Paddle's end.
  var grandTotalMinorUnits =
    txn && txn.details && txn.details.totals && txn.details.totals.grand_total;
  var value = grandTotalMinorUnits ? Number(grandTotalMinorUnits) / 100 : 99;
  var currency = (txn && txn.currency_code) || 'SAR';

  var userData = {};
  if (email) userData.em = [sha256(email)];
  if (custom.fbp) userData.fbp = custom.fbp;
  if (custom.fbc) userData.fbc = custom.fbc;

  var payload = {
    data: [
      {
        event_name: 'Purchase',
        event_time: Math.floor(Date.now() / 1000),
        event_id: txn && txn.id,
        event_source_url: custom.event_source_url || 'https://masarprojects.net/',
        action_source: 'website',
        user_data: userData,
        custom_data: {
          currency: currency,
          value: value
        }
      }
    ]
  };

  var url = 'https://graph.facebook.com/' + META_API_VERSION + '/' + PIXEL_ID + '/events?access_token=' + accessToken;

  var resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  return resp.json();
}

// Tells Vercel's Node runtime not to auto-parse the body, since signature
// verification needs the exact raw bytes Paddle signed — parsing/re-serializing
// JSON can change whitespace and break the signature check.
module.exports.config = {
  api: {
    bodyParser: false
  }
};
