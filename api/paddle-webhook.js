// api/paddle-webhook.js
//
// Receives Paddle Billing webhooks, verifies their signature, and forwards
// completed transactions to Meta's and Snap's Conversions APIs (server-side)
// as a "Purchase" event. This is what makes conversion counting reliable for
// traffic the browser pixel alone misses — iOS App Tracking Transparency,
// Safari ITP, ad blockers, or the Snapchat in-app browser dropping cookies.
//
// ── Deduplication ──────────────────────────────────────────────────────────
// The event_id sent here is the Paddle transaction ID — the exact same ID
// the browser-side pixels use as their dedup key when firing Purchase right
// after checkout.completed (see index.html: `eventID` for Meta,
// `transaction_id` for Snap). Both platforms deduplicate any Pixel + CAPI
// event pair that shares that ID, so a single real purchase is counted
// exactly once even when:
//   - both the browser pixel and this server call succeed (normal case)
//   - only this server call succeeds (iOS blocked the browser pixel, or the
//     buyer completed checkout inside Snapchat's in-app browser)
//   - Paddle retries the webhook delivery (network hiccup, timeout, etc.)
//   - the customer reloads /access.html afterwards (nothing here re-fires)
//
// ── Required environment variables (set in Vercel → Project → Settings → Environment Variables) ──
//   PADDLE_WEBHOOK_SECRET   — from Paddle Dashboard → Developer Tools → Notifications
//                             (shown once you create a webhook destination pointing at
//                             this endpoint's live URL)
//   META_CAPI_ACCESS_TOKEN  — from Meta Events Manager → Data sources → your dataset
//                             → Settings → Conversions API → "Generate access token"
//   SNAP_CAPI_ACCESS_TOKEN  — from Snapchat Ads Manager → account menu → Business Details
//                             → "Conversions API Tokens" section → Generate Token
//                             (must be an Organization Admin to see this section;
//                             the token is static/long-lived, no refresh needed)
//
// ── One-time setup on Paddle's side ─────────────────────────────────────────
//   1. Deploy this file (just push to the repo — Vercel auto-detects /api/*.js).
//   2. In Paddle Dashboard → Developer Tools → Notifications, add a new
//      destination pointing to: https://masarprojects.net/api/paddle-webhook
//   3. Subscribe it to the "transaction.completed" event.
//   4. Copy the signing secret Paddle shows you into PADDLE_WEBHOOK_SECRET.
//   5. Generate the Meta access token and put it in META_CAPI_ACCESS_TOKEN.
//   6. Generate the Snap access token and put it in SNAP_CAPI_ACCESS_TOKEN.
//   7. Redeploy so the new environment variables take effect.
//
// ── Verifying it's actually working ─────────────────────────────────────────
//   - Vercel → Project → your deployment → Functions → paddle-webhook → Logs
//     will show a line per received webhook and the raw response from Meta
//     and from Snap.
//   - Meta Events Manager → Test Events, and Snapchat Events Manager →
//     Test Events, will show incoming CAPI events live if you trigger a real
//     (or Paddle sandbox) transaction while each is open.
//   - Meta Events Manager → Diagnostics, and Snapchat Events Manager →
//     Ads Readiness, will start reporting match-quality signals for the
//     Purchase event once real traffic comes through — worth watching over
//     the first few days.

const crypto = require('crypto');

const PIXEL_ID = '894972786659768';
const META_API_VERSION = 'v21.0';

const SNAP_PIXEL_ID = 'd419b2dc-f722-4879-b09b-1c5e5d46c5c9';
const SNAP_CAPI_VERSION = 'v3';

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

  const txnId = event.data && event.data.id;

  // Fire both platforms independently — one failing (bad token, transient
  // network error) must never stop the other's Purchase event from sending.
  const [metaResult, snapResult] = await Promise.allSettled([
    sendPurchaseToMeta(event.data),
    sendPurchaseToSnap(event.data)
  ]);

  if (metaResult.status === 'fulfilled') {
    console.log('Meta CAPI response for transaction', txnId, ':', JSON.stringify(metaResult.value));
  } else {
    console.error('Meta CAPI call failed for transaction', txnId, ':', metaResult.reason);
  }

  if (snapResult.status === 'fulfilled') {
    console.log('Snap CAPI response for transaction', txnId, ':', JSON.stringify(snapResult.value));
  } else {
    console.error('Snap CAPI call failed for transaction', txnId, ':', snapResult.reason);
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

async function sendPurchaseToSnap(txn) {
  var accessToken = process.env.SNAP_CAPI_ACCESS_TOKEN;
  if (!accessToken) {
    throw new Error('SNAP_CAPI_ACCESS_TOKEN is not set.');
  }

  var custom = (txn && txn.custom_data) || {};
  var email = txn && txn.customer && txn.customer.email;

  var grandTotalMinorUnits =
    txn && txn.details && txn.details.totals && txn.details.totals.grand_total;
  var value = grandTotalMinorUnits ? Number(grandTotalMinorUnits) / 100 : 99;
  var currency = (txn && txn.currency_code) || 'SAR';

  var userData = {};
  if (email) userData.em = [sha256(email)];
  // sc_click_id: the &ScCid= param from a Snapchat ad click, if the browser
  // pixel captured it into custom_data on checkout — improves match rate for
  // swipe-up traffic but is optional, so this is only sent when present.
  if (custom.sc_click_id) userData.sc_click_id = custom.sc_click_id;
  if (custom.sc_cookie1) userData.sc_cookie1 = custom.sc_cookie1;

  var payload = {
    data: [
      {
        event_name: 'PURCHASE',
        event_time: Math.floor(Date.now() / 1000),
        // Matches the transaction_id the browser Pixel sends on PURCHASE
        // (see index.html) — Snap dedupes Pixel + CAPI events that share
        // this ID, per their Conversions API deduplication guide.
        event_id: txn && txn.id,
        action_source: 'WEB',
        event_source_url: custom.event_source_url || 'https://masarprojects.net/',
        user_data: userData,
        custom_data: {
          currency: currency,
          value: String(value),
          content_ids: ['masar-bundle'],
          content_category: 'business-launch',
          num_items: 1
        }
      }
    ]
  };

  var url = 'https://tr.snapchat.com/' + SNAP_CAPI_VERSION + '/' + SNAP_PIXEL_ID + '/events?access_token=' + accessToken;

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
