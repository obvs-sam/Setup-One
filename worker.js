// ============================================================
// HomeKey – Cloudflare Worker
//
// ✅ STEP 1 – Environment Variables (Settings → Variables → Add Secret):
//   SA_EMAIL  →  firebase-adminsdk-fbsvc@codebysam123.iam.gserviceaccount.com
//   SA_KID    →  41c15e5bac4e424f258977c77c0c7fdb927ed94e
//   SA_KEY    →  Paste FULL private key WITH real newlines (not \n), like:
//                -----BEGIN PRIVATE KEY-----
//                MIIEvgIBADANBgkqhkiG9w0BAQEF...
//                -----END PRIVATE KEY-----
//
// ✅ STEP 2 – KV Namespace (for daily cleanup):
//   Workers → KV → Create namespace "HK_KV"
//   Worker Settings → Variables → KV Namespace Bindings → Add:
//     Variable name: HK_KV  →  KV Namespace: HK_KV
// ============================================================

const PROJECT_ID   = 'codebysam123';
const GROUP_ALIAS  = 'home';
const MAX_TESTERS  = 199;
const DAILY_DELETE = 100;
const SA_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDD52/wdiCxdsxe\n3uInpcGhboasrpG1+TM/UWrybDnYcgdXEIH5n6teHn+/t0ntETqAF6HhWndFp0A4\n6ZBj9qJ/rGAukTV0p4mJ7gDZduT6A8Dr4zc6/NPiH402b2T99Pw8zi3c0C6ytia0\n3ULGb0JLaxFNpPCN6Swtp+JrXTqAPiT5O1vYQWkTY6YzVb8oSkf8P93SmUXwBxdu\nxwWCouwrrwXahu+OdncC4vKGXcIy0uId5tL+QN90aJ8eO2xBcB3s5RvNE8XJuQ6p\nLrFgrLsfMr1eSHtvDwNS+VQ0/O7z73My12e9TWQMER86iPvfe0iZx8CRQGtqkpQY\nY8xRxAEZAgMBAAECggEAEp/RkgxA7m4rXseUu400G9tMnWUZQDIZT6c3YiWs2Cl7\nDilpGei2m4ONxJWxxwJwy9WzU5/MoAgXAHIgAojjiPzDxhmS+eyllEHWvdXiTeyG\nbkaTLR31LNWwEKFFeilMw6EcVhZKoj3T7zTr0L6qEE50/is0nWEyDIMd8PQTiDZ1\npFzSDm1T6XcqME9TQyghS2uoWK3bTvXaLrjC337zEnquxFDwFE0/q/7SI2p/5ZiN\nw9ERibxWoUvlwjNN5NSsf/5bPGeOSfHO1CCTqXv+XBfKZKgBsDLmNBhlo1xWbUdw\nOPsOShHpy2CC6ba2ZT+waQeTu2aDNyuJfM+BGng6QQKBgQDoT1421Z7cTzQPtq8s\nP9+eKgYt7+fa3YvGEj7iqk+BEVfPgiKRf0JlA6SKkjyCIHXwOa7CJYMWlzeDdgiz\neBe8TnWKDHx4QEZca5vCJnLgFjLoseCg6SiFOD5P+d8xqDRiSXOV6v6tfv9jcUOY\nIkLwiPtaoo3SxE1HlrfjMe4OSQKBgQDX4anEYZgzxx7bzcIZmIEpQRANwhoMwwKy\nkrV5GWAxqh5Lhrsrp6XNssyrH4Nq7Dw5Tt7JgUpKjaocSjTQPghuPyM9FFEYgzgd\nIlYcsGOmEaRo+8WKhBF+0tz3YVmID6+U87EN6GeTt4V3khBcXYrx/lmwke5VcTco\ndTjeAtWcUQKBgQDPyL2iGiv/LbCJJYNE9tSSaVAhomUk8+fi/8rTfjWiYdrCtckp\njkPaigmQEACi+1nBxjYzXM4FVLfIk7hwncfNG/gxw71I6WSFoZItc6poGDLswr0B\n78nYblf9vKcPiT1hdAU4YHnuwJq5XUNyPaLV9g+sH5zumbntgDd1tOESUQKBgE21\nrq3BT897ovEOfQtHqV7XS9cYAtaLMCJlyytfZhAao7MeOav6OiX0cdY7jsvjY75h\nVLMGdl6l5hEu6Rn46oH8+ktXT+XZ/k4GeSb0m7pA6YTc9HvrFH0pnF70TQ08UED3\nA8n02awDyOiEzJzjE0wO+ewka72X9nn60FCihpAxAoGBAIdDoEy8s5Bdu01HG08D\nFb/fazuqADDum9Z7zo3UmGKNm2m+T6G5KXLvONpKopMa0XOipO182BwLDQEnncHR\nw0MkFKWbhMCOELORNe8KOnqXJ86ZN7JjDRt8iNiNCS2l+oVeFbEFRJ7cJDkoLU1P\nPoRRMMOFyD4dyzyfuYxTY1KC\n-----END PRIVATE KEY-----\n";
const SA_KID = "41c15e5bac4e424f258977c77c0c7fdb927ed94e";
const SA_EMAIL = "firebase-adminsdk-fbsvc@codebysam123.iam.gserviceaccount.com";
// ---- JWT signing with WebCrypto ----
async function getAccessToken(env) {
  const now    = Math.floor(Date.now() / 1000);
  const header  = { alg: 'RS256', typ: 'JWT', kid: env.SA_KID };
  const payload = {
    iss: env.SA_EMAIL,
    scope: 'https://www.googleapis.com/auth/cloud-platform',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600
  };

  const enc = o => btoa(JSON.stringify(o))
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const sigInput = enc(header) + '.' + enc(payload);

  // FIX 1: Handle literal \n strings from Cloudflare env secrets
  const rawKey = env.SA_KEY.replace(/\\n/g, '\n');
  const pem = rawKey
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');

  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'pkcs8', der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );

  const sigBuf = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(sigInput)
  );

  // FIX 2: Use forEach instead of spread (...) to avoid stack overflow
  const sigArr = new Uint8Array(sigBuf);
  let sigStr = '';
  sigArr.forEach(b => { sigStr += String.fromCharCode(b); });
  const sigB64 = btoa(sigStr)
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

  const jwt = sigInput + '.' + sigB64;

  const res  = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Token failed: ' + JSON.stringify(data));
  return data.access_token;
}

// ---- Firebase App Distribution helpers ----
async function listTesters(token) {
  // FIX 3: correct field is "members" (not "testers") per Firebase API docs
  const url  = `https://firebaseappdistribution.googleapis.com/v1/projects/${PROJECT_ID}/groups/${GROUP_ALIAS}/members?pageSize=200`;
  const res  = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  const data = await res.json();
  return data.members || [];
}

async function addTester(email, token) {
  const url = `https://firebaseappdistribution.googleapis.com/v1/projects/${PROJECT_ID}/groups/${GROUP_ALIAS}:batchJoin`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ emails: [email] })
  });
  if (!res.ok) {
    const e = await res.json();
    throw new Error(e.error?.message || 'Failed to add tester');
  }
}

async function deleteTesters(emails, token) {
  if (!emails.length) return;
  const url = `https://firebaseappdistribution.googleapis.com/v1/projects/${PROJECT_ID}/groups/${GROUP_ALIAS}:batchLeave`;
  await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ emails })
  });
}

// ---- Daily cleanup via KV ----
async function runDailyCleanup(testers, token, env) {
  if (!env.HK_KV) return testers;
  const today = new Date().toDateString();
  const last  = await env.HK_KV.get('last_cleanup');
  if (last === today) return testers;

  // FIX 4: Run cleanup whenever testers exist (not just when >= MAX)
  // This ensures old testers are removed daily regardless of count
  if (testers.length > 0) {
    const toDelete = testers.slice(0, DAILY_DELETE).map(t => t.email);
    await deleteTesters(toDelete, token);
    await env.HK_KV.put('last_cleanup', today);
    return testers.slice(DAILY_DELETE);
  }
  return testers;
}

// ---- CORS ----
const CORS = {
  'Access-Control-Allow-Origin' : '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: CORS });

// ---- Main handler ----
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const { pathname } = new URL(request.url);

    try {
      const token = await getAccessToken(env);

      // GET /count
      if (pathname === '/count' && request.method === 'GET') {
        const testers = await listTesters(token);
        return json({ count: testers.length, slots: Math.max(0, MAX_TESTERS - testers.length) });
      }

      // POST /register
      if (pathname === '/register' && request.method === 'POST') {
        const body  = await request.json();
        const email = (body.email || '').trim().toLowerCase();

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: 'Invalid email address' }, 400);
        }

        let testers = await listTesters(token);
        testers = await runDailyCleanup(testers, token, env);

        if (testers.some(t => t.email === email)) {
          return json({ ok: true, already: true });
        }
        if (testers.length >= MAX_TESTERS) {
          return json({ error: 'Beta slots are full. Check back tomorrow!' }, 403);
        }

        await addTester(email, token);
        return json({ ok: true });
      }

      return json({ error: 'Not found' }, 404);

    } catch (err) {
      console.error(err);
      return json({ error: err.message }, 500);
    }
  }
};