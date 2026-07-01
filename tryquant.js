/**
 * TryQuant Whitelist Farming Bot
 * Flow: X OAuth connect -> daily claim, quantify, tasks verify, follow X targets
 *
 * Usage:
 *   node tryquant.js <mode> <scope>
 *
 * mode:  all | verify | daily | quantify | follow
 * scope: 1:<index> | all | from:<index>
 *
 * Examples:
 *   node tryquant.js all all
 *   node tryquant.js all 1:3
 *   node tryquant.js all from:5
 *   node tryquant.js verify all
 *   node tryquant.js follow all
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// ================= CONFIG =================
const BASE = 'https://whitelist.tryquant.io';
const X_CLIENT_ID = 'bmFUcmRjQUdqb3N2UnUzZ2tJa3k6MTpjaQ';
const X_REDIRECT_URI = `${BASE}/auth/x/callback`;
const X_SCOPE = 'users.read tweet.read follows.read offline.access';
const START_LINK_REF = '6a44ed4f0afd4f7bc4ef5970'; // dari ?startapp=ref-XXXX

const FOLLOW_TARGETS = ['tryquantio', 'nftquants'];

// taskId yang langsung bisa verify tanpa start
const DIRECT_VERIFY_TASKS = [
  'join-the-whitelist',      // butuh /api/me/email dulu
  'follow-x',                // butuh x-follow/url dulu (auto/silent)
  'follow-quants-on-x',
  'apply-to-the-quant-ai-ambassador-program',
  'meet-quant-ai',
  'like-and-rt-our-announcement',
  'join-quant-community-qtsul7',
];

// taskId yang butuh start dulu, baru verify setelah readyAt
const TIMER_TASKS = [
  'follow-telegram-channel-janjs7',
  'like-rt-and-comment',
  'follow-on-instagram-2awrat',
  'like-and-rt-a-daily-post',
  'comment-and-rt-a-daily-instagram-post',
  'comment-and-rt-a-daily-tiktok-post',
];

const ACCOUNTS_FILE = path.join(__dirname, 'accounts.txt');
const EMAILS_FILE = path.join(__dirname, 'emails.txt');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json'); // simpen access_token per akun biar ga connect X berulang-ulang
const STATE_FILE = path.join(__dirname, 'timer_state.json'); // simpen startedAt/readyAt per akun per task

const UA = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

// ================= UTIL =================
function log(msg) {
  console.log(msg);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function genPkce() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

function genState() {
  return b64url(crypto.randomBytes(32));
}

function readAccounts() {
  const raw = fs.readFileSync(ACCOUNTS_FILE, 'utf-8');
  const blocks = raw.split(/\r?\n\r?\n/).map((b) => b.trim()).filter(Boolean);
  return blocks.map((b) => {
    const lines = b.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    return { auth_token: lines[0], ct0: lines[1] };
  });
}

function readEmails() {
  if (!fs.existsSync(EMAILS_FILE)) return [];
  return fs.readFileSync(EMAILS_FILE, 'utf-8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}

function loadJson(file) {
  if (!fs.existsSync(file)) return {};
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch {
    return {};
  }
}

function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function parseScope(scopeArg, total) {
  if (scopeArg === 'all') return Array.from({ length: total }, (_, i) => i);
  if (scopeArg.startsWith('from:')) {
    const start = parseInt(scopeArg.split(':')[1], 10) - 1;
    return Array.from({ length: total - start }, (_, i) => start + i).filter((i) => i < total && i >= 0);
  }
  if (scopeArg.startsWith('1:')) {
    const idx = parseInt(scopeArg.split(':')[1], 10) - 1;
    return idx >= 0 && idx < total ? [idx] : [];
  }
  throw new Error(`Scope invalid: ${scopeArg}. Pakai "all", "1:<index>", atau "from:<index>"`);
}

// ================= HTTP HELPERS =================
// Bearer token publik yang dipakai web X (dipakai banyak client, bukan token pribadi)
const X_PUBLIC_BEARER =
  'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA';

async function xRequest(method, url, { auth_token, ct0 }, opts = {}) {
  const headers = {
    'User-Agent': UA,
    'Cookie': `auth_token=${auth_token}; ct0=${ct0}`,
    'x-csrf-token': ct0,
    'Authorization': `Bearer ${X_PUBLIC_BEARER}`,
    'x-twitter-auth-type': 'OAuth2Session',
    'x-twitter-active-user': 'yes',
    'x-twitter-client-language': 'en',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    ...opts.headers,
  };
  const res = await fetch(url, { method, headers, body: opts.body, redirect: 'manual' });
  return res;
}

// Khusus buat x.com/i/oauth2/authorize (halaman OAuth App consent) -- ini endpoint
// browser-facing yang pakai session cookie biasa, BUKAN api.x.com yang butuh bearer
// app-only + x-twitter-auth-type. Ngirim header itu ke sini kemungkinan besar
// yang bikin 401, karena servernya expect user session murni lewat cookie.
async function xAuthorizeRequest(method, url, { auth_token, ct0 }, opts = {}) {
  const headers = {
    'User-Agent': UA,
    'Cookie': `auth_token=${auth_token}; ct0=${ct0}`,
    'x-csrf-token': ct0,
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    ...opts.headers,
  };
  const res = await fetch(url, { method, headers, body: opts.body, redirect: 'manual' });
  return res;
}

async function tqRequest(method, path_, { token }, opts = {}) {
  const headers = {
    'User-Agent': UA,
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'Origin': BASE,
    'Referer': `${BASE}/`,
    'X-App-Context': 'web',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...opts.headers,
  };
  const res = await fetch(`${BASE}${path_}`, {
    method,
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    // response kosong, gapapa
  }
  return { status: res.status, data };
}

// ================= CONNECT X (OAuth PKCE) =================
async function connectX(account) {
  const { auth_token, ct0 } = account;

  // Step 1: minta authorize URL dari backend tryquant (pakai fetch manual biar dapet Set-Cookie)
  // PENTING: redirect: 'manual' -- kalau step1 sebenernya 302 redirect, fetch default bakal
  // ngikutin redirect itu dan Set-Cookie dari response PERTAMA jadi keburu ilang / gak kebaca.
  const step1Res = await fetch(
    `${BASE}/api/auth/x?redirectUri=${encodeURIComponent(X_REDIRECT_URI)}&startParam=ref-${START_LINK_REF}`,
    {
      headers: { 'User-Agent': UA, 'Accept': 'application/json, text/plain, */*' },
      redirect: 'manual',
    }
  );
  console.log('--- STEP1 STATUS ---', step1Res.status);
  console.log('--- STEP1 LOCATION ---', step1Res.headers.get('location') || '(none)');

  // Ambil semua Set-Cookie dari response step 1 buat dipakai lagi di step 4
  let setCookies = step1Res.headers.getSetCookie ? step1Res.headers.getSetCookie() : [];
  let sessionCookie = setCookies.map((c) => c.split(';')[0]).join('; ');
  console.log('--- STEP1 SET-COOKIE ---', sessionCookie || '(kosong)');

  // Kalau ternyata redirect (3xx) dan belum dapet cookie, ikutin manual sambil nyimpen cookie di tiap hop
  if (step1Res.status >= 300 && step1Res.status < 400) {
    let nextUrl = step1Res.headers.get('location');
    let hops = 0;
    const collectedCookies = [...setCookies];
    while (nextUrl && hops < 5) {
      const resolved = new URL(nextUrl, BASE).toString();
      const hopRes = await fetch(resolved, {
        headers: {
          'User-Agent': UA,
          'Accept': 'application/json, text/plain, */*',
          ...(collectedCookies.length ? { Cookie: collectedCookies.map((c) => c.split(';')[0]).join('; ') } : {}),
        },
        redirect: 'manual',
      });
      const hopCookies = hopRes.headers.getSetCookie ? hopRes.headers.getSetCookie() : [];
      collectedCookies.push(...hopCookies);
      console.log(`--- STEP1 HOP ${hops + 1} ---`, hopRes.status, resolved, 'SET-COOKIE:', hopCookies.join(' | ') || '(kosong)');
      if (hopRes.status >= 300 && hopRes.status < 400) {
        nextUrl = hopRes.headers.get('location');
        hops++;
      } else {
        nextUrl = null;
      }
    }
    setCookies = collectedCookies;
    sessionCookie = setCookies.map((c) => c.split(';')[0]).join('; ');
    console.log('--- STEP1 FINAL SESSION COOKIE (after redirects) ---', sessionCookie || '(masih kosong)');
  } else if (step1Res.status !== 200) {
    throw new Error(`Step1 gagal: ${step1Res.status}`);
  }

  // Backend ngasih authUrl siap pakai, LENGKAP dengan state & code_challenge yang DIA generate
  // dan simpen sendiri di server side (makanya gak butuh cookie -- dia track pake state itu).
  // Kita HARUS pakai authUrl ini apa adanya, JANGAN generate state/PKCE sendiri,
  // karena kalau beda, server gak bakal nemu sesi yang cocok pas step4 -> 403.
  let step1Data = null;
  try {
    step1Data = await step1Res.clone().json();
    console.log('--- STEP1 BODY ---', JSON.stringify(step1Data).slice(0, 1000));
  } catch {
    const t = await step1Res.text().catch(() => '');
    console.log('--- STEP1 BODY (non-JSON) ---', t.slice(0, 500));
  }

  if (!step1Data || !step1Data.authUrl) {
    throw new Error('Step1 gagal: authUrl tidak ditemukan di response');
  }

  const authorizeUrl = step1Data.authUrl;
  const authorizeUrlObj = new URL(authorizeUrl);
  const state = authorizeUrlObj.searchParams.get('state');
  console.log('--- STATE (dari backend) ---', state);

  // Step 2: GET authorize (buat approval token dari X)
  // PENTING: x.com/i/oauth2/authorize cuma HTML shell (SPA), bukan API.
  // Endpoint yang bener buat dapet JSON auth_code itu di api.x.com, dengan
  // path yang sama tapi host beda -- makanya butuh header API (bearer dll),
  // makanya pakai xRequest (bukan xAuthorizeRequest) di sini.
  const apiAuthorizeUrl = authorizeUrl.replace('https://x.com/i/oauth2/authorize', 'https://api.x.com/2/oauth2/authorize');
  console.log('--- STEP2 URL ---', apiAuthorizeUrl);
  const step2 = await xRequest('GET', apiAuthorizeUrl, { auth_token, ct0 });
  const step2Text = await step2.text();
  console.log('--- STEP2 STATUS ---', step2.status);
  console.log('--- STEP2 BODY (awal) ---', step2Text.slice(0, 1500));
  let approvalCode;
  try {
    const j = JSON.parse(step2Text);
    approvalCode = j.auth_code;
  } catch {
    const m = step2Text.match(/"auth_code"\s*:\s*"([^"]+)"/);
    if (m) approvalCode = m[1];
  }
  if (!approvalCode) throw new Error(`Gagal ambil approval code dari halaman authorize X (status ${step2.status}, body: ${step2Text.slice(0, 300)})`);

  // Step 3: POST approve
  const step3 = await xRequest(
    'POST',
    'https://x.com/i/api/2/oauth2/authorize',
    { auth_token, ct0 },
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `approval=true&code=${encodeURIComponent(approvalCode)}`,
    }
  );
  const step3Data = await step3.json();
  console.log('--- STEP3 STATUS ---', step3.status);
  console.log('--- STEP3 BODY ---', JSON.stringify(step3Data).slice(0, 1000));
  const finalRedirect = step3Data.redirect_uri;
  console.log('--- FINAL REDIRECT ---', finalRedirect);
  if (!finalRedirect) throw new Error('Gagal ambil redirect_uri final dari approve');

  // Step 4: exchange code -> access_token via backend tryquant
  const step4Res = await fetch(`${BASE}/api/auth/x`, {
    method: 'POST',
    headers: {
      'User-Agent': UA,
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      'Origin': BASE,
      'Referer': `${BASE}/auth/x/callback?state=${state}&code=${approvalCode}`,
      ...(sessionCookie ? { Cookie: sessionCookie } : {}),
    },
    body: JSON.stringify({
      code: finalRedirect.match(/[?&]code=([^&]+)/)?.[1] || approvalCode,
      redirectUri: X_REDIRECT_URI,
      state: finalRedirect.match(/[?&]state=([^&]+)/)?.[1] || state,
    }),
  });
  const step4Text = await step4Res.text();
  console.log('--- STEP4 STATUS ---', step4Res.status);
  console.log('--- STEP4 BODY (awal) ---', step4Text.slice(0, 800));

  let step4Data = null;
  try {
    step4Data = JSON.parse(step4Text);
  } catch {
    // bukan JSON, coba cari access_token di HTML/script embed
    const m = step4Text.match(/"access_token"\s*:\s*"([^"]+)"/);
    const m2 = step4Text.match(/"refresh_token"\s*:\s*"([^"]+)"/);
    if (m) step4Data = { access_token: m[1], refresh_token: m2 ? m2[1] : null };
  }

  if (!step4Data || !step4Data.access_token) {
    throw new Error(`Callback gagal ambil access_token. status=${step4Res.status}`);
  }

  return {
    access_token: step4Data.access_token,
    refresh_token: step4Data.refresh_token,
  };
}

async function getOrCreateSession(account, idx) {
  const sessions = loadJson(SESSIONS_FILE);
  const key = account.auth_token.slice(0, 12);

  if (sessions[key] && sessions[key].access_token) {
    // TODO: bisa tambah validasi expiry kalau JWT-nya ada field exp
    return sessions[key].access_token;
  }

  log(`[akun ${idx + 1}] Connect X...`);
  const tokens = await connectX(account);
  sessions[key] = tokens;
  saveJson(SESSIONS_FILE, sessions);
  log(`[akun ${idx + 1}] Connect X berhasil.`);
  return tokens.access_token;
}

// ================= FEATURES =================
async function doDailyClaim(token, idx) {
  const info = await tqRequest('GET', '/api/tasks/daily-claim', { token });
  const verify = await tqRequest('POST', '/api/me/tasks/verify', { token }, { body: { taskId: 'daily-claim' } });
  log(`[akun ${idx + 1}] daily-claim -> ${verify.status}`);
}

async function doQuantify(token, idx) {
  const res = await tqRequest('POST', '/api/me/quantify', { token });
  if (res.data) {
    log(`[akun ${idx + 1}] quantify -> started, finishesAt: ${res.data.finishesAt}`);
  } else {
    log(`[akun ${idx + 1}] quantify -> status ${res.status}`);
  }
}

async function doEmailAndJoin(token, idx, email) {
  if (!email) {
    log(`[akun ${idx + 1}] SKIP join-the-whitelist: email kosong (cek emails.txt)`);
    return;
  }
  await tqRequest('POST', '/api/me/email', { token }, { body: { email } });
  const verify = await tqRequest('POST', '/api/me/tasks/verify', { token }, { body: { taskId: 'join-the-whitelist' } });
  log(`[akun ${idx + 1}] join-the-whitelist -> ${verify.status}`);
}

async function doFollowXTask(token, idx) {
  // silent oauth buat follow-x task
  const urlRes = await tqRequest(
    'GET',
    `/api/me/x-follow/url?redirectUri=${encodeURIComponent(`${BASE}/auth/x/follow/callback`)}`,
    { token }
  );
  if (urlRes.data && urlRes.data.authUrl) {
    // silent:true -> biasanya auto-approve karena udah authorize sebelumnya
    // di sini kita skip actual fetch ke authUrl karena butuh cookie x per akun
    // (bisa ditambah kalau perlu, tapi task ini sering udah auto lolos verify)
  }
  const verify = await tqRequest('POST', '/api/me/tasks/verify', { token }, { body: { taskId: 'follow-x' } });
  log(`[akun ${idx + 1}] follow-x -> ${verify.status}`);
}

async function doDirectVerifyTasks(token, idx) {
  for (const taskId of DIRECT_VERIFY_TASKS) {
    if (taskId === 'join-the-whitelist' || taskId === 'follow-x') continue; // udah dihandle terpisah
    const res = await tqRequest('POST', '/api/me/tasks/verify', { token }, { body: { taskId } });
    log(`[akun ${idx + 1}] ${taskId} -> ${res.status}`);
    await sleep(500);
  }
}

async function doStartTimerTasks(token, idx) {
  const state = loadJson(STATE_FILE);
  const key = String(idx);
  state[key] = state[key] || {};

  for (const taskId of TIMER_TASKS) {
    const res = await tqRequest('POST', '/api/me/tasks/start', { token }, { body: { taskId } });
    if (res.data && res.data.readyAt) {
      state[key][taskId] = res.data.readyAt;
      log(`[akun ${idx + 1}] start ${taskId} -> readyAt ${res.data.readyAt}`);
    } else {
      log(`[akun ${idx + 1}] start ${taskId} -> status ${res.status} (mungkin udah pernah start / verified)`);
    }
    await sleep(500);
  }
  saveJson(STATE_FILE, state);
}

async function doVerifyTimerTasks(token, idx) {
  const state = loadJson(STATE_FILE);
  const key = String(idx);
  const myState = state[key] || {};

  for (const taskId of TIMER_TASKS) {
    const readyAt = myState[taskId];
    if (!readyAt) {
      log(`[akun ${idx + 1}] ${taskId} -> belum pernah di-start, skip`);
      continue;
    }
    if (new Date(readyAt) > new Date()) {
      log(`[akun ${idx + 1}] ${taskId} -> belum ready sampai ${readyAt}, skip`);
      continue;
    }
    const res = await tqRequest('POST', '/api/me/tasks/verify', { token }, { body: { taskId } });
    log(`[akun ${idx + 1}] verify ${taskId} -> ${res.status}`);
    await sleep(500);
  }
}

async function doFollowTargets(account, idx) {
  const { auth_token, ct0 } = account;
  // ambil user id sendiri
  const meRes = await xRequest('GET', 'https://x.com/i/api/1.1/account/settings.json', { auth_token, ct0 });
  if (meRes.status !== 200) {
    log(`[akun ${idx + 1}] follow: gagal ambil sesi X (${meRes.status})`);
    return;
  }

  for (const username of FOLLOW_TARGETS) {
    const res = await xRequest(
      'POST',
      `https://x.com/i/api/1.1/friendships/create.json?screen_name=${username}`,
      { auth_token, ct0 },
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    log(`[akun ${idx + 1}] follow @${username} -> ${res.status}`);
    await sleep(800);
  }
}

// ================= INTERACTIVE PROMPT =================
function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function promptMenu() {
  console.log('\n=== TryQuant Bot ===\n');
  console.log('Pilih mode:');
  console.log('  1. all       (connect X, daily, quantify, semua task)');
  console.log('  2. verify    (verify task yang ada timer)');
  console.log('  3. daily     (daily claim doang)');
  console.log('  4. quantify  (quantify doang)');
  console.log('  5. follow    (follow akun X target)');
  const modeChoice = await ask('\nPilih (1-5): ');
  const modeMap = { 1: 'all', 2: 'verify', 3: 'daily', 4: 'quantify', 5: 'follow' };
  const mode = modeMap[modeChoice];
  if (!mode) {
    console.log('Pilihan tidak valid.');
    process.exit(1);
  }

  console.log('\nPilih akun:');
  console.log('  1. Semua akun');
  console.log('  2. 1 akun (pilih index)');
  console.log('  3. Dari index tertentu sampai akhir');
  const scopeChoice = await ask('\nPilih (1-3): ');

  let scopeArg;
  if (scopeChoice === '1') {
    scopeArg = 'all';
  } else if (scopeChoice === '2') {
    const idx = await ask('Index akun (mulai dari 1): ');
    scopeArg = `1:${idx}`;
  } else if (scopeChoice === '3') {
    const idx = await ask('Mulai dari index (mulai dari 1): ');
    scopeArg = `from:${idx}`;
  } else {
    console.log('Pilihan tidak valid.');
    process.exit(1);
  }

  return { mode, scopeArg };
}

// ================= MAIN =================
async function runAccount(account, idx, mode, email) {
  try {
    const token = await getOrCreateSession(account, idx);

    if (mode === 'follow') {
      await doFollowTargets(account, idx);
      return;
    }

    if (mode === 'daily') {
      await doDailyClaim(token, idx);
      return;
    }

    if (mode === 'quantify') {
      await doQuantify(token, idx);
      return;
    }

    if (mode === 'verify') {
      await doVerifyTimerTasks(token, idx);
      return;
    }

    if (mode === 'all') {
      await doDailyClaim(token, idx);
      await doQuantify(token, idx);
      await doEmailAndJoin(token, idx, email);
      await doFollowXTask(token, idx);
      await doDirectVerifyTasks(token, idx);
      await doStartTimerTasks(token, idx);
      return;
    }

    throw new Error(`Mode tidak dikenal: ${mode}`);
  } catch (err) {
    log(`[akun ${idx + 1}] ERROR: ${err.message}`);
  }
}

async function main() {
  let [, , mode, scopeArg] = process.argv;

  // Kalau dijalankan tanpa argumen (npm start / node tryquant.js), munculin menu interaktif
  if (!mode || !scopeArg) {
    const answer = await promptMenu();
    mode = answer.mode;
    scopeArg = answer.scopeArg;
  }

  const accounts = readAccounts();
  const emails = readEmails();
  const indices = parseScope(scopeArg, accounts.length);

  log(`Mode: ${mode} | Total akun diproses: ${indices.length}/${accounts.length}`);

  for (const idx of indices) {
    await runAccount(accounts[idx], idx, mode, emails[idx]);
    await sleep(1000);
  }

  log('Selesai.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
