/**
 * DAISUKE先生から逃げる — アカウント（パスワードで引き継ぎ）用サーバー
 * Google スプレッドシートの「拡張機能 → Apps Script」に貼りつけて、ウェブアプリとしてデプロイする。
 *
 * 安全のために：
 *  - パスワードはそのまま保存しない（ユーザーごとのソルト＋HMAC-SHA256 を何千回もくり返したハッシュだけを保存）
 *  - ログインした端末ごとにトークンを発行し、シートにはトークンのハッシュだけを保存（端末6台まで）
 *  - 同じ名前で5回まちがえると10分ロック、同じ端末からの連続アクセスも制限
 *  - シートには「書式なしテキスト」で書くので、= で始まる名前が数式として動くことはない
 */
const SHEET = 'accounts';
const COLS = ['key', 'name', 'salt', 'hash', 'iter', 'data', 'updated', 'created', 'tokens'];
const MAX_TOKENS = 6;                    // 同時にログインしておける端末の数
const ITER = 2000;                       // ハッシュをくり返す回数
const TOKEN_DAYS = 180;                  // ログインしたままでいられる日数
const MAX_FAILS = 5, LOCK_MIN = 10;      // パスワードを5回まちがえたら10分ロック
const MAX_DATA = 45000;                  // セーブデータの最大文字数（セル1つに入る大きさ）

function doGet() { return out({ ok: true, app: 'daisuke-chase', v: 1 }); }

function doPost(e) {
  let req;
  try { req = JSON.parse(e.postData.contents); } catch (err) { return out({ ok: false, err: 'bad' }); }
  if (!req || typeof req !== 'object') return out({ ok: false, err: 'bad' });
  const a = String(req.a || '');
  const name = cleanName(req.name);
  if (!name) return out({ ok: false, err: 'name' });
  const key = keyOf(name);
  const cache = CacheService.getScriptCache();
  // あまりに多いアクセスは止める（同じ名前あてに1分30回まで）
  const rk = 'r:' + digestHex(key), rc = (+cache.get(rk) || 0) + 1;
  cache.put(rk, String(rc), 60);
  if (rc > 30) return out({ ok: false, err: 'busy' });

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return out({ ok: false, err: 'busy' });
  try {
    const sh = sheet();
    const row = findRow(sh, key);
    const rec = row ? readRow(sh, row) : null;
    if (rec) rec.key = key;

    if (a === 'register') {
      const pass = String(req.pass || '');
      if (!okPass(pass, name)) return out({ ok: false, err: 'pass' });
      if (rec) return out({ ok: false, err: 'taken' });
      const data = cleanData(req.data); if (data === null) return out({ ok: false, err: 'data' });
      const salt = Utilities.getUuid(), now = Date.now(), tok = newToken();
      const rec2 = { key: key, name: name, salt: salt, hash: hashPass(pass, salt, ITER), iter: ITER, data: data, updated: now, created: now, tokens: [] };
      addToken(rec2, tok); writeRow(sh, null, rec2);
      return out({ ok: true, token: tok, updated: now });
    }

    if (a === 'login') {
      const pass = String(req.pass || '');
      const fk = 'f:' + digestHex(key), fails = +cache.get(fk) || 0;
      if (fails >= MAX_FAILS) return out({ ok: false, err: 'locked' });
      if (!rec) return out({ ok: false, err: 'noname' });
      if (!same(hashPass(pass, rec.salt, +rec.iter || ITER), rec.hash)) {
        cache.put(fk, String(fails + 1), LOCK_MIN * 60);
        return out({ ok: false, err: fails + 1 >= MAX_FAILS ? 'locked' : 'wrong' });
      }
      cache.remove(fk);
      const tok = newToken(), now = Date.now();
      addToken(rec, tok); writeRow(sh, row, rec);
      return out({ ok: true, token: tok, name: rec.name, data: rec.data, updated: +rec.updated });
    }

    // ここから下はログイン済み（トークンが必要）
    if (!rec || !okToken(rec, req.token)) return out({ ok: false, err: 'auth' });

    if (a === 'load') return out({ ok: true, name: rec.name, data: rec.data, updated: +rec.updated });

    if (a === 'save') {
      const data = cleanData(req.data); if (data === null) return out({ ok: false, err: 'data' });
      // ほかの端末があとから保存していたら上書きしない（その端末のデータを返す）
      if (req.base && +rec.updated > +req.base) return out({ ok: false, err: 'conflict', data: rec.data, updated: +rec.updated });
      rec.data = data; rec.updated = Date.now();
      writeRow(sh, row, rec);
      return out({ ok: true, updated: rec.updated });
    }

    if (a === 'setpass') {
      const pass = String(req.pass || '');
      if (!okPass(pass, name)) return out({ ok: false, err: 'pass' });
      rec.salt = Utilities.getUuid(); rec.iter = ITER; rec.hash = hashPass(pass, rec.salt, ITER);
      const tok = newToken(); rec.tokens = []; addToken(rec, tok);   // ほかの端末はログアウトされる
      writeRow(sh, row, rec);
      return out({ ok: true, token: tok });
    }

    if (a === 'logout') { const h = digestHex(String(req.token)); rec.tokens = rec.tokens.filter(t => !same(t.h, h)); writeRow(sh, row, rec); return out({ ok: true }); }

    return out({ ok: false, err: 'bad' });
  } finally { lock.releaseLock(); }
}

// ---------------------------------------------------------------- helpers
function out(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
function cleanName(n) {
  if (typeof n !== 'string') return '';
  n = n.normalize('NFKC').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().replace(/^[=+\-@]+/, '');   // 数式に見える頭文字は消す
  return n.length >= 1 && n.length <= 10 ? n : '';
}
function keyOf(name) { return name.normalize('NFKC').toLowerCase(); }
function okPass(p, name) { return typeof p === 'string' && p.length >= 6 && p.length <= 64 && keyOf(p) !== keyOf(name); }
function cleanData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const s = JSON.stringify(d);
  return s.length <= MAX_DATA ? s : null;
}
function newToken() { return Utilities.getUuid() + Utilities.getUuid(); }
function okToken(rec, tok) {
  if (typeof tok !== 'string' || tok.length < 20) return false;
  const h = digestHex(tok), now = Date.now();
  return rec.tokens.some(t => t.e > now && same(t.h, h));
}
function addToken(rec, tok) {
  const now = Date.now();
  rec.tokens = rec.tokens.filter(t => t.e > now).slice(-(MAX_TOKENS - 1));
  rec.tokens.push({ h: digestHex(tok), e: now + TOKEN_DAYS * 864e5 });
}
function hex(bytes) { return bytes.map(b => ('0' + (b & 255).toString(16)).slice(-2)).join(''); }
function digestHex(s) { return hex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8)); }
function hashPass(pass, salt, iter) {   // PBKDF2 と同じ考え方：HMAC をくり返して計算に時間をかける
  let h = Utilities.computeHmacSha256Signature(salt, pass, Utilities.Charset.UTF_8);
  let acc = h.slice();
  for (let i = 1; i < iter; i++) { h = Utilities.computeHmacSha256Signature(h, Utilities.newBlob(pass).getBytes()); for (let j = 0; j < acc.length; j++) acc[j] ^= h[j]; }
  return hex(acc);
}
function same(a, b) {   // 比べる時間で中身が分からないように
  a = String(a); b = String(b); if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}
function sheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(SHEET);
  if (!sh) {
    sh = ss.insertSheet(SHEET);
    sh.getRange(1, 1, 1000, COLS.length).setNumberFormat('@');   // すべて文字として保存（数式にならない）
    sh.getRange(1, 1, 1, COLS.length).setValues([COLS]); sh.setFrozenRows(1);
  }
  return sh;
}
function findRow(sh, key) {
  const n = sh.getLastRow(); if (n < 2) return 0;
  const keys = sh.getRange(2, 1, n - 1, 1).getValues();
  for (let i = 0; i < keys.length; i++) if (String(keys[i][0]) === key) return i + 2;
  return 0;
}
function readRow(sh, row) {
  const v = sh.getRange(row, 1, 1, COLS.length).getValues()[0], o = {};
  COLS.forEach((c, i) => o[c] = v[i]);
  try { o.data = JSON.parse(o.data || '{}'); } catch (e) { o.data = {}; }
  try { o.tokens = JSON.parse(o.tokens || '[]'); if (!Array.isArray(o.tokens)) o.tokens = []; } catch (e) { o.tokens = []; }
  return o;
}
function writeRow(sh, row, o) {
  const vals = COLS.map(c => c === 'data' ? (typeof o.data === 'string' ? o.data : JSON.stringify(o.data || {})) : c === 'tokens' ? JSON.stringify(o.tokens || []) : String(o[c] ?? ''));
  if (!row) row = sh.getLastRow() + 1;
  const rg = sh.getRange(row, 1, 1, COLS.length); rg.setNumberFormat('@'); rg.setValues([vals]);
}

/** はじめに1回だけ、エディタ上で実行して「承認」しておくと、デプロイがスムーズになる */
function setup() { sheet(); Logger.log('OK: シート「' + SHEET + '」を準備しました'); }
