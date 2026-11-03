/* bphotosx.com: the web face of bPics. Private by default (owner, 2 Nov 2026).

   One photo = one transaction, two outputs, both 1 sat:
     0. a blurred preview, image/jpeg, to a key bWalletX hands out ([1,'bwalletx ordinal receive']) in basket '1sat'.
        It shows in Wallet › NFTs, can be sent, and a seed restore finds it. Format follows bWalletX
        src/services/siteTokens.ts readImageInscription: OP_0 OP_IF "ord" OP_1 <type> OP_0 <body> OP_ENDIF + P2PKH,
        nothing else (no MAP), at most 1 MB.
     1. the sealed original, in this site's own basket 'bphotosx', locked to this wallet's one vault key
        ([1,'bphotosx photo'], keyID 'vault'), so a seed restore can find every sealed photo by that address.
   Sealing: a fresh AES-256-GCM key per photo, made and used in this browser; only that 32-byte key goes to the
   wallet, which encrypts it to itself (BRC-2, [1,'bphotosx photo'], keyID = the photo id). The photo never
   leaves this device unencrypted. Sizing matches bPics (bwalletX src/mobile/bpics/bpics.ts): 1600 px, JPEG 0.85.
   Needs @bwalletx/connect's global build (window.bWalletXConnect) and the @bsv/sdk UMD build (window.bsv). */
(() => {
  const C = window.bWalletXConnect;
  const B = window.bsv;
  const $ = (id) => document.getElementById(id);

  const PROTO = [1, 'bphotosx photo'];
  const ORDINAL_RECEIVE = [1, 'bwalletx ordinal receive'];
  const BASKET = 'bphotosx';
  const VAULT_KEY = 'vault';
  const SEALED_TYPE = 'application/vnd.bphotosx.sealed';
  const MAGIC = [0x42, 0x50, 0x58, 0x31]; // "BPX1"
  const MAX_EDGE = 1600, QUALITY = 0.85;
  const PREVIEW_EDGE = 480, PREVIEW_QUALITY = 0.7;
  const PREVIEW_GUESS = 15_000; // bytes, for the fee quote before a fetched photo's preview is made
  const MAX_SEALED_BYTES = 2_000_000;
  const FEE_SAT_PER_BYTE = 0.1; // 100 sat/kB, the bMintX / NPG rate (bMarketX lib/mint.js)
  const SEEN = 'bphotosx.connected';
  // Off until bWalletX handles big inscription txs on iPhone (bwalletx-x-25, 2 Nov 2026: the address sync and
  // internalizeBeef unpack whole source txs at ~40x their size, and 200-700 KB inscriptions get the web view killed).
  // `?mint=test` turns it on for this tab on a local preview only, for desktop testing.
  const MINTING_OPEN = false;
  const mintTest = /^(127\.0\.0\.1|localhost)$/.test(location.hostname) && new URLSearchParams(location.search).get('mint') === 'test';
  const canMint = MINTING_OPEN || mintTest;

  const enc = (s) => new TextEncoder().encode(s);
  const toHex = (a) => Array.from(a, (x) => x.toString(16).padStart(2, '0')).join('');
  const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const short = (k) => k.slice(0, 6) + '…' + k.slice(-4);
  const remember = (on) => { try { on ? localStorage.setItem(SEEN, '1') : localStorage.removeItem(SEEN); } catch {} };
  const remembered = () => { try { return localStorage.getItem(SEEN) === '1'; } catch { return false; } };

  /* ---------- scripts ---------- */

  function push(b) {
    const n = b.length;
    if (n < 0x4c) return [n, ...b];
    if (n <= 0xff) return [0x4c, n, ...b];
    if (n <= 0xffff) return [0x4d, n & 0xff, n >> 8, ...b];
    return [0x4e, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >>> 24, ...b];
  }
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const p2pkh = (pubHex) => [0x76, 0xa9, 0x14, ...B.Hash.hash160(B.Utils.toArray(pubHex, 'hex')), 0x88, 0xac];
  // Spread-free for big bodies: a 1 MB photo would overflow the call stack as function arguments.
  const inscription = (type, body, pubHex) => toHex(concat(
    Uint8Array.from([0x00, 0x63, ...push(enc('ord')), 0x51, ...push(enc(type)), 0x00]),
    Uint8Array.from(pushHeader(body.length)), body,
    Uint8Array.from([0x68, ...p2pkh(pubHex)]),
  ));
  function pushHeader(n) {
    if (n < 0x4c) return [n];
    if (n <= 0xff) return [0x4c, n];
    if (n <= 0xffff) return [0x4d, n & 0xff, n >> 8];
    return [0x4e, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >>> 24];
  }
  /** Content type and body of an ord envelope anywhere in a locking script, or null. */
  function readInscription(hex) {
    try {
      const ch = B.Script.fromHex(hex).chunks;
      const i = ch.findIndex((c, k) => c.op === 0 && ch[k + 1]?.op === 0x63 && ch[k + 2]?.data && B.Utils.toUTF8(ch[k + 2].data) === 'ord');
      if (i < 0) return null;
      let type = '', body = null;
      for (let k = i + 3; k < ch.length && ch[k].op !== 0x68; k++) {
        if (ch[k].op === 0x51) type = B.Utils.toUTF8(ch[++k]?.data ?? []);
        else if (ch[k].op === 0 && !ch[k].data) body = Uint8Array.from(ch[++k]?.data ?? []);
      }
      return body ? { type, body } : null;
    } catch { return null; }
  }

  /* ---------- images ---------- */

  async function decode(file) {
    try { return await createImageBitmap(file, { imageOrientation: 'from-image' }); } catch {}
    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      img.src = url;
      await img.decode();
      return img;
    } catch {
      throw new Error('This browser can’t open that file as a photo.');
    } finally { URL.revokeObjectURL(url); }
  }
  const canvas = (w, h) => { const c = document.createElement('canvas'); c.width = w; c.height = h; return c; };
  const fit = (w, h, edge) => { const s = Math.min(1, edge / Math.max(w, h)); return [Math.max(1, Math.round(w * s)), Math.max(1, Math.round(h * s))]; };
  const jpeg = (c, q) => new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error('Couldn’t encode the photo.'))), 'image/jpeg', q));

  /** Re-encoded JPEG (drops EXIF, so GPS goes too) and a blurred preview: pixelate down, smooth back up, blur. */
  async function prepare(file) {
    const src = await decode(file);
    const [w, h] = fit(src.width, src.height, MAX_EDGE);
    const full = canvas(w, h);
    full.getContext('2d').drawImage(src, 0, 0, w, h);
    src.close?.();
    const [photo, preview] = await Promise.all([jpeg(full, QUALITY), blurred(full)]);
    return { photo: new Uint8Array(await photo.arrayBuffer()), preview, w, h };
  }

  async function blurred(img) {
    const { width: w, height: h } = img;
    const [pw, ph] = fit(w, h, PREVIEW_EDGE);
    const [tw, th] = fit(w, h, 24);
    const tiny = canvas(tw, th);
    tiny.getContext('2d').drawImage(img, 0, 0, tw, th);
    const prev = canvas(pw, ph);
    const g = prev.getContext('2d');
    g.imageSmoothingEnabled = true;
    g.imageSmoothingQuality = 'high';
    if ('filter' in g) g.filter = 'blur(6px)';
    g.drawImage(tiny, -8, -8, pw + 16, ph + 16);
    return new Uint8Array(await (await jpeg(prev, PREVIEW_QUALITY)).arrayBuffer());
  }

  /* ---------- sealing ---------- */
  // Sealed body: "BPX1" | idLen u8 | id | wrapLen u16 BE | wrapped key | iv (12) | AES-GCM(metaLen u32 BE | meta JSON | JPEG)

  const u16 = (n) => [n >> 8, n & 0xff];
  const u32 = (n) => [n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];

  async function seal(wallet, id, meta, photo) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const m = enc(JSON.stringify(meta));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, concat(Uint8Array.from(u32(m.length)), m, photo)));
    const { ciphertext } = await wallet.encrypt({ plaintext: Array.from(raw), protocolID: PROTO, keyID: id, counterparty: 'self' });
    raw.fill(0);
    const idb = enc(id), wrap = Uint8Array.from(ciphertext);
    return concat(Uint8Array.from(MAGIC), Uint8Array.from([idb.length]), idb, Uint8Array.from(u16(wrap.length)), wrap, iv, ct);
  }

  async function unseal(wallet, body) {
    if (MAGIC.some((b, i) => body[i] !== b)) throw new Error('Not a bPhotosX photo');
    let o = 4;
    const idLen = body[o++];
    const id = new TextDecoder().decode(body.subarray(o, o + idLen)); o += idLen;
    const wrapLen = (body[o] << 8) | body[o + 1]; o += 2;
    const wrap = body.subarray(o, o + wrapLen); o += wrapLen;
    const iv = body.subarray(o, o + 12); o += 12;
    const { plaintext } = await wallet.decrypt({ ciphertext: Array.from(wrap), protocolID: PROTO, keyID: id, counterparty: 'self' });
    const key = await crypto.subtle.importKey('raw', Uint8Array.from(plaintext), 'AES-GCM', false, ['decrypt']);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, body.subarray(o)));
    const mLen = ((pt[0] << 24) | (pt[1] << 16) | (pt[2] << 8) | pt[3]) >>> 0;
    const meta = JSON.parse(new TextDecoder().decode(pt.subarray(4, 4 + mLen)));
    return { id, meta, blob: new Blob([pt.subarray(4 + mLen)], { type: meta.type || 'image/jpeg' }) };
  }

  /* ---------- upload and mint ---------- */
  // Two steps on purpose (owner, 2 Nov 2026): people know "upload"; minting is new, costs a fee and is permanent.
  // Upload seals the photo and keeps it in this browser (IndexedDB, ciphertext only) until bDriveX can hold the library.
  // Mint takes one uploaded photo on chain: the blurred preview to Wallet › NFTs, the sealed original to this basket.

  const quoteSats = (bytes) => Math.ceil((bytes + 600) * FEE_SAT_PER_BYTE + 2);

  async function upload(wallet, file, onStep, src) {
    onStep('Preparing');
    // src: sha256 of the original file, so importing the same photo again is skipped. Sealed in meta, and on this device.
    src = src || await sha256(await file.arrayBuffer());
    const { photo, preview, w, h } = await prepare(file);
    const id = toHex(crypto.getRandomValues(new Uint8Array(8)));
    const name = (file.name || 'Photo').replace(/\.[^.]+$/, '').slice(0, 100) || 'Photo';
    const addedAt = new Date().toISOString();
    onStep('Sealing with your wallet');
    const sealed = await seal(wallet, id, { v: 1, name, type: 'image/jpeg', w, h, addedAt, src }, photo);
    if (sealed.length > MAX_SEALED_BYTES) throw new Error('That photo is too big.');
    const item = { key: `${identity}:${id}`, identity, id, name, addedAt, sealed, preview, src };
    await store.put(item);
    if (syncing) await syncing; // signing in to bDriveX right now: wait for its answer
    if (drive.state === 'on') {
      onStep('Saving to bDriveX');
      // If bDriveX can't take it now, it stays on this device and moves in on the next visit.
      await driveKeep(item).catch(() => {});
    }
    return item;
  }

  async function mintPhoto(wallet, item, onStep, photoUrl) {
    const { sealed, id } = item;
    const name = item.name || 'Photo';
    // A photo fetched from bDriveX has no preview on this device yet: blur one from the opened photo.
    const preview = item.preview || await blurred(await decode(await (await fetch(photoUrl)).blob()));
    const ord = await wallet.getPublicKey({ protocolID: ORDINAL_RECEIVE, keyID: 'ordinal', counterparty: 'self' });
    const vault = await wallet.getPublicKey({ protocolID: PROTO, keyID: VAULT_KEY, counterparty: 'self' });
    onStep(`Approve in bWalletX (about ${quoteSats(preview.length + sealed.length).toLocaleString()} sats)`);
    const { txid } = await wallet.createAction({
      description: `Mint a private photo: ${name}`.slice(0, 50),
      outputs: [
        {
          lockingScript: inscription('image/jpeg', preview, ord.publicKey), satoshis: 1, basket: '1sat',
          customInstructions: JSON.stringify({ keyID: ord.keyID || 'ordinal' }), outputDescription: `bPhotosX preview: ${name}`.slice(0, 120),
        },
        {
          lockingScript: inscription(SEALED_TYPE, sealed, vault.publicKey), satoshis: 1, basket: BASKET, tags: ['sealed'],
          customInstructions: JSON.stringify({ protocolID: PROTO, keyID: VAULT_KEY, counterparty: 'self', id }),
          outputDescription: `bPhotosX sealed photo: ${name}`.slice(0, 120),
        },
      ],
      options: { randomizeOutputs: false },
    });
    if (!txid) throw new Error('bWalletX didn’t return a transaction.');
    await store.put({ ...item, preview, txid });
    return txid;
  }

  /* ---------- this device's library (IndexedDB, sealed photos only) ---------- */

  const store = (() => {
    let dbp = null;
    const db = () => dbp || (dbp = new Promise((res, rej) => {
      const r = indexedDB.open('bphotosx', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('photos', { keyPath: 'key' }).createIndex('identity', 'identity');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    }));
    const tx = async (mode, fn) => {
      const d = await db();
      return new Promise((res, rej) => {
        const t = d.transaction('photos', mode), req = fn(t.objectStore('photos'));
        t.oncomplete = () => res(req && req.result);
        t.onerror = t.onabort = () => rej(t.error || new Error('This browser couldn’t save the photo.'));
      });
    };
    return {
      put: (item) => tx('readwrite', (s) => s.put(item)),
      del: (key) => tx('readwrite', (s) => s.delete(key)),
      mine: (who) => tx('readonly', (s) => s.index('identity').getAll(who)).catch(() => []),
    };
  })();

  /* ---------- bDriveX: the same library on every device ---------- */
  // Sealed bodies go to bDriveX as they are (opaque ciphertext, addressed by sha256) and are labelled DRIVE_LABEL so
  // bDriveX's own file list can tell photos from files. Sign-in is bDriveX's challenge signed by this wallet (one
  // approval); the token is tied to this site and lasts 7 days. bDriveX is invite-only for now: a wallet that isn't on
  // its list keeps its photos on this device, as before. IndexedDB stays as this device's copy of the library.

  const DRIVE = /^(127\.0\.0\.1|localhost)$/.test(location.hostname) ? 'http://127.0.0.1:8788' : 'https://files.bdrivex.com';
  const DRIVE_LABEL = 'bpx1';
  const drive = { token: null, until: 0, state: 'off', why: '' }; // state: off | on | invite | declined | down
  const driveSaved = () => `bphotosx.drive:${identity}`;

  class DriveError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
  async function driveCall(path, { method = 'GET', body, headers = {}, raw = false, auth = true } = {}) {
    let r;
    try {
      r = await fetch(DRIVE + path, { method, body, headers: { ...headers, ...(auth ? { authorization: `Bearer ${drive.token}` } : {}) } });
    } catch { throw new DriveError(0, 'bDriveX can’t be reached right now.'); }
    if (!r.ok) {
      const j = await r.json().catch(() => null);
      throw new DriveError(r.status, j?.error || `bDriveX answered ${r.status}.`);
    }
    if (raw) return r;
    return r.status === 204 ? null : r.json();
  }
  const drivePost = (path, obj) => driveCall(path, { method: 'POST', body: JSON.stringify(obj), headers: { 'content-type': 'application/json' }, auth: false });
  function driveForget() {
    drive.token = null;
    drive.until = 0;
    try { localStorage.removeItem(driveSaved()); } catch {}
  }

  /** This wallet's saved bDriveX session, if it has one that isn't about to end. */
  function driveRestore() {
    if (drive.token && drive.until > Date.now() + 60_000) return true;
    try {
      const s = JSON.parse(localStorage.getItem(driveSaved()) || 'null');
      if (s && s.until > Date.now() + 60_000) { drive.token = s.token; drive.until = s.until; return true; }
    } catch {}
    return false;
  }

  /** A bDriveX session for this wallet: the saved one, or a new one the wallet signs. */
  async function driveSignIn() {
    if (driveRestore()) return;
    const who = identity;
    const c = await drivePost('/v1/auth/challenge', { identityKey: who }).catch((e) => {
      throw e.status === 403 ? new DriveError(0, 'bDriveX isn’t open to bPhotosX yet.') : e;
    });
    const { signature } = await wallet.createSignature({
      protocolID: c.protocolID || [2, 'bwallet sign in'], keyID: c.keyID, counterparty: 'anyone', data: Array.from(enc(c.message)),
    });
    const v = await drivePost('/v1/auth/verify', { identityKey: who, nonce: c.nonce, signature: Array.from(signature) });
    if (v.scope && v.scope !== 'full') {
      // Invited only to open a file someone sent this wallet: that session can't keep photos.
      fetch(`${DRIVE}/v1/auth/signout`, { method: 'POST', headers: { authorization: `Bearer ${v.token}` } }).catch(() => {});
      throw new DriveError(403, 'bDriveX is invite-only for now.');
    }
    if (who !== identity) throw new DriveError(0, 'The wallet changed.');
    drive.token = v.token;
    drive.until = v.expiresAt;
    try { localStorage.setItem(driveSaved(), JSON.stringify({ token: v.token, until: v.expiresAt })); } catch {}
  }

  /** A call with the session; a 401 (signed out elsewhere, or expired) signs in again once. */
  async function authed(fn) {
    await driveSignIn();
    try { return await fn(); } catch (e) {
      if (!(e instanceof DriveError) || e.status !== 401) throw e;
      driveForget();
      await driveSignIn();
      return fn();
    }
  }
  const sha256 = async (b) => toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', b)));
  const driveList = async () => ((await authed(() => driveCall('/v1/files'))).files || []).filter((f) => f.meta === DRIVE_LABEL);
  const driveGet = async (hash) => new Uint8Array(await (await authed(() => driveCall(`/v1/blobs/${hash}`, { raw: true }))).arrayBuffer());
  const driveDelete = (hash) => authed(() => driveCall(`/v1/files/${hash}`, { method: 'DELETE' }));
  async function driveKeep(item) {
    const hash = await sha256(item.sealed);
    await authed(() => driveCall(`/v1/blobs/${hash}`, {
      method: 'PUT', body: item.sealed, headers: { 'content-type': 'application/octet-stream', 'x-bdx-meta': DRIVE_LABEL },
    }));
    item.drive = hash;
    await store.put(item);
    if (drive.usage) drive.usage.bytes = (drive.usage.bytes || 0) + item.sealed.length;
  }

  /* ---------- wallet and account ---------- */

  let wallet = null, identity = null, displayName = '';
  const STATUS = { finding: 'Opening your wallet…', opening: 'Approve in bWalletX…', signing: 'Approve in bWalletX…', pairing: 'Scan the QR…' };
  const connectButtons = () => [$('navBtn'), $('heroBtn'), $('libBtn')];
  const label = (t) => connectButtons().forEach((b) => { b.textContent = t; });
  const PAYMAIL_API = 'https://pay.bwallet.space/api/paymail/lookup';
  const flag = (k, v) => { try { if (v === undefined) return localStorage.getItem(k) === '1'; localStorage.setItem(k, '1'); } catch {} return false; };

  async function lookupName(key) {
    try {
      const r = await fetch(`${PAYMAIL_API}?key=${encodeURIComponent(key)}`);
      const j = r.ok ? await r.json() : null;
      return typeof j?.paymail === 'string' ? j.paymail : '';
    } catch { return ''; }
  }

  function toast(text) {
    const t = $('toast');
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toast.t);
    toast.t = setTimeout(() => { t.hidden = true; }, 4200);
  }

  function drawNav() {
    const on = !!identity;
    document.body.classList.toggle('signed-in', on);
    route();
    $('navBtn').hidden = on;
    $('acct').hidden = !on;
    $('navBtn').textContent = 'Connect bWalletX';
    $('heroBtn').textContent = 'Open your library';
    $('libBtn').textContent = 'Connect bWalletX';
    $('out').hidden = on;
    $('libHead').hidden = on;
    $('in').hidden = !on;
    if (on) {
      const name = displayName || short(identity);
      $('acctName').textContent = name;
      $('libName').textContent = name;
      $('acctAv').textContent = $('libAv').textContent = (displayName ? displayName[0] : 'b').toUpperCase();
      $('acctKey').textContent = short(identity);
      $('acctKey').title = identity;
    }
    menu(false);
  }

  // Two views while signed in: the front page (logo, "/") and your library ("#library").
  const inLibrary = () => !!identity && location.hash === '#library';
  function route() { document.body.classList.toggle('app-view', inLibrary()); }
  function goLibrary() {
    if (location.hash !== '#library') history.pushState(null, '', '#library');
    route();
    scrollTo({ top: 0 });
  }
  function goHome() {
    if (location.hash) history.pushState(null, '', location.pathname + location.search);
    route();
    scrollTo({ top: 0 });
  }
  addEventListener('popstate', route);
  addEventListener('hashchange', route);
  document.querySelectorAll('a.xs-brand, .foot a.brand').forEach((a) => a.addEventListener('click', (e) => {
    if (!identity) return;
    e.preventDefault();
    goHome();
  }));

  const menu = (open) => {
    $('acctMenu').hidden = !open;
    $('acctBtn').setAttribute('aria-expanded', open ? 'true' : 'false');
  };
  $('acctBtn').onclick = (e) => { e.stopPropagation(); menu($('acctMenu').hidden); };
  document.addEventListener('click', (e) => { if (!e.target.closest('#acct')) menu(false); });
  $('menuLib').onclick = (e) => { e.preventDefault(); menu(false); goLibrary(); };
  $('disconnectBtn').onclick = () => disconnect();

  // Before the wallet opens the first time: say what it will ask, and why.
  function explainFirst() {
    if (flag('bphotosx.explained')) return Promise.resolve(true);
    return new Promise((res) => {
      const sh = $('connectSheet');
      sh.hidden = false;
      $('sheetGo').focus();
      const done = (ok) => { sh.hidden = true; if (ok) flag('bphotosx.explained', true); res(ok); };
      $('sheetGo').onclick = () => done(true);
      $('sheetNo').onclick = () => done(false);
      sh.onclick = (e) => { if (e.target === sh) done(false); };
    });
  }

  async function connect(quiet) {
    const err = $('connErr');
    err.hidden = true;
    if (!quiet && !(await explainFirst())) return;
    const modal = quiet ? null : C.pairingModal?.({ title: 'Connect bWalletX' });
    try {
      const r = await C.connectBwalletX({
        ...(modal ? { pairing: modal } : {}),
        onStatus: quiet ? undefined : (st) => STATUS[st] && label(STATUS[st]),
      });
      wallet = r.wallet;
      identity = (await wallet.getPublicKey({ identityKey: true })).publicKey;
      remember(true);
      displayName = '';
      drawNav();
      lookupName(identity).then((n) => { if (n && identity) { displayName = n; drawNav(); } });
      loadPhotos().then(() => syncDrive());
      // Coming back signed in: open on your account, not the front page (the logo still goes there).
      if (quiet && !location.hash) { history.replaceState(null, '', '#library'); route(); }
      if (!quiet) {
        goLibrary();
        toast('Signed in with bWalletX. This is your private library.');
      }
    } catch (e) {
      wallet = identity = null;
      if (!quiet) {
        err.innerHTML = e && e.code === 'NOT_FOUND'
          ? 'No bWalletX found on this device. <a href="https://bwalletx.com/get">Get bWalletX</a>, or open bphotosx.com inside the bWalletX app.'
          : esc((e && e.message) || 'That didn’t work. Try again.');
        err.hidden = false;
      }
      drawNav();
    } finally { modal?.close(); }
  }
  function disconnect() {
    try { C.clearPairing?.(); } catch {}
    remember(false);
    // End the bDriveX session too. Sealed copies stay on this device, and only this wallet can open them.
    if (drive.token) fetch(`${DRIVE}/v1/auth/signout`, { method: 'POST', headers: { authorization: `Bearer ${drive.token}` } }).catch(() => {});
    if (identity) driveForget();
    Object.assign(drive, { state: 'off', why: '' });
    wallet = identity = null;
    displayName = '';
    urls.forEach((u) => URL.revokeObjectURL(u.url));
    urls.clear();
    shown = [];
    $('grid').innerHTML = '';
    $('jobs').innerHTML = '';
    closePhoto();
    if (location.hash) history.replaceState(null, '', location.pathname + location.search);
    drawNav();
    scrollTo({ top: 0 });
    toast('Disconnected. Your photos stay sealed.');
  }

  /* ---------- library ---------- */

  const urls = new Map(); // photo id -> { url, meta } of the opened photo (memory only, never stored)
  let loadSeq = 0, shown = [];

  /** The photo id from a sealed body's header (plaintext there, reveals nothing), or null. */
  function sealedId(body) {
    if (!body || MAGIC.some((b, i) => body[i] !== b)) return null;
    return new TextDecoder().decode(body.subarray(5, 5 + body[4]));
  }

  const emptyState = () =>
    `<label class="empty-drop" for="pick">${$('addBtn').querySelector('svg').outerHTML}<b>Upload your first photos</b>` +
    '<span>Drop them anywhere on this page, or tap here to choose. They’re encrypted with your wallet, and only you can open them.</span></label>';

  async function loadPhotos() {
    const seq = ++loadSeq;
    const grid = $('grid');
    // Uploaded on this device, plus anything minted (also found when uploaded elsewhere), one entry per photo id.
    const byId = new Map();
    for (const it of await store.mine(identity)) byId.set(it.id, { id: it.id, body: it.sealed, local: it, txid: it.txid || null, drive: it.drive || null });
    try {
      const r = await wallet.listOutputs({ basket: BASKET, include: 'locking scripts', limit: 200 });
      for (const o of r.outputs || []) {
        if (o.spendable === false) continue;
        const ins = o.lockingScript && readInscription(o.lockingScript);
        const id = ins && ins.type === SEALED_TYPE && sealedId(ins.body);
        if (!id) continue;
        const e = byId.get(id);
        const txid = String(o.outpoint).split(/[._]/)[0];
        if (e) e.txid = e.txid || txid; else byId.set(id, { id, body: ins.body, local: null, txid, drive: null });
      }
    } catch {
      // the wallet can refuse a listing; this device's uploads still show
    }
    if (seq !== loadSeq) return;
    shown = [...byId.values()].sort((a, b) => String(b.local?.addedAt || '').localeCompare(String(a.local?.addedAt || '')));
    drawCount();
    grid.innerHTML = '';
    if (!shown.length) { grid.innerHTML = emptyState(); return; }
    const tiles = shown.map((e, i) => {
      const t = document.createElement('button');
      t.type = 'button';
      t.className = 'tile locked';
      t.innerHTML = '<span class="tile-wait">Opening…</span>';
      t.disabled = true;
      grid.appendChild(t);
      return { e, t, i };
    });
    // Two at a time: every photo is one wallet decrypt, and the phone relay allows about 60 frames a minute.
    let next = 0;
    const work = async () => {
      while (next < tiles.length && seq === loadSeq) {
        const { e, t, i } = tiles[next++];
        try {
          const { url, meta } = await opened(e);
          if (seq !== loadSeq) return;
          t.className = 'tile';
          t.disabled = false;
          t.innerHTML = `<img alt=""><span class="badge${e.txid ? ' on' : ''}">${e.txid ? 'Minted' : e.drive ? 'Private · bDriveX' : 'Private · on this device'}</span><span class="tile-nm"></span>`;
          t.querySelector('img').src = url;
          t.querySelector('img').alt = meta.name || 'Photo';
          t.querySelector('.tile-nm').textContent = meta.name || 'Photo';
          t.onclick = () => openPhoto(i);
        } catch {
          t.innerHTML = '<span class="tile-wait">Can’t open</span>';
        }
      }
    };
    await Promise.all([work(), work()]);
  }

  /** Where the library is, in the line under "Signed in as". */
  function drawCount() {
    const count = $('count'), n = shown.length;
    if (!identity) return;
    const kept = shown.filter((e) => e.drive).length, minted = shown.filter((e) => e.txid).length;
    const retry = ` <button class="lib-retry" type="button" id="driveRetry">${n ? 'Keep them in bDriveX' : 'Use bDriveX for your photos'}</button>`;
    const where = {
      on: kept === n ? 'in bDriveX, on all your devices' : `moving into bDriveX, ${kept} of ${n}`,
      signing: 'on this device · approve in bWalletX to keep them in bDriveX',
      invite: 'on this device · bDriveX is invite-only for now',
    }[drive.state] || 'on this device';
    const empty = 'No photos yet.' + ({
      on: ' New photos are kept in bDriveX, on all your devices.',
      invite: ' bDriveX is invite-only for now, so they’ll stay on this device.',
    }[drive.state] || '');
    let html = !n ? esc(empty) : esc(`${n === 1 ? '1 photo' : `${n} photos`} · private · ${where}${minted ? ` · ${minted} minted` : ''}`);
    if (drive.state === 'declined' || drive.state === 'down') {
      html += drive.why && drive.state === 'down' ? ` <span class="lib-why">(${esc(drive.why)})</span>` : '';
      html += retry;
    }
    count.innerHTML = html;
    const u = drive.state === 'on' && drive.usage;
    $('libStore').hidden = !u;
    if (u) $('libStore').textContent = `bDriveX storage: ${size(u.bytes || 0)} of ${size(u.quota || 0)} used`;
    const b = $('driveRetry');
    if (b) b.onclick = () => syncDrive(true);
  }

  /**
   * Level this device with bDriveX: fetch photos added on other devices, move this device's photos in, and drop
   * copies of photos deleted elsewhere. The first time, the wallet asks to sign in to bDriveX.
   * ask: also after a "no" earlier on this page (the retry button).
   */
  let syncing = null;
  function syncDrive(ask) {
    if (syncing) return syncing;
    if (!ask && ['declined', 'invite'].includes(drive.state)) return Promise.resolve();
    const who = identity;
    let changed = 0;
    return (syncing = (async () => {
      try {
        if (!driveRestore()) { drive.state = 'signing'; drawCount(); }
        await driveSignIn();
        if (who !== identity) return;
        drive.state = 'on';
        drive.why = '';
        drawCount();
        const remote = await driveList();
        const live = new Set(remote.map((f) => f.hash));
        let local = await store.mine(who);
        for (const it of local) {
          if (it.drive && !live.has(it.drive)) { await store.del(it.key); changed++; } // deleted on another device
        }
        local = local.filter((it) => !it.drive || live.has(it.drive));
        const held = new Set(local.map((it) => it.drive).filter(Boolean));
        for (const f of remote) {
          if (held.has(f.hash) || who !== identity) continue;
          const sealed = await driveGet(f.hash);
          const id = sealedId(sealed);
          if (!id || (await sha256(sealed)) !== f.hash) continue;
          const same = local.find((it) => it.id === id);
          if (same) { same.drive = f.hash; await store.put(same); continue; }
          const addedAt = new Date(f.createdAt || Date.now()).toISOString();
          await store.put({ key: `${who}:${id}`, identity: who, id, name: '', addedAt, sealed, preview: null, drive: f.hash });
          changed++;
        }
        for (const it of local) {
          if (it.drive || who !== identity) continue;
          await driveKeep(it);
          changed++;
          const e = shown.find((x) => x.id === it.id);
          if (e) { e.drive = it.drive; drawCount(); }
        }
        drive.usage = (await authed(() => driveCall('/v1/me')).catch(() => null))?.usage || null;
      } catch (e) {
        if (who !== identity) return;
        drive.state = e instanceof DriveError ? (e.status === 403 ? 'invite' : 'down') : 'declined';
        drive.why = (e && e.message) || '';
      } finally {
        syncing = null;
        if (who === identity) { if (changed) loadPhotos(); else drawCount(); }
      }
    })());
  }

  async function opened(e) {
    let o = urls.get(e.id);
    if (!o) {
      const r = await unseal(wallet, e.body);
      o = { url: URL.createObjectURL(r.blob), meta: r.meta, bytes: r.blob.size };
      urls.set(e.id, o);
      // Fetched from bDriveX: its fingerprint was sealed inside. Keep it on this device so imports skip it.
      if (e.local && !e.local.src && r.meta.src) { e.local.src = r.meta.src; store.put(e.local).catch(() => {}); }
    }
    return o;
  }

  /* ---------- the photo page ---------- */

  let current = -1, usdPerBsv = null;
  fetch('https://api.whatsonchain.com/v1/bsv/main/exchangerate').then((r) => r.json()).then((j) => { if (j && j.rate > 0) usdPerBsv = j.rate; }).catch(() => {});
  const feeText = (sats) => {
    const usd = usdPerBsv ? (sats / 1e8) * usdPerBsv : null;
    return usd != null ? `${usd < 0.01 ? 'under 1 cent' : `about $${usd.toFixed(2)}`}, ${sats.toLocaleString()} sats` : `about ${sats.toLocaleString()} sats`;
  };
  const kb = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1e3))} KB`);
  const size = (n) => { const g = n / 1024 ** 3; return g >= 1 ? `${+g.toFixed(g >= 10 ? 0 : 1)} GB` : n ? kb(n) : '0 KB'; };

  async function openPhoto(i) {
    const e = shown[i];
    if (!e) return;
    current = i;
    const { url, meta, bytes } = await opened(e);
    if (current !== i) return;
    $('lbImg').src = url;
    $('lbImg').alt = meta.name || 'Photo';
    $('pvName').textContent = meta.name || 'Photo';
    const chips = e.txid
      ? ['Private', 'Encrypted with your wallet', 'Minted on chain', 'Preview in Wallet › NFTs']
      : ['Private', 'Encrypted with your wallet', e.drive ? 'In bDriveX, on all your devices' : e.local ? 'On this device only' : 'From your wallet', 'Not on chain', 'Nothing paid'];
    $('pvStatus').innerHTML = chips.map((c, k) => `<li class="${k < 2 || (k === 2 && (e.txid || e.drive)) ? 'ok' : ''}">${esc(c)}</li>`).join('');
    const mint = $('lbMint');
    mint.hidden = !!e.txid || !e.local;
    mint.disabled = !canMint;
    mint.textContent = canMint ? 'Mint on chain' : 'Minting opens soon';
    const fee = e.local ? quoteSats((e.local.preview?.length || PREVIEW_GUESS) + e.local.sealed.length) : 0;
    $('lbNote').textContent = e.txid
      ? 'Minted. The sealed original is on chain and held by your wallet, with a blurred preview in Wallet › NFTs.'
      : canMint
        ? `Minting puts this photo on chain, held by your wallet: the original stays sealed, and a blurred preview shows in Wallet › NFTs. The network fee is ${feeText(fee)}, and your wallet shows it before you approve. Minting is permanent.`
        : `Minting will put this photo on chain, held by your wallet. The network fee will be ${feeText(fee)}. Minting opens when the bWalletX phone update ships; until then the photo stays private ${e.drive ? 'in bDriveX' : 'on this device'}, and nothing is paid.`;
    $('lbTx').hidden = !e.txid;
    if (e.txid) $('lbTx').href = `https://whatsonchain.com/tx/${e.txid}`;
    $('lbSave').href = url;
    $('lbSave').download = `${(meta.name || 'photo').replace(/[^\w .-]/g, '')}.jpg`;
    $('lbDel').hidden = !e.local || !!e.txid;
    $('lbDel').textContent = e.drive ? 'Delete from all your devices' : 'Remove from this device';
    const when = meta.addedAt || meta.mintedAt;
    const rows = [
      ['Added', when ? new Date(when).toLocaleString() : ''],
      ['Size', meta.w && meta.h ? `${meta.w} × ${meta.h} px · ${kb(bytes)}` : kb(bytes)],
      ['Location data', 'Removed'],
      ['Stored', e.txid && e.drive ? 'On chain and in bDriveX, sealed' : e.txid ? 'On chain, sealed' : e.drive ? 'In bDriveX, sealed' : 'In this browser, sealed'],
      ['Photo id', e.id],
    ].filter((r) => r[1]);
    $('pvMeta').innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
    $('pvPrev').hidden = $('pvNext').hidden = shown.length < 2;
    $('lb').hidden = false;
    document.body.classList.add('pv-open');
    $('lbX').focus();
  }
  function closePhoto() {
    $('lb').hidden = true;
    $('lbImg').removeAttribute('src');
    document.body.classList.remove('pv-open');
    current = -1;
  }
  const step = (d) => { if (shown.length > 1 && current >= 0) openPhoto((current + d + shown.length) % shown.length); };
  $('lbX').onclick = closePhoto;
  $('pvPrev').onclick = () => step(-1);
  $('pvNext').onclick = () => step(1);
  document.addEventListener('keydown', (e) => {
    if (!$('connectSheet').hidden && e.key === 'Escape') { $('sheetNo').click(); return; }
    if (!$('importSheet').hidden && e.key === 'Escape') { $('impDone').click(); return; }
    if ($('lb').hidden) return;
    if (e.key === 'Escape') closePhoto();
    if (e.key === 'ArrowLeft') step(-1);
    if (e.key === 'ArrowRight') step(1);
  });

  let minting = false;
  $('lbMint').onclick = async () => {
    const e = shown[current];
    if (!e || !e.local || !canMint || minting) return;
    minting = true;
    const btn = $('lbMint');
    btn.disabled = true;
    try {
      const o = urls.get(e.id);
      const txid = await mintPhoto(wallet, { ...e.local, name: e.local.name || o?.meta.name }, (s) => { btn.textContent = s; }, o?.url);
      e.local = { ...e.local, txid };
      closePhoto();
      toast('Minted. It’s on chain, held by your wallet.');
      loadPhotos();
    } catch (err) {
      btn.textContent = 'Mint on chain';
      $('lbNote').textContent = (err && err.message) || 'Not minted.';
    } finally {
      btn.disabled = !canMint;
      minting = false;
    }
  };
  // Removing an upload that isn't minted: a second tap confirms (no browser dialogs).
  $('lbDel').onclick = async () => {
    const e = shown[current], btn = $('lbDel');
    if (!e || !e.local || e.txid) return;
    const again = e.drive ? 'Tap again to delete everywhere' : 'Tap again to remove';
    if (btn.textContent !== again) { btn.textContent = again; return; }
    if (e.drive) {
      btn.disabled = true;
      try {
        await driveDelete(e.drive);
      } catch (err) {
        btn.textContent = (err && err.message) || 'Not deleted. Try again.';
        return;
      } finally { btn.disabled = false; }
    }
    await store.del(e.local.key);
    const u = urls.get(e.id);
    if (u) URL.revokeObjectURL(u.url);
    urls.delete(e.id);
    closePhoto();
    toast(e.drive ? 'Deleted from bDriveX and this device. Your other devices drop it when they next open bPhotosX.' : 'Removed from this device.');
    loadPhotos();
  };

  /* ---------- import: phones, folders and downloads (.zip) from other services ---------- */
  // iCloud, Photobox and the rest don't let other sites read your photos, so their downloads are the way in. A zip is
  // read from its central directory and inflated one entry at a time from slices of the file, so a multi-GB Google
  // Takeout never has to fit in memory. Stored and deflated entries, ZIP64 for big exports; encrypted zips are skipped.

  const PHOTO_FILE = /\.(jpe?g|png|heic|heif|webp|gif|tiff?|bmp|avif)$/i;
  const PHOTO_TYPE = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', heic: 'image/heic', heif: 'image/heif', webp: 'image/webp', gif: 'image/gif', tif: 'image/tiff', tiff: 'image/tiff', bmp: 'image/bmp', avif: 'image/avif' };
  const isPhoto = (f) => /^image\//.test(f.type) || PHOTO_FILE.test(f.name);
  const isZip = (f) => /\.zip$/i.test(f.name) || f.type === 'application/zip';

  async function zipPhotos(file) {
    const tailStart = Math.max(0, file.size - 65_557);
    const tail = new DataView(await file.slice(tailStart).arrayBuffer());
    let e = -1;
    for (let i = tail.byteLength - 22; i >= 0; i--) if (tail.getUint32(i, true) === 0x06054b50) { e = i; break; }
    if (e < 0) throw new Error(`${file.name} isn’t a zip file bPhotosX can read.`);
    let count = tail.getUint16(e + 10, true), cdSize = tail.getUint32(e + 12, true), cdOff = tail.getUint32(e + 16, true);
    if ((cdOff === 0xffffffff || count === 0xffff) && e >= 20 && tail.getUint32(e - 20, true) === 0x07064b50) {
      const at = Number(tail.getBigUint64(e - 12, true));
      const z = new DataView(await file.slice(at, at + 56).arrayBuffer());
      count = Number(z.getBigUint64(32, true)); cdSize = Number(z.getBigUint64(40, true)); cdOff = Number(z.getBigUint64(48, true));
    }
    const cd = new DataView(await file.slice(cdOff, cdOff + cdSize).arrayBuffer());
    const out = [];
    for (let n = 0, p = 0; n < count && p + 46 <= cd.byteLength && cd.getUint32(p, true) === 0x02014b50; n++) {
      const flags = cd.getUint16(p + 8, true), method = cd.getUint16(p + 10, true);
      let csize = cd.getUint32(p + 20, true), usize = cd.getUint32(p + 24, true), off = cd.getUint32(p + 42, true);
      const nameLen = cd.getUint16(p + 28, true), extraLen = cd.getUint16(p + 30, true), commentLen = cd.getUint16(p + 32, true);
      const path = new TextDecoder().decode(new Uint8Array(cd.buffer, p + 46, nameLen));
      for (let x = p + 46 + nameLen, end = x + extraLen; x + 4 <= end; x += 4 + cd.getUint16(x + 2, true)) {
        if (cd.getUint16(x, true) !== 1) continue; // ZIP64 sizes and offset, in this order, only where the 32-bit field is full
        let q = x + 4;
        if (usize === 0xffffffff) { usize = Number(cd.getBigUint64(q, true)); q += 8; }
        if (csize === 0xffffffff) { csize = Number(cd.getBigUint64(q, true)); q += 8; }
        if (off === 0xffffffff) off = Number(cd.getBigUint64(q, true));
      }
      p += 46 + nameLen + extraLen + commentLen;
      const name = path.split('/').pop();
      if (!PHOTO_FILE.test(name) || name.startsWith('._') || path.includes('__MACOSX/') || flags & 1 || (method !== 0 && method !== 8)) continue;
      out.push({
        name, size: usize,
        open: async () => {
          const h = new DataView(await file.slice(off, off + 30).arrayBuffer());
          const start = off + 30 + h.getUint16(26, true) + h.getUint16(28, true);
          const raw = file.slice(start, start + csize);
          const body = method === 0 ? raw : await new Response(raw.stream().pipeThrough(new DecompressionStream('deflate-raw'))).blob();
          return new File([body], name, { type: PHOTO_TYPE[name.split('.').pop().toLowerCase()] || '' });
        },
      });
    }
    return out;
  }

  /** Bring in many photos with one progress line: skips photos already here, and keeps going past ones that fail. */
  function importPhotos(label, sources) {
    if (!wallet || !sources.length) return;
    const li = document.createElement('li');
    li.className = 'job';
    li.innerHTML = '<span class="jn"></span><span class="js">Waiting</span><button class="stop" type="button">Stop</button>';
    li.querySelector('.jn').textContent = `Importing from ${label}`;
    const st = li.querySelector('.js'), stopBtn = li.querySelector('.stop');
    $('jobs').prepend(li);
    let stop = false, added = 0, dupes = 0, heic = 0, failed = 0;
    stopBtn.onclick = () => { stop = true; stopBtn.remove(); };
    const extras = () => [dupes && `${dupes} already here`, heic && `${heic} HEIC ${heic === 1 ? 'photo needs' : 'photos need'} Safari`, failed && `${failed} couldn’t be opened`].filter(Boolean);
    queue = queue.then(async () => {
      const who = identity;
      if (syncing) await syncing; // photos still arriving from bDriveX count as already here
      const mine = await store.mine(who);
      const seen = new Set(mine.map((it) => it.src).filter(Boolean));
      st.textContent = 'Checking your library';
      for (const it of mine) {
        if (it.src) continue;
        const o = await opened({ id: it.id, body: it.sealed, local: it }).catch(() => null);
        if (o?.meta.src) seen.add(o.meta.src);
      }
      for (let i = 0; i < sources.length && !stop && identity === who; i++) {
        st.textContent = [`${i + 1} of ${sources.length}`, ...extras()].join(' · ');
        try {
          const file = await sources[i].open();
          const src = await sha256(await file.arrayBuffer());
          if (seen.has(src)) { dupes++; continue; }
          await upload(wallet, file, (s) => {
            if (s === 'Sealing with your wallet' && !flag('bphotosx.sealed')) st.textContent = 'Approve in bWalletX: let bPhotosX seal your photos';
          }, src);
          flag('bphotosx.sealed', true);
          seen.add(src);
          added++;
          if (added % 8 === 0) loadPhotos();
        } catch {
          if (/\.(heic|heif)$/i.test(sources[i].name)) heic++; else failed++;
        }
      }
      stopBtn.remove();
      li.classList.add(added || dupes ? 'ok' : 'bad');
      st.textContent = [`${stop ? 'Stopped. ' : ''}${added === 1 ? '1 photo' : `${added} photos`} imported`, ...extras()].join(' · ');
      if (added) loadPhotos();
    });
  }

  async function importZip(z) {
    try {
      const list = await zipPhotos(z);
      if (!list.length) { toast(`No photos found in ${z.name}.`); return; }
      importPhotos(z.name, list);
    } catch (e) { toast((e && e.message) || `Couldn’t read ${z.name}.`); }
  }

  /* ---------- uploads ---------- */

  let queue = Promise.resolve();
  function addFiles(files, label) {
    if (!wallet) return;
    files.filter(isZip).forEach(importZip);
    const imgs = files.filter((f) => !isZip(f) && isPhoto(f));
    if (!imgs.length) { if (!files.some(isZip)) toast('Those aren’t photos. Try JPEG, PNG or HEIC photos, or a .zip of them.'); return; }
    // Many at once (a folder, a big selection): one progress line instead of one per photo.
    if (label || imgs.length > 6) { importPhotos(label || `${imgs.length} photos`, imgs.map((f) => ({ name: f.name, open: async () => f }))); return; }
    for (const file of imgs) {
      const li = document.createElement('li');
      li.className = 'job';
      const thumb = URL.createObjectURL(file);
      li.innerHTML = `<img alt=""><span class="jn"></span><span class="js">Waiting</span>`;
      li.querySelector('img').src = thumb;
      li.querySelector('.jn').textContent = file.name || 'Photo';
      const st = li.querySelector('.js');
      $('jobs').prepend(li);
      // One at a time: each photo is one wallet call to seal its key.
      queue = queue.then(async () => {
        try {
          const item = await upload(wallet, file, (s) => {
            st.textContent = s === 'Sealing with your wallet' && !flag('bphotosx.sealed')
              ? 'Approve in bWalletX: let bPhotosX seal your photos'
              : s;
          });
          flag('bphotosx.sealed', true);
          li.classList.add('ok');
          st.textContent = item.drive ? 'Uploaded · private · in bDriveX' : 'Uploaded · private · on this device';
          setTimeout(() => { li.remove(); URL.revokeObjectURL(thumb); }, 5000);
          loadPhotos();
        } catch (e) {
          li.classList.add('bad');
          st.textContent = (e && e.message) || 'Not uploaded.';
        }
      });
    }
  }
  $('pick').onchange = (e) => { addFiles([...e.target.files]); e.target.value = ''; };
  $('pickZip').onchange = (e) => { addFiles([...e.target.files]); e.target.value = ''; };
  $('pickDir').onchange = (e) => {
    const files = [...e.target.files];
    e.target.value = '';
    if (!files.length) return;
    const folder = (files[0].webkitRelativePath || '').split('/')[0] || 'a folder';
    const photos = files.filter((f) => isPhoto(f) && !f.name.startsWith('._'));
    if (!photos.length) { toast(`No photos found in ${folder}.`); return; }
    addFiles(photos, folder);
  };

  // Import sheet: where each kind of photo comes from, and a button for each.
  const importSheet = (open) => { $('importSheet').hidden = !open; if (open) $('importSheet').querySelector('[data-imp]').focus(); };
  $('importBtn').onclick = () => importSheet(true);
  $('impDone').onclick = () => importSheet(false);
  $('importSheet').onclick = (e) => { if (e.target === $('importSheet')) importSheet(false); };
  document.querySelectorAll('[data-imp]').forEach((b) => {
    b.onclick = () => {
      importSheet(false);
      $({ photos: 'pick', folder: 'pickDir', zip: 'pickZip' }[b.dataset.imp]).click();
    };
  });
  // Drop anywhere on the page while signed in.
  let dragDepth = 0;
  const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes('Files');
  document.addEventListener('dragenter', (e) => { if (!identity || !hasFiles(e)) return; e.preventDefault(); dragDepth++; $('dropzone').hidden = false; });
  document.addEventListener('dragover', (e) => { if (identity && hasFiles(e)) e.preventDefault(); });
  document.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('dropzone').hidden = true; } });
  document.addEventListener('drop', (e) => {
    if (!identity || !hasFiles(e)) return;
    e.preventDefault();
    dragDepth = 0;
    $('dropzone').hidden = true;
    goLibrary();
    addFiles([...e.dataTransfer.files]);
  });

  /* ---------- start ---------- */

  if (!C || !B) {
    $('connErr').textContent = 'Couldn’t load the wallet connector. Check your connection and reload.';
    $('connErr').hidden = false;
    return;
  }
  connectButtons().forEach((b) => {
    b.onclick = () => (identity ? goLibrary() : connect(false));
    C.bindPrewarm?.(b); // wakes the wallet on hover, focus or touch, before the click
  });
  try { C.prewarmBwalletX?.(); } catch {}
  drawNav();
  if (remembered()) connect(true); // extension, in-app browser or a stored pairing: no new QR
})();
