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
    const [pw, ph] = fit(w, h, PREVIEW_EDGE);
    const [tw, th] = fit(w, h, 24);
    const tiny = canvas(tw, th);
    tiny.getContext('2d').drawImage(full, 0, 0, tw, th);
    const prev = canvas(pw, ph);
    const g = prev.getContext('2d');
    g.imageSmoothingEnabled = true;
    g.imageSmoothingQuality = 'high';
    if ('filter' in g) g.filter = 'blur(6px)';
    g.drawImage(tiny, -8, -8, pw + 16, ph + 16);
    src.close?.();
    const [photo, preview] = await Promise.all([jpeg(full, QUALITY), jpeg(prev, PREVIEW_QUALITY)]);
    return { photo: new Uint8Array(await photo.arrayBuffer()), preview: new Uint8Array(await preview.arrayBuffer()), w, h };
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

  async function upload(wallet, file, onStep) {
    onStep('Preparing');
    const { photo, preview, w, h } = await prepare(file);
    const id = toHex(crypto.getRandomValues(new Uint8Array(8)));
    const name = (file.name || 'Photo').replace(/\.[^.]+$/, '').slice(0, 100) || 'Photo';
    const addedAt = new Date().toISOString();
    onStep('Sealing with your wallet');
    const sealed = await seal(wallet, id, { v: 1, name, type: 'image/jpeg', w, h, addedAt }, photo);
    if (sealed.length > MAX_SEALED_BYTES) throw new Error('That photo is too big.');
    const item = { key: `${identity}:${id}`, identity, id, name, addedAt, sealed, preview };
    await store.put(item);
    return item;
  }

  async function mintPhoto(wallet, item, onStep) {
    const { sealed, preview, name, id } = item;
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
    await store.put({ ...item, txid });
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

  /* ---------- wallet ---------- */

  let wallet = null, identity = null;
  const STATUS = { finding: 'Opening your wallet…', opening: 'Approve in bWalletX…', signing: 'Approve in bWalletX…', pairing: 'Scan the QR…' };
  const buttons = () => [$('navBtn'), $('heroBtn'), $('libBtn')];
  const label = (t) => buttons().forEach((b) => { b.textContent = t; });

  function drawNav() {
    const nav = $('navBtn');
    if (identity) {
      nav.className = 'xs-btn xs-ghost who';
      nav.innerHTML = `<span class="dot"></span><span class="who-key">${esc(short(identity))}</span><span>Disconnect</span>`;
      nav.title = 'Connected to bWalletX. Click to disconnect.';
    } else {
      nav.className = 'xs-btn xs-gold';
      nav.textContent = 'Connect bWalletX';
      nav.title = '';
    }
    $('heroBtn').textContent = 'Open your library';
    $('libBtn').textContent = 'Connect bWalletX';
    $('out').hidden = !!identity;
    $('in').hidden = !identity;
  }

  async function connect(quiet) {
    const err = $('connErr');
    err.hidden = true;
    const modal = quiet ? null : C.pairingModal?.({ title: 'Connect bWalletX' });
    try {
      const r = await C.connectBwalletX({
        ...(modal ? { pairing: modal } : {}),
        onStatus: quiet ? undefined : (st) => STATUS[st] && label(STATUS[st]),
      });
      wallet = r.wallet;
      identity = (await wallet.getPublicKey({ identityKey: true })).publicKey;
      remember(true);
      drawNav();
      loadPhotos();
      if (!quiet) $('library').scrollIntoView({ behavior: 'smooth', block: 'start' });
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
    wallet = identity = null;
    urls.forEach((u) => URL.revokeObjectURL(u.url));
    urls.clear();
    $('grid').innerHTML = '';
    $('jobs').innerHTML = '';
    drawNav();
  }

  /* ---------- library ---------- */

  const urls = new Map(); // photo id -> { url, meta } of the opened photo (memory only, never stored)
  let loadSeq = 0;

  /** The photo id from a sealed body's header (plaintext there, reveals nothing), or null. */
  function sealedId(body) {
    if (!body || MAGIC.some((b, i) => body[i] !== b)) return null;
    return new TextDecoder().decode(body.subarray(5, 5 + body[4]));
  }

  async function loadPhotos() {
    const seq = ++loadSeq;
    const grid = $('grid'), count = $('count');
    count.textContent = 'Opening your photos…';
    // Uploaded on this device, plus anything minted (also found when uploaded elsewhere), one entry per photo id.
    const byId = new Map();
    for (const it of await store.mine(identity)) byId.set(it.id, { id: it.id, body: it.sealed, local: it, txid: it.txid || null });
    try {
      const r = await wallet.listOutputs({ basket: BASKET, include: 'locking scripts', limit: 200 });
      for (const o of r.outputs || []) {
        if (o.spendable === false) continue;
        const ins = o.lockingScript && readInscription(o.lockingScript);
        const id = ins && ins.type === SEALED_TYPE && sealedId(ins.body);
        if (!id) continue;
        const e = byId.get(id);
        const txid = String(o.outpoint).split(/[._]/)[0];
        if (e) e.txid = e.txid || txid; else byId.set(id, { id, body: ins.body, local: null, txid });
      }
    } catch {
      // the wallet can refuse a listing; this device's uploads still show
    }
    if (seq !== loadSeq) return;
    const entries = [...byId.values()].sort((a, b) => String(b.local?.addedAt || '').localeCompare(String(a.local?.addedAt || '')));
    const minted = entries.filter((e) => e.txid).length;
    count.textContent = !entries.length ? 'No photos yet.'
      : `${entries.length === 1 ? '1 photo' : `${entries.length} photos`}, sealed to your keys${minted ? ` · ${minted} minted` : ''}`;
    grid.innerHTML = '';
    if (!entries.length) {
      grid.innerHTML = '<p class="empty">Upload your first photo. It stays encrypted, and only your wallet can open it.</p>';
      return;
    }
    const tiles = entries.map((e) => {
      const t = document.createElement('button');
      t.type = 'button';
      t.className = 'tile locked';
      t.textContent = 'Opening…';
      t.disabled = true;
      grid.appendChild(t);
      return { e, t };
    });
    // Two at a time: every photo is one wallet decrypt, and the phone relay allows about 60 frames a minute.
    let next = 0;
    const work = async () => {
      while (next < tiles.length && seq === loadSeq) {
        const { e, t } = tiles[next++];
        try {
          let open = urls.get(e.id);
          if (!open) {
            const r = await unseal(wallet, e.body);
            if (seq !== loadSeq) return;
            open = { url: URL.createObjectURL(r.blob), meta: r.meta };
            urls.set(e.id, open);
          }
          const { url, meta } = open;
          t.className = 'tile';
          t.disabled = false;
          t.innerHTML = `<img alt=""><span class="badge${e.txid ? ' on' : ''}">${e.txid ? 'Minted' : 'On this device'}</span>`;
          const img = t.querySelector('img');
          img.src = url;
          img.alt = meta.name || 'Photo';
          t.onclick = () => openPhoto(e, url, meta);
        } catch {
          t.textContent = 'Can’t open';
        }
      }
    };
    await Promise.all([work(), work()]);
  }

  let current = null;
  function openPhoto(e, url, meta) {
    current = e;
    $('lbImg').src = url;
    $('lbImg').alt = meta.name || 'Photo';
    const when = meta.addedAt || meta.mintedAt;
    $('lbMeta').textContent = [meta.name, when && new Date(when).toLocaleDateString()].filter(Boolean).join(' · ');
    $('lbSave').href = url;
    $('lbSave').download = `${(meta.name || 'photo').replace(/[^\w .-]/g, '')}.jpg`;
    $('lbTx').hidden = !e.txid;
    if (e.txid) $('lbTx').href = `https://whatsonchain.com/tx/${e.txid}`;
    const mint = $('lbMint');
    mint.hidden = !!e.txid || !e.local;
    mint.disabled = !canMint;
    mint.textContent = canMint ? 'Mint on chain' : 'Minting opens soon';
    mint.title = canMint ? '' : 'Minting opens once the bWalletX phone update is out.';
    $('lbDel').hidden = !e.local || !!e.txid;
    $('lbDel').textContent = 'Remove';
    $('lbNote').textContent = e.txid
      ? 'Minted: the sealed original is on chain, held by your wallet, with a blurred preview in Wallet › NFTs.'
      : 'Uploaded: kept encrypted on this device. Mint it to put it on chain, held by your wallet. Your wallet shows the fee first, and minting is permanent.';
    $('lb').hidden = false;
    $('lbX').focus();
  }
  const closePhoto = () => { $('lb').hidden = true; $('lbImg').removeAttribute('src'); current = null; };
  $('lbX').onclick = closePhoto;
  $('lb').onclick = (e) => { if (e.target.closest('.lb-img') && e.target.tagName !== 'IMG') closePhoto(); };
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('lb').hidden) closePhoto(); });

  let minting = false;
  $('lbMint').onclick = async () => {
    const e = current;
    if (!e || !e.local || !canMint || minting) return;
    minting = true;
    const btn = $('lbMint');
    btn.disabled = true;
    try {
      const txid = await mintPhoto(wallet, e.local, (s) => { btn.textContent = s; });
      e.txid = txid;
      e.local = { ...e.local, txid };
      closePhoto();
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
    const e = current, btn = $('lbDel');
    if (!e || !e.local || e.txid) return;
    if (btn.textContent !== 'Tap again to remove') { btn.textContent = 'Tap again to remove'; return; }
    await store.del(e.local.key);
    const u = urls.get(e.id);
    if (u) URL.revokeObjectURL(u.url);
    urls.delete(e.id);
    closePhoto();
    loadPhotos();
  };

  /* ---------- uploads ---------- */

  let queue = Promise.resolve();
  function addFiles(files) {
    if (!wallet) return;
    for (const file of files) {
      if (!/^image\//.test(file.type) && !/\.(heic|heif)$/i.test(file.name)) continue;
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
          await upload(wallet, file, (s) => { st.textContent = s; });
          li.classList.add('ok');
          st.textContent = 'Uploaded · on this device';
          setTimeout(() => { li.remove(); URL.revokeObjectURL(thumb); }, 6000);
          loadPhotos();
        } catch (e) {
          li.classList.add('bad');
          st.textContent = (e && e.message) || 'Not uploaded.';
        }
      });
    }
  }
  $('pick').onchange = (e) => { addFiles([...e.target.files]); e.target.value = ''; };
  const drop = $('drop');
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); addFiles([...e.dataTransfer.files]); });

  /* ---------- start ---------- */

  if (!C || !B) {
    $('connErr').textContent = 'Couldn’t load the wallet connector. Check your connection and reload.';
    $('connErr').hidden = false;
    return;
  }
  buttons().forEach((b) => {
    b.onclick = () => {
      if (!identity) return connect(false);
      if (b.id === 'navBtn') return disconnect();
      $('library').scrollIntoView({ behavior: 'smooth', block: 'start' }); // already connected: go to the library
    };
    C.bindPrewarm?.(b); // wakes the wallet on hover, focus or touch, before the click
  });
  try { C.prewarmBwalletX?.(); } catch {}
  drawNav();
  if (remembered()) connect(true); // extension, in-app browser or a stored pairing: no new QR
})();
