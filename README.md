# bPhotosX

bphotosx.com: the web face of bPics. Your photos, minted to your keys, private by default.

Open source (MIT, see LICENSE and TRADEMARKS.md). Static HTML, no build, no server, no database. Connects bWalletX with `@bwalletx/connect` (global build) and
mints through standard BRC-100 calls, so any BRC-100 wallet works.

## How a photo is minted

One transaction, two 1-sat outputs:

| vout | What | Basket | Key |
|---|---|---|---|
| 0 | Blurred preview, `image/jpeg`, ≤1 MB, plain ord envelope + P2PKH (no MAP) | `1sat` (shows in Wallet › NFTs) | `[1,'bwalletx ordinal receive']`, keyID `ordinal` (the wallet picks a fresh key) |
| 1 | Sealed original, `application/vnd.bphotosx.sealed` | `bphotosx` | `[1,'bphotosx photo']`, keyID `vault` (one address per wallet, so a seed restore can find them) |

vout 0 follows bWalletX's site-delivery rule (`src/services/siteTokens.ts`, `readImageInscription`) byte for byte.

Sealed body: `"BPX1" | idLen u8 | id | wrapLen u16 BE | wrapped key | iv(12) | AES-256-GCM(metaLen u32 BE | meta JSON | JPEG)`.
The AES key is random per photo and made in the browser; the wallet wraps it to itself with BRC-2
`encrypt({ protocolID: [1,'bphotosx photo'], keyID: id, counterparty: 'self' })`. Meta: `{ v, name, type, w, h, mintedAt }`.

Photos are re-encoded to 1600 px JPEG 0.85 (bPics sizing), which also drops EXIF and GPS.

## Run locally

```sh
python3 -m http.server 4321 --bind 127.0.0.1
```

## Deploy

Vercel project (team b0ase); `vercel.json` sets headers and the www → apex redirect.
