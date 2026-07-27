---
title: "The Last Toast"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: medium
points: ?
flag_format: "pbctf{...}"
author: "vikas1337"
---

# The Last Toast

## summary

webview murder-mystery android app. the dex is thin, all the logic is in assets/www/*.js. the case data is a base64 blob xor'd with a sha256 counter-mode stream keyed on a fixed phrase. decode it, brute the 4-digit safe, then brute who|how|why through a 50k-round sha256 KDF, verify, and xor out the flag.

## how i solved it

### 1. unpack, find the logic in js

```bash
unzip -o the-last-toast.apk -d ext && ls ext/assets/www
```

```text
index.html  engine.js  case_data.js  ...  # classes.dex is just a webview shell
```

### 2. decode the case blob

```text
case_data.js has window.CASE_BIN="57yAncYSc3bwr1Vl...". engine.js xors it with a sha256 counter-mode stream keyed "the-gilded-hour-strikes-eleven-forty-seven". decode with node.
```

```text
top-level keys: [ 'meta','rooms','suspects','evidence','safe','accuse','epilogue' ]
```

### 3. dead end: no plaintext 'gardener/foxglove' check

```text
the old writeup claimed suspect=='gardener' && poison=='foxglove' and a repeating-xor with b'gardener:foxglove'. none of that is in the code. the real check is a hash of a stretched key.
```

```text
no such strings
```

### 4. brute the safe code

```text
safe.check == sha256('safe-of-edmund-blackwood-'+code)[:16]. brute all 0000..9999.
```

```text
SAFE CODE = 1938
```

### 5. brute the accusation + xor the flag

```text
for each who/how/why option: sol=w.id|h.id|y.id|safe; key=deriveKey(sol, 50000 chained sha256 rounds); accept iff sha256(key||'verify')[:16]==accuse.verify. then flag = xorStream(b64decode(accuse.flag_ct), key).
```

```text
WHO = Dr. Elias Crane | HOW = Digitalis in the tonic | WHY = Nine years of blackmail
FLAG = pbctf{d34d_m3n_d0nt_bl33d_but_f0xgl0v3s_st1ll_bl00m}
```

## full solve script

```python
// node solve.js  - run against the decoded case.json
const crypto = require('crypto');
const C = require('./case.json');            // decoded CASE_BIN
const sha  = b => crypto.createHash('sha256').update(b).digest();
const hex16 = b => sha(b).toString('hex').slice(0, 16);
const U = s => Buffer.from(s, 'utf8');

// 1) brute the 4-digit safe
let safe = null;
for (let n = 0; n < 10000; n++) {
  const code = String(n).padStart(4, '0');
  if (hex16(U('safe-of-edmund-blackwood-' + code)) === C.safe.check) { safe = code; break; }
}
console.log('SAFE CODE =', safe);

// 2) 50k-round chained sha256 KDF
function deriveKey(solution, iters) {
  const s = U(solution);
  let h = sha(s);
  for (let i = 0; i < iters; i++) h = sha(Buffer.concat([h, s]));
  return h;
}
// sha256 counter-mode xor stream
function xorStream(data, key) {
  const out = Buffer.alloc(data.length); let n = 0;
  for (let off = 0; off < data.length; off += 32) {
    const ctr = Buffer.from([(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255]);
    const blk = sha(Buffer.concat([key, ctr]));
    for (let i = 0; i < 32 && off + i < data.length; i++) out[off+i] = data[off+i] ^ blk[i];
    n++;
  }
  return out;
}

// 3) brute who|how|why|safe, verify, xor the flag
const A = C.accuse;
let found = null;
outer:
for (const w of A.who) for (const h of A.how) for (const y of A.why) {
  const sol = [w.id, h.id, y.id, safe].join('|');
  const key = deriveKey(sol, A.kdf_iters);   // 50000
  if (hex16(Buffer.concat([key, U('verify')])) === A.verify) { found = { w, h, y, key }; break outer; }
}
console.log('WHO =', found.w.label, '| HOW =', found.h.label, '| WHY =', found.y.label);
console.log('FLAG =', xorStream(Buffer.from(A.flag_ct, 'base64'), found.key).toString('utf8'));
```

```text
SAFE CODE = 1938
WHO = Dr. Elias Crane | HOW = Digitalis in the tonic | WHY = Nine years of blackmail
FLAG = pbctf{d34d_m3n_d0nt_bl33d_but_f0xgl0v3s_st1ll_bl00m}
```

## flag

```
pbctf{d34d_m3n_d0nt_bl33d_but_f0xgl0v3s_st1ll_bl00m}
```
