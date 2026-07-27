---
title: "Qrly License Check"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: medium
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Qrly License Check

## summary

flutter AOT apk with a client-side 'Pro' license gate. blutter it, the validator is ^QRLY-(\d{5})-([0-9a-f]{8})$ where the checksum is HMAC-SHA256(secret,serial) first 8 hex (NOT crc32). but the flag isn't from the pro unlock at all - the success handler just xors a 34-byte const against the key "Keyg". fully static.

## how i solved it

### 1. blutter the apk

```text
com.* flutter AOT app, run blutter (dart 3.12.1) on libapp.so and read the license logic.
```

```text
validator regex: ^QRLY-(\d{5})-([0-9a-f]{8})$
```

### 2. figure out the checksum

```text
checksum(serial) = HMAC-SHA256(key='qrly_v2_9f3c2a77_secret', serial).hexdigest()[:8]. the old writeup said 'plain crc32' and even self-contradicted (crc32 of its example != 96acc00a). it's hmac, not crc32.
```

```text
checksum('13371') = 0e93a09c
```

### 3. mint a valid key (keygen)

```python
import hmac,hashlib
cs=lambda s: hmac.new(b'qrly_v2_9f3c2a77_secret',s.encode(),hashlib.sha256).hexdigest()[:8]
for s in ['00000','13371','12345','99999']: print(f'QRLY-{s}-{cs(s)}')
```

```text
QRLY-00000-b28ae04d
QRLY-13371-0e93a09c
QRLY-12345-885f43c2
QRLY-99999-8f2d456f
```

### 4. dead end: the pro unlock doesn't print a flag

```text
no 'PRO-UNLIMITED-...' format, no 'scan forged QR -> PRO reveals flag'. that whole story is fabricated (and 500af714 is just bleed from the Qrly Diagnostics flag). the flag lives in the success handler as an xor'd const.
```

```text
success handler: 34-byte data array xor key [0x4b,0x65,0x79,0x67]
```

### 5. xor out the flag

```python
data=[0x3b,0x7,0x1a,...]; key=[0x4b,0x65,0x79,0x67]
print(bytes(data[i]^key[i%4] for i in range(len(data))).decode())
```

```text
KEY  : Keyg
FLAG : pbctf{f0rg3_th3_ch3cksum_96acc00a}
```

## full solve script

```python
#!/usr/bin/env python3
import hmac, hashlib, re

# --- the license validator (HMAC-SHA256, not crc32) ---
SECRET = b'qrly_v2_9f3c2a77_secret'
LICENSE_RE = re.compile(r'^QRLY-(\d{5})-([0-9a-f]{8})$')
def checksum(serial): return hmac.new(SECRET, serial.encode(), hashlib.sha256).hexdigest()[:8]
def mint(serial):     return f'QRLY-{serial}-{checksum(serial)}'
def validate(lic):
    m = LICENSE_RE.match(lic)
    return bool(m) and checksum(m.group(1)) == m.group(2)
print(mint('13371'), 'valid=', validate(mint('13371')))

# --- but the flag is just the xor'd const in the success handler ---
data = [0x3b,0x7,0x1a,0x13,0x2d,0x1e,0x1f,0x57,0x39,0x2,0x4a,0x38,0x3f,0xd,0x4a,0x38,
        0x28,0xd,0x4a,0x4,0x20,0x16,0xc,0xa,0x14,0x5c,0x4f,0x6,0x28,0x6,0x49,0x57,0x2a,0x18]
key = [0x4b,0x65,0x79,0x67]   # "Keyg"
print('KEY  :', bytes(key).decode())
print('FLAG :', bytes(data[i] ^ key[i % 4] for i in range(len(data))).decode())
```

```text
QRLY-13371-0e93a09c valid= True
KEY  : Keyg
FLAG : pbctf{f0rg3_th3_ch3cksum_96acc00a}
```

## flag

```
pbctf{f0rg3_th3_ch3cksum_96acc00a}
```
