---
title: "Sh*t Secrets Got Exposed"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: forensics
difficulty: medium
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Sh*t Secrets Got Exposed

## summary

long forensics trail: four torn QR fragments stitch into a google drive link -> valentine.png with LSB stego pointing at 'Saibar-Security' -> their github repo Attestation. the leaked CI deployment secret decrypts the encrypted export bundles, and the row checksums in the march bundle don't match what the code recomputes. the per-row deltas spell the flag. checksums lied and the bundle told on them.

## how i solved it

### 1. stitch the qr -> drive

```bash
unzip qr_slices.zip   # four 4096x4096 corner fragments of one big QR
# crop each finder quadrant, overlap-align, decode
python3 stitch.py && zbarimg qr_clean.png   # opencv fallback also works
```

```text
https://drive.google.com/file/d/1SBZQvK6F5CUKaDCkKNvpvKMS6t7AfMBz/view
```

### 2. grab the drive file + stego

```bash
curl -sL 'https://drive.google.com/uc?export=download&id=1SBZQvK6F5CUKaDCkKNvpvKMS6t7AfMBz' -o valentine_page.zip
unzip valentine_page.zip   # valentine.png
zsteg -a valentine.png | grep -i saibar
```

```text
b1,rgb,lsb,xy       .. text: "Saibar-Security"
```

### 3. clone the repo, dig history

```bash
git clone https://github.com/Saibar-Security/Attestation
cd Attestation
# ci pipeline leaked the deployment SECRET_KEY before it was moved to repo secrets
git log --all -p -- .github/workflows/ci.yml | grep -i secret_key
```

```text
SECRET_KEY: "3f9d2c7a1e6b48d05c93a7f21e4d8b60"   # <- the march deployment secret
```

### 4. note the decoys

```text
there are literally three pbctf strings in this repo ("three may keep a secret if two are dead"):
- .env EXPORT_SIGNING_KEY base64 -> pbctf{r0t4t3d_4nd_r3v0k3d_l0ng_ag0}  (decoy, flavor says revoked)
- NOTES.md on unmerged branch spike/import-perf -> pbctf{d3m0_d4t4_1s_n0t_ev1d3nc3}  (decoy)
- the checksum deltas in the march export bundle  (the real one)
```

```text
the two easy/signposted ones are traps. the real flag is in the encrypted bundle.
```

### 5. decrypt bundles + recompute checksums

```text
bundle = LKB1 header (magic/version/profile_id/reserved/len) + NDJSON XOR keystream. key = PBKDF2-HMAC-SHA256(deploy_secret, profile.salt, profile.iters), keystream = sha256(key||counter_be32). checksum.py: record = crc32(url + '\n' + title). recompute per row and compare to the stored 'checksum' field.
```

```text
2021_11 bundle: 96 rows, 0 drift (clean control). 2022_03 bundle: 240 rows, 49 drifted.
```

### 6. the deltas spell it

```text
for each drifted row: delta = stored_checksum XOR recomputed_checksum. the low byte of delta is a printable ascii char. read them in row order.
```

```text
[2022_03] drifted=49 lowbytes='pbctf{ch3cksums_l13d_4nd_th3_bundl3_t0ld_0n_th3m}'
```

## full solve script

```python
#!/usr/bin/env python3
# after: QR -> drive -> valentine.png (zsteg 'Saibar-Security') -> Attestation repo
# leaked CI deployment secret:
import os, json, hashlib, binascii, struct

SECRET = b'3f9d2c7a1e6b48d05c93a7f21e4d8b60'   # from .github/workflows/ci.yml history
# export_profiles from migrations/0007 (id -> salt, iterations)
PROFILES = {
    1: ('9c1f4a7d2e6b08f35a9d4c7e1b02f68a', 120000),
    2: ('42b7e0c95d18a36f7c04e9b2d5a81f30', 180000),
    3: ('d70e5b13c8a94f26b0d7e3a91c58f402', 210000),
    4: ('6a3c9e07f4b21d85e09c6a3f7d14b298', 240000),
}
EXPORTS = 'Attestation/tests/data/exports'

def keystream(key, n):
    out = b''
    c = 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack('>I', c)).digest()
        c += 1
    return out[:n]

def decrypt(path):
    blob = open(path, 'rb').read()
    assert blob[:4] == b'LKB1', 'bad magic'
    profile_id = blob[5]
    plen = struct.unpack('>I', blob[8:12])[0]
    payload = blob[12:12+plen]
    salt, iters = PROFILES[profile_id]
    key = hashlib.pbkdf2_hmac('sha256', SECRET, bytes.fromhex(salt), iters)
    ks = keystream(key, len(payload))
    ndjson = bytes(a ^ b for a, b in zip(payload, ks))
    return [json.loads(l) for l in ndjson.splitlines() if l.strip()]

def record_checksum(url, title):
    return f"{binascii.crc32(f'{url}\n{title}'.encode()) & 0xFFFFFFFF:08x}"

for name in sorted(os.listdir(EXPORTS)):
    rows = decrypt(os.path.join(EXPORTS, name))
    low = ''
    drift = 0
    for r in rows:
        want = record_checksum(r.get('url', ''), r.get('title', ''))
        have = r.get('checksum', '')
        if have != want:
            drift += 1
            delta = int(have, 16) ^ int(want, 16)
            low += chr(delta & 0xff)
    tag = name.split('.')[0]
    print(f"[{tag}] rows={len(rows)} drifted={drift} lowbytes={low!r}")
    if 'pbctf{' in low:
        print(low)
```

```text
[2021_11] rows=96 drifted=0 lowbytes=''
[2022_03] rows=240 drifted=49 lowbytes='pbctf{ch3cksums_l13d_4nd_th3_bundl3_t0ld_0n_th3m}'
pbctf{ch3cksums_l13d_4nd_th3_bundl3_t0ld_0n_th3m}
```

## flag

```
pbctf{ch3cksums_l13d_4nd_th3_bundl3_t0ld_0n_th3m}
```
