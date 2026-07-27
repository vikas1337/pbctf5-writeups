---
title: "VaultKey"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: medium
points: 250
flag_format: "pbctf{...}"
author: "vikas1337"
---

# VaultKey

## summary

android apk, kotlin + a JNI native lib (NOT flutter). the token signer lives in libvault.so which is unstripped and exports hmac_sha256/computeToken. token = base64url_nopad(HMAC-SHA256(key, nonce)), key is sitting in .rodata. flag is 3 frags: part1 = a smali const-string, part2 = the /verify json body, part3 = the pdf /Keywords metadata (white-text in the pdf body is bait).

## how i solved it

### 1. crack open the apk

```bash
unzip -l vaultkey.apk | grep -E 'classes.dex|libvault'
apktool d -f -s vaultkey.apk -o apktool_out
```

```text
  1377692  classes.dex
    11872  lib/arm64-v8a/libvault.so
     8440  lib/armeabi-v7a/libvault.so
# it's kotlin/JNI, not dart. the signing happens in the native lib.
```

### 2. part1 + endpoints from smali

```bash
grep -RhoE '"[^"]*(vaultkey|part2|challenge|verify|pdfUrl)[^"]*"' apktool_out/smali | sort -u
```

```text
"ctf.vaultkey/C0NGR4TUL4T10NS_y0u_F0uND_1T"        <- part1 (a Log tag)
"https://pbctf-challenge.chetanr25.in/api/vaultkey/challenge"
"https://pbctf-challenge.chetanr25.in/api/vaultkey/verify"
"part2"   "pdfUrl"   "nonce"   "sig"   "exp"   "token"
```

### 3. libvault.so is unstripped -> read the exports

```bash
nm -D --defined-only lib/arm64-v8a/libvault.so | grep ' T '
```

```text
0000000000002198 T base64url_encode
0000000000001ff4 T hmac_sha256
0000000000001160 T Java_ctf_vaultkey_Native_computeToken
0000000000001de4 T sha256_final
# token = base64url( HMAC-SHA256(key, nonce) ). now find the key.
```

### 4. pull the 32-byte key out of .rodata

```bash
objdump -s -j .rodata lib/arm64-v8a/libvault.so | sed -n '/0b00/,/0b20/p'
```

```text
# computeToken assembles the key from TWO non-adjacent 16-byte constants:
#   ldr q0, [x?, #0xb00]     ; first half
#   ldr q1, [x?, #0xae0]     ; second half (NOT contiguous with the first)
0ae0  af97505d 274e80c8 e16a3904 0d7d57a7   .P]'N..j9...}W..
0b00  10e297e2 2ae1caf6 13f79749 e6314018   ....*......I.1@.
# key = 0xb00 half || 0xae0 half =
# 10e297e22ae1caf613f79749e6314018af97505d274e80c8e16a39040d7d57a7
```

### 5. sign live -> part2 + pdfUrl, then pdf metadata

```bash
python3 vaultkey.py
# then the pdf: DONT trust the white body text (bait: pbctf{n0t_th3_r34l_0ne_keep_digging})
pdfinfo premium.pdf | grep Keywords
```

```text
challenge 200 {"nonce":"577270aa868caab787d12fd5f1b96901","exp":1785061434,"sig":"..."}
token= BebomD6LfAi_g6CqvcLGOf0LAQfYq9kR9-oAFKOxjpw
verify 200 {"part2":"1N_7H3_N4T1v3","pdfUrl":"https://drive.google.com/uc?export=download&id=11Mfr1z6jRGq-9DiK7ldj6kbKo9xWaCnO"}
Keywords:  vaultkey; part3=0R4cL3_5uP3r
```

## full solve script

```python
#!/usr/bin/env python3
# vaultkey.py - sign the challenge with the native-lib key, collect all 3 frags
import hmac, hashlib, base64, json, urllib.request, urllib.error

# key lifted straight out of libvault.so .rodata (32 bytes @ 0xb00), the same bytes
# Java_ctf_vaultkey_Native_computeToken feeds to hmac_sha256.
KEY = bytes.fromhex('10e297e22ae1caf613f79749e6314018af97505d274e80c8e16a39040d7d57a7')
BASE = 'https://pbctf-challenge.chetanr25.in/api/vaultkey'

def b64url(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def token(nonce): return b64url(hmac.new(KEY, nonce.encode(), hashlib.sha256).digest())

def get(u):
    r = urllib.request.urlopen(urllib.request.Request(u, headers={'User-Agent':'okhttp/4'}))
    return r.read()
def post(u, obj):
    d = json.dumps(obj).encode()
    req = urllib.request.Request(u, data=d, headers={'Content-Type':'application/json','User-Agent':'okhttp/4'}, method='POST')
    try: return urllib.request.urlopen(req).read()
    except urllib.error.HTTPError as e: return e.read()

# part1: const-string in T0.smali  ->  Log tag "ctf.vaultkey/C0NGR4TUL4T10NS_y0u_F0uND_1T"
part1 = 'C0NGR4TUL4T10NS_y0u_F0uND_1T'

# part2 + pdfUrl come back from /verify once the token checks out
ch = json.loads(get(BASE+'/challenge'))
tok = token(ch['nonce'])
print('nonce', ch['nonce'], 'token', tok)
res = json.loads(post(BASE+'/verify', {'nonce':ch['nonce'],'exp':ch['exp'],'sig':ch['sig'],'token':tok}))
part2 = res['part2']
print('verify ->', res)

# part3: NOT the white-text bait in the pdf body (pbctf{n0t_th3_r34l_0ne_keep_digging}).
# the real frag hides in the pdf metadata /Keywords field.
pdf = get(res['pdfUrl'])
open('premium.pdf','wb').write(pdf)
import re
part3 = re.search(rb'/Keywords \(vaultkey; part3=([^)]+)\)', pdf).group(1).decode()

print('FLAG: pbctf{%s_%s_%s}' % (part1, part2, part3))
```

```text
nonce 577270aa868caab787d12fd5f1b96901 token BebomD6LfAi_g6CqvcLGOf0LAQfYq9kR9-oAFKOxjpw
verify -> {'part2': '1N_7H3_N4T1v3', 'pdfUrl': 'https://drive.google.com/uc?export=download&id=11Mfr1z6jRGq-9DiK7ldj6kbKo9xWaCnO'}
FLAG: pbctf{C0NGR4TUL4T10NS_y0u_F0uND_1T_1N_7H3_N4T1v3_0R4cL3_5uP3r}
```

## flag

```
pbctf{C0NGR4TUL4T10NS_y0u_F0uND_1T_1N_7H3_N4T1v3_0R4cL3_5uP3r}
```
