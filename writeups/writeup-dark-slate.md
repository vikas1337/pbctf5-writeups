---
title: "The Dark Slate"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: web
difficulty: medium
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# The Dark Slate

> ⚠️ **UNSOLVED.** the flag below is a **decoy** - it got produced but it's not the accepted one. leaving my notes up but this chall stays unsolved.

## summary

UNSOLVED (re-attacked live). ctfd desc is just 'Draw it, ink it, seal it -> Slate Studio, a nocturnal drawing studio'. it's a next.js app ABSOLUTELY PACKED with decoy flags - i found 7 fake ones, each basically self-labeled. the real path is: develop the darkroom plate -> caesar-decode it with a shift hidden in the plate's 'grain' -> real clearance key -> a 'sealed export'. i mapped the whole thing and confirmed every decoy, but couldn't crack the grain-stego + the final seal step. the flag i first submitted (sl4t3_d4rkr00m_cl34r4nc3_k3y) is one of the decoys.

## how i solved it

### 1. recon: real endpoints

```bash
# next.js on vercel, bot-wall on pages/plate but /api/login works via curl
$ curl -s $B/api/status
$ curl -s $B/robots.txt
# fuzz /api -> only these are real:
```

```text
/api/plate   (POST, returns a PNG plate)
/api/login   (POST username+password)
/api/gallery (GET, community pieces)
/api/status  (GET, red herring)
robots.txt   -> mentions /vault (legacy, dead end)
```

### 2. develop the plate + the shift-42 decode

```python
# POST strokes for the studio mark '<. >' -> static PNG, ciphertext printed on it:
# ;-.?1F>7^?]*/^=6=ZZ8*.7]^=^9.]*6]DH
# only shift 42 (of 95 printable) decodes to clean text:
ct=';-.?1F>7^?]*/^=6=ZZ8*.7]^=^9.]*6]DH'
print(''.join(chr((ord(x)-32-42)%95+32) for x in ct))
```

```text
pbctf{sl4t3_d4rkr00m_cl34r4nc3_k3y}
# looks like the flag... it's a DECOY. plate even says:
# 'the shift is not written here - it is kept in the grain of the plate'
# (the tEXt chunk 'shift=53' is also a decoy)
```

### 3. the decoy minefield (7 fakes, all self-labeled)

```text
# every place you'd normally look has a taunting fake flag:
```

```text
plate (shift 42)      pbctf{sl4t3_d4rkr00m_cl34r4nc3_k3y}
gallery watermark #1  pbctf{w4t3rm4rk_l00ks_r34l_but_1snt}
gallery watermark #2  pbctf{f0lded_c0rn3r_d3c0y_h3r3}
gallery watermark #3  pbctf{4uto_g3n_pl4c3h0ld3r_fl4g}
gallery (mw bypass)   pbctf{g4ll3ry_s1gn4tur3_n0t_r34l}
/api/status           pbctf{st4tus_3ndp01nt_1s_a_r3d_h3rr1ng}
robots.txt /vault     pbctf{r0b0ts_txt_vault_1s_a_dead_3nd}
```

### 4. intended flow (per /api/status + robots + home)

```text
# /api/status clearance note + home page 'Sealed Exports' section:
```

```text
status: 'draw the studio mark to develop; the shift lives in the plate's grain'
home:   'every finished piece is signed and sealed with the clearance key you
         develop in the darkroom. your work, locked to you.'
=> real shift is in the plate GRAIN -> real clearance key -> unlock a 'sealed export'
```

### 5. dead-ends i cleared

```text
# so it's not the easy stuff:
```

```text
- login: rejects the clearance key + all 95 shift-decodes on every username;
  no sqli / nosql ($ne,$gt,$regex) / type-juggle / proto-pollution
- next.js CVE-2025-29927 (x-middleware-subrequest) -> no bypass
- plate is byte-identical every time (score/strokes/fields don't change it)
- no stego in LSB / residual / gamma / equalize; no data appended after IEND
- gallery ignores every clearance param/header/cookie
```

### 6. the wall

```text
# what's left uncracked:
```

```text
how 'the shift lives in the plate's grain' actually encodes the real shift
(not LSB, not visible even boosted, not the gradient banding) - and then how
the real clearance key unlocks the sealed export. that's the needle.
```

## full solve script

```python
#!/usr/bin/env python3
# the-dark-slate - live recon + decode (UNSOLVED: yields the decoy, real path is the grain-stego)
import requests
UA={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36'}
B='https://pctf-5-0-rqy2.vercel.app'

def seg(p1,p2,n=40):
    (x1,y1),(x2,y2)=p1,p2
    return [{'x':x1+(x2-x1)*i/(n-1),'y':y1+(y2-y1)*i/(n-1)} for i in range(n)]
# studio mark '<. >'
MARK=[seg((100,40),(55,85))+seg((55,85),(100,130)), seg((150,110),(151,111),4),
      seg((200,40),(245,85))+seg((245,85),(200,130))]

# 1) develop the plate
r=requests.post(B+'/api/plate',json={'strokes':MARK},
                headers={**UA,'Referer':B+'/darkroom'})
open('plate.png','wb').write(r.content)
print('match score:', r.headers.get('X-Match-Score'))

# 2) the ciphertext rendered on the plate, shift-42 caesar -> DECOY clearance key
ct=';-.?1F>7^?]*/^=6=ZZ8*.7]^=^9.]*6]DH'
for s in range(95):
    d=''.join(chr((ord(c)-32-s)%95+32) for c in ct)
    if d.startswith('pbctf{'):
        print('shift',s,'->',d)   # shift 42 -> pbctf{sl4t3_d4rkr00m_cl34r4nc3_k3y}  (DECOY)

# 3) the real shift is hidden 'in the plate's grain' -> real clearance key -> sealed export
#    ^ NOT cracked. every obvious path returns a labeled decoy (see notes).
```

```text
match score: 0.84
shift 42 -> pbctf{sl4t3_d4rkr00m_cl34r4nc3_k3y}
# that's a DECOY (ctfd rejected it). 6 other decoys found across gallery/status/robots.
# real flag = grain-shift -> real clearance key -> sealed export : UNSOLVED
```

## flag

**decoy - not the real flag. chall unsolved.**

```
pbctf{sl4t3_d4rkr00m_cl34r4nc3_k3y}   <- decoy
```
