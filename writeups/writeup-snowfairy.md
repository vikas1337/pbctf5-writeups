---
title: "Snowfalls Snowfairy"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: misc
difficulty: medium
points: 250
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Snowfalls Snowfairy

## summary

MNEMO web app that's really a scrambled rubik's cube behind a FastAPI. gather all the white stickers onto the top face and a QR in the render resolves, pointing at a drive png. the QR is a decoy tho, the actual flag is in that image's LSB.

## how i solved it

### 1. map the api

```bash
# base = https://snowfall-mnemo.onrender.com/api
# endpoints: /new /move /rotate /scramble /reset  (no /state, no facelets json)
curl -s https://snowfall-mnemo.onrender.com/api/new | jq 'keys'
```

```text
["image", "qr", "progress", "session"]
# each response is a RENDERED cube image + a QR + progress 0..9
```

### 2. read the cube from pixels (no state endpoint)

```python
# /rotate only yaws through top + 4 sides (never the bottom).
# extract 27 visible stickers/view via connected-components, classify by hue
# (side faces render darker: olive=shaded yellow, grey=shaded white -> 6 colors)
faces = read_faces_from_images(rotate_all())
```

```text
U=white F=green R=red B=blue L=orange D=yellow
read all 54 stickers directly - the 4 yaw views plus F2/B2/R2/L2 rotations bring the
bottom (D) face into view, so nothing has to be inferred.
```

### 3. solve with magiccube, not kociemba

```python
import magiccube
from magiccube.solver.basic.basic_solver import BasicSolver
c = magiccube.Cube(3, state_string)
sol = BasicSolver(c).solve()
print('len', len(sol), 'solved', c.is_done())
```

```text
119 moves
solved: True
# LBL solver, longer than optimal but who cares
```

### 4. replay moves -> progress 9/9 -> QR resolves

```python
for m in sol: post('/api/move', {'move': str(m)})
# QR starts as noise, more true modules appear as white lands on top
print(decode_qr(final_image))
```

```text
progress: 9/9
QR -> https://drive.google.com/file/d/1BLvkuGnxMojGXkYCKWbijQZalQQr5D1H/view
# a Vajpayee poem PNG, 'MNEMO // recovered memory'
```

### 5. QR was a decoy - flag is in the png LSB

```python
im = np.array(Image.open('frag.png').convert('RGB'))  # 3840 x 3840
bits = (im & 1).reshape(-1)           # interleaved R,G,B
b = np.packbits(bits).tobytes()
print(b[b.find(b'pbctf'):][:60])
```

```text
frag.bin: PNG image data, 3840 x 3840, 8-bit/color RGB
[RGB-interleaved] FOUND b'pbctf' @bit 0: b'pbctf{wh1t3_f4c3_r3m3mb3r3d_th3_cub3_sp34ks}\x00...'
```

## full solve script

```python
#!/usr/bin/env python3
# pbctf "Snowfalls Snowfairy"
# MNEMO SPA over a FastAPI cube (/api/new,/move,/rotate,/scramble,/reset).
# solve the cube by gathering white onto the top face -> progress hits 9/9 ->
# the QR in the rendered image resolves -> a Google Drive PNG (3840x3840).
# the real flag is in that PNG's LSB (interleaved R,G,B, from the very first pixel).
# the QR itself is just a pointer / misdirection.
import numpy as np, requests
from PIL import Image
from io import BytesIO

# QR (decoded with OpenCV) pointed here:
DRIVE_ID = "1BLvkuGnxMojGXkYCKWbijQZalQQr5D1H"
raw = requests.get(f"https://drive.google.com/uc?export=download&id={DRIVE_ID}",
                   allow_redirects=True, timeout=60).content
im = np.array(Image.open(BytesIO(raw)).convert('RGB'))   # 3840 x 3840
bits = (im & 1).reshape(-1)                               # interleaved R,G,B LSBs
b = np.packbits(bits[:len(bits)//8*8].astype(np.uint8)).tobytes()
i = b.find(b'pbctf')
print("FLAG:", b[i:b.find(b'\x00', i)].decode())

```

```text
FLAG: pbctf{wh1t3_f4c3_r3m3mb3r3d_th3_cub3_sp34ks}
```

## flag

```
pbctf{wh1t3_f4c3_r3m3mb3r3d_th3_cub3_sp34ks}
```
