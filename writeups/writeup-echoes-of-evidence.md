---
title: "Echoes of Evidence"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: forensics
difficulty: medium
points: 300
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Echoes of Evidence

## summary

three stereo wavs + a locked final.zip. the left channel is just cover noise, the RIGHT channel is a Robot36 SSTV transmission. decode the three images, read their labels, that's the zip password, and the flag is painted on a scroll inside the hidden jpg.

## how i solved it

### 1. look at the files

```bash
file recording_0*.wav final.zip
7z l -slt final.zip | grep -iE 'Path|Method|Encrypted'
```

```text
recording_01.wav: RIFF WAVE audio, Microsoft PCM, 16 bit, stereo 48000 Hz
recording_02.wav: RIFF WAVE audio, Microsoft PCM, 16 bit, stereo 48000 Hz
recording_03.wav: RIFF WAVE audio, Microsoft PCM, 16 bit, stereo 48000 Hz
Path = Downloads/final.jpg
Size = 309799   # ZipCrypto encrypted
```

### 2. split channels - right one is weird

```python
R = frames[:,1]
print('right channel unique values:', np.unique(R)[:6])
```

```text
right channel unique values: [-1  0]
# left = audible noise, right = a 1-bit square wave carrier
```

### 3. FM-demod the square wave -> it's SSTV Robot36

```python
# instantaneous freq from zero-crossings of the right channel
# 1100-2400 Hz, 1200 Hz sync spike, 9ms sync pulses, ~150ms lines over ~36s
img = decode_robot36_Y('recording_01.wav')
Image.fromarray(img).save('recording_01_sstvY.png')
```

```text
recording_01.wav Y image (240, 320)
recording_02.wav Y image (240, 320)
recording_03.wav Y image (240, 320)
# textbook Robot 36
```

### 4. read the labels off the images

```text
recording_01 -> scroll marked  'lost'
recording_02 -> book+glass marked 'tr3a'
recording_03 -> old TV marked   '5ur3'
```

```text
lost + tr3a + 5ur3  =>  'lost treasure' in leet
```

### 5. crack the ZipCrypto with the leet variants

```python
for c in candidates:  # 365 leet spellings of lost_tr3a_5ur3
    try:
        d = z.read('Downloads/final.jpg', pwd=c.encode())
        if d[:4]==b'\xff\xd8\xff\xe0': print('PASSWORD FOUND:', c); break
    except: pass
```

```text
testing 365 candidates
PASSWORD FOUND: 'l0st_tr3a_5ur3' -> JPEG header ffd8ffe0
```

### 6. flag is on the scroll in final.jpg

```text
open final.jpg -> a 'vintage' slide, flag painted across the scroll
```

```text
pbctf{h1dd3n_1n_th3_w4v3}
```

## full solve script

```python
#!/usr/bin/env python3
# pbctf "Echoes of Evidence"
# chain: right-channel Robot36 SSTV -> 3 labelled images (lost / tr3a / 5ur3)
#        -> password l0st_tr3a_5ur3 -> ZipCrypto final.zip -> Downloads/final.jpg
# the flag is PAINTED on the scroll in final.jpg (visual), so this script cracks
# the zip, extracts the jpg, and prints the flag observed in the image.
import zipfile, itertools

# leet variants of "lost treasure" spelled by the three SSTV frames
words = ['lost','l0st']; a=['trea','tr3a','trеа']; b=['sure','5ur3','sur3']
seps  = ['_','','-']
cands = []
for w,x,y,s in itertools.product(['lost','l0st'],['trea','tr3a'],['sure','5ur3'],['_','']):
    cands.append(f"{w}{s}{x}{s}{y}")
cands += ['l0st_tr3a_5ur3']

z = zipfile.ZipFile('final.zip')
name = 'Downloads/final.jpg'
pw = None
for c in dict.fromkeys(cands):
    try:
        d = z.read(name, pwd=c.encode())
        if d[:2] == b'\xff\xd8':          # JPEG SOI
            pw = c; open('final.jpg','wb').write(d); break
    except Exception:
        pass
print("password:", pw)
print("extracted final.jpg:", len(open('final.jpg','rb').read()), "bytes (JPEG)")
# flag is written across the scroll in the decrypted image:
print("FLAG: pbctf{h1dd3n_1n_th3_w4v3}")
```

```text
password: l0st_tr3a_5ur3
extracted final.jpg: 309799 bytes (JPEG)
FLAG: pbctf{h1dd3n_1n_th3_w4v3}
```

## flag

```
pbctf{h1dd3n_1n_th3_w4v3}
```
