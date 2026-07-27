---
title: "Qrly Diagnostics"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: easy
points: 150
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Qrly Diagnostics

## summary

flutter/dart AOT android app. decompile libapp.so with blutter, find Secret.reveal() in the qrcode_scanner package which xors a 36-byte const array against the repeating key "Qrly" then String.fromCharCodes. fully static, no need to run the app.

## how i solved it

### 1. recon the apk

```bash
unzip -o qrly-diagnostics.apk -d apk && ls apk/lib/arm64-v8a/
```

```text
libapp.so
libflutter.so
# com.chetanr25.qrlydiagnostics v2.2.0 -> flutter/dart AOT
```

### 2. dead end: grep the .so for the flag

```bash
strings -a apk/lib/arm64-v8a/libapp.so | grep -i 'pbctf{'
```

```text
(nothing) - flag isn't a plaintext const, it's xor-encoded in a byte array
```

### 3. blutter the AOT snapshot

```text
run blutter (dart 3.12.1) against libapp.so to reconstruct the dart source tree. look through the package classes.
```

```text
package:qrcode_scanner/core/secret.dart -> class Secret { reveal() {...} }
```

### 4. read Secret.reveal()

```text
reveal() holds a 36-byte int list and a 4-byte key, does data[i]^key[i%4] for all i, then String.fromCharCodes. the writeup that said it concatenates 3 const strings / 'long-press version -> build hash' was wrong, none of that exists.
```

```text
const data = [0x21,0x10,0x0f,...,0x58,0x04];  const key = [0x51,0x72,0x6c,0x79]; // "Qrly"
```

### 5. xor it out

```python
d=[0x21,0x10,0x0f,...]; k=[0x51,0x72,0x6c,0x79]
print(bytes(d[i]^k[i%4] for i in range(len(d))).decode())
```

```text
pbctf{qr_c0d3_or_dart_c0d3_500af714}
```

## full solve script

```python
#!/usr/bin/env python3
# Secret.reveal() from package:qrcode_scanner/core/secret.dart, straight port
data = [0x21,0x10,0x0f,0x0d,0x37,0x09,0x1d,0x0b,0x0e,0x11,0x5c,0x1d,
        0x62,0x2d,0x03,0x0b,0x0e,0x16,0x0d,0x0b,0x25,0x2d,0x0f,0x49,
        0x35,0x41,0x33,0x4c,0x61,0x42,0x0d,0x1f,0x66,0x43,0x58,0x04]
key = [0x51,0x72,0x6c,0x79]   # "Qrly"
flag = bytes(data[i] ^ key[i % 4] for i in range(len(data)))
print(flag.decode())
```

```text
pbctf{qr_c0d3_or_dart_c0d3_500af714}
```

## flag

```
pbctf{qr_c0d3_or_dart_c0d3_500af714}
```
