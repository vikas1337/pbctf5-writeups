---
title: "Atmanirbhar Bharat"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: crypto
difficulty: easy
points: 100
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Atmanirbhar Bharat

## summary

rainbow table challenge. they give you a hash function + a position-seeded reduce function and 3 target hashes. you rebuild the chains, crack the 3 hashes to their plaintexts, then feed those to the provided flagcrypto.py to reveal the flag.

## how i solved it

### 1. peek at the zip

```bash
unzip -l atmanirbhar.zip
```

```text
flag.enc
flagcrypto.py
README.md
reduce_spec.py
target_hashes.txt
```

### 2. read the spec

```text
reduce_spec.py: H(x)=sha256, reduce(digest,column) maps a digest -> a length-5 string over charset a-zA-Z0-9 (62 chars), seeded by the column index. so keyspace is 62^5 = 916,132,832. classic rainbow table.
```

```text
charset=62, PWLEN=5, 62^5=916132832
```

### 3. dead end: dont brute the full space in python

```text
916M candidates * chain len in pure python = never finishing on this laptop. also byte-grepping flag.enc for pbctf{ obviously finds nothing since it's actually xor'd.
```

```text
too slow / nothing
```

### 4. reimpl H + reduce in C, build the table

```text
port H() and reduce(digest,column) to C. chain length 2000, ~458k chains per table. generate, then walk each target hash forward to find its chain and recover the plaintext.
```

```text
...902945a30f1b72a8e9c66d415  S3kDk
5e6d8edec8022823eea9787093cc0fae54098c131c20b89b7de019623a9d6988  MUGRp
2284985488dfe5b37398fc37669365ce5d1331394dc5feb46fc1378ea7b7b333  ZKorn
```

### 5. let flagcrypto reveal the flag

```python
import flagcrypto
flagcrypto.reveal(['S3kDk','MUGRp','ZKorn'], 'flag.enc')
```

```text
pbctf{s3dce_aka_reduc3}
```

## full solve script

```python
#!/usr/bin/env python3
# after the C cracker recovers the 3 plaintexts from target_hashes.txt,
# the shipped flagcrypto.py does the actual decrypt.
import hashlib

CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'  # 62
PWLEN = 5

def H(s):
    return hashlib.sha256(s.encode()).digest()

def reduce(digest, column):
    # position-seeded reduction, mirrors reduce_spec.py
    out = []
    v = int.from_bytes(digest, 'big') ^ (column * 0x9E3779B1)
    for _ in range(PWLEN):
        out.append(CHARSET[v % 62]); v //= 62
    return ''.join(out)

# the C build did the heavy lifting; recovered plaintexts:
plains = ['S3kDk', 'MUGRp', 'ZKorn']

# sanity: these H() match the 3 target hashes
for p in plains:
    print(H(p).hex(), p)

# now hand them to the provided reveal()
import flagcrypto
print('--- decrypt ---')
print(flagcrypto.reveal(plains, 'flag.enc'))
```

```text
902945a30f1b72a8e9c66d415... S3kDk
5e6d8edec8022823eea9787093cc0fae54098c131c20b89b7de019623a9d6988 MUGRp
2284985488dfe5b37398fc37669365ce5d1331394dc5feb46fc1378ea7b7b333 ZKorn
--- decrypt ---
pbctf{s3dce_aka_reduc3}
```

## flag

```
pbctf{s3dce_aka_reduc3}
```
