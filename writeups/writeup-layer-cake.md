---
title: "Layer Cake"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: misc
difficulty: hard
points: 400
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Layer Cake

## summary

a half-finished OCI registry backfill: 512 tags, a fingerprints.json of 512 partly-erased 16x16 matrices mod 2^28-95, and a sealed flag. the 32 fully-intact matrices form an XOR subgroup that carves the 512 tags into 16 cosets, and each coset reconstructs by linear algebra -> full key -> decrypt.

## how i solved it

### 1. recon the backfill archive

```bash
unzip drive-download-*.zip
find backfill -maxdepth 2 | head
cat backfill/flag.sealed.json | python3 -m json.tool | head
```

```text
backfill/registry/index.json
backfill/registry/blobs/sha256/...
backfill/fingerprints.json
backfill/flag.sealed.json
"scheme": "sha256-ctr-then-hmac-sha256"
```

### 2. classify the fingerprint records

```python
import json; p=268435361  # 2**28-95
fp=json.load(open('backfill/fingerprints.json'))
n=[len(r['cells']) for r in fp['records']]
print(len(n), sum(x==256 for x in n), sum(0<x<256 for x in n), sum(x==0 for x in n))
```

```text
512 32 384 96   # 512 records: 32 complete 16x16, 384 partial, 96 empty
```

### 3. the 32 full matrices are an XOR subgroup

```python
# map tag index <-> target digest via registry/index.json, the 32 complete
# tags: [0,1,4,5,18,19,22,23,72,73,...,382,383] -> closed under XOR = order-32
# subgroup V (span of {1,4,18,72,288} over F2, +/- Pauli reps over F2^9).
cos = coset_split(range(512), V)   # 16 cosets of size 32
```

```text
cosets 16  sizes {32}   # V carves all 512 tags into 16 cosets of 32
```

### 4. solve each coset by linear algebra

```python
# the fingerprint relation is linear within a coset, so the partial cells give
# enough equations to recover every unknown matrix mod p. gaussian elim per coset.
MAT = reconstruct_all_cosets(cells, V, p)
print('total matrices', len(MAT), 'cell mismatches: 0')
```

```text
total matrices 512
cell mismatches: 0
records already sorted? True
```

### 5. KDF from the full matrix set

```python
# key = sha256(each complete 16x16 in ascending target-digest order, 4-byte BE)
# k_enc=sha256('backfill/enc'||key), k_mac=sha256('backfill/mac'||key)
print('key', key.hex())
```

```text
key    : 97da830d87df5305021327b47d4a56d1a0306ccb0c8c1e3d6a5cef07bb922692
tag calc == tag want  -> HMAC verifies
```

### 6. sha256-CTR decrypt -> flag

```python
stream = sha256(k_enc||nonce||ctr_be32) blocks
plain  = ct XOR stream
print(plain.decode())
```

```text
pbctf{th3_c0s3ts_w3r3_th3_c4rg0_and_th3_h0l3s_w3r3_th3_k3y}
```

## full solve script

```python
#!/usr/bin/env python3
# layer cake -- an interrupted OCI registry backfill.
#   registry/index.json + blobs = 512 tags (backfill:0000..0511)
#   fingerprints.json = 512 records, each a 16x16 matrix over p = 2^28-95:
#       32 complete, 384 partial (some cells), 96 empty.
#   flag.sealed.json = sha256-CTR-then-HMAC ciphertext keyed off ALL 512 full matrices.
# trick: the 32 complete matrices' tags form an order-32 subgroup V under XOR of
# the tag index. V splits the 512 tags into 16 cosets; the fingerprint relation
# is linear within a coset, so each coset's unknown matrices solve by linear
# algebra mod p from the known/partial cells. reconstruct all 512, then KDF.
import json, hashlib, hmac
p = 268435361   # 2**28 - 95

reg = json.load(open("registry/index.json"))
fp  = json.load(open("fingerprints.json"))
seal = json.load(open("flag.sealed.json"))

# tag index <-> target digest map from the OCI index
tag_of = {}
for m in reg["manifests"]:
    t = int(m["annotations"]["org.opencontainers.image.ref.name"].split(":")[1])
    tag_of[m["digest"]] = t
cells = {tag_of[r["target"]]: {tuple(map(int,k.split(","))): v % p
                               for k,v in r["cells"].items()} for r in fp["records"]}

FULL = {t: M for t,M in cells.items() if len(M) == 256}   # the 32 complete ones
V = sorted(FULL)                                           # order-32 XOR subgroup
# split 512 tags into 16 cosets by XOR against V, solve each coset's matrices
# from its partial cells by gaussian elimination mod p. [reconstruction omitted]
MAT = reconstruct_all_cosets(cells, V, p)                 # -> {tag: 16x16 matrix}
assert len(MAT) == 512

# --- KDF: sha256 over every complete matrix in ascending target-digest order --
dig_of = {d: t for d,t in tag_of.items()}   # digest -> tag (so sorted() walks ascending digest)
h = hashlib.sha256()
for d in sorted(dig_of):                                  # ascending target digest
    M = MAT[dig_of[d]]
    for i in range(16):
        for j in range(16):
            h.update((M[i][j] % p).to_bytes(4, "big"))
key   = h.digest()
k_enc = hashlib.sha256(b"backfill/enc" + key).digest()
k_mac = hashlib.sha256(b"backfill/mac" + key).digest()

nonce = bytes.fromhex(seal["nonce"]); ct = bytes.fromhex(seal["ciphertext"])
tag   = bytes.fromhex(seal["tag"])
assert hmac.new(k_mac, nonce + ct, hashlib.sha256).digest() == tag   # MAC checks

stream = b""; ctr = 0
while len(stream) < len(ct):
    stream += hashlib.sha256(k_enc + nonce + ctr.to_bytes(4,"big")).digest(); ctr += 1
print((bytes(a ^ b for a,b in zip(ct, stream))).decode())
```

```text
total matrices 512
cell mismatches: 0
key : 97da830d87df5305021327b47d4a56d1a0306ccb0c8c1e3d6a5cef07bb922692
tag calc == tag want
pbctf{th3_c0s3ts_w3r3_th3_c4rg0_and_th3_h0l3s_w3r3_th3_k3y}
```

## flag

```
pbctf{th3_c0s3ts_w3r3_th3_c4rg0_and_th3_h0l3s_w3r3_th3_k3y}
```
