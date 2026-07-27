---
title: "Peephole"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: easy
points: 150
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Peephole

## summary

tiny static stripped binary. name screams obfuscation but the compiler's peephole pass already folded the MBA junk away, so the check is just plain ChaCha quarter-rounds + a murmur3 finalizer sitting inline in main. all invertible, no bruteforce.

## how i solved it

### 1. recon

```bash
file peephole
wc -c peephole
```

```text
peephole: ELF 64-bit LSB executable, x86-64, statically linked, stripped
7544 peephole
```

### 2. read main - structural check first

```text
objdump -d, everything is inline at 0x10013b0. no VM, no anti-debug.
len == 23; dword[0..4]==0x74636270 ('pbct'); word[4..6]==0x7b66 ('f{'); byte[22]=='}'
leaves 16 unknown bytes read as four LE u32.
```

```text
prefix pbctf{ , suffix } , 16 bytes in the middle to solve
```

### 3. the middle is a ChaCha quarter-round x4

```text
a=edx b=ecx c=esi d=eax and the sequence
 a+=b; d^=a; d<<<=16; c+=d; b^=c; b<<<=12; a+=b; d^=a; d<<<=8; c+=d; b^=c; b<<<=7
is exactly the ChaCha QR. before each round 'a' is XOR'd with a round const:
 0x2265b1f6, 0x91b7584b, 0xd8f16ae0, 0xcd613e31
```

```text
4 rounds, one const XOR per round
```

### 4. then a murmur3-style finalizer, compared to targets

```text
x = rol32(x*0x6c568775, 19) * 0xb56fa523  # both multipliers odd -> invertible
result XOR'd vs 4 targets, OR'd together, cmovne picks 'Nope' vs 'Correct'
```

```text
targets: dfc31daf 60417263 37de2fe6 15acf4a6
```

### 5. invert the whole chain

```python
a,b,c,d = [ifmix(t) for t in TARGET]
for k in reversed(CONSTS[1:]):
    a,b,c,d = iQR(a,b,c,d); a ^= k
a,b,c,d = iQR(a,b,c,d); a ^= CONSTS[0]
print(b'pbctf{' + struct.pack('<4I', a,b,c,d) + b'}')
```

```text
23 b'pbctf{MBA_tr4p_spr1ng!}'
verify: True
```

### 6. confirm against the binary

```bash
./peephole 'pbctf{MBA_tr4p_spr1ng!}'; echo EXIT=$?
```

```text
Correct
EXIT=0
```

## full solve script

```python
#!/usr/bin/env python3
# pbctf "Peephole" - 7.5KB static stripped clang/LLD binary, check inline in main.
# despite the name there's NO obfuscation left (peephole optimizer folded the MBA).
# 23-byte flag: pbctf{ + 16 mystery bytes + }. the 16 bytes = four LE u32 run
# through 4x ChaCha quarter-rounds (with a round const XOR'd into 'a' each round)
# then a Murmur3 finalizer, XOR-compared to 4 target consts. all invertible.
import struct
M = 0xffffffff
def rol(x, n): x &= M; return ((x << n) | (x >> (32 - n))) & M
def ror(x, n): x &= M; return ((x >> n) | (x << (32 - n))) & M

def QR(a, b, c, d):
    a=(a+b)&M; d^=a; d=rol(d,16)
    c=(c+d)&M; b^=c; b=rol(b,12)
    a=(a+b)&M; d^=a; d=rol(d,8)
    c=(c+d)&M; b^=c; b=rol(b,7)
    return a,b,c,d
def iQR(a, b, c, d):
    b=ror(b,7); b^=c; c=(c-d)&M
    d=ror(d,8); d^=a; a=(a-b)&M
    b=ror(b,12); b^=c; c=(c-d)&M
    d=ror(d,16); d^=a; a=(a-b)&M
    return a,b,c,d

K1, K2 = 0x6c568775, 0xb56fa523
iK1, iK2 = pow(K1,-1,1<<32), pow(K2,-1,1<<32)
def ifmix(y): return (ror((y*iK2)&M,19)*iK1)&M

CONSTS = [0x2265b1f6, 0x91b7584b, 0xd8f16ae0, 0xcd613e31]
TARGET = [0xdfc31daf, 0x60417263, 0x37de2fe6, 0x15acf4a6]   # a,b,c,d after finalizer

a,b,c,d = [ifmix(t) for t in TARGET]
for k in reversed(CONSTS[1:]):
    a,b,c,d = iQR(a,b,c,d); a ^= k
a,b,c,d = iQR(a,b,c,d); a ^= CONSTS[0]

flag = b'pbctf{' + struct.pack('<4I', a,b,c,d) + b'}'
print(len(flag), flag.decode())
```

```text
23 pbctf{MBA_tr4p_spr1ng!}
```

## flag

```
pbctf{MBA_tr4p_spr1ng!}
```
