---
title: "Cipher"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: medium
points: 300
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Cipher

## summary

reverse chall where the binary happily prints the 'encoded flag' every run but it looks different each time. turns out the whole cipher is seeded ONLY from the answer to its little math question, so there's no secret at all, just decode it.

## how i solved it

### 1. get past the login wall

```text
the unauth api blanks the connection info, but the authenticated CTFd description spells it out:
nc 172.198.160.128 1337
plus a Start-button ticket: 30.75a0cc5bbb8a768f (deterministic per-team HMAC, reusable)
```

```text
nc 172.198.160.128 1337
Ticket: 30.75a0cc5bbb8a768f
```

### 2. poke the service

```python
s = socket.create_connection(('172.198.160.128',1337))
print(s.recv(4096))
```

```text
b'Welcome to Cipher!\nPaste the ticket obtained from the CTFd Start button.\n\nTicket: '
# after ticket it asks: 'What is 2 * 4? ' then dumps 'Encoded flag values: ...'
```

### 3. output changes every run (the decoy)

```python
# run the local ./cipher binary twice, same FLAG env
print('run1:', run())
print('run2:', run())
print('AAAA :', run('AAAA'))
print('BA   :', run('BA'))
```

```text
run1: [133, 32, 77, 115, 238, 179, 239, 11, 29, 132, 104, 127, 99, 166, 67, 171]
run2: [133, 32, 77, 115, 238, 179, 239, 11, 29, 132, 104, 127, 99, 166, 67, 171]
AAAA : [133, 240, 118, 215]
BA   : [22, 150]
# wait it's stable per-answer? srand(time) only picks the QUESTION, not the cipher
```

### 4. spot where the seed comes from

```text
in the disasm the correct answer is left in ebx after the compare at 0x1241, and at 0x13aa
that SAME register gets reused as the cipher seed. no key.
seed  = (answer ^ 0x5A5A5A5A) + 0x13371337
state = xorshift32(seed)   // x^=x<<13; x^=x>>17; x^=x<<5
# xorshift Fisher-Yates shuffles positions, then per pos:
# out[p] = ((idx^k) + rol8(rol8(k,3)+(flag[idx]^k),2)) & 0xff
```

```text
seed depends only on the answer i already know -> whole thing invertible
```

### 5. decode + re-encode check across 3 live runs

```python
# connect 3x, answer the (different each time) question, decode
for i in range(3):
    q,a,v,f = once()
    assert encode(a,f)==v   # round-trips
    print(f'run{i+1}: {q:14s} ans={a:3d} ct[:6]={v[:6]} -> {f.decode()}')
```

```text
run1: What is 8 * 3?  ans= 24 ct[:6]=[48, 227, 53, 68, 51, 80]   -> pbctf{b3740b561656436b}
run2: What is 10 * 1? ans= 10 ct[:6]=[143, 26, 235, 181, 118, 246] -> pbctf{b3740b561656436b}
run3: What is 9 - 8?  ans=  1 ct[:6]=[8, 141, 224, 92, 216, 166]   -> pbctf{b3740b561656436b}

consistent across runs: True
```

## full solve script

```python
#!/usr/bin/env python3
# pbctf "Cipher" - the whole cipher is seeded ONLY from the answer you give
# to the arithmetic question, so it's fully deterministic + invertible.
# offline decode of one captured run: "What is 2 * 4?" -> answer 8
M = 0xffffffff
def rol8(x, n): x &= 0xff; return ((x << n) | (x >> (8 - n))) & 0xff
def ror8(x, n): x &= 0xff; return ((x >> n) | (x << (8 - n))) & 0xff

class XorShift32:
    def __init__(self, answer):
        s = ((answer ^ 0x5a5a5a5a) + 0x13371337) & M
        s ^= (s << 13) & M
        s ^= s >> 17
        nxt = (s ^ ((s << 5) & M)) & M
        self.x = 0x6d2b79f5 if s == 0 else nxt   # zero-state guard at 0x13e2
    def next(self):
        x = self.x
        x ^= (x << 13) & M
        x ^= x >> 17
        x ^= (x << 5) & M
        self.x = x & M
        return self.x

def permutation(answer, n):
    r = XorShift32(answer)
    arr = list(range(n))
    cnt = n
    for i in range(n - 1, 0, -1):
        j = r.next() % cnt
        cnt -= 1
        arr[i], arr[j] = arr[j], arr[i]
    return arr, r

def decode(answer, vals):
    n = len(vals)
    arr, r = permutation(answer, n)
    out = [0] * n
    for p in range(n):
        idx = arr[p]
        k = r.next()
        t3 = (vals[p] - (idx ^ k)) & 0xff
        t2 = ror8(t3, 2)
        t1 = rol8(k & 0xff, 3)
        out[idx] = ((t2 - t1) & 0xff) ^ (k & 0xff)
    return bytes(out)

# captured from the remote instance (ticket 30.75a0cc5bbb8a768f) on the "2 * 4" run
answer = 8
vals = [59,241,111,241,151,193,213,32,100,157,67,195,82,84,166,53,174,233,96,224,59,45,251]
print("FLAG:", decode(answer, vals).decode())
```

```text
FLAG: pbctf{b3740b561656436b}
```

## flag

```
pbctf{b3740b561656436b}
```
