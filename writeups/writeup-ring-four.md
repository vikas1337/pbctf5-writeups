---
title: "Ring Four"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: pwn
difficulty: hard
points: 250
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Ring Four

## summary

peg-solitaire-ish counting game over nc. leap = burn a neighbour, jump 3 rings up. the whole thing is the plastic number rho^3=rho+1: W=sum(rho^x) is conserved so pad 5 is unreachable (thats the 'fifth ring'). stage1/2 u answer a PLAN or IMPOSSIBLE, stage3 u count ordered leap sequences with a memoized bitmask dfs.

## how i solved it

### 1. read the handout

```text
nc 172.198.160.128 1341
# board: pads -140..12, one frog per pad.
# leap a:eps needs frogs on a and a+eps and empty a+3eps;
#   mover -> a+3eps, donor on a+eps destroyed. pad a+2eps irrelevant.
# 3 stages, 45 rounds, 600s, ONE wrong answer ends the session.
```

```text
stages: 12 (DELIVERY) + 8 (RETRIEVAL) + 25 (THE LONG LINE), 600s for the lot.
```

### 2. the key: plastic number invariant

```text
# a rightward leap removes a and a+1, adds a+3. weight W=sum(rho^x) is EXACTLY
# conserved iff rho^3 = rho+1 (rho~1.3247, the plastic number). leftward strictly
# decreases it. rho^5 = rho/(rho-1) = sup of infinitely many frogs on pads<=0,
# so no finite set on pads<=0 ever reaches pad 5. thats the fifth ring.
```

```text
min k, DELIVERY:  m1->2  m2->2  m3->3  m4->5  m>=5 IMPOSSIBLE
min k, RETRIEVAL: q1->1  q2->2  q3->2  q4->6  q>=5 IMPOSSIBLE
```

### 3. stage 1 DELIVERY (answer PLAN or IMPOSSIBLE)

```text
# place exactly k frogs on pads<=0 then leap a frog onto pad m.
[1/12] DELIVER m=3 k=6   -> PLAN -2,-1,0,-140,-138,-136 | -2:1,0:1
[3/12] DELIVER m=3 k=2   -> IMPOSSIBLE   (need k>=3 for m=3)
[6/12] DELIVER m=5 k=6   -> IMPOSSIBLE   (pad 5 never)
```

```text
ok ... ok ... ok   (12/12)
```

### 4. stage 2 RETRIEVAL

```text
[8/8] RETRIEVE q=1 k=5  -> PLAN 0,-140,-138,-136,-134 | 1:-1
```

```text
ok   (8/8)
```

### 5. stage 3 THE LONG LINE = count leap sequences

```text
# 'report the exact number of ordered leap sequences that end with pad T as the
#  one and only occupied pad.' -> memoized bitmask dfs over the position.
[2/25] COUNT T=2 frogs=-36,-35,...,-2   -> 384472
[7/25] COUNT T=1 frogs=-36,...,-3       -> 241113600   (python took 93s, ported to C)
[23/25] COUNT T=2 frogs=-34,...,-2      -> 6170644480
```

```text
ok x25
the relay is warm.  pbctf{th3_h0us3_k33p5_th3_f1fth_r1ng}
```

## full solve script

```python
#!/usr/bin/env python3
# ring.py - RING FOUR / the ladder. 3 stages, 45 rounds, 600s, one wrong = dead.
import socket, re, sys, time
sys.setrecursionlimit(300000)
HOST, PORT = '172.198.160.128', 1341
LO, HI = -140, 12
WIDTH = HI - LO + 1
FULL = (1 << WIDTH) - 1

# --- leap: mover a, donor a+eps destroyed, mover lands at a+3eps ("three rings on") ---
# W = sum(rho**x) with plastic number rho^3=rho+1 is conserved by rightward leaps,
# strictly decreases leftward => W non-increasing. rho^5 = rho/(rho-1) is the sup of
# infinite frogs on pads<=0, so pad 5 (and beyond) is unreachable for any k.

# STAGE 1 DELIVERY: place k frogs on pads<=0 then leap one onto pad m, or IMPOSSIBLE.
# min k table (from potential + tiny search):  m1:2  m2:2  m3:3  m4:5  m>=5:IMPOSSIBLE
DEL = {1:([-2,-1],[(-2,1)]),
       2:([-1,0],[(-1,1)]),
       3:([-2,-1,0],[(-2,1),(0,1)]),
       4:([-4,-3,-2,-1,0],[(-1,1),(-4,1),(-2,1),(1,1)])}
# STAGE 2 RETRIEVAL: bring the marked frog home (pad<=0).  q4 needs k=6, q>=5 IMPOSSIBLE.
RET = {1:([0],[(1,-1)]),
       2:([-2,-1],[(-2,1),(2,-1)]),
       3:([-1,0],[(-1,1),(3,-1)]),
       4:([-5,-4,-3,-2,-1,0],[(-2,1),(0,1),(4,-1),(-5,1),(-3,1),(1,-1)])}

def fillers(n, used):
    out=[]; p=-140
    while len(out)<n:
        if p not in used: out.append(p)
        p += 2
    return out

def fmt(S, L):
    return 'PLAN '+','.join(map(str,S))+' | '+','.join('%d:%d'%(a,e) for a,e in L)

def deliver(m, k):
    if m not in DEL: return 'IMPOSSIBLE'
    S,L = DEL[m]
    if k < len(S): return 'IMPOSSIBLE'
    return fmt(S+fillers(k-len(S), set(S)), L)

def retrieve(q, k):
    if q not in RET: return 'IMPOSSIBLE'
    S,L = RET[q]
    if k < len(S): return 'IMPOSSIBLE'
    return fmt(S+fillers(k-len(S), set(S)), L)

# STAGE 3 THE LONG LINE: count ordered leap sequences ending with only pad T occupied.
# memoized bitmask DFS. (python is slow on the big ones; a tiny C port does it instant,
# but the memo below is the same recurrence.)
def count(frogs, T):
    tgt = 1 << (T - LO)
    memo = {}
    def rec(m):
        if m == tgt: return 1
        r = memo.get(m)
        if r is not None: return r
        t = 0
        # rightward: mover a, donor a+1, land a+3
        c = m & (m>>1) & ~(m>>3) & (FULL>>3)
        cc = c
        while cc:
            b = cc & -cc; cc ^= b
            t += rec((m & ~b & ~(b<<1)) | (b<<3))
        # leftward: mover a, donor a-1, land a-3
        c = m & (m<<1) & ~(m<<3) & (FULL<<3) & FULL
        cc = c
        while cc:
            b = cc & -cc; cc ^= b
            t += rec((m & ~b & ~(b>>1)) | (b>>3))
        memo[m] = t
        return t
    start = 0
    for f in frogs: start |= 1 << (f - LO)
    return rec(start)

s = socket.create_connection((HOST, PORT), timeout=30)
buf = b''
def line():
    global buf
    while b'\n' not in buf:
        buf += s.recv(4096)
    ln, buf = buf.split(b'\n',1)
    return ln.decode(errors='replace')
def send(x):
    s.sendall(x.encode()+b'\n')

while True:
    ln = line()
    print(ln)
    if 'pbctf{' in ln: break
    m = re.search(r'DELIVER m=(-?\d+) k=(\d+)', ln)
    if m: send(deliver(int(m.group(1)), int(m.group(2)))); continue
    m = re.search(r'RETRIEVE q=(-?\d+) k=(\d+)', ln)
    if m: send(retrieve(int(m.group(1)), int(m.group(2)))); continue
    m = re.search(r'COUNT T=(-?\d+) frogs=([-\d,]+)', ln)
    if m:
        frogs = [int(x) for x in m.group(2).split(',')]
        send(str(count(frogs, int(m.group(1)))))
```

```text
-- STAGE 1 : DELIVERY --
[1/12] DELIVER m=3 k=6 ... ok
[3/12] DELIVER m=3 k=2 -> IMPOSSIBLE  ok
-- STAGE 2 : RETRIEVAL --
[8/8] RETRIEVE q=1 k=5 ... ok
-- STAGE 3 : THE LONG LINE --
[2/25] COUNT T=2 ... -> 384472  ok
[7/25] COUNT T=1 ... -> 241113600  ok
[25/25] COUNT T=1 ... -> 0  ok
the relay is warm.  pbctf{th3_h0us3_k33p5_th3_f1fth_r1ng}
```

## flag

```
pbctf{th3_h0us3_k33p5_th3_f1fth_r1ng}
```
