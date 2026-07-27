---
title: "Meridian ACU"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: misc
difficulty: medium
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Meridian ACU

## summary

spacecraft attitude-control unit whose 'provably correct' scheduler keeps missing deadlines. the firmware exposes more lock HANDLES than actual physical mutexes, so some handles secretly alias the same lock -> priority inversion. judge feeds you handles round by round and you submit the partition of handles by physical lock.

## how i solved it

### 1. read the drop, ignore the rabbit holes

```bash
./acu.elf --symbols   # hint: more handles than mutexes
cat mpu_config.txt    # README screams CVE-2025-ACU-0001 stack overflow -> bait
```

```text
mpu region is contained, the CVE/MPU stuff is a deliberate rabbit hole.
real bug: handles alias physical mutexes -> low prio task blocks high prio one.
```

### 2. connect to the judge

```bash
nc 172.198.160.128 1340
```

```text
{'meridian':'v1','rounds':7,'note':'submit the handle->lock partition of the handles revealed so far'}
```

### 3. the reconstruction rule

```text
each blocked_by(A,B) in the trace = tasks A and B contended on the SAME physical lock.
constraint C1: a single task's own handles are always distinct locks.
union-find: merge handles across tasks that share a blocked_by edge, keep one task's own handles apart.
```

```text
e.g. handles 5 and 6 turn out to alias -> 6 physical locks from 7 handles.
round k answer = the partition of all handles revealed up to round k (only 5&6 ever alias).
```

### 4. reply each round

```text
-> {"answer":[[0],[1],[2],[3],[4]]}   # partition so far
```

```text
<- {"status":"fragment", ...}  # correct, next partial view
... 7 rounds ... final fragment reveals the flag
```

## full solve script

```python
import socket, json
HOST, PORT = '172.198.160.128', 1340

class DSU:
    def __init__(s): s.p={}
    def find(s,x):
        s.p.setdefault(x,x)
        while s.p[x]!=x: s.p[x]=s.p[s.p[x]]; x=s.p[x]
        return x
    def union(s,a,b): s.p[s.find(a)]=s.find(b)

def recvjson(f):
    line=f.readline()
    return json.loads(line) if line.strip() else None

s=socket.create_connection((HOST,PORT)); f=s.makefile('rwb',buffering=0)
banner=recvjson(f); rounds=banner['rounds']
dsu=DSU(); handles=set()
for _ in range(rounds):
    frag=recvjson(f)['fragment']
    for h in frag['handles']: handles.add(h)
    # own-handle-sets stay split; blocked_by edges merge across tasks
    for a,b in frag.get('blocked_by',[]):
        dsu.union(a,b)
    groups={}
    for h in handles: groups.setdefault(dsu.find(h),[]).append(h)
    part=[sorted(v) for v in groups.values()]
    f.write((json.dumps({'answer':part})+'\n').encode())
    resp=recvjson(f)
    if resp and resp.get('flag'):
        print(resp['flag']); break

```

```text
banner {'meridian':'v1','rounds':7}
round 0 handles [0]            -> answer [[0]]                              -> fragment
round 1 handles [0,1]          -> answer [[0],[1]]                          -> fragment
round 2 handles [0,1,2]        -> answer [[0],[1],[2]]                      -> fragment
round 3 handles [0,1,2,3]      -> answer [[0],[1],[2],[3]]                  -> fragment
round 4 handles [0..4]         -> answer [[0],[1],[2],[3],[4]]              -> fragment
round 5 handles [0..5]         -> answer [[0],[1],[2],[3],[4],[5]]          -> fragment
round 6 handles [0..6]         -> answer [[0],[1],[2],[3],[4],[5,6]]        -> fragment
contention proves handles 5 and 6 alias the same physical lock -> 6 locks from 7 handles
pbctf{5tfu_c1aud3_a1}
```

## flag

```
pbctf{5tfu_c1aud3_a1}
```
