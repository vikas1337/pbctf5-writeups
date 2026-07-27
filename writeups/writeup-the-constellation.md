---
title: "The Constellation"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: web
difficulty: hard
points: 400
flag_format: "pbctf{...}"
author: "vikas1337"
---

# The Constellation

## summary

web + crypto. the star chart isn't on the page, it's in the `x-star-catalog` response header (base64 -> 6 points). app.js treats every browser window as a 'star' at its viewport centre and streams that over a websocket; all windows in one CTFd session (shared via a SharedWorker) share a `session` id, and the server unlocks when it sees `need:6` stars whose arrangement matches the catalog constellation. i opened 6 websocket clients under one session, each posing one catalog point. the matcher is similarity-invariant (rotation/scale/translation) but has a MINIMUM-SCALE gate, so a 1:1 reproduction is rejected - scaling the whole shape up (x4) crosses the threshold and the server returns a sealed ciphertext. no ticket or jwt is involved. unseal with AES-256-CBC (IV=0), key = SHA-256 of the chart string.

## how i solved it

### 1. the chart rides the response header, not the page

```bash
curl -sI https://<instance>.fly.dev/ | grep -i star
# x-star-catalog: MTAsOTA7NzAsMjA7MTUwLDYwOzIxMCwxMDsxODAsMTIwOzkwLDE1MA==
echo MTAsOTA7NzAsMjA7MTUwLDYwOzIxMCwxMDsxODAsMTIwOzkwLDE1MA== | base64 -d
```

```text
x-star-catalog (base64) -> 10,90;70,20;150,60;210,10;180,120;90,150
6 points = the constellation the server wants to see.
```

### 2. read app.js: windows are 'stars' over a websocket

```text
# app.js: each browser WINDOW reports its viewport centre as a star, streamed over a websocket.
# windows in one CTFd session share a `session` (SharedWorker). server wants need:6 matching stars.
# protocol: {"type":"hello"} -> {session}; {"type":"hello","session":S} to join; {"type":"pose","x":..,"y":..}
```

```text
a single star does nothing - you need a CROWD of 6 in ONE session forming the catalog shape.
no ticket / no jwt anywhere in the protocol.
```

### 3. 1:1 reproduction is rejected (minimum-scale gate)

```text
# first tried posing the 6 catalog points at their exact coords (spread ~200px).
# server keeps replying 'need 6' / stays locked despite 6 connected stars.
```

```text
the similarity matcher has a MIN-SCALE gate: the shape is right but too small to register.
```

### 4. scale the shape up x4 across 6 websocket clients -> unlocked

```python
# open one session, then 6 ws clients each posing ONE catalog point scaled x4 (+offset 200,200)
for sc in (4, 8):        # both cross the gate
    # star i poses (x*sc+200, y*sc+200) on a loop
    ...
```

```text
[0..5] unlocked: {"type":"unlocked","ciphertext":"0vJGGDvR+it7+bZk2jGMAe0ybvzI/O7uBJfcQfjSoQrvuQOPTlMYCQYFcbAOSSU3"}
SC=4 OFF=(200,200) -> unlocked (same for SC=8). scaling up = the whole trick.
```

### 5. unseal: the chart you read was the key

```python
import base64, hashlib
from Crypto.Cipher import AES
ct=base64.b64decode("0vJGGDvR+it7+bZk2jGMAe0ybvzI/O7uBJfcQfjSoQrvuQOPTlMYCQYFcbAOSSU3")
chart="10,90;70,20;150,60;210,10;180,120;90,150"
key=hashlib.sha256(chart.encode()).digest()      # AES-256
pt=AES.new(key, AES.MODE_CBC, b'\x00'*16).decrypt(ct)
print(pt)
```

```text
b'pbctf{th3_sk1es_r3m3mb3r_wh4t_y0u_dr3w}\t\t\t\t\t\t\t\t\t'  (zero IV, \t padding)
```

## full solve script

```python
#!/usr/bin/env python3
# the constellation - 6 websocket 'stars' in one session, scaled up past the min-scale gate,
# then AES-256-CBC(IV=0, key=sha256(chart)) on the sealed ciphertext. NO ticket / NO jwt.
import asyncio, json, base64, hashlib, websockets
from Crypto.Cipher import AES

URL="wss://<instance>.fly.dev/"
PTS=[(10,90),(70,20),(150,60),(210,10),(180,120),(90,150)]   # from the x-star-catalog header
SC, OX, OY = 4, 200, 200                                       # scale up to clear the gate

async def star(session, pt, res):
    async with websockets.connect(URL) as ws:
        await ws.send(json.dumps({"type":"hello","session":session})); await ws.recv()
        x,y = pt[0]*SC+OX, pt[1]*SC+OY
        async def pose():
            while True:
                await ws.send(json.dumps({"type":"pose","x":x,"y":y})); await asyncio.sleep(0.2)
        t=asyncio.create_task(pose())
        try:
            while True:
                m=json.loads(await ws.recv())
                if m.get("type")=="unlocked": res["ct"]=m["ciphertext"]; return
        finally: t.cancel()

async def main():
    async with websockets.connect(URL) as w0:
        await w0.send(json.dumps({"type":"hello"})); session=json.loads(await w0.recv())["session"]
    res={}
    tasks=[asyncio.create_task(star(session,p,res)) for p in PTS]
    for _ in range(10):
        await asyncio.sleep(1)
        if res: break
    for t in tasks: t.cancel()
    ct=base64.b64decode(res["ct"])
    chart="10,90;70,20;150,60;210,10;180,120;90,150"
    key=hashlib.sha256(chart.encode()).digest()
    print(AES.new(key, AES.MODE_CBC, b'\x00'*16).decrypt(ct))

asyncio.run(main())

```

```text
6 stars unlocked -> ciphertext 0vJGGDvR+it7+bZk2jGMAe0ybvzI/O7uBJfcQfjSoQrvuQOPTlMYCQYFcbAOSSU3
AES-256-CBC (IV=0), key=sha256(chart) ->
b'pbctf{th3_sk1es_r3m3mb3r_wh4t_y0u_dr3w}\t\t\t\t\t\t\t\t\t'
```

## flag

```
pbctf{th3_sk1es_r3m3mb3r_wh4t_y0u_dr3w}
```
