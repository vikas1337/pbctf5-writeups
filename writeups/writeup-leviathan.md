---
title: "Leviathan"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: forensics
difficulty: hard
points: ?
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Leviathan

> ⚠️ **UNSOLVED.** the flag below is a **decoy** - it got produced but it's not the accepted one. leaving my notes up but this chall stays unsolved.

## summary

UNSOLVED (re-attacked the pcap hard with forensics). 94MB / 431k packets that DROWN a tiny real signal in engineered high-entropy noise. the obvious DNS exfil channel (sync-telemetry-io.net) decodes to a flag - but it's a DECOY that literally taunts 'lurks beneath the dns entropy'. i mapped every covert channel i could think of (fake-TLS, CDN-hidden base32, response counts/sizes/IPs/TTLs/txids/timing) and applied the 'leviathan' key hint everywhere - none give the real flag. genuinely stuck on the extraction method.

## how i solved it

### 1. protocol breakdown

```bash
tshark -r capture.pcap -q -z io,phs
```

```text
frames:431063
  udp/dns   337681   <- the loud channel
  tcp/tls    35453   (1303 _ws.malformed)
  http           4   (rickroll + 'the flag is in the DNS traffic :)')
```

### 2. the DNS exfil channel -> DECOY

```python
# sync-telemetry-io.net: 30 unique 32-char base32 labels, each queried 60x
# base32-decode the 30 -> 600 bytes, xor key 'kraken' (derived from pbctf{ prefix)
blob=b''.join(b32(l) for l in unique_30)
print(bytes(blob[i]^b'kraken'[i%6] for i in range(len(blob)))[:49])
```

```text
pbctf{th3_l3v14th4n_lurks_b3n34th_th3_dns_3ntr0py}
# DECOY (ctfd rejected). the remaining 550 bytes are pure random padding.
# all 60 rounds byte-identical, all labels exactly 60x -> no permutation/frequency channel.
```

### 3. fake TLS channel = noise

```bash
tshark -r capture.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.random | head
tshark -r capture.pcap -Y tls.handshake.extensions_server_name   # SNI
```

```text
1303 ClientHellos, NO SNI, NO ServerHello, NO cert. randoms all end in 0000.
37MB of 'application_data' (20561 records) - all high-entropy.
no xor key (leviathan/kraken/...) surfaces a PK/gzip/flag. synthetic filler.
```

### 4. second base32 channel hidden in the CDN cover

```python
# 1094 more 32-char base32 labels smuggled onto cloudflare/fbcdn/edgekey/... subdomains
# (real cover subdomains are english words; these aren't)
blob=b''.join(b32(l) for l in cdn_labels)  # 21880 bytes
```

```text
1094 labels across ~12 CDN domains. base32-decode -> high entropy under every key.
the decoy (sync-telemetry) decodes CLEAN under kraken; these don't -> engineered noise.
```

### 5. every low-bandwidth covert channel i tried

```text
# 'beneath the entropy' -> hunted the subtle channels:
```

```text
- DNS answer-count 1/2 (=response len 184/254): garbage in every bit-map/order/xor
- response IPs (last octet), TTLs (low byte / mod95): no ascii
- transaction IDs: random, no ordering key
- per-round permutation: identity every round; per-label frequency: uniform 60
- packet timing / txid sort: nothing
```

### 6. the 'leviathan' hint

```text
# vikas pointed out the challenge NAME is probably a clue
```

```text
tried leviathan/Leviathan/LEVIATHAN (+ kraken/nemo/Job41) as the xor key on EVERY
channel above -> no flag. if it points to the Leviathan stream cipher (McGrew/Fluhrer)
or a Job-41 chapter:verse index, that's a deep rabbit hole i couldn't find blind.
the real signal is buried too well for black-box forensics. UNSOLVED.
```

## full solve script

```python
#!/usr/bin/env python3
# leviathan - the DNS exfil decodes to a DECOY; real flag buried in engineered noise (UNSOLVED)
import base64, re
from collections import Counter

def b32(x):
    x=x.upper(); x+='='*((8-len(x)%8)%8)
    return base64.b32decode(x)

# 1) pull the sync-telemetry exfil labels (first-seen order), 30 unique x60
labels=[l.split('.')[0] for l in open('dns_queries_ordered.txt')
        if 'sync-telemetry-io' in l]
seen=[]; s=set()
for l in labels:
    if l not in s: s.add(l); seen.append(l)

# 2) base32 -> 600 bytes -> xor 'kraken' -> DECOY flag (first 49 bytes)
blob=b''.join(b32(l) for l in seen)
dec=bytes(blob[i]^b'kraken'[i%6] for i in range(len(blob)))
print(re.search(rb'pbctf\{[^}]*\}', dec).group(0))   # decoy

# 3) real flag is 'beneath the dns entropy' - NOT cracked.
#    checked: fake-TLS randoms/appdata, 1094 CDN-hidden base32 labels, DNS answer-count
#    (184/254), response IPs/TTLs/txids, round permutation, per-label frequency, timing.
#    tried xor key 'leviathan' everywhere. nothing surfaced.
```

```text
b'pbctf{th3_l3v14th4n_lurks_b3n34th_th3_dns_3ntr0py}'
# ^ DECOY (rejected). real flag hidden in the noise - extraction method unknown. UNSOLVED.
```

## flag

**decoy - not the real flag. chall unsolved.**

```
pbctf{th3_l3v14th4n_lurks_b3n34th_th3_dns_3ntr0py}   <- decoy
```
