---
title: "Echo"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: web
difficulty: easy
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Echo

> ⚠️ **UNSOLVED.** the flag below is a **decoy** - it got produced but it's not the accepted one. leaving my notes up but this chall stays unsolved.

## summary

UNSOLVED. turned out the flag i pulled from flaghere.chetanr25.in (y0u_d1g_1t_y0u_k33p_1t) was actually a DIFFERENT challenge's flag, not echo's - so echo stays unsolved. the whole thing is a dig pun. the /wrong-number page is a dead end (wrong door), the apex TXT record decodes to 'right house, wrong door' which is itself a decoy. enumerate subdomains, hit flaghere.chetanr25.in, and its TXT record base64-decodes to the flag. you dig it, you keep it.

## how i solved it

### 1. the page is a dead end

```bash
curl -sL https://pbctf-challenge.chetanr25.in/wrong-number
```

```text
<title>pbctf</title> ... nothing useful, just a 'wrong number / wrong door' next.js page. dns is the channel.
```

### 2. apex TXT (decoy)

```bash
dig +short TXT chetanr25.in @8.8.8.8
echo 'cmlnaHQgaG91c2UsIHdyb25nIGRvb3I=' | base64 -d
```

```text
"flag=cmlnaHQgaG91c2UsIHdyb25nIGRvb3I="
right house, wrong door
```

### 3. enumerate subdomains

```bash
curl -s 'https://crt.sh/?q=%25.chetanr25.in&output=json' | python3 -c 'import sys,json;[print(n) for e in json.load(sys.stdin) for n in e["name_value"].split(chr(10))]' | sort -u
```

```text
flag.chetanr25.in
flaghere.chetanr25.in
ghost-notes.chetanr25.in
pbctf-challenge.chetanr25.in
...
```

### 4. dig the right door

```bash
dig +short TXT flaghere.chetanr25.in @8.8.8.8
dig +short TXT flaghere.chetanr25.in @8.8.8.8 | tr -d '"' | base64 -d
```

```text
"IHBiY3Rme3kwdV9kMWdfMXRfeTB1X2szM3BfMXR9"
 pbctf{y0u_d1g_1t_y0u_k33p_1t}   (leading space is just TXT formatting)
```

## full solve script

```python
#!/usr/bin/env bash
# apex TXT is a decoy: 'right house, wrong door'
dig +short TXT chetanr25.in @8.8.8.8 | tr -d '"' | sed 's/^flag=//' | base64 -d; echo
# crt.sh -> flaghere.chetanr25.in is the real door
dig +short TXT flaghere.chetanr25.in @8.8.8.8 | tr -d '"' | base64 -d | tr -d ' '; echo
```

```text
right house, wrong door
pbctf{y0u_d1g_1t_y0u_k33p_1t}
```

## flag

**decoy - not the real flag. chall unsolved.**

```
pbctf{y0u_d1g_1t_y0u_k33p_1t}   <- decoy
```
